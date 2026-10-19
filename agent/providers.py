"""Model providers behind one interface, so the agent loop doesn't care which LLM is answering.

Claude is the primary model. Ollama (a local or self-hosted open model) is the backup for when Claude is
UNAVAILABLE: no key, account problem, network outage, rate limit, server error.

The backup is deliberately NOT used when Claude DECLINES a request (stop_reason "refusal"). Sending a refused
request to a model with weaker safeguards would turn the backup into a way around them.

The loop stores the conversation in a neutral shape, and each provider translates it to its own API:
    {"role": "user", "content": "<question>"}
    {"role": "assistant", "turn": ModelTurn}
    {"role": "tool_results", "results": [ToolResult, ...]}
"""
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anthropic
import ollama
from dotenv import dotenv_values

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
CLAUDE_MODEL = "claude-opus-5-5"


class ProviderUnavailable(Exception):
    """This provider can't serve the request right now. The loop moves on to the next one."""


@dataclass
class ToolRequest:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ToolResult:
    id: str
    name: str
    content: str
    is_error: bool


@dataclass
class ModelTurn:
    """One model response, normalised so the loop treats every provider the same way."""
    provider: str
    model: str
    stop_reason: str            # "tool_use" | "end_turn" | "max_tokens" | "refusal" | anything else = unexpected
    text: str = ""
    thinking: str = ""
    tool_calls: list[ToolRequest] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    refusal_category: str | None = None
    warning: str | None = None
    raw: Any = None             # Claude's original content blocks: must be sent back unchanged


def _env() -> dict:
    """Settings: Sentinel/.env first (so a stale key exported in the shell can't win locally), then environment
    variables, which is how a container or a Hugging Face Space receives its secrets."""
    return {**os.environ, **{k: v for k, v in dotenv_values(ENV_FILE).items() if v}}


# ---------------------------------------------------------------- Claude

class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = CLAUDE_MODEL, effort: str = "medium", client=None):
        self.model = model
        self.effort = effort
        self._client = client  # tests inject a fake client

    @property
    def client(self):
        if self._client is None:
            try:
                # Sentinel's own key in Sentinel/.env wins over any ANTHROPIC_API_KEY exported in the shell
                self._client = anthropic.Anthropic(api_key=_env().get("ANTHROPIC_API_KEY") or None)
            except anthropic.AnthropicError as e:
                raise ProviderUnavailable(f"Claude client could not start: {e}") from e
        return self._client

    def complete(self, system: str, tools: list[dict], history: list[dict]) -> ModelTurn:
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                tools=tools,
                messages=self._messages(history),
                thinking={"type": "adaptive", "display": "summarized"},  # summarized: so we can watch it reason
                output_config={"effort": self.effort},
                cache_control={"type": "ephemeral"},  # the system prompt, tools and history repeat every step
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",  # a safety decline is retried on Anthropic's recommended model, not Ollama
            )
        except (anthropic.APIConnectionError, anthropic.AuthenticationError, anthropic.PermissionDeniedError,
                anthropic.RateLimitError, anthropic.InternalServerError) as e:
            raise ProviderUnavailable(f"{type(e).__name__}: {e}") from e
        except anthropic.BadRequestError as e:
            if _is_account_problem(e):
                raise ProviderUnavailable(f"Claude account problem: {e}") from e
            raise  # a malformed request is OUR bug: fail loudly instead of hiding it behind the backup

        usage = response.usage
        blocks = response.content
        return ModelTurn(
            provider=self.name,
            model=self.model,
            stop_reason=response.stop_reason,
            text="\n".join(b.text for b in blocks if b.type == "text"),
            thinking="\n".join(b.thinking for b in blocks if b.type == "thinking" and b.thinking),
            tool_calls=[ToolRequest(b.id, b.name, b.input) for b in blocks if b.type == "tool_use"],
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_input_tokens or 0,
            refusal_category=response.stop_details.category if response.stop_reason == "refusal" else None,
            raw=blocks,
        )

    @staticmethod
    def _messages(history: list[dict]) -> list[dict]:
        messages = []
        for item in history:
            if item["role"] == "user":
                messages.append({"role": "user", "content": item["content"]})
            elif item["role"] == "assistant":
                turn: ModelTurn = item["turn"]
                if turn.provider == "anthropic":
                    content = turn.raw  # unchanged, thinking blocks included
                else:
                    content = ([{"type": "text", "text": turn.text}] if turn.text else []) + [
                        {"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in turn.tool_calls
                    ]
                messages.append({"role": "assistant", "content": content})
            else:  # all tool results go back in ONE user message, each matched to its tool_use id
                messages.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": r.id, "content": r.content, "is_error": r.is_error}
                    for r in item["results"]
                ]})
        return messages


def _is_account_problem(error: anthropic.BadRequestError) -> bool:
    body = error.body if isinstance(error.body, dict) else {}
    code = body.get("error", {}).get("details", {}).get("error_code")
    return code == "organization_on_hold" or "credit balance" in str(error).lower()


# ---------------------------------------------------------------- Ollama (backup)

class OllamaProvider:
    """A local or self-hosted open model, configured in Sentinel/.env:
        OLLAMA_HOST=http://localhost:11434   (or another machine's address)
        OLLAMA_MODEL=qwen3:14b               (must be a model with tool-calling support)
        OLLAMA_NUM_CTX=32768                 (context window; Ollama's small default silently cuts long prompts)
    """
    name = "ollama"

    def __init__(self, model: str | None = None, host: str | None = None, num_ctx: int | None = None, client=None):
        env = _env()
        self.model = model or env.get("OLLAMA_MODEL")
        self.host = host or env.get("OLLAMA_HOST") or "http://localhost:11434"
        self.num_ctx = int(num_ctx or env.get("OLLAMA_NUM_CTX") or 32768)
        self._client = client

    @property
    def client(self):
        if self._client is None:
            self._client = ollama.Client(host=self.host, timeout=300)  # local models can be slow
        return self._client

    def complete(self, system: str, tools: list[dict], history: list[dict]) -> ModelTurn:
        if not self.model:
            raise ProviderUnavailable("No backup model: set OLLAMA_MODEL in Sentinel/.env")
        try:
            response = self.client.chat(
                model=self.model,
                messages=[{"role": "system", "content": system}, *self._messages(history)],
                tools=[{"type": "function", "function": {
                    "name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
                    for t in tools],
                options={"num_ctx": self.num_ctx},
                stream=False,
            )
        except Exception as e:  # last resort in the chain: any failure means no model is available
            raise ProviderUnavailable(f"Ollama at {self.host} ({self.model}): {type(e).__name__}: {e}") from e

        message = response.message
        calls = [
            # Ollama tool calls carry no id; Sentinel makes one so every result can be matched to its call
            ToolRequest(id=f"ollama-{uuid.uuid4().hex[:8]}", name=c.function.name, input=_as_dict(c.function.arguments))
            for c in message.tool_calls or []
        ]
        prompt_tokens = response.prompt_eval_count or 0
        return ModelTurn(
            provider=self.name,
            model=self.model,
            stop_reason="tool_use" if calls else ("max_tokens" if response.done_reason == "length" else "end_turn"),
            text=message.content or "",
            thinking=message.thinking or "",
            tool_calls=calls,
            input_tokens=prompt_tokens,
            output_tokens=response.eval_count or 0,
            warning=f"prompt used {prompt_tokens:,} of {self.num_ctx:,} context tokens: earlier evidence may have "
                    f"been cut. Raise OLLAMA_NUM_CTX." if prompt_tokens >= self.num_ctx * 0.95 else None,
        )

    @staticmethod
    def _messages(history: list[dict]) -> list[dict]:
        messages = []
        for item in history:
            if item["role"] == "user":
                messages.append({"role": "user", "content": item["content"]})
            elif item["role"] == "assistant":
                turn: ModelTurn = item["turn"]
                messages.append({"role": "assistant", "content": turn.text, "tool_calls": [
                    {"function": {"name": c.name, "arguments": c.input}} for c in turn.tool_calls]})
            else:  # Ollama: one "tool" message per result, matched by tool name and order
                for r in item["results"]:
                    messages.append({"role": "tool", "tool_name": r.name,
                                     "content": f"ERROR: {r.content}" if r.is_error else r.content})
        return messages


def _as_dict(arguments: Any) -> dict:
    if isinstance(arguments, str):  # some models return arguments as a JSON string
        return json.loads(arguments)
    return dict(arguments or {})


# ---------------------------------------------------------------- Hugging Face Inference Providers

class HuggingFaceProvider:
    """Open models hosted by Hugging Face's inference providers, for the public demo. Configured in Sentinel/.env
    (or as Space secrets):
        HF_TOKEN=hf_...                 a Hugging Face access token with "Inference Providers" permission
        HF_MODEL=Qwen/Qwen3-32B         must support tool calling with the chosen provider
        HF_PROVIDER=auto                or a specific one: together, novita, fireworks-ai, ...
    Uses the OpenAI-style chat format: tool calls carry ids, and each result goes back as a "tool" message.
    """
    name = "huggingface"

    def __init__(self, model: str | None = None, token: str | None = None, provider: str | None = None, client=None):
        env = _env()
        self.model = model or env.get("HF_MODEL") or "Qwen/Qwen3-32B"
        self.token = token or env.get("HF_TOKEN")
        self.provider = provider or env.get("HF_PROVIDER") or "auto"
        self._client = client

    @property
    def client(self):
        if self._client is None:
            if not self.token:
                raise ProviderUnavailable("No Hugging Face token: set HF_TOKEN")
            from huggingface_hub import InferenceClient
            self._client = InferenceClient(provider=self.provider, api_key=self.token, timeout=180)
        return self._client

    def complete(self, system: str, tools: list[dict], history: list[dict]) -> ModelTurn:
        try:
            response = self.client.chat_completion(
                model=self.model,
                messages=[{"role": "system", "content": system}, *self._messages(history)],
                tools=[{"type": "function", "function": {
                    "name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
                    for t in tools],
                max_tokens=4096,
            )
        except ProviderUnavailable:
            raise
        except Exception as e:
            code = getattr(getattr(e, "response", None), "status_code", None)
            if code in (400, 422):  # a malformed request is our bug: don't hide it
                raise
            reason = "out of credits" if code == 402 else f"{type(e).__name__}: {e}"
            raise ProviderUnavailable(f"Hugging Face ({self.model}): {reason}") from e

        choice = response.choices[0]
        message = choice.message
        calls = [ToolRequest(id=c.id or f"hf-{uuid.uuid4().hex[:8]}", name=c.function.name,
                             input=_as_dict(c.function.arguments)) for c in message.tool_calls or []]
        usage = response.usage
        return ModelTurn(
            provider=self.name, model=self.model,
            stop_reason="tool_use" if calls else ("max_tokens" if choice.finish_reason == "length" else "end_turn"),
            text=message.content or "", thinking=getattr(message, "reasoning", None) or "", tool_calls=calls,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0, output_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )

    @staticmethod
    def _messages(history: list[dict]) -> list[dict]:
        messages = []
        for item in history:
            if item["role"] == "user":
                messages.append({"role": "user", "content": item["content"]})
            elif item["role"] == "assistant":
                turn: ModelTurn = item["turn"]
                message = {"role": "assistant", "content": turn.text or ""}
                if turn.tool_calls:
                    message["tool_calls"] = [{"id": c.id, "type": "function",
                                              "function": {"name": c.name, "arguments": json.dumps(c.input)}}
                                             for c in turn.tool_calls]
                messages.append(message)
            else:  # one "tool" message per result, matched to its call by tool_call_id
                for r in item["results"]:
                    messages.append({"role": "tool", "tool_call_id": r.id,
                                     "content": f"ERROR: {r.content}" if r.is_error else r.content})
        return messages


PROVIDER_CHOICES = ("auto", "claude", "ollama", "huggingface")


def build_providers(choice: str, effort: str = "medium") -> list:
    """auto = Claude first, then the local Ollama model; any other choice = only that provider."""
    return {
        "auto": lambda: [AnthropicProvider(effort=effort), OllamaProvider()],
        "claude": lambda: [AnthropicProvider(effort=effort)],
        "ollama": lambda: [OllamaProvider()],
        "huggingface": lambda: [HuggingFaceProvider()],
    }[choice]()
