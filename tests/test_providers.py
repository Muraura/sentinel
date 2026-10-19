"""Fallback rules and the Ollama adapter, with fake clients: no API calls, no Ollama server needed."""
from types import SimpleNamespace as NS

import anthropic
import httpx2
import ollama
import pytest
from ollama import ChatResponse, Message

import agent.investigator as investigator
import agent.providers as providers
from agent.investigator import investigate
from agent.providers import AnthropicProvider, ModelTurn, OllamaProvider, ProviderUnavailable, ToolRequest, ToolResult

WINDOW = {"start": "2026-09-30T01:45:00Z", "end": "2026-09-30T03:00:00Z"}
REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


class RaisingClaude:
    """A Claude client whose every call fails with the given exception."""

    def __init__(self, error):
        self.beta = NS(messages=NS(create=lambda **_: (_ for _ in ()).throw(error)))


class FakeOllama:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def chat(self, **kwargs):
        self.requests.append(kwargs)
        return next(self.responses)


def ollama_reply(content="", tool_calls=(), done_reason="stop", prompt_tokens=500):
    calls = [Message.ToolCall(function=Message.ToolCall.Function(name=n, arguments=a)) for n, a in tool_calls]
    return ChatResponse(model="qwen3:14b", done=True, done_reason=done_reason, prompt_eval_count=prompt_tokens,
                        eval_count=50, message=Message(role="assistant", content=content, tool_calls=calls or None))


def bad_request(body):
    response = httpx2.Response(400, request=REQUEST)
    return anthropic.BadRequestError("bad request", response=response, body=body)


@pytest.fixture(autouse=True)
def no_trace_files(monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "TRACES_DIR", tmp_path)


def test_falls_back_to_ollama_when_claude_is_unreachable():
    backup = FakeOllama([
        ollama_reply(tool_calls=[("get_auth_events", {**WINDOW, "outcome": "failure"})]),
        ollama_reply(content="## Summary\\nSix failed logins. AUTH-00003"),
    ])
    trace = investigate("What happened?", providers=[
        AnthropicProvider(client=RaisingClaude(anthropic.APIConnectionError(request=REQUEST))),
        OllamaProvider(model="qwen3:14b", client=backup),
    ])
    assert trace.answer.startswith("## Summary")
    assert trace.models_used == ["qwen3:14b"]
    assert trace.provider_errors[0]["provider"] == "anthropic"
    assert len(backup.requests) == 2  # sticky: Claude is not retried on step 2


def test_account_on_hold_counts_as_unavailable():
    error = bad_request({"error": {"type": "invalid_request_error",
                                   "details": {"error_code": "organization_on_hold"}}})
    with pytest.raises(ProviderUnavailable):
        AnthropicProvider(client=RaisingClaude(error)).complete("system", [], [{"role": "user", "content": "hi"}])


def test_a_malformed_request_is_not_hidden_behind_the_backup():
    error = bad_request({"error": {"type": "invalid_request_error", "message": "tools.0: bad schema"}})
    with pytest.raises(anthropic.BadRequestError):
        AnthropicProvider(client=RaisingClaude(error)).complete("system", [], [{"role": "user", "content": "hi"}])


def test_a_refusal_is_never_sent_to_the_backup():
    refused = NS(stop_reason="refusal", content=[], stop_details=NS(category="cyber"),
                 usage=NS(input_tokens=10, output_tokens=0, cache_read_input_tokens=0))
    claude = NS(beta=NS(messages=NS(create=lambda **_: refused)))
    backup = FakeOllama([])
    trace = investigate("What happened?",
                        providers=[AnthropicProvider(client=claude), OllamaProvider(model="qwen3:14b", client=backup)])
    assert "declined" in trace.answer and backup.requests == []


def test_no_model_available_is_reported_clearly(monkeypatch):
    monkeypatch.setattr(providers, "_env", lambda: {})  # ignore the developer's own Sentinel/.env
    trace = investigate("What happened?", providers=[
        AnthropicProvider(client=RaisingClaude(anthropic.APIConnectionError(request=REQUEST))),
        OllamaProvider(model=None, client=FakeOllama([])),
    ])
    assert trace.answer.startswith("No model available")
    assert "OLLAMA_MODEL" in trace.answer


def test_ollama_translation_of_tools_and_history():
    backup = FakeOllama([ollama_reply(tool_calls=[("get_device_events", {**WINDOW, "status": "offline"})])])
    history = [
        {"role": "user", "content": "What happened?"},
        {"role": "assistant", "turn": ModelTurn(provider="ollama", model="m", stop_reason="tool_use",
                                                 tool_calls=[ToolRequest("x1", "count_events", {"group_by": ["service"]})])},
        {"role": "tool_results", "results": [ToolResult("x1", "count_events", "bad args", is_error=True)]},
    ]
    tools = [{"name": "count_events", "description": "Count events.", "input_schema": {"type": "object"}}]
    turn = OllamaProvider(model="qwen3:14b", client=backup).complete("You are Sentinel.", tools, history)

    sent = backup.requests[0]
    assert sent["messages"][0] == {"role": "system", "content": "You are Sentinel."}
    assert sent["messages"][-1] == {"role": "tool", "tool_name": "count_events", "content": "ERROR: bad args"}
    assert sent["tools"][0]["function"]["parameters"] == {"type": "object"}
    assert sent["options"]["num_ctx"] == 32768
    assert turn.stop_reason == "tool_use" and turn.tool_calls[0].id.startswith("ollama-")


def test_ollama_warns_when_context_is_nearly_full():
    backup = FakeOllama([ollama_reply(content="done", prompt_tokens=8000)])
    turn = OllamaProvider(model="m", num_ctx=8192, client=backup).complete("s", [], [{"role": "user", "content": "q"}])
    assert turn.warning and "OLLAMA_NUM_CTX" in turn.warning


# ---------- Hugging Face ----------

def hf_reply(content="", calls=(), finish="stop"):
    tool_calls = [NS(id=f"call_{i}", type="function", function=NS(name=n, arguments=a)) for i, (n, a) in enumerate(calls)]
    message = NS(role="assistant", content=content, reasoning=None, tool_calls=tool_calls or None)
    return NS(choices=[NS(finish_reason=finish, message=message)], usage=NS(prompt_tokens=900, completion_tokens=40))


class FakeHF:
    def __init__(self, responses):
        self.responses, self.requests = iter(responses), []

    def chat_completion(self, **kwargs):
        self.requests.append(kwargs)
        return next(self.responses)


def test_huggingface_runs_an_investigation():
    from agent.providers import HuggingFaceProvider
    hf = FakeHF([
        hf_reply(calls=[("get_auth_events", '{"start": "2026-09-30T01:45:00Z", "end": "2026-09-30T03:00:00Z"}')],
                 finish="tool_calls"),
        hf_reply(content="## Summary\nDone."),
    ])
    trace = investigate("What happened?", providers=[HuggingFaceProvider(model="Qwen/Qwen3-32B", token="x", client=hf)])
    assert trace.answer.startswith("## Summary") and trace.models_used == ["Qwen/Qwen3-32B"]
    second = hf.requests[1]["messages"]
    assert second[0]["role"] == "system"
    assert second[2]["tool_calls"][0]["id"] == "call_0"           # the model's own call, with its id
    assert second[3]["role"] == "tool" and second[3]["tool_call_id"] == "call_0"  # the result, matched by id


def test_huggingface_without_token_is_unavailable(monkeypatch):
    from agent.providers import HuggingFaceProvider
    monkeypatch.setattr(providers, "_env", lambda: {})
    monkeypatch.delenv("HF_TOKEN", raising=False)
    with pytest.raises(ProviderUnavailable, match="HF_TOKEN"):
        HuggingFaceProvider().complete("s", [], [{"role": "user", "content": "q"}])


def test_gemini_without_key_is_unavailable(monkeypatch):
    from agent.providers import GeminiProvider
    monkeypatch.setattr(providers, "_env", lambda: {})
    with pytest.raises(ProviderUnavailable, match="GEMINI_API_KEY"):
        GeminiProvider().complete("s", [], [{"role": "user", "content": "q"}])
