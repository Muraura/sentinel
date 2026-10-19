"""Step-by-step log narration of an investigation: what the loop is doing, and which concept it shows.

Every line carries the investigation id, so concurrent investigations can be told apart in one log stream.
Concept notes (💡) explain the idea behind a phase the first time it happens in a run; set
SENTINEL_EXPLAIN=0 to turn them off and keep only the operational lines.
"""
import json
import logging
import os

log = logging.getLogger("sentinel.agent")

CONCEPTS = {
    "setup": "Every step the model receives exactly three things: the system prompt (rules), the tool definitions, "
             "and the conversation history. Nothing else: no database access, no memory.",
    "stateless": "The model has no memory between calls. The loop re-sends the whole history every step, "
                 "which is why each step costs more tokens than the last.",
    "tool_use": "stop_reason=tool_use: the model is asking for tools to be run. It cannot run them itself, "
                "so the loop continues.",
    "act": "ACT: the model only *requested* this call. Sentinel's code validates every argument and executes it. "
           "The LLM decides; deterministic code does the work.",
    "observe": "OBSERVE: tool results are appended to the history, so the model will see them at the next step. "
               "This is how the agent 'learns' what the data says.",
    "error_observation": "A failed tool call is not a crash. The error goes back to the model as an observation, "
                         "and it can correct its call at the next step.",
    "parallel": "The model asked for several tools in one turn. They all run, and all results go back together "
                "in one message.",
    "end_turn": "stop_reason=end_turn: the model decided it has enough evidence and wrote its answer. "
                "The model chooses when to stop; the step limit is the safety net.",
    "fallback": "FALLBACK: the primary model is unavailable, so the same history goes to the backup. It is sticky "
                "for the rest of the run, and never used when a model *declines* a request.",
    "report_submitted": "OUTPUT VALIDATION: the answer arrived as a structured report through a tool. Code checked "
                        "the schema and that every cited evidence ID exists before accepting it; a rejected report "
                        "goes back to the model as an error to fix.",
    "nudge": "The model answered in plain text instead of calling submit_report, so the loop reminds it once. "
             "The format of the final answer is enforced by code, not left to the model.",
    "step_limit": "The hard step limit stopped the loop. Every agent loop needs one: the model might never decide "
                  "to stop on its own.",
}


def _short(text: str, width: int = 300) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= width else text[:width] + "…"


def _result_facts(text: str) -> str:
    """Pull the size/truncation fields out of a tool result, if it has them."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ""
    if not isinstance(data, dict):
        return ""
    keys = ("total_matching", "total_items", "total", "total_patterns", "truncated", "found")
    return " · ".join(f"{k}={data[k]}" for k in keys if k in data)


class Narrator:
    def __init__(self, investigation_id: str):
        self.id = investigation_id
        self.explain = os.environ.get("SENTINEL_EXPLAIN", "1") != "0"
        self._explained: set[str] = set()

    def _log(self, message: str, level: int = logging.INFO) -> None:
        log.log(level, f"[{self.id}] {message}")

    def concept(self, key: str) -> None:
        if self.explain and key not in self._explained:
            self._explained.add(key)
            self._log(f"   💡 {CONCEPTS[key]}")

    # --- lifecycle ---

    def started(self, question: str, providers: list, max_steps: int, tool_count: int) -> None:
        chain = " → ".join(f"{p.name}:{p.model or 'not configured'}" for p in providers)
        self._log("═" * 70)
        self._log(f"INVESTIGATION STARTED · question: {_short(question, 200)!r}")
        self._log(f"   models in fallback order: {chain} · {tool_count} tools · step limit {max_steps}")
        self.concept("setup")

    def step_start(self, step: int, max_steps: int, history: list[dict], model: str) -> None:
        self._log(f"── STEP {step} of max {max_steps} " + "─" * 40)
        self._log(f"   [REASON] sending {len(history)} history message(s), ~{_history_chars(history):,} chars, "
                  f"to {model} and waiting for its decision")
        if step > 1:
            self.concept("stateless")

    def fallback(self, step: int, provider, error: str, next_provider) -> None:
        target = f"{next_provider.name}:{next_provider.model}" if next_provider else "nothing left to try"
        self._log(f"   [FALLBACK] {provider.name} unavailable ({_short(error, 160)}) → {target}", logging.WARNING)
        self.concept("fallback")

    def model_replied(self, step: int, turn, seconds: float) -> None:
        self._log(f"   [REASON] {turn.model} replied in {seconds:.1f}s · {turn.input_tokens:,} tokens in / "
                  f"{turn.output_tokens:,} out · stop_reason={turn.stop_reason}")
        if turn.thinking:
            self._log(f"   [THINKING] {_short(turn.thinking)}")
        if turn.text and turn.stop_reason == "tool_use":
            self._log(f"   [SAYS] {_short(turn.text)}")
        if turn.warning:
            self._log(f"   [WARNING] {turn.warning}", logging.WARNING)
        if turn.stop_reason == "tool_use":
            names = ", ".join(c.name for c in turn.tool_calls)
            self._log(f"   [DECISION] the model wants {len(turn.tool_calls)} tool call(s): {names}")
            self.concept("tool_use")
            if len(turn.tool_calls) > 1:
                self.concept("parallel")

    def tool_started(self, index: int, total: int, request) -> None:
        args = ", ".join(f"{k}={v!r}" for k, v in request.input.items())
        self._log(f"   [ACT] tool {index} of {total}: {request.name}({_short(args, 250)})")
        self.concept("act")

    def tool_finished(self, request, text: str, is_error: bool, ms: int) -> None:
        if is_error:
            self._log(f"   [OBSERVE] ❌ {request.name} failed in {ms}ms: {_short(text, 250)}", logging.WARNING)
            self.concept("error_observation")
        else:
            facts = _result_facts(text)
            self._log(f"   [OBSERVE] ✅ {request.name} returned {len(text):,} chars in {ms}ms"
                      + (f" · {facts}" if facts else ""))

    def results_added(self, count: int, history: list[dict]) -> None:
        self._log(f"   [OBSERVE] {count} result(s) appended · history is now {len(history)} messages → next step")
        self.concept("observe")

    def stopped(self, step: int, stop_reason: str | None, why: str) -> None:
        self._log(f"   [STOP] at step {step}: {why}")
        if stop_reason == "end_turn":
            self.concept("end_turn")
        elif stop_reason == "step_limit":
            self.concept("step_limit")
        elif stop_reason == "report_submitted":
            self.concept("report_submitted")

    def nudged(self, step: int) -> None:
        self._log(f"   [NUDGE] step {step}: plain-text answer, no report submitted → reminding the model to call "
                  f"submit_report")
        self.concept("nudge")

    def finished(self, trace, trace_file) -> None:
        tokens = trace.input_tokens + trace.output_tokens
        self._log(f"INVESTIGATION FINISHED · {trace.steps} steps · {len(trace.tool_calls)} tool calls "
                  f"({sum(c.is_error for c in trace.tool_calls)} errors) · {trace.duration_s}s · {tokens:,} tokens · "
                  f"models: {', '.join(trace.models_used) or 'none'}")
        self._log(f"   trace saved: {trace_file}")
        self._log("═" * 70)


# ---------------------------------------------------------------- detailed view (DEBUG level)
# Shows the actual data moving through the loop. Turn it on with `--debug` (CLI) or SENTINEL_LOG_LEVEL=DEBUG (API).

DETAIL_WIDTH = 300  # long text (tool results, answers) is cut in the log; the full version is in the trace file


def _cut(text: str, width: int = DETAIL_WIDTH) -> str:
    text = text or ""
    return text if len(text) <= width else f"{text[:width]}… [{len(text):,} chars total]"


def _block(block) -> dict:
    """One content block (an SDK object or a dict) as a short, readable dict."""
    get = (lambda k: block.get(k)) if isinstance(block, dict) else (lambda k: getattr(block, k, None))
    kind = get("type")
    if kind == "text":
        return {"type": "text", "text": _cut(get("text"))}
    if kind == "thinking":
        return {"type": "thinking", "chars": len(get("thinking") or "")}
    if kind == "tool_use":
        return {"type": "tool_use", "id": get("id"), "name": get("name"), "input": get("input")}
    if kind == "tool_result":
        return {"type": "tool_result", "tool_use_id": get("tool_use_id"), "is_error": get("is_error"),
                "content": _cut(get("content"), 150)}
    return {"type": kind}


def _message(message: dict) -> dict:
    """One prompt message in the provider's own format, shortened for the log."""
    out = {"role": message["role"]}
    content = message.get("content")
    out["content"] = _cut(content, 150) if isinstance(content, str) else [_block(b) for b in content or []]
    if message.get("tool_calls"):  # Ollama's assistant format
        out["tool_calls"] = message["tool_calls"]
    if message.get("tool_name"):  # Ollama's tool-result format
        out["tool_name"] = message["tool_name"]
    return out


def _pretty(data) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


class Detail:
    """DEBUG-level logs of the raw data: what is sent, what comes back, what is appended."""

    def __init__(self, investigation_id: str):
        self.id = investigation_id

    def _debug(self, title: str, data=None) -> None:
        if log.isEnabledFor(logging.DEBUG):
            body = "" if data is None else "\n" + "\n".join(f"      {line}" for line in _pretty(data).splitlines())
            log.debug(f"[{self.id}]    🔍 {title}{body}")

    def system_prompt(self, system: str, tools: list[dict]) -> None:
        self._debug(f"SYSTEM PROMPT ({len(system):,} chars, sent unchanged every step): {_cut(system, 160)}")
        self._debug(f"TOOLS OFFERED ({len(tools)}, sent unchanged every step): {', '.join(t['name'] for t in tools)}")

    def prompt_sent(self, step: int, provider, history: list[dict]) -> None:
        """The history translated into this provider's API format: exactly what the model will read."""
        messages = [_message(m) for m in provider._messages(history)]
        note = " (plus the system prompt and tools)" if provider.name == "anthropic" else \
            " (plus a leading system message and the tools)"
        self._debug(f"PROMPT SENT AT STEP {step} → {provider.name} API format, {len(messages)} message(s){note}",
                    messages)

    def llm_response(self, step: int, turn) -> None:
        self._debug(f"LLM RESPONSE AT STEP {step} (normalised by agent/providers.py)", {
            "stop_reason": turn.stop_reason,
            "text": _cut(turn.text),
            "tool_calls": [{"id": c.id, "name": c.name, "input": c.input} for c in turn.tool_calls],
            "tokens": {"in": turn.input_tokens, "out": turn.output_tokens, "cache_read": turn.cache_read_tokens},
        })

    def appended_assistant(self, step: int, history: list[dict]) -> None:
        self._debug(f"HISTORY += assistant message (step {step}): the model's own reply is kept so it remembers "
                    f"what it asked for · history now {len(history)} messages")

    def appended_results(self, step: int, results: list, history: list[dict]) -> None:
        self._debug(f"HISTORY += tool results (step {step}), matched to their calls by id · history now "
                    f"{len(history)} messages", [
                        {"id": r.id, "name": r.name, "is_error": r.is_error, "content": _cut(r.content, 200)}
                        for r in results])

    def run_summary(self, trace) -> None:
        by_step: dict[int, list[str]] = {}
        for call in trace.tool_calls:
            by_step.setdefault(call.step, []).append(f"{call.name}{' ❌' if call.is_error else ''}")
        rows = [f"step {s}: {', '.join(by_step.get(s, [])) or '(no tools: final answer)'}"
                for s in range(1, trace.steps + 1)]
        self._debug(f"RUN SUMMARY · stopped at step {trace.steps} with stop_reason={trace.stop_reason}", rows)


def _history_chars(history: list[dict]) -> int:
    total = 0
    for item in history:
        if item["role"] == "user":
            total += len(item["content"])
        elif item["role"] == "assistant":
            turn = item["turn"]
            total += len(turn.text) + sum(len(json.dumps(c.input)) for c in turn.tool_calls)
        else:
            total += sum(len(r.content) for r in item["results"])
    return total
