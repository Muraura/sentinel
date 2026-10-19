"""The agent loop's mechanics, tested with a scripted fake model: no API calls, no cost, same result every run.
This checks OUR code (tool execution, history, errors, stop reasons, limits), not the model's judgement.
"""
from types import SimpleNamespace as NS

import agent.investigator as investigator
from agent.investigator import investigate
from agent.providers import AnthropicProvider

USAGE = NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=50)
WINDOW = {"start": "2026-09-30T01:45:00Z", "end": "2026-09-30T03:00:00Z"}


def tool_use(id, name, input):
    return NS(type="tool_use", id=id, name=name, input=input)


def reply(stop_reason, *blocks):
    return NS(stop_reason=stop_reason, content=list(blocks), usage=USAGE, stop_details=None)


class FakeClient:
    """Stands in for anthropic.Anthropic(): returns scripted responses and records every request."""

    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []
        self.beta = NS(messages=NS(create=self._create))

    def _create(self, **kwargs):
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})  # snapshot of the history
        return next(self.responses)


def run(responses, monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "TRACES_DIR", tmp_path)
    client = FakeClient(responses)
    trace = investigate("What happened at 02:00?", providers=[AnthropicProvider(client=client)])
    return trace, client


def test_runs_requested_tools_and_feeds_results_back(monkeypatch, tmp_path):
    trace, client = run([
        reply("tool_use",
              tool_use("t1", "get_auth_events", {**WINDOW, "outcome": "failure"}),
              tool_use("t2", "get_device_events", {**WINDOW, "status": "offline"})),
        reply("end_turn", NS(type="text", text="## Summary\nCredential compromise. AUTH-00009")),
    ], monkeypatch, tmp_path)

    assert trace.answer.startswith("## Summary")
    assert [c.name for c in trace.tool_calls] == ["get_auth_events", "get_device_events"]
    # Both results return in ONE user message, matched to their tool_use ids, containing real data
    results = client.requests[1]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2"]
    assert "AUTH-" in results[0]["content"] and "DEV-" in results[1]["content"]
    assert trace.input_tokens == 200 and trace.steps == 2


def test_bad_arguments_become_an_error_observation_not_a_crash(monkeypatch, tmp_path):
    trace, client = run([
        reply("tool_use", tool_use("t1", "get_auth_events", {"start": "yesterday", "end": "today"})),
        reply("end_turn", NS(type="text", text="I could not query that range.")),
    ], monkeypatch, tmp_path)

    result = client.requests[1]["messages"][-1]["content"][0]
    assert result["is_error"] is True and "Invalid arguments" in result["content"]
    assert trace.tool_calls[0].is_error and trace.answer


def test_unknown_tools_are_refused(monkeypatch, tmp_path):
    trace, client = run([
        reply("tool_use", tool_use("t1", "disable_account", {"user_name": "l.ortiz"})),
        reply("end_turn", NS(type="text", text="I can only recommend that.")),
    ], monkeypatch, tmp_path)
    result = client.requests[1]["messages"][-1]["content"][0]
    assert result["is_error"] is True and "Unknown tool" in result["content"]


def test_loop_stops_at_step_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "MAX_STEPS", 3)
    endless = [reply("tool_use", tool_use(f"t{i}", "count_events", {**WINDOW, "group_by": ["service"]}))
               for i in range(10)]
    trace, client = run(endless, monkeypatch, tmp_path)
    assert len(client.requests) == 3
    assert "step limit" in trace.answer


def test_refusal_ends_the_run_without_running_tools(monkeypatch, tmp_path):
    refused = reply("refusal", tool_use("t1", "get_auth_events", WINDOW))
    refused.stop_details = NS(category="cyber")
    trace, _ = run([refused], monkeypatch, tmp_path)
    assert trace.tool_calls == [] and "declined" in trace.answer


def test_trace_is_saved(monkeypatch, tmp_path):
    run([reply("end_turn", NS(type="text", text="Nothing found."))], monkeypatch, tmp_path)
    assert len(list(tmp_path.glob("*.json"))) == 1
