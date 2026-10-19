"""submit_report: the final answer as a validated structure. Scripted model, real database."""
from types import SimpleNamespace as NS

import pytest
from pydantic import ValidationError

import agent.investigator as investigator
from agent.investigator import investigate
from agent.providers import AnthropicProvider
from agent.tool_registry import tool_definitions
from schemas.report import submit_report

USAGE = NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=0)
REPORT = {
    "summary": "l.ortiz compromised from 203.0.113.45.", "severity": "HIGH", "confidence": 80,
    "timeline": [{"time": "2026-09-30 02:08", "what": "successful login without MFA", "evidence": ["AUTH-00009"]}],
    "facts": [{"statement": "Login succeeded after 6 failures", "evidence": ["AUTH-00008", "AUTH-00009"]}],
    "inferences": [{"statement": "Password guessed", "confidence": "medium", "reasoning": "failures then success"}],
    "missing_evidence": ["camera footage"], "not_suspicious": [{"item": "a.khan", "reason": "typos"}],
    "recommended_actions": [{"action": "disable account", "target": "l.ortiz", "reason": "compromise"}],
}


def run(*responses, monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "TRACES_DIR", tmp_path)
    monkeypatch.setattr(investigator, "REQUIRE_STRUCTURED_REPORT", True)
    it = iter(responses)
    fake = NS(beta=NS(messages=NS(create=lambda **_: next(it))))
    return investigate("What happened?", providers=[AnthropicProvider(client=fake)])


def call(id, name, payload):
    return NS(stop_reason="tool_use", usage=USAGE, stop_details=None,
              content=[NS(type="tool_use", id=id, name=name, input=payload)])


def test_valid_report_ends_the_investigation(monkeypatch, tmp_path):
    trace = run(call("t1", "submit_report", REPORT), monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert trace.stop_reason == "report_submitted" and trace.steps == 1
    assert trace.report["severity"] == "HIGH"
    assert "## Facts" in trace.answer and "AUTH-00009" in trace.answer


def test_invented_evidence_is_rejected_then_fixed(monkeypatch, tmp_path):
    invented = {**REPORT, "facts": [{"statement": "Exports happened", "evidence": ["AUTH-12345"]}]}
    trace = run(call("t1", "submit_report", invented), call("t2", "submit_report", REPORT),
                monkeypatch=monkeypatch, tmp_path=tmp_path)
    first, second = trace.tool_calls
    assert first.is_error and "AUTH-12345" in first.result_preview and "do not exist" in first.result_preview
    assert not second.is_error and trace.stop_reason == "report_submitted" and trace.steps == 2


def test_plain_text_answer_gets_one_reminder(monkeypatch, tmp_path):
    text = NS(stop_reason="end_turn", usage=USAGE, stop_details=None, content=[NS(type="text", text="All good.")])
    trace = run(text, call("t1", "submit_report", REPORT), monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert trace.stop_reason == "report_submitted" and trace.steps == 2
    # A second plain-text answer is accepted as it is, unstructured
    trace = run(text, text, monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert trace.answer == "All good." and trace.report is None


def test_schema_rules():
    with pytest.raises(ValidationError):  # a fact without evidence
        submit_report(**{**REPORT, "facts": [{"statement": "x", "evidence": []}]})
    with pytest.raises(ValidationError):  # an ID that isn't even shaped like one
        submit_report(**{**REPORT, "facts": [{"statement": "x", "evidence": ["ACCESS-12349"]}]})
    with pytest.raises(ValidationError):  # not a severity level
        submit_report(**{**REPORT, "severity": "SEVERE"})


def test_report_schema_is_self_contained():
    schema = next(t for t in tool_definitions() if t["name"] == "submit_report")["input_schema"]
    assert "$defs" not in schema and "$ref" not in str(schema)
    assert schema["properties"]["facts"]["items"]["properties"]["evidence"]["minItems"] == 1


def test_invented_ids_in_free_text_are_rejected_too():
    with pytest.raises(ValueError, match="USER-00001"):
        submit_report(**{**REPORT, "summary": "Compromise of USER-00001 confirmed."})
    submit_report(**{**REPORT, "summary": "Badge BDG-1001 used; change CHG-2231 unrelated."})  # not evidence IDs
