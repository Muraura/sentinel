"""The demo app's run() generator with a scripted model: streaming, limits, proposals."""
from types import SimpleNamespace as NS

import pytest

import agent.investigator as investigator
import demo.app as demo
from agent.providers import AnthropicProvider

USAGE = NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=0)


@pytest.fixture
def scripted(monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "TRACES_DIR", tmp_path)
    script = iter([
        NS(stop_reason="tool_use", usage=USAGE, stop_details=None, content=[NS(
            type="tool_use", id="t1", name="get_auth_events",
            input={"start": "2026-09-30T01:45:00Z", "end": "2026-09-30T03:00:00Z", "source_ip": "203.0.113.45"})]),
        NS(stop_reason="end_turn", usage=USAGE, stop_details=None, content=[NS(type="text", text="## Summary\nDone.")]),
    ])
    fake = NS(beta=NS(messages=NS(create=lambda **_: next(script))))
    monkeypatch.setattr(demo, "build_providers", lambda choice: [AnthropicProvider(client=fake)])
    monkeypatch.setattr(demo, "_visitors", demo.defaultdict(demo.deque))
    monkeypatch.setitem(demo._today, "count", 0)


def visitor(ip="203.0.113.1"):
    return NS(headers={}, client=NS(host=ip))


def test_streams_the_narration_then_the_report(scripted):
    updates = list(demo.run("What happened around 02:00?", visitor()))
    log, report, actions = updates[-1]
    assert "[ACT] tool 1 of 1: get_auth_events" in log and "INVESTIGATION FINISHED" in log
    assert report.startswith("## Summary") and "no actions" in actions
    assert len(updates) >= 2  # intermediate updates were streamed


def test_per_visitor_limit(scripted, monkeypatch):
    monkeypatch.setattr(demo, "PER_VISITOR_PER_HOUR", 0)
    assert "Limit" in list(demo.run("What happened around 02:00?", visitor()))[-1][0]


def test_rejects_empty_questions(scripted):
    assert "between 3 and 500" in list(demo.run("  ", visitor()))[-1][0]
