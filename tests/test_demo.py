"""The demo page's endpoints with a scripted model: live events, the report, limits, and the page itself."""
import time
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

import agent.investigator as investigator
import demo.app as demo
from agent import events
from agent.providers import AnthropicProvider

USAGE = NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=0)


@pytest.fixture
def client(monkeypatch, tmp_path):
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
    return TestClient(demo.app)


def wait_for(client, investigation_id: str) -> dict:
    """Poll like the page does, collecting events, until the run is finished."""
    collected, since = [], 0
    for _ in range(100):
        run = client.get(f"/demo-api/investigations/{investigation_id}", params={"since": since}).json()
        collected += run["events"]
        since = run["next"]
        if run["status"] != "running":
            return {**run, "events": collected}
        time.sleep(0.05)
    raise AssertionError("the investigation did not finish")


def test_streams_structured_events_then_the_answer(client):
    started = client.post("/demo-api/investigations", json={"question": "What happened around 02:00?"})
    assert started.status_code == 202
    run = wait_for(client, started.json()["id"])

    kinds = [e["kind"] for e in run["events"]]
    assert kinds[0] == "started" and kinds[-1] == "finished"
    assert {"step_started", "model_replied", "tool_started", "tool_finished", "stopped"} <= set(kinds)
    call = next(e for e in run["events"] if e["kind"] == "tool_finished")
    assert call["name"] == "get_auth_events" and call["evidence"] and all(i.startswith("AUTH-") for i in call["evidence"])
    assert run["status"] == "completed" and run["answer"].startswith("## Summary")
    assert run["stats"]["tool_calls"] == 1 and run["proposals"] == []
    assert events._listeners.get(run["id"]) is None  # unsubscribed when finished


def test_per_visitor_limit(client, monkeypatch):
    monkeypatch.setattr(demo, "PER_VISITOR_PER_HOUR", 0)
    response = client.post("/demo-api/investigations", json={"question": "What happened around 02:00?"})
    assert response.status_code == 429 and "Limit" in response.json()["detail"]


def test_rejects_empty_questions(client):
    assert client.post("/demo-api/investigations", json={"question": "  "}).status_code == 422


def test_unknown_investigation(client):
    assert client.get("/demo-api/investigations/inv-nothere").status_code == 404


def test_serves_the_page_config_and_keeps_the_api(client):
    page = client.get("/")
    assert page.status_code == 200 and "app.js" in page.text
    config = client.get("/demo-api/config").json()
    assert [s["id"] for s in config["scenarios"]] == ["INC-001", "INC-002", "BENIGN-001"]
    assert all(s["questions"] for s in config["scenarios"])
    assert client.get("/actions").status_code == 401  # the API's own keys still apply


def test_events_reach_only_their_subscribers():
    seen = []
    events.subscribe("inv-a", seen.append)
    events.emit("inv-a", "ping", n=1)
    events.emit("inv-b", "ping", n=2)
    events.unsubscribe("inv-a", seen.append)
    events.emit("inv-a", "ping", n=3)
    assert [e["n"] for e in seen] == [1]
    assert events.evidence_ids('{"ref": "AUTH-00009"} ACC-00007 AUTH-00009 BDG-1001 LOG-10030') == \
        ["AUTH-00009", "ACC-00007", "LOG-10030"]
