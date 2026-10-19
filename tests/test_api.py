"""The HTTP API, with the agent replaced by a scripted fake model: no LLM calls."""
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

import agent.investigator as investigator
import api.main as api
from agent.providers import AnthropicProvider

USAGE = NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=0)
USERS = [("k-alice", api.User(name="alice", role="analyst")), ("k-bob", api.User(name="bob", role="approver")),
         ("k-carol", api.User(name="carol", role="approver"))]
ALICE, BOB, CAROL = {"X-API-Key": "k-alice"}, {"X-API-Key": "k-bob"}, {"X-API-Key": "k-carol"}


def scripted_claude(*responses):
    it = iter(responses)
    return NS(beta=NS(messages=NS(create=lambda **_: next(it))))


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "TRACES_DIR", tmp_path)
    monkeypatch.setattr(api, "TRACES_DIR", tmp_path)
    answer = NS(type="text", text="## Summary\nl.ortiz compromised from 203.0.113.45 (AUTH-00009)\n## Severity\nHIGH")
    fake = scripted_claude(
        NS(stop_reason="tool_use", usage=USAGE, stop_details=None, content=[NS(
            type="tool_use", id="t1", name="get_auth_events",
            input={"start": "2026-09-30T01:45:00Z", "end": "2026-09-30T03:00:00Z", "source_ip": "203.0.113.45"})]),
        NS(stop_reason="end_turn", usage=USAGE, stop_details=None, content=[answer]),
    )
    monkeypatch.setattr(api, "_providers", lambda choice, effort: [AnthropicProvider(client=fake)])
    monkeypatch.setattr(api, "_api_users", lambda: USERS)
    return TestClient(api.app, headers=ALICE)


def test_start_then_fetch_completed_investigation(client):
    started = client.post("/investigations", json={"question": "What happened at 02:00?", "score_against": "INC-001"})
    assert started.status_code == 202
    job_id = started.json()["id"]
    assert job_id.startswith("inv-")

    # TestClient runs background tasks before returning, so the job is already finished here
    done = client.get(f"/investigations/{job_id}").json()
    assert done["status"] == "completed"
    assert "AUTH-00009" in done["answer"]
    assert [c["name"] for c in done["tool_calls"]] == ["get_auth_events"]
    assert done["score"]["scenario"] == "INC-001"

    trace = client.get(f"/investigations/{job_id}/trace").json()
    assert trace["id"] == job_id


def test_validation_errors(client):
    assert client.post("/investigations", json={"question": "hi"}).status_code == 422          # too short
    assert client.post("/investigations", json={"question": "What happened?", "provider": "gpt"}).status_code == 422
    assert client.post("/investigations", json={"question": "What happened?", "score_against": "INC-999"}).status_code == 404


def test_unknown_investigation_is_404(client):
    assert client.get("/investigations/inv-nope").status_code == 404


def test_health_reports_each_dependency(client):
    body = client.get("/health").json()
    assert set(body) >= {"database", "ollama", "claude", "status"}


def test_requests_without_a_valid_key_are_refused(client):
    assert client.get("/investigations", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/health", headers={"X-API-Key": "wrong"}).status_code == 200  # health stays open


def test_no_configured_users_means_no_access(client, monkeypatch):
    monkeypatch.setattr(api, "_api_users", lambda: [])
    assert client.get("/investigations").status_code == 401  # fail closed
