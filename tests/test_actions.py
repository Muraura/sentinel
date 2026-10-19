"""The approval flow end to end: agent proposes -> roles and separation of duties -> execution -> audit."""
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update

import agent.investigator as investigator
import api.main as api
from agent.providers import AnthropicProvider
from agent.tool_registry import TOOLS
from db.tables import audit_log, blocked_ips, get_engine, proposed_actions, users

USAGE = NS(input_tokens=100, output_tokens=20, cache_read_input_tokens=0)
USERS = [("k-bob", api.User(name="bob", role="approver")), ("k-carol", api.User(name="carol", role="approver")),
         ("k-alice", api.User(name="alice", role="analyst"))]
BOB, CAROL, ALICE = ({"X-API-Key": k} for k in ("k-bob", "k-carol", "k-alice"))


def step(*calls):
    return NS(stop_reason="tool_use", usage=USAGE, stop_details=None,
              content=[NS(type="tool_use", id=f"t{i}", name=name, input=args) for i, (name, args) in enumerate(calls)])


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(investigator, "TRACES_DIR", tmp_path)
    monkeypatch.setattr(api, "TRACES_DIR", tmp_path)
    monkeypatch.setattr(api, "_api_users", lambda: USERS)
    script = iter([
        step(("propose_action", {"action_type": "disable_account", "target": "l.ortiz",
                                 "justification": "Login from 203.0.113.45 after 6 failures", "evidence": ["AUTH-00009"]}),
             ("propose_action", {"action_type": "block_ip", "target": "203.0.113.45",
                                 "justification": "Source of the brute-force logins", "evidence": ["AUTH-00003"]})),
        NS(stop_reason="end_turn", usage=USAGE, stop_details=None, content=[NS(type="text", text="Proposed 2 actions.")]),
    ])
    fake = NS(beta=NS(messages=NS(create=lambda **_: next(script))))
    monkeypatch.setattr(api, "_providers", lambda choice, effort: [AnthropicProvider(client=fake)])
    client = TestClient(api.app)
    client.started = []  # investigation ids this test created
    yield client
    with get_engine().begin() as conn:  # remove only what this test created; other runs may share the database
        ours = select(proposed_actions.c.id).where(proposed_actions.c.investigation_id.in_(client.started))
        conn.execute(delete(audit_log).where(audit_log.c.action_id.in_(ours)))
        conn.execute(delete(blocked_ips).where(blocked_ips.c.action_id.in_(ours)))
        conn.execute(delete(proposed_actions).where(proposed_actions.c.investigation_id.in_(client.started)))
        conn.execute(update(users).values(account_disabled=False, badge_revoked=False, mfa_required=False))


def start(client) -> list[dict]:
    """Start an investigation as bob; return the actions it proposed."""
    job_id = client.post("/investigations", json={"question": "What happened at 02:00?"}, headers=BOB).json()["id"]
    client.started.append(job_id)
    return [a for a in client.get("/actions", headers=ALICE).json() if a["investigation_id"] == job_id]


def test_execution_is_not_an_agent_tool():
    assert "propose_action" in TOOLS
    assert not any("execute" in name or "disable" in name for name in TOOLS)


def test_propose_approve_execute_audit(client):
    pending = start(client)
    assert {(a["action_type"], a["target"]) for a in pending} == {("disable_account", "l.ortiz"),
                                                                   ("block_ip", "203.0.113.45")}
    disable = next(a for a in pending if a["action_type"] == "disable_account")
    assert disable["requested_by"] == "bob" and disable["evidence"] == ["AUTH-00009"]

    url = f"/actions/{disable['id']}/approve"
    assert client.post(url, json={}, headers=ALICE).status_code == 403   # analysts can't approve
    assert client.post(url, json={}, headers=BOB).status_code == 403     # bob started the investigation
    done = client.post(url, json={"note": "confirmed with the user's manager"}, headers=CAROL).json()
    assert done["status"] == "executed" and done["decided_by"] == "carol"
    assert client.post(url, json={}, headers=CAROL).status_code == 409   # can't decide twice

    with get_engine().connect() as conn:
        assert conn.execute(select(users.c.account_disabled).where(users.c.user_name == "l.ortiz")).scalar_one()
    trail = [e["event"] for e in client.get("/audit", headers=CAROL).json() if e["action_id"] == disable["id"]]
    assert trail == ["action_executed", "action_approved", "action_proposed"]  # newest first


def test_reject_executes_nothing(client):
    block = next(a for a in start(client) if a["action_type"] == "block_ip")
    rejected = client.post(f"/actions/{block['id']}/reject", json={"note": "IP is a partner VPN"}, headers=CAROL).json()
    assert rejected["status"] == "rejected" and rejected["executed_at"] is None
    with get_engine().connect() as conn:
        assert conn.execute(select(blocked_ips).where(blocked_ips.c.action_id == block["id"])).first() is None


def test_proposals_must_cite_real_evidence():
    from tools.action_tools import propose_action
    with pytest.raises(ValueError, match="do not exist"):
        propose_action("disable_account", "l.ortiz", "made-up reasons here", ["AUTH-99999"])
    with pytest.raises(ValueError, match="no user"):
        propose_action("disable_account", "nobody", "made-up reasons here", ["AUTH-00009"])
