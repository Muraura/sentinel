"""Sentinel HTTP API: the entry point users hit to ask questions.

Run:   .venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8800
Docs:  http://127.0.0.1:8800/docs  (interactive, generated from the code)

An investigation takes from seconds to minutes, far longer than an HTTP request should stay open.
So the API uses the job pattern:
    POST /investigations          -> 202 Accepted + an id, the investigation starts in the background
    GET  /investigations/{id}     -> status "running" ... then "completed" with the report
The server log narrates every step of the agent loop, tagged with the same id.

Every endpoint except /health needs an X-API-Key header. Keys map to a user and a role (SENTINEL_API_USERS in
Sentinel/.env, "key:name:role,..."). Roles, lowest to highest:
    analyst   start and read investigations, list proposed actions
    approver  + approve or reject proposed actions, read the audit log
    admin     everything
With no users configured, every protected endpoint refuses: fail closed, never open.

The agent can only PROPOSE actions. Approving one runs actions/executor.py, which no model can reach.
"""
import hmac
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Literal

import ollama
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import insert, select, text, update

from agent.investigator import TRACES_DIR, investigate, new_investigation_id
from agent.providers import OllamaProvider, _env, build_providers
from actions.executor import execute
from db.tables import audit_log, get_engine, proposed_actions
from evals.scoring import GROUND_TRUTH_DIR, load_scenario, score_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
logging.getLogger("sentinel").setLevel(os.environ.get("SENTINEL_LOG_LEVEL", "INFO").upper())
log = logging.getLogger("sentinel.api")

app = FastAPI(title="Sentinel", version="0.1.0",
              description="Agentic security investigator: ask a question, get an evidence-based assessment.")


# ---------- Who is calling: API keys -> users with roles ----------

Role = Literal["analyst", "approver", "admin"]
RANK = {"analyst": 1, "approver": 2, "admin": 3}


class User(BaseModel):
    name: str
    role: Role


def _api_users() -> list[tuple[str, User]]:
    entries = (_env().get("SENTINEL_API_USERS") or "").split(",")
    users = []
    for entry in filter(None, (e.strip() for e in entries)):
        key, name, role = entry.split(":")
        users.append((key, User(name=name, role=role)))
    return users


def require(role: Role):
    """Dependency: the caller must present a valid key whose role is at least `role`."""
    def check(x_api_key: str | None = Header(default=None)) -> User:
        # compare_digest takes the same time whether the key is right or wrong, so timing reveals nothing
        user = next((u for key, u in _api_users() if x_api_key and hmac.compare_digest(key, x_api_key)), None)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid X-API-Key")
        if RANK[user.role] < RANK[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role {role}; you are {user.role}")
        return user
    return check


# ---------- Request and response shapes ----------

class InvestigationRequest(BaseModel):
    question: str = Field(min_length=3, max_length=1000,
                          examples=["Investigate the authentication failures around 02:00."])
    provider: Literal["auto", "claude", "ollama", "huggingface", "gemini"] = Field(
        "auto", description="auto = Claude first, Ollama if Claude is unavailable")
    effort: Literal["low", "medium", "high", "xhigh", "max"] = Field("medium", description="Claude only")
    score_against: str | None = Field(None, pattern=r"^[A-Z]+-\d{3}$", examples=["INC-001"],
                                      description="Optional: score the finished report against this scenario's answer key")


class ToolCallSummary(BaseModel):
    step: int
    name: str
    input: dict
    is_error: bool
    duration_ms: int
    result_chars: int


class Investigation(BaseModel):
    id: str
    status: Literal["running", "completed", "failed"]
    question: str
    provider: str
    requested_by: str
    created_at: datetime
    finished_at: datetime | None = None
    answer: str | None = None
    report: dict | None = None  # the validated structured report, if the agent submitted one
    steps: int | None = None
    tool_calls: list[ToolCallSummary] = []
    models_used: list[str] = []
    provider_errors: list[dict] = []
    tokens_in: int | None = None
    tokens_out: int | None = None
    duration_s: float | None = None
    score: dict | None = None
    error: str | None = None


# ---------- In-memory job store ----------
# Enough for one machine. Restarting the server forgets running jobs; finished traces stay in traces/.
# A production version would keep jobs in Postgres and run them on a worker queue.

_jobs: dict[str, Investigation] = {}
_lock = threading.Lock()


def _providers(choice: str, effort: str) -> list:
    return build_providers(choice, effort)


def _run(job_id: str, request: InvestigationRequest) -> None:
    """Runs in a background thread after the 202 response has been sent."""
    try:
        trace = investigate(request.question, effort=request.effort,
                            providers=_providers(request.provider, request.effort), investigation_id=job_id,
                            requested_by=_jobs[job_id].requested_by)
        score = score_report(trace.answer, load_scenario(request.score_against)).model_dump() \
            if request.score_against else None
        update = dict(
            status="completed", answer=trace.answer, report=trace.report, steps=trace.steps,
            tool_calls=[ToolCallSummary(**{k: getattr(c, k) for k in ToolCallSummary.model_fields})
                        for c in trace.tool_calls],
            models_used=trace.models_used, provider_errors=trace.provider_errors,
            tokens_in=trace.input_tokens, tokens_out=trace.output_tokens, duration_s=trace.duration_s, score=score,
        )
        if score:
            log.info(f"[{job_id}] SCORED against {request.score_against}: overall {score['overall']:.0%}, "
                     f"evidence steps {score['evidence_recall']:.0%}")
    except Exception as e:  # report the failure on the job instead of losing it in a background thread
        log.exception(f"[{job_id}] investigation failed")
        update = dict(status="failed", error=f"{type(e).__name__}: {e}")
    with _lock:
        _jobs[job_id] = _jobs[job_id].model_copy(update={**update, "finished_at": datetime.now(timezone.utc)})


# ---------- Endpoints ----------

@app.post("/investigations", status_code=status.HTTP_202_ACCEPTED, response_model=Investigation)
def start_investigation(request: InvestigationRequest, background: BackgroundTasks,
                        user: User = Depends(require("analyst"))) -> Investigation:
    """Start an investigation. Returns immediately with an id; poll GET /investigations/{id} for the result."""
    if request.score_against and not (GROUND_TRUTH_DIR / f"{request.score_against}.json").exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No scenario {request.score_against}")
    job = Investigation(id=new_investigation_id(), status="running", question=request.question,
                        provider=request.provider, requested_by=user.name, created_at=datetime.now(timezone.utc))
    with _lock:
        _jobs[job.id] = job
    log.info(f"[{job.id}] API · POST /investigations by {user.name} ({user.role}), provider={request.provider} "
             f"→ running in background")
    background.add_task(_run, job.id, request)
    return job


@app.get("/investigations/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: str, user: User = Depends(require("analyst"))) -> Investigation:
    """Status and, once completed, the report, tool calls, tokens and (optionally) the score."""
    with _lock:
        job = _jobs.get(investigation_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No investigation {investigation_id}")
    return job


@app.get("/investigations", response_model=list[Investigation])
def list_investigations(user: User = Depends(require("analyst"))) -> list[Investigation]:
    """Investigations started since the server started, newest first (answers omitted)."""
    with _lock:
        jobs = sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)
    return [j.model_copy(update={"answer": None, "tool_calls": []}) for j in jobs]


@app.get("/investigations/{investigation_id}/trace")
def get_trace(investigation_id: str, user: User = Depends(require("analyst"))) -> dict:
    """The full audit trace saved for a finished investigation (also works after a server restart)."""
    matches = sorted(TRACES_DIR.glob(f"*-{investigation_id}.json"))
    if not matches:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No trace for {investigation_id}")
    return json.loads(matches[-1].read_text())


# ---------- Proposed actions: human approval ----------

class Action(BaseModel):
    id: int
    investigation_id: str
    action_type: str
    target: str
    justification: str
    evidence: list[str]
    requested_by: str | None
    status: str
    proposed_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    executed_at: datetime | None
    execution_result: str | None


class Decision(BaseModel):
    note: str | None = Field(None, max_length=500)


def _load_action(conn, action_id: int):
    action = conn.execute(select(proposed_actions).where(proposed_actions.c.id == action_id)
                          .with_for_update()).one_or_none()
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No action {action_id}")
    if action.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Action {action_id} is already {action.status}")
    return action


def _get_action(action_id: int) -> Action:
    with get_engine().connect() as conn:
        return Action.model_validate(
            conn.execute(select(proposed_actions).where(proposed_actions.c.id == action_id)).one(), from_attributes=True)


@app.get("/actions", response_model=list[Action])
def list_actions(status_filter: Literal["pending", "rejected", "executed", "failed"] | None = None,
                 user: User = Depends(require("analyst"))) -> list[Action]:
    """Actions the agent has proposed, newest first. ?status_filter=pending for the approval queue."""
    query = select(proposed_actions).order_by(proposed_actions.c.proposed_at.desc()).limit(200)
    if status_filter:
        query = query.where(proposed_actions.c.status == status_filter)
    with get_engine().connect() as conn:
        return [Action.model_validate(r, from_attributes=True) for r in conn.execute(query)]


@app.post("/actions/{action_id}/approve", response_model=Action)
def approve_action(action_id: int, decision: Decision, user: User = Depends(require("approver"))) -> Action:
    """Approve a pending action; it is executed immediately and every step is audited."""
    with get_engine().begin() as conn:
        action = _load_action(conn, action_id)
        if action.requested_by == user.name:  # separation of duties
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "You started the investigation that proposed this; another approver must decide")
        conn.execute(update(proposed_actions).where(proposed_actions.c.id == action_id).values(
            status="approved", decided_by=user.name, decided_at=datetime.now(timezone.utc), decision_note=decision.note))
        conn.execute(insert(audit_log).values(actor=user.name, event="action_approved", action_id=action_id,
                                              details={"note": decision.note}))
    result = execute(action_id, approved_by=user.name)
    log.info(f"[{action.investigation_id}] ACTION {action_id} {action.action_type}({action.target}) approved by "
             f"{user.name} → {result}")
    return _get_action(action_id)


@app.post("/actions/{action_id}/reject", response_model=Action)
def reject_action(action_id: int, decision: Decision, user: User = Depends(require("approver"))) -> Action:
    """Reject a pending action. Nothing is executed; the decision is audited."""
    with get_engine().begin() as conn:
        action = _load_action(conn, action_id)
        conn.execute(update(proposed_actions).where(proposed_actions.c.id == action_id).values(
            status="rejected", decided_by=user.name, decided_at=datetime.now(timezone.utc), decision_note=decision.note))
        conn.execute(insert(audit_log).values(actor=user.name, event="action_rejected", action_id=action_id,
                                              details={"note": decision.note}))
    log.info(f"[{action.investigation_id}] ACTION {action_id} rejected by {user.name}")
    return _get_action(action_id)


@app.get("/audit")
def get_audit(limit: int = 100, user: User = Depends(require("approver"))) -> list[dict]:
    """The audit trail: who proposed, approved, rejected and executed what, and when. Newest first."""
    with get_engine().connect() as conn:
        rows = conn.execute(select(audit_log).order_by(audit_log.c.id.desc()).limit(min(limit, 500)))
        return [dict(r._mapping) for r in rows]


@app.get("/health")
def health() -> dict:
    """Is everything Sentinel needs reachable? Database, local model, Claude key."""
    checks: dict = {}
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {type(e).__name__}"
    local = OllamaProvider()
    try:
        names = [m.model for m in ollama.Client(host=local.host, timeout=3).list().models]
        checks["ollama"] = "ok" if local.model in names else f"running, but model {local.model!r} not pulled"
    except Exception as e:
        checks["ollama"] = f"unreachable at {local.host}: {type(e).__name__}"
    checks["claude"] = "key in Sentinel/.env" if _env().get("ANTHROPIC_API_KEY") else \
        "no key in Sentinel/.env (falls back to the shell's key, if any)"
    checks["status"] = "ok" if checks["database"] == "ok" else "degraded"
    return checks
