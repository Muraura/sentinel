"""Public demo: ask Sentinel a question and watch the agent loop run, step by step, in a web page.

Run locally:   DEMO_PROVIDER=ollama .venv/bin/uvicorn demo.app:app --port 7860   → http://127.0.0.1:7860
On a Space:    the Dockerfile starts it the same way, with DEMO_PROVIDER=gemini or huggingface

One server:
  /                  the web page (web/: plain HTML, CSS and JavaScript, no build step)
  /demo-api/...      the page's public endpoints: start an investigation, then poll its live events
  /investigations, /actions, /audit, /docs    Sentinel's API, with its own keys and roles (api/main.py)

Demo mode protects a public deployment:
  - synthetic data only (the database is loaded from data/synthetic/)
  - a daily cap and a per-visitor hourly limit on investigations, and a lower step limit
  - the agent can propose actions; approving them needs an approver key for the API (none is set on the Space)
"""
import os
import threading
import time
from collections import OrderedDict, defaultdict, deque
from datetime import date
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select

import agent.investigator as investigator
from agent import events
from agent.investigator import investigate, new_investigation_id
from agent.providers import build_providers
from api.main import app as api_app
from db.tables import get_engine, proposed_actions
from evals.scoring import load_scenario

PROVIDER = os.environ.get("DEMO_PROVIDER", "huggingface")
DAILY_LIMIT = int(os.environ.get("DEMO_DAILY_LIMIT", "50"))
PER_VISITOR_PER_HOUR = int(os.environ.get("DEMO_PER_VISITOR_PER_HOUR", "3"))
investigator.MAX_STEPS = int(os.environ.get("DEMO_MAX_STEPS", "15"))
REPO_URL = os.environ.get("DEMO_REPO_URL", "")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

# Example questions, grouped by the period they are about. The labels don't give the answer away.
SCENARIOS = [
    {"id": "INC-001", "label": "30 Sep · overnight"},
    {"id": "INC-002", "label": "1 Oct · afternoon"},
    {"id": "BENIGN-001", "label": "1 Oct · overnight"},
]
for _s in SCENARIOS:
    _s["questions"] = load_scenario(_s["id"])["example_questions"]


# ---------- Limits (in memory: they reset when the Space restarts, which is fine for a demo) ----------

_lock = threading.Lock()
_today = {"date": date.today(), "count": 0}
_visitors: dict[str, deque] = defaultdict(deque)


def _allowed(visitor: str) -> str | None:
    """None if this visitor may start an investigation now; otherwise the reason they can't."""
    with _lock:
        if _today["date"] != date.today():
            _today.update(date=date.today(), count=0)
        if _today["count"] >= DAILY_LIMIT:
            return f"The demo's daily limit ({DAILY_LIMIT} investigations) is reached. Please try again tomorrow."
        recent = _visitors[visitor]
        while recent and recent[0] < time.time() - 3600:
            recent.popleft()
        if len(recent) >= PER_VISITOR_PER_HOUR:
            return f"Limit of {PER_VISITOR_PER_HOUR} investigations per hour reached. Please try again later."
        recent.append(time.time())
        _today["count"] += 1
    return None


def _visitor(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    return (forwarded or (request.client.host if request.client else "") or "unknown").split(",")[0].strip()


# ---------- Runs: one background thread per investigation, its events collected for the page ----------

MAX_RUNS = 200  # oldest finished runs are forgotten first
_runs: "OrderedDict[str, dict]" = OrderedDict()


def _start(question: str) -> str:
    investigation_id = new_investigation_id()
    run = {"id": investigation_id, "question": question, "status": "running", "events": [], "started_at": time.time()}
    with _lock:
        _runs[investigation_id] = run
        while len(_runs) > MAX_RUNS:
            _runs.popitem(last=False)

    def collect(event: dict) -> None:
        with _lock:
            run["events"].append(event)

    def work() -> None:
        events.subscribe(investigation_id, collect)
        try:
            trace = investigate(question, providers=build_providers(PROVIDER),
                                investigation_id=investigation_id, requested_by="demo-visitor")
            answer = trace.answer or ""
            if answer.startswith("No model available") and "429" in answer:
                answer = "The free model quota for today is used up. Please try again tomorrow."
            result = {"status": "completed", "answer": answer, "report": trace.report, "stats": {
                "steps": trace.steps, "tool_calls": len(trace.tool_calls), "duration_s": trace.duration_s,
                "tokens": trace.input_tokens + trace.output_tokens, "models": trace.models_used,
                "stop_reason": trace.stop_reason}}
        except Exception as e:  # show the failure in the page instead of losing it in a thread
            result = {"status": "failed", "error": f"{type(e).__name__}: {e}"}
        finally:
            events.unsubscribe(investigation_id, collect)
        with _lock:
            run.update(result)

    threading.Thread(target=work, daemon=True, name=f"demo-{investigation_id}").start()
    return investigation_id


def _proposals(investigation_id: str) -> list[dict]:
    with get_engine().connect() as conn:
        rows = conn.execute(select(proposed_actions).where(proposed_actions.c.investigation_id == investigation_id)
                            .order_by(proposed_actions.c.id)).all()
    return [{"id": r.id, "action_type": r.action_type, "target": r.target, "justification": r.justification,
             "evidence": list(r.evidence), "status": r.status} for r in rows]


# ---------- The page's endpoints ----------

router = APIRouter(prefix="/demo-api", tags=["demo page"])


class Question(BaseModel):
    question: str = Field(min_length=3, max_length=500)


@router.get("/config")
def config() -> dict:
    """What the page needs to draw itself: example questions, the model in use, the limits."""
    models = []
    try:
        models = [{"name": p.name, "model": p.model} for p in build_providers(PROVIDER)]
    except Exception:  # a misconfigured provider shows up when an investigation runs; the page still loads
        pass
    return {"scenarios": SCENARIOS, "models": models, "max_steps": investigator.MAX_STEPS, "repo_url": REPO_URL,
            "limits": {"daily": DAILY_LIMIT, "per_visitor_per_hour": PER_VISITOR_PER_HOUR}}


@router.post("/investigations", status_code=status.HTTP_202_ACCEPTED)
def start_investigation(body: Question, request: Request) -> dict:
    """Start an investigation in the background; poll GET /demo-api/investigations/{id} for its events."""
    if reason := _allowed(_visitor(request)):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, reason)
    return {"id": _start(body.question.strip())}


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str, since: int = 0) -> dict:
    """The run so far: new events since index `since`, then (once finished) the report and proposed actions."""
    with _lock:
        run = _runs.get(investigation_id)
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"No investigation {investigation_id} on this server")
        snapshot = {k: v for k, v in run.items() if k != "events"}
        new_events, total = run["events"][max(since, 0):], len(run["events"])
    snapshot.update(events=new_events, next=total, elapsed_s=round(time.time() - snapshot.pop("started_at"), 1))
    if snapshot["status"] != "running":
        snapshot["proposals"] = _proposals(investigation_id)
    return snapshot


api_app.include_router(router)
# Last, so every API route above wins: anything else is a file of the page
api_app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
app = api_app
