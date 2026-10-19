"""Public demo: ask Sentinel a question and watch the agent loop run, step by step.

Run locally:   DEMO_PROVIDER=ollama .venv/bin/uvicorn demo.app:app --port 7860
On a Space:    the Dockerfile starts it the same way, with DEMO_PROVIDER=huggingface

One server: the Gradio page at "/", Sentinel's API (with its own keys) at /investigations, /actions, /docs.

Demo mode protects a public deployment:
  - synthetic data only (the database is loaded from data/synthetic/)
  - a daily cap and a per-visitor hourly limit on investigations, and a lower step limit
  - the agent can propose actions, but nothing here can approve or execute them
"""
import logging
import os
import queue
import threading
import time
from collections import defaultdict, deque
from datetime import date

import gradio as gr
from sqlalchemy import select

import agent.investigator as investigator
from agent.investigator import investigate, new_investigation_id
from agent.providers import build_providers
from api.main import app as api_app
from db.tables import get_engine, proposed_actions
from evals.scoring import GROUND_TRUTH_DIR, load_scenario

PROVIDER = os.environ.get("DEMO_PROVIDER", "huggingface")
DAILY_LIMIT = int(os.environ.get("DEMO_DAILY_LIMIT", "50"))
PER_VISITOR_PER_HOUR = int(os.environ.get("DEMO_PER_VISITOR_PER_HOUR", "3"))
investigator.MAX_STEPS = int(os.environ.get("DEMO_MAX_STEPS", "10"))
REPO_URL = os.environ.get("DEMO_REPO_URL", "")

EXAMPLES = [q for sid in ("INC-001", "INC-002", "BENIGN-001") for q in load_scenario(sid)["example_questions"]]


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


# ---------- Streaming the narration of one investigation into the page ----------

class _Capture(logging.Handler):
    """Collects the narration lines of one investigation (they all start with its id)."""

    def __init__(self, investigation_id: str):
        super().__init__(level=logging.INFO)
        self.prefix = f"[{investigation_id}] "
        self.lines: queue.Queue[str] = queue.Queue()

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if message.startswith(self.prefix):
            self.lines.put(message[len(self.prefix):])


def _proposals(investigation_id: str) -> str:
    with get_engine().connect() as conn:
        rows = conn.execute(select(proposed_actions).where(proposed_actions.c.investigation_id == investigation_id)).all()
    if not rows:
        return "_The agent proposed no actions._"
    lines = ["| action | target | evidence | status |", "|---|---|---|---|"]
    lines += [f"| {r.action_type} | {r.target} | {', '.join(r.evidence)} | {r.status} |" for r in rows]
    return "\n".join(lines) + "\n\n_Proposals wait for a human approver. Approval is disabled in this public demo._"


def run(question: str, request: gr.Request):
    question = (question or "").strip()
    if not 3 <= len(question) <= 500:
        yield "Please ask a question between 3 and 500 characters.", "", ""
        return
    visitor = (request.headers.get("x-forwarded-for") or request.client.host or "unknown").split(",")[0].strip()
    if reason := _allowed(visitor):
        yield reason, "", ""
        return

    investigation_id = new_investigation_id()
    capture = _Capture(investigation_id)
    logging.getLogger("sentinel.agent").addHandler(capture)
    result: dict = {}

    def work():
        try:
            result["trace"] = investigate(question, providers=build_providers(PROVIDER),
                                          investigation_id=investigation_id, requested_by="demo-visitor")
        except Exception as e:  # show the failure in the page instead of losing it in a thread
            result["error"] = f"{type(e).__name__}: {e}"

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    log: list[str] = []
    try:
        while thread.is_alive() or not capture.lines.empty():
            while not capture.lines.empty():
                log.append(capture.lines.get())
            yield "\n".join(log), "_Investigating…_", ""
            time.sleep(0.5)
    finally:
        logging.getLogger("sentinel.agent").removeHandler(capture)

    if "error" in result:
        yield "\n".join(log), f"**The investigation failed:** {result['error']}", ""
        return
    trace = result["trace"]
    footer = (f"\n\n---\n_{trace.steps} steps · {len(trace.tool_calls)} tool calls · {trace.duration_s}s · "
              f"model: {', '.join(trace.models_used) or 'none'} · investigation {trace.id}_")
    yield "\n".join(log), (trace.answer or "_No answer._") + footer, _proposals(trace.id)


# ---------- The page ----------

INTRO = f"""# Sentinel
**An AI agent that investigates security incidents.** Ask a question; the agent decides which evidence to gather
(logins, badge access, device status, application logs), correlates it, and writes a report where every fact
cites evidence. It can *propose* actions, but cannot execute them: a human must approve.

The data is synthetic: two days at a fictional company, with a credential compromise on 30 Sep at 02:00,
an API outage on 1 Oct at 14:18, and a quiet night in between. {f"[Code on GitHub]({REPO_URL})" if REPO_URL else ""}
"""

with gr.Blocks(title="Sentinel: agentic security investigator") as demo:
    gr.Markdown(INTRO)
    question = gr.Textbox(label="Your question", placeholder="What happened around 02:00 on 2026-09-30?", lines=2)
    gr.Examples(EXAMPLES, inputs=question, label="Try one of these (incident on 30 Sep, outage on 1 Oct, quiet night)",
                examples_per_page=9)
    ask = gr.Button("Investigate", variant="primary")
    with gr.Row():
        with gr.Column(scale=1):
            steps = gr.Textbox(label="What the agent is doing (live)", lines=28, max_lines=28, autoscroll=True)
        with gr.Column(scale=1):
            report = gr.Markdown(label="Report")
            actions = gr.Markdown(label="Proposed actions")
    ask.click(run, inputs=question, outputs=[steps, report, actions])
    question.submit(run, inputs=question, outputs=[steps, report, actions])

demo.queue(default_concurrency_limit=2, max_size=20)
app = gr.mount_gradio_app(api_app, demo, path="/")
