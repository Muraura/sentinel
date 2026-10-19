"""Turns Sentinel's Python tool functions into tool definitions the LLM can see, and runs the ones it asks for.

Nothing here is written twice: each tool's name, description and input schema come from the
function itself (name, docstring, type hints), via the same Pydantic types @validate_call enforces.
"""
import inspect
import json
from typing import Any, Callable

from pydantic import TypeAdapter, ValidationError

from schemas.report import submit_report
from tools.action_tools import propose_action
from tools.knowledge import search_knowledge
from tools.log_tools import count_events, get_error_patterns, get_event_rate, get_events_around, search_logs
from tools.security_tools import get_access_events, get_auth_events, get_device_events
from tools.timeline import build_timeline
from tools.user_tools import get_user_profile

# The agent's entire capability. Every data tool is read-only. propose_action writes only a proposal;
# executing actions (actions/executor.py) is deliberately NOT here, so no model can ever call it.
TOOLS: dict[str, Callable] = {
    f.__name__: f
    for f in (
        count_events, get_error_patterns, get_event_rate, search_logs, get_events_around,
        get_auth_events, get_access_events, get_device_events,
        get_user_profile, build_timeline,
        search_knowledge,  # RAG over policies, runbooks and past incidents
        propose_action,  # writes a proposal for a human to approve; executes nothing
        submit_report,  # not a data tool: how the agent hands in its final, validated report
    )
}
FINAL_TOOL = "submit_report"

MAX_RESULT_CHARS = 60_000  # a backstop: the tools' own limits should keep results far below this


def _schema(func: Callable) -> dict:
    """JSON Schema from the type hints, made self-contained: nested types (Fact, TimelineEntry...) are inlined
    instead of referenced through $defs, and auto-generated "title" fields are dropped. Small models cope better."""
    schema = TypeAdapter(func).json_schema()
    defs = schema.pop("$defs", {})

    def resolve(node):
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(defs[node["$ref"].split("/")[-1]])
            return {k: resolve(v) for k, v in node.items() if k != "title"}
        if isinstance(node, list):
            return [resolve(item) for item in node]
        return node

    return resolve(schema)


def tool_definitions() -> list[dict]:
    """What the model sees: name + description (from the docstring) + JSON Schema (from the type hints)."""
    return [
        {"name": name, "description": inspect.getdoc(func), "input_schema": _schema(func)}
        for name, func in TOOLS.items()
    ]


def run_tool(name: str, tool_input: dict[str, Any]) -> tuple[str, bool]:
    """Execute one tool call. Returns (result_text, is_error).

    Errors become observations, not crashes: the model reads the message and can correct its next call.
    """
    func = TOOLS.get(name)
    if func is None:
        return f"Unknown tool '{name}'. Available tools: {', '.join(TOOLS)}", True
    try:
        result = func(**tool_input)  # @validate_call checks every argument the model chose
    except ValidationError as e:
        problems = "; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors())
        return f"Invalid arguments for {name}: {problems}", True
    except (ValueError, TypeError) as e:
        return f"{name} rejected the request: {e}", True
    except Exception as e:  # e.g. the database is down: report it, let the agent decide what to do
        return f"{name} failed: {type(e).__name__}: {e}", True

    text = result.model_dump_json() if hasattr(result, "model_dump_json") else json.dumps(result, default=str)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + '... [RESULT CUT BY SENTINEL: narrow the time range or lower "limit"]'
    return text, False
