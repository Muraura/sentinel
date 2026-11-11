"""Structured events of a running investigation, for live user interfaces.

The narrator (agent/narration.py) writes log lines for people reading a terminal. At the same moments it emits
an event here: a small dict such as {"kind": "tool_finished", "name": "get_auth_events", "facts": {...}}.
A web page subscribes to one investigation id and renders the events, instead of parsing log text.

Listeners run in the agent's thread and must be quick; a failing listener never breaks an investigation.
"""
import logging
import re
import threading
import time
from collections import defaultdict
from typing import Callable

Listener = Callable[[dict], None]

_lock = threading.Lock()
_listeners: dict[str, list[Listener]] = defaultdict(list)
log = logging.getLogger("sentinel.events")

_ID = re.compile(r"\b(?:AUTH|ACC|DEV)-\d{5}\b|\bLOG-\d+\b")


def subscribe(investigation_id: str, listener: Listener) -> None:
    with _lock:
        _listeners[investigation_id].append(listener)


def unsubscribe(investigation_id: str, listener: Listener) -> None:
    with _lock:
        if listener in _listeners.get(investigation_id, []):
            _listeners[investigation_id].remove(listener)
        if not _listeners.get(investigation_id):
            _listeners.pop(investigation_id, None)


def emit(investigation_id: str, kind: str, **data) -> None:
    with _lock:
        listeners = list(_listeners.get(investigation_id, ()))
    if not listeners:
        return
    event = {"kind": kind, "at": round(time.time(), 3), **data}
    for listener in listeners:
        try:
            listener(event)
        except Exception:  # a broken UI must never break the investigation
            log.exception(f"[{investigation_id}] event listener failed")


def evidence_ids(text: str) -> list[str]:
    """The evidence IDs in a tool result, in order of first appearance (for the live 'evidence collected' panel)."""
    return list(dict.fromkeys(_ID.findall(text or "")))
