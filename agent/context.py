"""Which investigation is running, and who asked for it, available to tools without passing it through the LLM.

The model never chooses these values: the loop sets them. A tool that records something (propose_action) reads
them from here, so the model can't claim a different investigation or requester.
"""
from contextvars import ContextVar

current_investigation: ContextVar[str] = ContextVar("current_investigation", default="unknown")
current_requester: ContextVar[str | None] = ContextVar("current_requester", default=None)
