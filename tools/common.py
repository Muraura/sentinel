"""Shared argument types and checks for every tool module."""
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import Field

LevelName = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "UNKNOWN"]
Limit = Annotated[int, Field(ge=1, le=200)]
Name = Annotated[str, Field(min_length=1, max_length=100)]

SEVERITY_ORDER = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def utc(value: datetime) -> datetime:
    """Treat timezone-less times as UTC: everything is stored in UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def time_range(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    start, end = utc(start), utc(end)
    if start >= end:
        raise ValueError("start must be before end")
    return start, end
