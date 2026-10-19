"""Read-only investigation tools over log_events.

Rules every tool follows (see the design discussion):
  1. A time range and a result limit are required: no tool returns "everything".
  2. Results say how much was left out (total_matching / truncated).
  3. Every returned item carries an ID the agent can cite as evidence.
  4. Inputs are validated (validate_call): an LLM chooses these arguments, so treat them as untrusted.
  5. Column names come from allowlists, values go in as bound parameters. No string-built SQL.
"""
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import BaseModel, Field, validate_call
from sqlalchemy import and_, func, literal, select

from db.tables import get_engine, log_events as t
from tools.common import SEVERITY_ORDER, LevelName, Limit, time_range

MAX_BUCKETS = 500


# ---------- Result shapes (what the agent receives) ----------

class LogEventOut(BaseModel):
    id: int
    timestamp: datetime
    service: str
    level: str
    logger: str | None
    message: str | None
    error: str | None
    format: str


class SearchResult(BaseModel):
    events: list[LogEventOut]
    total_matching: int
    truncated: bool


class CountGroup(BaseModel):
    key: dict[str, str]
    count: int


class CountResult(BaseModel):
    groups: list[CountGroup]
    total: int


class ErrorPattern(BaseModel):
    service: str
    level: str
    template: str
    count: int
    first_seen: datetime
    last_seen: datetime
    example_event_id: int


class PatternResult(BaseModel):
    patterns: list[ErrorPattern]
    total_patterns: int
    truncated: bool


class RateBucket(BaseModel):
    bucket_start: datetime
    count: int


class RateResult(BaseModel):
    bucket_minutes: int
    buckets: list[RateBucket]  # includes zero-count buckets: silence is a signal too
    total: int


class AroundResult(BaseModel):
    anchor: LogEventOut
    events: list[LogEventOut]
    total_matching: int
    truncated: bool


# ---------- Helpers ----------

OUT_COLUMNS = [t.c.id, t.c.timestamp, t.c.service, t.c.level, t.c.logger, t.c.message, t.c.error, t.c.format]


def _filters(start, end, service=None, level=None, levels=None):
    conditions = [t.c.timestamp >= start, t.c.timestamp < end]
    if service:
        conditions.append(t.c.service == service)
    if level:
        conditions.append(t.c.level == level)
    if levels:
        conditions.append(t.c.level.in_(levels))
    return and_(*conditions)


def _events(rows) -> list[LogEventOut]:
    return [LogEventOut.model_validate(row, from_attributes=True) for row in rows]


# ---------- Tools ----------

@validate_call
def search_logs(
    start: datetime,
    end: datetime,
    service: str | None = None,
    level: LevelName | None = None,
    text: Annotated[str, Field(max_length=200)] | None = None,
    limit: Limit = 50,
) -> SearchResult:
    """Find individual log events in a time range, optionally filtered by service, level and text in the message."""
    start, end = time_range(start, end)
    where = _filters(start, end, service, level)
    if text:
        # autoescape: a "%" or "_" typed by the agent is matched literally, not as a wildcard
        where = and_(where, t.c.message.icontains(text, autoescape=True) | t.c.error.icontains(text, autoescape=True))

    with get_engine().connect() as conn:
        total = conn.execute(select(func.count()).where(where)).scalar_one()
        rows = conn.execute(select(*OUT_COLUMNS).where(where).order_by(t.c.timestamp).limit(limit)).all()
    return SearchResult(events=_events(rows), total_matching=total, truncated=total > len(rows))


GROUPABLE = {"service": t.c.service, "level": t.c.level, "logger": t.c.logger, "format": t.c.format}


@validate_call
def count_events(
    start: datetime,
    end: datetime,
    group_by: Annotated[list[Literal["service", "level", "logger", "format"]], Field(min_length=1, max_length=2)],
    service: str | None = None,
    level: LevelName | None = None,
) -> CountResult:
    """Count events in a time range grouped by one or two fields. Use this before search_logs to see the big picture."""
    start, end = time_range(start, end)
    columns = [GROUPABLE[name].label(name) for name in group_by]  # allowlist: never a column name from the caller
    query = (
        select(*columns, func.count().label("count"))
        .where(_filters(start, end, service, level))
        .group_by(*columns)
        .order_by(func.count().desc())
    )
    with get_engine().connect() as conn:
        rows = conn.execute(query).all()
    groups = [
        CountGroup(key={name: str(getattr(row, name)) for name in group_by}, count=row.count) for row in rows
    ]
    return CountResult(groups=groups, total=sum(g.count for g in groups))


def _template(column):
    """Replace variable parts of a message so similar messages group together.
    "Camera CAM-A-LOBBY-02 offline" and "Camera CAM-A-LOBBY-01 offline" -> "Camera CAM-A-LOBBY-<N> offline" """
    uuid = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    result = func.regexp_replace(column, uuid, "<UUID>", "g")
    result = func.regexp_replace(result, r"\m0x[0-9a-fA-F]+\M|\m[0-9a-fA-F]{16,}\M", "<HEX>", "g")
    result = func.regexp_replace(result, r"\d+(\.\d+)?", "<N>", "g")
    return result


@validate_call
def get_error_patterns(
    start: datetime,
    end: datetime,
    service: str | None = None,
    min_level: Literal["WARNING", "ERROR", "CRITICAL"] = "WARNING",
    limit: Limit = 20,
) -> PatternResult:
    """Group warnings/errors into message patterns with counts and first/last seen. Answers "what kinds of problems happened?"."""
    start, end = time_range(start, end)
    levels = SEVERITY_ORDER[SEVERITY_ORDER.index(min_level):]
    template = _template(func.coalesce(t.c.message, t.c.error, t.c.raw)).label("template")
    grouped = (
        select(
            t.c.service,
            t.c.level,
            template,
            func.count().label("count"),
            func.min(t.c.timestamp).label("first_seen"),
            func.max(t.c.timestamp).label("last_seen"),
            func.min(t.c.id).label("example_event_id"),
        )
        .where(_filters(start, end, service, levels=levels))
        .group_by(t.c.service, t.c.level, template)
        .subquery()
    )
    with get_engine().connect() as conn:
        total = conn.execute(select(func.count()).select_from(grouped)).scalar_one()
        rows = conn.execute(select(grouped).order_by(grouped.c.count.desc()).limit(limit)).all()
    patterns = [ErrorPattern.model_validate(row, from_attributes=True) for row in rows]
    return PatternResult(patterns=patterns, total_patterns=total, truncated=total > len(patterns))


@validate_call
def get_event_rate(
    start: datetime,
    end: datetime,
    bucket_minutes: Annotated[int, Field(ge=1, le=1440)] = 5,
    service: str | None = None,
    level: LevelName | None = None,
) -> RateResult:
    """Count events per time bucket to find spikes, drops and when something started."""
    start, end = time_range(start, end)
    bucket = timedelta(minutes=bucket_minutes)
    n_buckets = -(-(end - start) // bucket)  # ceiling division
    if n_buckets > MAX_BUCKETS:
        raise ValueError(f"{n_buckets} buckets requested; max is {MAX_BUCKETS}. Use a bigger bucket_minutes.")

    bucket_start = func.date_bin(literal(bucket), t.c.timestamp, literal(start)).label("bucket_start")
    query = (
        select(bucket_start, func.count().label("count"))
        .where(_filters(start, end, service, level))
        .group_by(bucket_start)
    )
    with get_engine().connect() as conn:
        counts = {row.bucket_start: row.count for row in conn.execute(query)}

    buckets = [
        RateBucket(bucket_start=start + i * bucket, count=counts.get(start + i * bucket, 0)) for i in range(n_buckets)
    ]
    return RateResult(bucket_minutes=bucket_minutes, buckets=buckets, total=sum(b.count for b in buckets))


@validate_call
def get_events_around(
    event_id: int,
    before_seconds: Annotated[int, Field(ge=0, le=3600)] = 60,
    after_seconds: Annotated[int, Field(ge=0, le=3600)] = 60,
    service: str | None = None,
    limit: Limit = 50,
) -> AroundResult:
    """Show what happened just before and after one event, across all services unless one is given."""
    with get_engine().connect() as conn:
        anchor = conn.execute(select(*OUT_COLUMNS, t.c.timestamp_ns).where(t.c.id == event_id)).one_or_none()
        if anchor is None:
            raise ValueError(f"No log event with id {event_id}")

        start = anchor.timestamp - timedelta(seconds=before_seconds)
        end = anchor.timestamp + timedelta(seconds=after_seconds)
        where = and_(t.c.timestamp >= start, t.c.timestamp <= end, t.c.id != event_id)
        if service:
            where = and_(where, t.c.service == service)

        total = conn.execute(select(func.count()).where(where)).scalar_one()
        # If there are too many, keep the ones closest in time to the anchor
        distance = func.abs(t.c.timestamp_ns - anchor.timestamp_ns)
        nearest = select(*OUT_COLUMNS).where(where).order_by(distance).limit(limit).subquery()
        rows = conn.execute(select(nearest).order_by(nearest.c.timestamp)).all()

    return AroundResult(
        anchor=_events([anchor])[0], events=_events(rows), total_matching=total, truncated=total > len(rows)
    )
