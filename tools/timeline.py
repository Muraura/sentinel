"""build_timeline: merge logins, badge swipes, device changes and logs into one ordered, citable timeline.

Correlation without request IDs works through shared entities (user, IP, area, device) plus time.
An event is included if it matches ANY entity you pass, so one call can pull an incident together:
    build_timeline(start, end, user_name="l.ortiz", source_ip="203.0.113.45", area="A-ServerRoom")
With no entities, everything in the window is included (bounded by the limits).
"""
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import BaseModel, Field, IPvAnyNetwork, validate_call
from sqlalchemy import and_, case, cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET

from db.tables import access_events, areas, auth_events, device_events, get_engine, log_events
from tools.common import SEVERITY_ORDER, Name, time_range
from tools.security_tools import in_network

Source = Literal["auth", "access", "device", "logs"]
ALL_SOURCES: list[Source] = ["auth", "access", "device", "logs"]
MAX_ROWS_PER_SOURCE = 2000
COLLAPSE_MAX_GAP = timedelta(seconds=30)  # identical log lines further apart than this stay separate: timing is evidence


class TimelineItem(BaseModel):
    timestamp: datetime
    end_timestamp: datetime | None = None  # set when several identical log lines were collapsed into one item
    source: Source
    ref: str                               # AUTH-00010, ACC-00006, DEV-00001, LOG-5123 (first line if collapsed)
    count: int = 1
    summary: str
    user_name: str | None = None           # entity fields: what the agent can pivot on next
    source_ip: str | None = None
    area: str | None = None
    device_id: str | None = None


class TimelineResult(BaseModel):
    items: list[TimelineItem]
    total_items: int
    truncated: bool
    sources_truncated: list[Source]        # sources that hit MAX_ROWS_PER_SOURCE: narrow the window


def _fetch(query) -> tuple[list, bool]:
    with get_engine().connect() as conn:
        rows = conn.execute(query.limit(MAX_ROWS_PER_SOURCE + 1)).all()
    return rows[:MAX_ROWS_PER_SOURCE], len(rows) > MAX_ROWS_PER_SOURCE


def _where(window, entity_conditions, any_entity_given):
    """None means: entities were given, but this source can't match any of them -> skip it."""
    if any_entity_given and not entity_conditions:
        return None
    return and_(*window, or_(*entity_conditions)) if entity_conditions else and_(*window)


def _auth_items(start, end, user_name, source_ip, any_entity):
    t = auth_events
    conditions = []
    if user_name:
        conditions.append(t.c.user_name == user_name)
    if source_ip:
        conditions.append(in_network(t.c.source_ip, source_ip))
    where = _where([t.c.timestamp >= start, t.c.timestamp < end], conditions, any_entity)
    if where is None:
        return [], False
    rows, over = _fetch(select(t, func.host(t.c.source_ip).label("ip")).where(where).order_by(t.c.timestamp))
    items = []
    for r in rows:
        detail = r.failure_reason if r.outcome == "failure" else f"mfa={'yes' if r.mfa_used else 'no'}"
        items.append(TimelineItem(
            timestamp=r.timestamp, source="auth", ref=r.ref, user_name=r.user_name, source_ip=r.ip,
            summary=f"login {r.outcome} for {r.user_name} from {r.ip} ({detail}, agent={r.user_agent})",
        ))
    return items, over


def _access_items(start, end, user_name, area, device_id, any_entity):
    t = access_events
    conditions = []
    if user_name:
        conditions.append(t.c.user_name == user_name)
    if area:
        conditions.append(t.c.area == area)
    if device_id:
        conditions.append(t.c.door_id == device_id)
    where = _where([t.c.timestamp >= start, t.c.timestamp < end], conditions, any_entity)
    if where is None:
        return [], False
    query = (select(t, areas.c.restricted).select_from(t.join(areas, t.c.area == areas.c.area))
             .where(where).order_by(t.c.timestamp))
    rows, over = _fetch(query)
    items = []
    for r in rows:
        kind = "restricted area " if r.restricted else ""
        items.append(TimelineItem(
            timestamp=r.timestamp, source="access", ref=r.ref, user_name=r.user_name, area=r.area,
            device_id=r.door_id,
            summary=f"badge {r.badge_id} ({r.user_name}) {r.decision} into {kind}{r.area} ({r.reason})",
        ))
    return items, over


def _device_items(start, end, area, device_id, any_entity):
    t = device_events
    conditions = []
    if area:
        conditions.append(t.c.area == area)
    if device_id:
        conditions.append(t.c.device_id == device_id)
    where = _where([t.c.timestamp >= start, t.c.timestamp < end], conditions, any_entity)
    if where is None:
        return [], False
    rows, over = _fetch(select(t).where(where).order_by(t.c.timestamp))
    items = [
        TimelineItem(
            timestamp=r.timestamp, source="device", ref=r.ref, area=r.area, device_id=r.device_id,
            summary=f"{r.device_type} {r.device_id} {r.status} ({r.reason})",
        )
        for r in rows
    ]
    return items, over


def _log_items(start, end, user_name, source_ip, device_id, any_entity, levels):
    t = log_events
    log_user = t.c.attributes["user"].astext
    log_ip = t.c.attributes["client_ip"].astext
    conditions = []
    if user_name:
        conditions.append(log_user == user_name)
    if source_ip:
        # Only cast values that look like IPs: a malformed client_ip must not break the whole query
        looks_like_ip = log_ip.regexp_match(r"^[0-9a-fA-F:.]+$")
        conditions.append(in_network(case((looks_like_ip, cast(log_ip, INET))), source_ip))
    if device_id:
        conditions.append(t.c.message.contains(device_id, autoescape=True))
    where = _where([t.c.timestamp >= start, t.c.timestamp < end, t.c.level.in_(levels)], conditions, any_entity)
    if where is None:
        return [], False
    query = (select(t.c.id, t.c.timestamp, t.c.service, t.c.level, t.c.message, log_user.label("user"),
                    log_ip.label("ip")).where(where).order_by(t.c.timestamp))
    rows, over = _fetch(query)

    # Collapse bursts of identical lines: 140 "export requested" lines 3s apart become one item with count=140
    items: list[TimelineItem] = []
    previous_key, previous_time = None, None
    for r in rows:
        key = (r.service, r.level, r.message, r.user, r.ip)
        is_burst = key == previous_key and r.timestamp - previous_time <= COLLAPSE_MAX_GAP
        previous_key, previous_time = key, r.timestamp
        if is_burst:
            items[-1].count += 1
            items[-1].end_timestamp = r.timestamp
            continue
        who = " ".join(f"{k}={v}" for k, v in (("user", r.user), ("client_ip", r.ip)) if v)
        items.append(TimelineItem(
            timestamp=r.timestamp, source="logs", ref=f"LOG-{r.id}", user_name=r.user, source_ip=r.ip,
            summary=f"{r.service} {r.level}: {r.message}" + (f" [{who}]" if who else ""),
        ))
    for item in items:
        if item.count > 1:
            item.summary = f"{item.count}x {item.summary}"
    return items, over


@validate_call
def build_timeline(
    start: datetime,
    end: datetime,
    user_name: Name | None = None,
    source_ip: IPvAnyNetwork | None = None,
    area: Name | None = None,
    device_id: Name | None = None,
    sources: Annotated[list[Source], Field(min_length=1)] = ALL_SOURCES,
    log_min_level: Literal["INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO",
    limit: Annotated[int, Field(ge=1, le=300)] = 100,
) -> TimelineResult:
    """One chronological timeline across logins, badge swipes, device status and logs.
    Includes events matching ANY of the given entities (user_name, source_ip, area, device_id).
    Identical consecutive log lines are collapsed into one item with a count."""
    start, end = time_range(start, end)
    any_entity = any(v is not None for v in (user_name, source_ip, area, device_id))
    levels = SEVERITY_ORDER[SEVERITY_ORDER.index(log_min_level):]

    fetchers = {
        "auth": lambda: _auth_items(start, end, user_name, source_ip, any_entity),
        "access": lambda: _access_items(start, end, user_name, area, device_id, any_entity),
        "device": lambda: _device_items(start, end, area, device_id, any_entity),
        "logs": lambda: _log_items(start, end, user_name, source_ip, device_id, any_entity, levels),
    }
    items: list[TimelineItem] = []
    sources_truncated: list[Source] = []
    for source in dict.fromkeys(sources):  # de-duplicate, keep order
        source_items, over = fetchers[source]()
        items += source_items
        if over:
            sources_truncated.append(source)

    items.sort(key=lambda i: i.timestamp)
    return TimelineResult(
        items=items[:limit],
        total_items=len(items),
        truncated=len(items) > limit or bool(sources_truncated),
        sources_truncated=sources_truncated,
    )
