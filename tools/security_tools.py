"""Read-only tools over the security tables: logins, badge swipes, device status.

Same rules as log_tools.py: required time range and limit, truncation reported, citable refs
(AUTH-00010, ACC-00006, DEV-00001), validated inputs, no string-built SQL.
Each result also counts ALL matches by outcome/decision/status, so the agent sees the big picture
even when only the first page of events comes back.
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, IPvAnyNetwork, validate_call
from sqlalchemy import and_, cast, func, select
from sqlalchemy.dialects.postgresql import INET

from db.tables import access_events, areas, auth_events, device_events, get_engine
from tools.common import Limit, Name, time_range


# ---------- Result shapes ----------

class AuthEventOut(BaseModel):
    ref: str
    timestamp: datetime
    user_name: str
    source_ip: str
    outcome: str
    failure_reason: str | None
    auth_method: str
    mfa_used: bool
    user_agent: str | None
    session_id: str | None


class AuthResult(BaseModel):
    events: list[AuthEventOut]
    by_outcome: dict[str, int]
    total_matching: int
    truncated: bool


class AccessEventOut(BaseModel):
    ref: str
    timestamp: datetime
    user_name: str
    badge_id: str
    area: str
    building: str
    restricted: bool
    door_id: str
    decision: str
    reason: str


class AccessResult(BaseModel):
    events: list[AccessEventOut]
    by_decision: dict[str, int]
    total_matching: int
    truncated: bool


class DeviceEventOut(BaseModel):
    ref: str
    timestamp: datetime
    device_id: str
    device_type: str
    area: str
    building: str
    status: str
    reason: str | None


class DeviceResult(BaseModel):
    events: list[DeviceEventOut]
    by_status: dict[str, int]
    total_matching: int
    truncated: bool


# ---------- Helpers ----------

def in_network(column, network: IPvAnyNetwork):
    """Postgres INET containment: '203.0.113.45' <<= '203.0.113.0/24'."""
    return column.op("<<=")(cast(str(network), INET))


def run(source, columns, conditions, group_column, limit, timestamp_column):
    """Count all matches per group, then fetch the first `limit` events in time order."""
    where = and_(*conditions)
    with get_engine().connect() as conn:
        groups = dict(conn.execute(
            select(group_column, func.count()).select_from(source).where(where).group_by(group_column)
        ).all())
        rows = conn.execute(
            select(*columns).select_from(source).where(where).order_by(timestamp_column).limit(limit)
        ).all()
    return rows, groups, sum(groups.values())


# ---------- Tools ----------

@validate_call
def get_auth_events(
    start: datetime,
    end: datetime,
    user_name: Name | None = None,
    source_ip: IPvAnyNetwork | None = None,
    outcome: Literal["success", "failure"] | None = None,
    limit: Limit = 50,
) -> AuthResult:
    """Login attempts in a time range. source_ip accepts one address (203.0.113.45) or a range (198.51.100.0/24)."""
    start, end = time_range(start, end)
    t = auth_events
    conditions = [t.c.timestamp >= start, t.c.timestamp < end]
    if user_name:
        conditions.append(t.c.user_name == user_name)
    if source_ip:
        conditions.append(in_network(t.c.source_ip, source_ip))
    if outcome:
        conditions.append(t.c.outcome == outcome)

    columns = [t.c.ref, t.c.timestamp, t.c.user_name, func.host(t.c.source_ip).label("source_ip"), t.c.outcome,
               t.c.failure_reason, t.c.auth_method, t.c.mfa_used, t.c.user_agent, t.c.session_id]
    rows, groups, total = run(t, columns, conditions, t.c.outcome, limit, t.c.timestamp)
    events = [AuthEventOut.model_validate(r, from_attributes=True) for r in rows]
    return AuthResult(events=events, by_outcome=groups, total_matching=total, truncated=total > len(events))


@validate_call
def get_access_events(
    start: datetime,
    end: datetime,
    user_name: Name | None = None,
    area: Name | None = None,
    building: Name | None = None,
    decision: Literal["granted", "denied"] | None = None,
    restricted_only: bool = False,
    limit: Limit = 50,
) -> AccessResult:
    """Badge swipes at doors in a time range. restricted_only=True keeps only restricted areas (server room, labs...)."""
    start, end = time_range(start, end)
    t = access_events
    conditions = [t.c.timestamp >= start, t.c.timestamp < end]
    if user_name:
        conditions.append(t.c.user_name == user_name)
    if area:
        conditions.append(t.c.area == area)
    if building:
        conditions.append(t.c.building == building)
    if decision:
        conditions.append(t.c.decision == decision)
    if restricted_only:
        conditions.append(areas.c.restricted.is_(True))

    source = t.join(areas, t.c.area == areas.c.area)
    columns = [t.c.ref, t.c.timestamp, t.c.user_name, t.c.badge_id, t.c.area, t.c.building, areas.c.restricted,
               t.c.door_id, t.c.decision, t.c.reason]
    rows, groups, total = run(source, columns, conditions, t.c.decision, limit, t.c.timestamp)
    events = [AccessEventOut.model_validate(r, from_attributes=True) for r in rows]
    return AccessResult(events=events, by_decision=groups, total_matching=total, truncated=total > len(events))


@validate_call
def get_device_events(
    start: datetime,
    end: datetime,
    device_id: Name | None = None,
    area: Name | None = None,
    device_type: Literal["camera", "door_controller"] | None = None,
    status: Literal["online", "offline"] | None = None,
    limit: Limit = 50,
) -> DeviceResult:
    """Cameras and door controllers going offline/online in a time range, with the reason the device reported."""
    start, end = time_range(start, end)
    t = device_events
    conditions = [t.c.timestamp >= start, t.c.timestamp < end]
    if device_id:
        conditions.append(t.c.device_id == device_id)
    if area:
        conditions.append(t.c.area == area)
    if device_type:
        conditions.append(t.c.device_type == device_type)
    if status:
        conditions.append(t.c.status == status)

    columns = [t.c.ref, t.c.timestamp, t.c.device_id, t.c.device_type, t.c.area, t.c.building, t.c.status,
               t.c.reason]
    rows, groups, total = run(t, columns, conditions, t.c.status, limit, t.c.timestamp)
    events = [DeviceEventOut.model_validate(r, from_attributes=True) for r in rows]
    return DeviceResult(events=events, by_status=groups, total_matching=total, truncated=total > len(events))
