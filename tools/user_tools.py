"""get_user_profile: who a user is (directory) and, optionally, what they did in a time window (activity).

Answers "is this normal for this person?". Call it twice with different windows to compare,
e.g. a normal working day against the incident window.

Every activity count carries the evidence IDs behind it (first and last few, in time order). Without them,
a model told to cite evidence for every claim has nothing to cite, and invents plausible-looking IDs.
"""
from datetime import datetime

from pydantic import BaseModel, validate_call
from sqlalchemy import and_, func, literal, select

from sqlalchemy.dialects.postgresql import aggregate_order_by

from db.tables import access_events, areas, auth_events, get_engine, log_events, users
from tools.common import Name, time_range


EVIDENCE_PER_GROUP = 6  # IDs listed per count: the first 3 and the last 3, so the start and end are both citable


class Counted(BaseModel):
    count: int
    evidence: list[str]             # citable IDs behind this count (AUTH-..., ACC-..., LOG-...)


class Activity(BaseModel):
    start: datetime
    end: datetime
    logins: dict[str, Counted]          # {"failure": {"count": 6, "evidence": ["AUTH-00003", ...]}}
    source_ips: dict[str, Counted]      # IP -> login attempts
    user_agents: dict[str, Counted]
    areas_accessed: dict[str, Counted]  # area -> granted badge swipes
    api_actions: dict[str, Counted]     # log message -> count, from log lines that name this user


class UserProfile(BaseModel):
    user_name: str
    found: bool                     # False = not in the directory. That is evidence too (e.g. "admin" sprays).
    full_name: str | None = None
    department: str | None = None
    badge_id: str | None = None
    groups: list[str] = []
    shift: str | None = None
    mfa_enrolled: bool | None = None
    allowed_areas: list[str] = []   # what the department permits
    group_granted_areas: list[str] = []  # restricted areas reachable ONLY through extra groups
    activity: Activity | None = None


def _counts(conn, column, ref, timestamp, where) -> dict[str, Counted]:
    """Count rows per value of `column`, keeping the evidence IDs (`ref`) in time order."""
    rows = conn.execute(
        select(column.label("key"), func.count().label("n"),
               func.array_agg(aggregate_order_by(ref, timestamp)).label("refs"))
        .where(where).group_by(column).order_by(func.count().desc())
    )
    result = {}
    for row in rows:
        ids = row.refs
        half = EVIDENCE_PER_GROUP // 2
        sample = ids if len(ids) <= EVIDENCE_PER_GROUP else ids[:half] + ids[-half:]
        result[str(row.key)] = Counted(count=row.n, evidence=sample)
    return result


@validate_call
def get_user_profile(
    user_name: Name,
    activity_start: datetime | None = None,
    activity_end: datetime | None = None,
) -> UserProfile:
    """Directory facts for a user (department, groups, MFA, permitted areas). Pass activity_start and
    activity_end to also summarise their logins, IPs, badge use and API actions in that window."""
    if (activity_start is None) != (activity_end is None):
        raise ValueError("pass both activity_start and activity_end, or neither")

    with get_engine().connect() as conn:
        user = conn.execute(select(users).where(users.c.user_name == user_name)).one_or_none()
        profile = UserProfile(user_name=user_name, found=user is not None)

        if user is not None:
            restricted = [r.area for r in conn.execute(select(areas.c.area).where(areas.c.restricted.is_(True)))]
            extra_groups = [g for g in user.groups if g != user.department.lower()]
            profile = UserProfile(
                user_name=user_name, found=True, full_name=user.full_name, department=user.department,
                badge_id=user.badge_id, groups=user.groups, shift=user.shift, mfa_enrolled=user.mfa_enrolled,
                allowed_areas=user.allowed_areas,
                # Mirrors the access system's rule: legacy-all-access opens every door
                group_granted_areas=sorted(set(restricted) - set(user.allowed_areas))
                if "legacy-all-access" in extra_groups else [],
            )

        if activity_start is not None:
            start, end = time_range(activity_start, activity_end)
            a, ac, lg = auth_events, access_events, log_events
            auth_where = and_(a.c.user_name == user_name, a.c.timestamp >= start, a.c.timestamp < end)
            access_where = and_(ac.c.user_name == user_name, ac.c.decision == "granted",
                                ac.c.timestamp >= start, ac.c.timestamp < end)
            log_where = and_(lg.c.attributes["user"].astext == user_name, lg.c.timestamp >= start, lg.c.timestamp < end)
            log_ref = func.concat(literal("LOG-"), lg.c.id)
            profile.activity = Activity(
                start=start,
                end=end,
                logins=_counts(conn, a.c.outcome, a.c.ref, a.c.timestamp, auth_where),
                source_ips=_counts(conn, func.host(a.c.source_ip), a.c.ref, a.c.timestamp, auth_where),
                user_agents=_counts(conn, a.c.user_agent, a.c.ref, a.c.timestamp, auth_where),
                areas_accessed=_counts(conn, ac.c.area, ac.c.ref, ac.c.timestamp, access_where),
                api_actions=_counts(conn, lg.c.message, log_ref, lg.c.timestamp, log_where),
            )
    return profile
