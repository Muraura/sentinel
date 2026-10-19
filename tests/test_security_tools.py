"""The security tools and build_timeline, checked against the INC-001 answer key."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.security_tools import get_access_events, get_auth_events, get_device_events
from tools.timeline import build_timeline

TRUTH = json.loads(
    (Path(__file__).resolve().parent.parent / "data/synthetic/ground_truth/INC-001.json").read_text())
STEPS = TRUTH["expected"]["timeline"]
FAILED_REFS, SUCCESS_REFS, ACCESS_REFS, CAMERA_REFS = (STEPS[i]["refs"] for i in range(4))

DAY_START = datetime(2026, 9, 30, tzinfo=timezone.utc)
DAY_END = datetime(2026, 10, 1, tzinfo=timezone.utc)
INC_START = datetime(2026, 9, 30, 1, 45, tzinfo=timezone.utc)
INC_END = datetime(2026, 9, 30, 3, 0, tzinfo=timezone.utc)


# ---------- get_auth_events ----------

def test_auth_events_for_attacker_ip_match_answer_key():
    result = get_auth_events(INC_START, INC_END, source_ip="203.0.113.45")
    assert [e.ref for e in result.events] == FAILED_REFS + SUCCESS_REFS
    assert result.by_outcome == {"failure": 6, "success": 1}
    assert result.events[-1].mfa_used is False


def test_auth_events_accept_ip_ranges():
    result = get_auth_events(DAY_START, DAY_END, source_ip="198.51.100.0/24", limit=200)
    assert result.total_matching == 25
    assert {e.failure_reason for e in result.events} == {"unknown_user"}


def test_auth_events_summary_counts_everything_even_when_truncated():
    result = get_auth_events(DAY_START, DAY_END, limit=3)
    assert len(result.events) == 3
    assert result.truncated is True
    assert sum(result.by_outcome.values()) == result.total_matching > 3


def test_auth_events_reject_bad_ip():
    with pytest.raises(ValidationError):
        get_auth_events(DAY_START, DAY_END, source_ip="not-an-ip")
    with pytest.raises(ValidationError):
        get_auth_events(DAY_START, DAY_END, source_ip="203.0.113.45'; DROP TABLE auth_events; --")


# ---------- get_access_events ----------

def test_access_events_restricted_only_finds_server_room_entry():
    result = get_access_events(INC_START, INC_END, restricted_only=True)
    assert all(e.restricted for e in result.events)
    entry = next(e for e in result.events if e.ref in ACCESS_REFS)
    assert (entry.user_name, entry.area, entry.decision) == ("l.ortiz", "A-ServerRoom", "granted")
    assert "legacy-all-access" in entry.reason


def test_access_events_denied_filter():
    result = get_access_events(DAY_START, DAY_END, decision="denied")
    assert result.by_decision.keys() <= {"denied"}
    assert all(e.decision == "denied" for e in result.events)


# ---------- get_device_events ----------

def test_device_events_offline_includes_incident_and_decoys():
    result = get_device_events(DAY_START, DAY_END, status="offline")
    refs = {e.ref for e in result.events}
    decoy_refs = {r for d in TRUTH["decoys"] for r in d["refs"] if r.startswith("DEV-")}
    assert set(CAMERA_REFS) <= refs
    assert decoy_refs <= refs  # the tool returns facts; deciding what's benign is the agent's job


def test_device_events_by_device():
    result = get_device_events(DAY_START, DAY_END, device_id="CAM-A-SERVERROOM-01")
    assert [e.status for e in result.events] == ["offline", "online"]


# ---------- build_timeline ----------

def incident_timeline(**overrides):
    args = dict(start=INC_START, end=INC_END, user_name="l.ortiz", source_ip="203.0.113.45", area="A-ServerRoom")
    return build_timeline(**(args | overrides))


def test_timeline_contains_every_answer_key_ref_in_order():
    refs = [item.ref for item in incident_timeline().items]
    expected = FAILED_REFS + SUCCESS_REFS + ACCESS_REFS + CAMERA_REFS
    assert [r for r in refs if r in expected] == expected


def test_timeline_is_chronological_across_sources():
    items = incident_timeline().items
    assert {i.source for i in items} == {"auth", "access", "device", "logs"}
    assert [i.timestamp for i in items] == sorted(i.timestamp for i in items)


def test_timeline_collapses_export_burst_but_keeps_spaced_failures():
    items = incident_timeline().items
    exports = [i for i in items if "Global profile export requested" in i.summary]
    assert sum(i.count for i in exports) == 140
    assert len(exports) <= 3
    failures = [i for i in items if i.source == "logs" and "Login failed" in i.summary]
    assert len(failures) == 6 and all(i.count == 1 for i in failures)


def test_timeline_entities_are_or_combined():
    by_user = {i.ref for i in incident_timeline(source_ip=None, area=None).items}
    by_area = {i.ref for i in incident_timeline(user_name=None, source_ip=None).items}
    combined = {i.ref for i in incident_timeline().items}
    assert by_user | by_area <= combined
    assert set(CAMERA_REFS) <= by_area and not set(CAMERA_REFS) & by_user  # the camera has no user


def test_timeline_sources_filter_and_limit():
    result = incident_timeline(sources=["auth"], limit=3)
    assert {i.source for i in result.items} == {"auth"}
    assert len(result.items) == 3 and result.truncated is True
