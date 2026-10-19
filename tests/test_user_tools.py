from datetime import datetime, timezone

import pytest

from tools.user_tools import get_user_profile

DAY = (datetime(2026, 9, 30, 6, tzinfo=timezone.utc), datetime(2026, 9, 30, 18, tzinfo=timezone.utc))
INCIDENT = (datetime(2026, 9, 30, 1, 45, tzinfo=timezone.utc), datetime(2026, 9, 30, 3, tzinfo=timezone.utc))


def test_directory_facts_expose_the_misconfiguration():
    p = get_user_profile("l.ortiz")
    assert p.found and p.department == "Finance" and p.mfa_enrolled is False
    assert "A-ServerRoom" not in p.allowed_areas
    assert "A-ServerRoom" in p.group_granted_areas  # reachable only via legacy-all-access
    assert p.activity is None


def test_normal_user_has_no_group_granted_areas():
    assert get_user_profile("a.khan").group_granted_areas == []


def test_day_and_incident_activity_differ():
    day = get_user_profile("l.ortiz", *DAY).activity
    night = get_user_profile("l.ortiz", *INCIDENT).activity
    assert {ip: c.count for ip, c in day.source_ips.items()} == {"10.20.7.18": 1}
    assert {ip: c.count for ip, c in night.source_ips.items()} == {"203.0.113.45": 7}
    assert {k: c.count for k, c in night.logins.items()} == {"failure": 6, "success": 1}
    assert "A-ServerRoom" in night.areas_accessed and "A-ServerRoom" not in day.areas_accessed
    assert night.api_actions["Global profile export requested"].count == 140
    assert day.api_actions["Global profile export requested"].count == 3


def test_every_count_carries_real_evidence_ids():
    night = get_user_profile("l.ortiz", *INCIDENT).activity
    assert night.logins["success"].evidence == ["AUTH-00009"]
    assert len(night.logins["failure"].evidence) == 6 and night.logins["failure"].evidence[0] == "AUTH-00003"
    exports = night.api_actions["Global profile export requested"].evidence
    assert len(exports) == 6 and all(e.startswith("LOG-") for e in exports)  # first 3 + last 3 of 140
    assert night.areas_accessed["A-ServerRoom"].evidence[0].startswith("ACC-")


def test_unknown_user_is_reported_not_raised():
    p = get_user_profile("admin")
    assert p.found is False and p.department is None


def test_activity_window_needs_both_ends():
    with pytest.raises(ValueError):
        get_user_profile("l.ortiz", activity_start=DAY[0])
