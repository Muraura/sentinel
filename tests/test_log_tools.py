"""Integration tests against the sample in Postgres (run scripts/ingest.py first).

Expected numbers come from data/sample/sample_logs.json (scripts/generate_sample_logs.py):
orders-api logs every event twice (JSON + plain text), so 200 errors show up as 400 rows.
The synthetic security data (scripts/generate_security_data.py) uses other service names, so these counts are unaffected.
"""
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tools.log_tools import count_events, get_error_patterns, get_event_rate, get_events_around, search_logs

START = datetime(2026, 9, 30, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)


def test_search_logs_reports_truncation():
    result = search_logs(START, END, service="orders-api", level="ERROR", limit=5)
    assert len(result.events) == 5
    assert result.total_matching == 400
    assert result.truncated is True
    assert all(e.level == "ERROR" for e in result.events)


def test_search_logs_text_is_matched_literally():
    assert search_logs(START, END, text="timeout").total_matching > 0
    # "%" would match everything if it were treated as a SQL wildcard
    assert search_logs(START, END, text="%").total_matching == 0
    assert search_logs(START, END, text="'; DROP TABLE log_events; --").total_matching == 0


def test_search_logs_rejects_bad_input():
    with pytest.raises(ValidationError):
        search_logs(START, END, level="SEVERE")  # not a known level
    with pytest.raises(ValidationError):
        search_logs(START, END, limit=10_000)  # over the cap
    with pytest.raises(ValueError):
        search_logs(END, START)  # reversed range


def test_count_events_by_service_and_level():
    result = count_events(START, END, group_by=["service", "level"])
    counts = {(g.key["service"], g.key["level"]): g.count for g in result.groups}
    assert counts[("metrics-agent", "INFO")] == 1686
    assert counts[("orders-api", "ERROR")] == 400
    assert result.total == sum(counts.values())


def test_count_events_only_allows_known_columns():
    with pytest.raises(ValidationError):
        count_events(START, END, group_by=["raw"])


def test_error_patterns_group_similar_messages():
    result = get_error_patterns(START, END, min_level="ERROR")
    templates = {p.template: p.count for p in result.patterns}
    assert templates["Payment gateway request failed: read timeout"] >= 198


def test_event_rate_fills_empty_buckets():
    result = get_event_rate(START, END, bucket_minutes=60)
    assert len(result.buckets) == 24
    assert result.total == count_events(START, END, group_by=["service"]).total
    assert any(b.count == 0 for b in result.buckets)  # hours outside the 4h sample


def test_event_rate_refuses_too_many_buckets():
    with pytest.raises(ValueError):
        get_event_rate(START, END, bucket_minutes=1)  # 1440 buckets


def test_events_around_returns_context_in_order():
    anchor_id = search_logs(START, END, level="ERROR", limit=1).events[0].id
    result = get_events_around(anchor_id, before_seconds=5, after_seconds=5)
    assert result.anchor.id == anchor_id
    assert all(e.id != anchor_id for e in result.events)
    timestamps = [e.timestamp for e in result.events]
    assert timestamps == sorted(timestamps)
