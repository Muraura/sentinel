"""Checks that INC-001 is in the database exactly as data/synthetic/ground_truth/INC-001.json describes it.
Run scripts/generate_security_data.py and scripts/ingest_security.py first.
"""
import json
from datetime import datetime, timezone

from sqlalchemy import text

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from clean_data import SENTINEL_DIR  # noqa: E402
from db.tables import get_engine  # noqa: E402
from tools.log_tools import search_logs  # noqa: E402

GROUND_TRUTH = json.loads((SENTINEL_DIR / "data" / "synthetic" / "ground_truth" / "INC-001.json").read_text())
WINDOW_START = datetime(2026, 9, 30, 1, 45, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 9, 30, 3, 0, tzinfo=timezone.utc)


def query(sql: str, **params):
    with get_engine().connect() as conn:
        return conn.execute(text(sql), params).all()


def test_every_ground_truth_ref_exists():
    refs = [r for step in GROUND_TRUTH["expected"]["timeline"] for r in step["refs"]]
    refs += [r for decoy in GROUND_TRUTH["decoys"] for r in decoy["refs"]]
    found = {row.ref for row in query(
        "SELECT ref FROM auth_events UNION ALL SELECT ref FROM access_events UNION ALL SELECT ref FROM device_events")}
    assert set(refs) <= found


def test_failed_logins_then_success_without_mfa():
    rows = query("""SELECT outcome, mfa_used FROM auth_events
                    WHERE user_name = 'l.ortiz' AND source_ip = '203.0.113.45' ORDER BY timestamp""")
    assert [r.outcome for r in rows] == ["failure"] * 6 + ["success"]
    assert rows[-1].mfa_used is False


def test_server_room_access_granted_only_by_legacy_group():
    row = query("SELECT decision, reason FROM access_events WHERE user_name = 'l.ortiz' AND area = 'A-ServerRoom'")[0]
    assert row.decision == "granted"
    assert "legacy-all-access" in row.reason
    finance_areas = query("SELECT allowed_areas FROM users WHERE user_name = 'l.ortiz'")[0].allowed_areas
    assert "A-ServerRoom" not in finance_areas


def test_server_room_camera_offline_during_incident():
    rows = query("""SELECT status FROM device_events WHERE device_id = 'CAM-A-SERVERROOM-01' ORDER BY timestamp""")
    assert [r.status for r in rows] == ["offline", "online"]


def test_log_tools_see_the_bulk_export():
    # The existing log tool finds the synthetic API logs: the sources line up
    result = search_logs(WINDOW_START, WINDOW_END, text="Global profile export requested", limit=1)
    assert result.total_matching == 140


def test_no_answer_key_leaks_into_the_data():
    for table in ("auth_events", "access_events", "device_events"):
        columns = {r.column_name for r in query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = :t", t=table)}
        assert not columns & {"tag", "_tag", "incident", "is_attack", "label"}
