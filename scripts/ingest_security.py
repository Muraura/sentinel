"""Load data/synthetic/ into Postgres: directory, security events, and the portal-api log lines.

Usage:  .venv/bin/python scripts/ingest_security.py           # add what's new
        .venv/bin/python scripts/ingest_security.py --reset   # replace all synthetic data
Safe to re-run: rows already stored (same ref / user / fingerprint) are skipped. That also means a CHANGED
row is skipped, so after changing the generator, use --reset.
"""
import argparse
import json
import os

import psycopg

from clean_data import SENTINEL_DIR
from ingest import ingest as ingest_logs

DATA_DIR = SENTINEL_DIR / "data" / "synthetic"
SCHEMA = SENTINEL_DIR / "db" / "schema.sql"

DIRECTORY_SQL = {
    "users": """INSERT INTO users (user_name, full_name, department, badge_id, groups, allowed_areas, shift, mfa_enrolled)
                VALUES (%(user_name)s, %(full_name)s, %(department)s, %(badge_id)s, %(groups)s, %(allowed_areas)s,
                        %(shift)s, %(mfa_enrolled)s)
                ON CONFLICT (user_name) DO NOTHING""",
    "areas": """INSERT INTO areas (area, building, restricted) VALUES (%(area)s, %(building)s, %(restricted)s)
                ON CONFLICT (area) DO NOTHING""",
    "devices": """INSERT INTO devices (device_id, device_type, area, building)
                  VALUES (%(device_id)s, %(device_type)s, %(area)s, %(building)s)
                  ON CONFLICT (device_id) DO NOTHING""",
}

# Column lists per event table; values come from the JSONL keys with the same names
EVENT_TABLES = {
    "auth_events": ["ref", "timestamp", "user_name", "source_ip", "outcome", "failure_reason", "auth_method",
                    "mfa_used", "user_agent", "session_id"],
    "access_events": ["ref", "timestamp", "user_name", "badge_id", "area", "building", "door_id", "decision",
                      "reason"],
    "device_events": ["ref", "timestamp", "device_id", "device_type", "area", "building", "status", "reason"],
}


def event_sql(table: str, columns: list[str]) -> str:
    # Table and column names come from the constant above, never from input
    cols = columns + ["source_file"]
    return (f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(f'%({c})s' for c in cols)}) "
            f"ON CONFLICT (ref) DO NOTHING")


def main(reset: bool) -> None:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(SCHEMA.read_text())  # every statement is IF NOT EXISTS, so this only adds what's missing
        if reset:
            cur.execute("TRUNCATE auth_events, access_events, device_events, devices, users, areas")
            cur.execute("DELETE FROM log_events WHERE source_file IN ('app_logs.json', 'platform_logs.json')")
            print(f"reset: synthetic security data and {cur.rowcount} synthetic log lines removed")

        directory = json.loads((DATA_DIR / "directory.json").read_text())
        for key in ("areas", "devices", "users"):  # areas first: devices reference them
            cur.executemany(DIRECTORY_SQL[key], directory[key])
            print(f"{key}: {len(directory[key])} in file")

        for table, columns in EVENT_TABLES.items():
            path = DATA_DIR / f"{table}.jsonl"
            rows = [{**json.loads(line), "source_file": path.name} for line in path.read_text().splitlines()]
            before = cur.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            cur.executemany(event_sql(table, columns), rows)
            after = cur.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            print(f"{table}: {len(rows)} in file, {after - before} inserted")

    ingest_logs(DATA_DIR / "app_logs.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="delete all synthetic data first, then reload")
    main(parser.parse_args().reset)
