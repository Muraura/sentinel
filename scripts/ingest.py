"""Parse a Grafana/Loki JSON export and store it in Postgres.

Usage:  .venv/bin/python scripts/ingest.py [path/to/export.json]
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from psycopg.types.json import Jsonb

from clean_data import LOG_FILE, SENTINEL_DIR, parse_entry
from schemas.log_event import LogEvent

load_dotenv(SENTINEL_DIR / ".env")

INSERT_SQL = """
INSERT INTO log_events (
    service, container, compose_project, compose_service, vm, environment,
    timestamp, timestamp_ns,
    level, message, logger, event_id, error, exc_info, attributes,
    format, parse_ok,
    raw, source_file, fingerprint
) VALUES (
    %(service)s, %(container)s, %(compose_project)s, %(compose_service)s, %(vm)s, %(environment)s,
    %(timestamp)s, %(timestamp_ns)s,
    %(level)s, %(message)s, %(logger)s, %(event_id)s, %(error)s, %(exc_info)s, %(attributes)s,
    %(format)s, %(parse_ok)s,
    %(raw)s, %(source_file)s, %(fingerprint)s
)
ON CONFLICT (fingerprint) DO NOTHING
"""


def fingerprint(event: LogEvent) -> str:
    """Same line from the same service at the same nanosecond = same event."""
    key = f"{event.service}|{event.timestamp_ns}|{event.raw}"
    return hashlib.sha256(key.encode()).hexdigest()


def to_row(event: LogEvent, source_file: str) -> dict:
    row = event.model_dump(mode="json")  # enums -> their string values
    row["timestamp"] = event.timestamp   # keep the real datetime for TIMESTAMPTZ
    row["attributes"] = Jsonb(event.attributes)
    row["source_file"] = source_file
    row["fingerprint"] = fingerprint(event)
    return row


def ingest(path: Path) -> None:
    with open(path) as f:
        entries = json.load(f)
    rows = [to_row(parse_entry(e), path.name) for e in entries]

    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            before = cur.execute("SELECT count(*) FROM log_events").fetchone()[0]
            cur.executemany(INSERT_SQL, rows)
            after = cur.execute("SELECT count(*) FROM log_events").fetchone()[0]

    print(f"{path.name}: {len(rows)} parsed, {after - before} inserted, "
          f"{len(rows) - (after - before)} already stored. Table now has {after} rows.")


if __name__ == "__main__":
    ingest(Path(sys.argv[1]) if len(sys.argv) > 1 else LOG_FILE)
