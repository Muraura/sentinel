import json
import re
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Resolve relative to this file, not the folder you run it from:
# Sentinel/scripts/clean_data.py -> Sentinel/data/sample/sample_logs.json.
# Pass another Loki export path to scripts/ingest.py to load your own logs instead.
SENTINEL_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = SENTINEL_DIR / "data" / "sample" / "sample_logs.json"

sys.path.insert(0, str(SENTINEL_DIR))
from schemas.log_event import Level, LogEvent, LogFormat  # noqa: E402

# Every spelling we've seen (or expect) -> one canonical Level
LEVEL_ALIASES = {
    "debug": Level.DEBUG,
    "info": Level.INFO,
    "warn": Level.WARNING,
    "warning": Level.WARNING,
    "error": Level.ERROR,
    "err": Level.ERROR,
    "critical": Level.CRITICAL,
    "fatal": Level.CRITICAL,
}

# WARNING:orders-api:Coupon code not found: SPRING10
PYTHON_STD_RE = re.compile(r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL):([^:]+):(.*)$", re.DOTALL)

# orders.payments.errors.GatewayTimeoutError: pay.example.com did not respond within 5s
EXCEPTION_LINE_RE = re.compile(r"^[\w.]+(Error|Exception|Exit|Interrupt)\b")


def normalize_level(value: str | None) -> Level:
    if not value:
        return Level.UNKNOWN
    return LEVEL_ALIASES.get(value.strip().lower(), Level.UNKNOWN)


def source_fields(entry: dict) -> dict:
    """The parts every format shares: Loki labels + Loki's timestamp + the untouched raw line."""
    labels = entry["fields"]
    ns = int(entry["timestamp"])
    return {
        "service": labels["service_name"],
        "container": labels["container_name"],
        "compose_project": labels.get("compose_project"),
        "compose_service": labels.get("compose_service"),
        "vm": labels["vm"],
        "environment": labels["environment"],
        "timestamp": datetime.fromtimestamp(ns / 1e9, tz=timezone.utc),
        "timestamp_ns": ns,
        "raw": entry["line"],
    }


def parse_json_line(entry: dict) -> LogEvent:
    """{"asctime": ..., "levelname": "ERROR", "name": "orders-api", "message": ..., "event_id": null}"""
    data = json.loads(entry["line"])
    known = {"levelname", "message", "name", "event_id", "exc_info"}
    return LogEvent(
        **source_fields(entry),
        format=LogFormat.JSON,
        level=normalize_level(data.get("levelname")),
        message=data.get("message"),
        logger=data.get("name"),
        event_id=str(data["event_id"]) if data.get("event_id") is not None else None,
        exc_info=data.get("exc_info"),
        attributes={k: str(v) for k, v in data.items() if k not in known and v is not None},
    )


def parse_python_line(entry: dict) -> LogEvent:
    """WARNING:orders-api:Coupon code not found: SPRING10"""
    match = PYTHON_STD_RE.match(entry["line"].strip())
    level, logger, message = match.groups()
    return LogEvent(
        **source_fields(entry),
        format=LogFormat.PYTHON_STD,
        level=normalize_level(level),
        logger=logger,
        message=message.strip(),
    )


def parse_logfmt_line(entry: dict) -> LogEvent:
    """ts=2026-09-30T05:09:56Z level=info msg="scrape failed" attempt=2 err="..." """
    pairs = {}
    for token in shlex.split(entry["line"].strip()):  # shlex keeps "quoted values" together
        key, sep, value = token.partition("=")
        if sep:
            pairs[key] = value
    known = {"ts", "level", "msg", "err"}
    return LogEvent(
        **source_fields(entry),
        format=LogFormat.LOGFMT,
        level=normalize_level(pairs.get("level")),
        message=pairs.get("msg"),
        error=pairs.get("err"),
        attributes={k: v for k, v in pairs.items() if k not in known},
    )


def parse_traceback_line(entry: dict) -> LogEvent:
    """One fragment of a multi-line stack trace. Joining fragments back together is a later step."""
    line = entry["line"].strip()
    is_exception = bool(EXCEPTION_LINE_RE.match(line))
    return LogEvent(
        **source_fields(entry),
        format=LogFormat.TRACEBACK,
        message=line,
        error=line if is_exception else None,
        parse_ok=False,  # a fragment alone isn't a complete event
    )


def parse_entry(entry: dict) -> LogEvent:
    """Detect the format, then hand off to the right parser. Never raises: unparseable lines keep their raw text."""
    line = entry["line"]
    stripped = line.strip()
    try:
        if stripped.startswith("{"):
            return parse_json_line(entry)
        if PYTHON_STD_RE.match(stripped):
            return parse_python_line(entry)
        if stripped.startswith("ts=") or " level=" in stripped:
            return parse_logfmt_line(entry)
        if line[:1].isspace() or stripped.startswith("Traceback") or EXCEPTION_LINE_RE.match(stripped):
            return parse_traceback_line(entry)
    except (ValueError, AttributeError):
        pass  # json/shlex/regex failed: fall through and keep the raw line
    return LogEvent(**source_fields(entry), format=LogFormat.UNKNOWN, parse_ok=False)


if __name__ == "__main__":
    with open(LOG_FILE) as f:
        entries = json.load(f)

    events = [parse_entry(e) for e in entries]

    print(f"Parsed {len(events)} entries\n")
    print("By service / format / parse_ok:")
    for key, count in sorted(Counter((e.service, e.format.value, e.parse_ok) for e in events).items()):
        print(f"  {key}: {count}")
    print("\nBy level:")
    for key, count in Counter(e.level.value for e in events).most_common():
        print(f"  {key}: {count}")
