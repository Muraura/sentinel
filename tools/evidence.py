"""Evidence IDs: the citable references every tool returns, and the check that a cited ID really exists.

AUTH-00009 (login), ACC-00007 (badge swipe), DEV-00001 (device status change), LOG-10030 (log line).
Used by the report validation (agent side) and the scorer (eval side), so both apply the same rule.
"""
import re

from sqlalchemy import select

from db.tables import access_events, auth_events, device_events, get_engine, log_events

EVIDENCE_ID = r"(?:AUTH|ACC|DEV)-\d{5}|LOG-\d+"
EVIDENCE_ID_RE = re.compile(rf"^{EVIDENCE_ID}$")
# Anything shaped like an ID (PREFIX-digits) in free text. Real evidence prefixes are checked against the database;
# other prefixes count as invented, except identifiers that name something else (badges, change tickets, scenarios).
ID_LIKE = re.compile(r"\b[A-Z][A-Z0-9]{1,9}-\d{3,}\b")
NOT_EVIDENCE_PREFIXES = ("BDG", "CHG", "INC", "BENIGN", "CVE")


def evidence_like_tokens(text: str) -> set[str]:
    """Every token in the text that looks like an evidence ID and isn't a known non-evidence identifier."""
    return {t for t in ID_LIKE.findall(text) if t.split("-")[0] not in NOT_EVIDENCE_PREFIXES}


def existing_ids(ids: set[str]) -> set[str]:
    """Which of these evidence IDs really exist in the database."""
    refs = [i for i in ids if i.split("-")[0] in ("AUTH", "ACC", "DEV")]
    log_ids = [int(i[4:]) for i in ids if i.startswith("LOG-") and i[4:].isdigit()]
    found: set[str] = set()
    with get_engine().connect() as conn:
        for table in (auth_events, access_events, device_events):
            if refs:
                found |= set(conn.execute(select(table.c.ref).where(table.c.ref.in_(refs))).scalars())
        if log_ids:
            rows = conn.execute(select(log_events.c.id).where(log_events.c.id.in_(log_ids))).scalars()
            found |= {f"LOG-{i}" for i in rows}
    return found
