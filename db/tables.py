"""SQLAlchemy Core view of the tables in db/schema.sql. schema.sql stays the source of truth for creating them."""
import os
from functools import cache
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Engine, MetaData, Table, Text, create_engine, func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

metadata = MetaData()

log_events = Table(
    "log_events",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("service", Text, nullable=False),
    Column("container", Text, nullable=False),
    Column("compose_project", Text),
    Column("compose_service", Text),
    Column("vm", Text, nullable=False),
    Column("environment", Text, nullable=False),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Column("timestamp_ns", BigInteger, nullable=False),
    Column("level", Text, nullable=False),
    Column("message", Text),
    Column("logger", Text),
    Column("event_id", Text),
    Column("error", Text),
    Column("exc_info", Text),
    Column("attributes", JSONB, nullable=False),
    Column("format", Text, nullable=False),
    Column("parse_ok", Boolean, nullable=False),
    Column("raw", Text, nullable=False),
    Column("source_file", Text, nullable=False),
    Column("fingerprint", Text, nullable=False, unique=True),
    Column("ingested_at", DateTime(timezone=True), nullable=False),
)

users = Table(
    "users",
    metadata,
    Column("user_name", Text, primary_key=True),
    Column("full_name", Text, nullable=False),
    Column("department", Text, nullable=False),
    Column("badge_id", Text, nullable=False, unique=True),
    Column("groups", ARRAY(Text), nullable=False),
    Column("allowed_areas", ARRAY(Text), nullable=False),
    Column("shift", Text, nullable=False),
    Column("mfa_enrolled", Boolean, nullable=False),
    Column("account_disabled", Boolean, nullable=False, server_default="false"),
    Column("badge_revoked", Boolean, nullable=False, server_default="false"),
    Column("mfa_required", Boolean, nullable=False, server_default="false"),
)

areas = Table(
    "areas",
    metadata,
    Column("area", Text, primary_key=True),
    Column("building", Text, nullable=False),
    Column("restricted", Boolean, nullable=False),
)

devices = Table(
    "devices",
    metadata,
    Column("device_id", Text, primary_key=True),
    Column("device_type", Text, nullable=False),
    Column("area", Text, nullable=False),
    Column("building", Text, nullable=False),
)

auth_events = Table(
    "auth_events",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("ref", Text, nullable=False, unique=True),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Column("user_name", Text, nullable=False),
    Column("source_ip", INET, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("failure_reason", Text),
    Column("auth_method", Text, nullable=False),
    Column("mfa_used", Boolean, nullable=False),
    Column("user_agent", Text),
    Column("session_id", Text),
    Column("source_file", Text, nullable=False),
    Column("ingested_at", DateTime(timezone=True), nullable=False),
)

access_events = Table(
    "access_events",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("ref", Text, nullable=False, unique=True),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Column("user_name", Text, nullable=False),
    Column("badge_id", Text, nullable=False),
    Column("area", Text, nullable=False),
    Column("building", Text, nullable=False),
    Column("door_id", Text, nullable=False),
    Column("decision", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("source_file", Text, nullable=False),
    Column("ingested_at", DateTime(timezone=True), nullable=False),
)

device_events = Table(
    "device_events",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("ref", Text, nullable=False, unique=True),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Column("device_id", Text, nullable=False),
    Column("device_type", Text, nullable=False),
    Column("area", Text, nullable=False),
    Column("building", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("reason", Text),
    Column("source_file", Text, nullable=False),
    Column("ingested_at", DateTime(timezone=True), nullable=False),
)

proposed_actions = Table(
    "proposed_actions",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("investigation_id", Text, nullable=False),
    Column("action_type", Text, nullable=False),
    Column("target", Text, nullable=False),
    Column("justification", Text, nullable=False),
    Column("evidence", ARRAY(Text), nullable=False),
    Column("requested_by", Text),
    Column("status", Text, nullable=False, server_default="pending"),
    Column("proposed_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("decided_by", Text),
    Column("decided_at", DateTime(timezone=True)),
    Column("decision_note", Text),
    Column("executed_at", DateTime(timezone=True)),
    Column("execution_result", Text),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("actor", Text, nullable=False),
    Column("event", Text, nullable=False),
    Column("action_id", BigInteger),
    Column("details", JSONB, nullable=False, server_default="{}"),
)

blocked_ips = Table(
    "blocked_ips",
    metadata,
    Column("ip", INET, primary_key=True),
    Column("blocked_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("action_id", BigInteger),
)


@cache
def get_engine() -> Engine:
    # .env holds a plain postgresql:// URL (psycopg.connect needs that); SQLAlchemy needs the driver named
    url = os.environ["DATABASE_URL"].replace("postgresql://", "postgresql+psycopg://", 1)
    # Fail fast when the database is down: a hung tool call would freeze the whole agent loop
    return create_engine(url, connect_args={"connect_timeout": 5})
