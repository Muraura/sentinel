from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Level(str, Enum):
    """Canonical severity. Every source's spelling (WARN, WARNING, warn, err...) maps to one of these."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"  # couldn't tell (e.g. a bare traceback line)


class LogFormat(str, Enum):
    """How the raw line was written. Each format needs its own parsing strategy."""

    JSON = "json"            # {"asctime": ..., "levelname": ..., "message": ...}       orders-api
    PYTHON_STD = "python"    # WARNING:orders-api:Coupon code not found: ...           orders-api
    TRACEBACK = "traceback"  # "Traceback (most recent call last):", indented frames,   orders-api
                             # and the final "orders.payments.errors.GatewayTimeoutError: ..."
    LOGFMT = "logfmt"        # ts=... level=info msg="..." attempt=2 err="..."          metrics-agent
    UNKNOWN = "unknown"


class LogEvent(BaseModel):
    """One normalized log event. Everything downstream (storage, search tools, agents) uses this shape."""

    # --- Source layer: Loki labels from "fields". Always present, trustworthy. ---
    service: str                           # fields.service_name  -> "orders-api", "metrics-agent"
    container: str                         # fields.container_name
    compose_project: str | None = None     # fields.compose_project -> "app"
    compose_service: str | None = None     # fields.compose_service -> "api"
    vm: str                                # fields.vm -> "app-vm-1"
    environment: str                       # fields.environment -> "production"

    # --- Time ---
    timestamp: datetime                    # from Loki's nanosecond "timestamp", UTC. The source of truth for ordering.
    timestamp_ns: int                      # same value, full precision: keeps events in the same millisecond in order

    # --- Parsed layer: extracted from inside "line". May be missing if parsing fails. ---
    level: Level = Level.UNKNOWN
    message: str | None = None             # JSON "message" / logfmt "msg" / text after "LEVEL:logger:"
    logger: str | None = None              # JSON "name" / python "orders-api" / "orders.payments..."
    event_id: str | None = None            # JSON "event_id" (usually null; no request IDs exist yet)
    error: str | None = None               # logfmt "err", or exception text like "GatewayTimeoutError: ..."
    exc_info: str | None = None            # JSON "exc_info": the attached stack trace
    attributes: dict[str, str] = Field(default_factory=dict)  # any other key/values, e.g. attempt=2

    # --- Parsing metadata ---
    format: LogFormat = LogFormat.UNKNOWN
    parse_ok: bool = True                  # False = stored anyway, but only `raw` can be trusted

    # --- Raw layer: the evidence. Never modified. ---
    raw: str
