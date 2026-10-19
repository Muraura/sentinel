-- One row per LogEvent (schemas/log_event.py). Column names match the model's fields.

CREATE TABLE IF NOT EXISTS log_events (
    id              BIGSERIAL PRIMARY KEY,

    -- Source layer (Loki labels)
    service         TEXT        NOT NULL,
    container       TEXT        NOT NULL,
    compose_project TEXT,
    compose_service TEXT,
    vm              TEXT        NOT NULL,
    environment     TEXT        NOT NULL,

    -- Time
    timestamp       TIMESTAMPTZ NOT NULL,
    timestamp_ns    BIGINT      NOT NULL,

    -- Parsed layer
    level           TEXT        NOT NULL,
    message         TEXT,
    logger          TEXT,
    event_id        TEXT,
    error           TEXT,
    exc_info        TEXT,
    attributes      JSONB       NOT NULL DEFAULT '{}',

    -- Parsing metadata
    format          TEXT        NOT NULL,
    parse_ok        BOOLEAN     NOT NULL,

    -- Raw layer + provenance
    raw             TEXT        NOT NULL,
    source_file     TEXT        NOT NULL,           -- which export this row came from
    fingerprint     TEXT        NOT NULL UNIQUE,    -- sha256(service|timestamp_ns|raw): re-ingesting is a no-op
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes match how the agent's tools will filter: by time, then service/level
CREATE INDEX IF NOT EXISTS idx_log_events_timestamp     ON log_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_log_events_service_time  ON log_events (service, timestamp);
CREATE INDEX IF NOT EXISTS idx_log_events_level_time    ON log_events (level, timestamp);


-- ===================== Security data (synthetic for now) =====================
-- Every event has a citable `ref` (AUTH-00042, ACC-00006, DEV-00001). It is also the idempotency key.

-- Reference data: who people are, what places and devices exist
CREATE TABLE IF NOT EXISTS users (
    user_name     TEXT PRIMARY KEY,
    full_name     TEXT    NOT NULL,
    department    TEXT    NOT NULL,
    badge_id      TEXT    NOT NULL UNIQUE,
    groups        TEXT[]  NOT NULL,
    allowed_areas TEXT[]  NOT NULL,
    shift         TEXT    NOT NULL,          -- day | night
    mfa_enrolled  BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS areas (
    area       TEXT PRIMARY KEY,
    building   TEXT    NOT NULL,
    restricted BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,               -- camera | door_controller
    area        TEXT NOT NULL REFERENCES areas (area),
    building    TEXT NOT NULL
);

-- Events
CREATE TABLE IF NOT EXISTS auth_events (
    id             BIGSERIAL PRIMARY KEY,
    ref            TEXT        NOT NULL UNIQUE,
    timestamp      TIMESTAMPTZ NOT NULL,
    user_name      TEXT        NOT NULL,     -- no FK: attackers try usernames that don't exist
    source_ip      INET        NOT NULL,
    outcome        TEXT        NOT NULL,     -- success | failure
    failure_reason TEXT,
    auth_method    TEXT        NOT NULL,
    mfa_used       BOOLEAN     NOT NULL,
    user_agent     TEXT,
    session_id     TEXT,
    source_file    TEXT        NOT NULL,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_events_time      ON auth_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_user_time ON auth_events (user_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_time   ON auth_events (source_ip, timestamp);

CREATE TABLE IF NOT EXISTS access_events (
    id          BIGSERIAL PRIMARY KEY,
    ref         TEXT        NOT NULL UNIQUE,
    timestamp   TIMESTAMPTZ NOT NULL,
    user_name   TEXT        NOT NULL REFERENCES users (user_name),
    badge_id    TEXT        NOT NULL,
    area        TEXT        NOT NULL REFERENCES areas (area),
    building    TEXT        NOT NULL,
    door_id     TEXT        NOT NULL,
    decision    TEXT        NOT NULL,        -- granted | denied
    reason      TEXT        NOT NULL,
    source_file TEXT        NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_access_events_time      ON access_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_access_events_user_time ON access_events (user_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_access_events_area_time ON access_events (area, timestamp);

CREATE TABLE IF NOT EXISTS device_events (
    id          BIGSERIAL PRIMARY KEY,
    ref         TEXT        NOT NULL UNIQUE,
    timestamp   TIMESTAMPTZ NOT NULL,
    device_id   TEXT        NOT NULL REFERENCES devices (device_id),
    device_type TEXT        NOT NULL,
    area        TEXT        NOT NULL,
    building    TEXT        NOT NULL,
    status      TEXT        NOT NULL,        -- online | offline
    reason      TEXT,
    source_file TEXT        NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_device_events_time        ON device_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_device_events_device_time ON device_events (device_id, timestamp);


-- ===================== Actions: the agent proposes, a human approves, code executes =====================

CREATE TABLE IF NOT EXISTS proposed_actions (
    id               BIGSERIAL PRIMARY KEY,
    investigation_id TEXT        NOT NULL,
    action_type      TEXT        NOT NULL,   -- disable_account | revoke_badge | block_ip | require_mfa | open_ticket
    target           TEXT        NOT NULL,
    justification    TEXT        NOT NULL,
    evidence         TEXT[]      NOT NULL,
    requested_by     TEXT,                   -- the person who started the investigation
    status           TEXT        NOT NULL DEFAULT 'pending',  -- pending | rejected | executed | failed
    proposed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by       TEXT,
    decided_at       TIMESTAMPTZ,
    decision_note    TEXT,
    executed_at      TIMESTAMPTZ,
    execution_result TEXT
);
CREATE INDEX IF NOT EXISTS idx_proposed_actions_status ON proposed_actions (status, proposed_at);

-- Append-only record of every proposal, decision and execution
CREATE TABLE IF NOT EXISTS audit_log (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT        NOT NULL,          -- "agent:<investigation id>" or a person
    event     TEXT        NOT NULL,          -- action_proposed | action_rejected | action_executed | action_failed
    action_id BIGINT      REFERENCES proposed_actions (id),
    details   JSONB       NOT NULL DEFAULT '{}'
);

-- What executed actions change (simulated enforcement: Sentinel's own records, not real systems)
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_disabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS badge_revoked    BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_required     BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip         INET        PRIMARY KEY,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    action_id  BIGINT      REFERENCES proposed_actions (id)
);
