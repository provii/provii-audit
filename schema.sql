-- Provii Audit System v2.2: D1 Schema
-- Applied to: provii-audit-db (production) and provii-audit-db-sandbox (sandbox)

-- audit_events has no write-once constraint at the SQL level. The
-- event_id UNIQUE index rejects duplicate inserts (INSERT OR IGNORE), and the
-- digest chain in audit_digests provides cryptographic tamper DETECTION (not
-- prevention). An attacker with D1 write access could mutate rows, but chain
-- verification would detect the inconsistency. This is an accepted design choice:
-- D1 does not support triggers or row-level immutability, so tamper prevention
-- is delegated to Cloudflare access controls and the digest verification tooling.
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    timestamp_ms INTEGER NOT NULL,
    source_service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'error', 'critical')),
    client_ip_hash TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT '',
    user_agent_hash TEXT NOT NULL DEFAULT '',
    challenge_id TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    request_id TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'production' CHECK(environment IN ('production', 'sandbox')),
    worker_version TEXT NOT NULL DEFAULT '',
    geo_country TEXT NOT NULL DEFAULT '',
    event_category TEXT NOT NULL DEFAULT '' CHECK(event_category IN ('', 'AUTHENTICATION', 'AUTHORIZATION', 'KEY_ACCESS', 'DATA_MUTATION', 'SESSION_LIFECYCLE', 'CREDENTIAL_ISSUANCE', 'VERIFICATION', 'ADMIN_ACTION', 'EXTERNAL_CALL', 'SECURITY_EVENT')),
    actor_id TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT '' CHECK(actor_type IN ('', 'user', 'service', 'api_key', 'system')),
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('', 'success', 'failure', 'denied', 'error')),
    queue_message_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Indexing policy (R11 - D1 write-amplification reduction):
-- Only the two indexes that an actual query path uses are kept. D1 bills every
-- index entry as a written row on BOTH INSERT and the retention DELETE, so each
-- secondary index multiplied the per-row write cost (the #2/#3 cost drivers) and
-- consumed the single-threaded D1 ~100 write-query/sec budget for nothing.
--
-- KEPT (each has a real reader):
--   * event_id UNIQUE (on the table above) - backs the idempotent
--     `INSERT OR IGNORE INTO audit_events` dedup (rust/src/consumer.rs); also
--     guards the event_id-derived batch_hash against redelivery duplicates.
--   * idx_audit_timestamp - used by the paced retention DELETE
--     `WHERE timestamp_ms < ?1 LIMIT ?2` (rust/src/consumer.rs) and the
--     `SELECT MIN(timestamp_ms)` oldest-row-age metric.
--
-- DROPPED (verified to have NO query consumer platform-wide as of R11):
-- idx_audit_source, idx_audit_event_type, idx_audit_severity,
-- idx_audit_event_category, idx_audit_environment, idx_audit_outcome and the two
-- partials idx_audit_request_id / idx_audit_actor. The only other statements
-- touching audit_events are the unfiltered `SELECT COUNT(*)` (a full scan) and
-- the `WHERE json_extract(details, '$.is_test') = 1` test-data DELETE (an
-- unindexed expression). No query filters or sorts on source_service,
-- event_type, severity, event_category, environment, outcome, request_id or
-- actor_id, so those eight B-trees were pure write-amplification.
--
-- NOTE: this edit only affects FRESH databases. Existing prod/sandbox D1s keep
-- the dropped indexes until an operator runs the matching
-- `DROP INDEX IF EXISTS ...` against BOTH provii-audit-db and
-- provii-audit-db-sandbox (see the R11 remediation operator notes).

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_ms);

-- Digest chain table for tamper evidence.
-- Each batch of consumed queue messages produces one digest row.
-- The digest chain is a SHA-256 hash chain: each row's batch_hash
-- feeds into the next row's previous_hash. The signature is
-- HMAC-SHA256(key, batch_hash || "|" || previous_hash || "|" || key_id)
-- for verification.
-- key_id identifies which HMAC key signed the row, enabling key rotation.

CREATE TABLE IF NOT EXISTS audit_digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL UNIQUE,
    timestamp_ms INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    first_event_id TEXT NOT NULL,
    last_event_id TEXT NOT NULL,
    batch_hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT 'genesis',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_digest_timestamp ON audit_digests(timestamp_ms);

-- Dead-letter capture table (R3).
-- The audit consumer dead-letters un-processable queue messages to
-- provii-audit-events-dlq / provii-audit-events-sandbox-dlq. A dedicated DLQ
-- consumer persists each dead-lettered message body VERBATIM here and emits a
-- high-severity alert per arrival, so dead-lettered events (including
-- billing_event) are durably retained instead of being silently lost.
--
-- This table is durability/alerting only: the DLQ consumer NEVER writes to
-- audit_events or audit_digests and NEVER touches the digest hash chain, so
-- the single-writer chain invariant is preserved. `body` is the raw message
-- payload (not parsed); `queue_message_id` is the queue's system-generated
-- message id (best-effort, may collide across redeliveries, so it is NOT
-- unique); `received_at` is the ISO-8601 time the DLQ consumer persisted it.
CREATE TABLE IF NOT EXISTS audit_dlq (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_message_id TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_dlq_received_at ON audit_dlq(received_at);
