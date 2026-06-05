<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/provii-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="./assets/provii-logo-light.png">
    <img alt="Provii Audit" src="./assets/provii-logo-light.png" width="200">
  </picture>
</p>

<h1 align="center">provii-audit</h1>

<p align="center">Tamper evident audit logs for age verification. Cryptographically signed, independently verifiable.</p>

<p align="center">
  <a href="https://github.com/provii/provii-audit/actions/workflows/ci.yml"><img src="https://github.com/provii/provii-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/provii/provii-audit/actions/workflows/security-audit.yml"><img src="https://github.com/provii/provii-audit/actions/workflows/security-audit.yml/badge.svg" alt="Security audit"></a>
  <img src="https://img.shields.io/badge/licence-Proprietary-red" alt="Licence: Proprietary">
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust 1.75+">
</p>

## Why this exists

Regulators require evidence that age checks happened. Timestamps, outcomes, which service ran the check, what environment it ran in. All mandated. Users care about the opposite: that nothing beyond age was recorded. Every piece of personally identifiable information in a compliance log is a liability sitting in storage, waiting for a breach, a subpoena, a careless export, or an overly broad discovery order to make it someone else's problem.

These two requirements pull in different directions. A record detailed enough for compliance tends to be detailed enough to identify individuals. provii-audit resolves this by HMAC hashing all personally identifiable information before it leaves the producing service. The tension is real. Raw IP addresses and user agents are replaced with deterministic, domain separated HMAC-SHA-256 digests. Origin headers get the same treatment. The audit record proves something happened without revealing who was involved.

Once events reach storage, a SHA-256 digest chain links each batch to its predecessor. Every chain entry carries an HMAC-SHA-256 signature binding it to the previous batch hash. Tampering with any row breaks the chain: inserting a fake event, deleting a legitimate one, reordering batches, or modifying field values. Independent verification can detect all of these.

## Record format

Each `AuditEvent` carries 23 fields. The struct is defined in `rust/src/event.rs`.

### Included in every record

| Field | Type | Purpose |
|-------|------|---------|
| `event_id` | UUID v4 hex (32 chars) | Unique identifier, generated at build time |
| `timestamp_ms` | `u64` | Milliseconds since Unix epoch |
| `source_service` | `String` | Emitting service, e.g. `"provii-verifier"` or `"provii-issuer"` |
| `event_type` | `String` | Machine readable key like `"verification_success"` |
| `severity` | `Severity` enum | One of `info`, `warning`, `error`, `critical` |
| `event_category` | `String` (validated against `EventCategory`) | `VERIFICATION`, `AUTHENTICATION`, `KEY_ACCESS`, `CREDENTIAL_ISSUANCE`, and six others |
| `outcome` | `String` (validated against `Outcome`) | `success`, `failure`, `denied`, or `error` |
| `environment` | `String` (validated against `Environment`) | `production` or `sandbox` |
| `challenge_id` | `String` | Links the event to a specific verification challenge |
| `message` | `String` | Human readable description, PII stripped at build time |
| `client_ip_hash` | `String` | HMAC-SHA-256 of the raw IP, 64 hex chars |
| `user_agent_hash` | `String` | HMAC-SHA-256 of the raw user agent, 64 hex chars |
| `origin` | `String` | HMAC-SHA-256 of the request origin, 64 hex chars |
| `actor_id` | `String` | Who performed the action |
| `actor_type` | `String` (validated against `ActorType`) | `user`, `service`, `api_key`, or `system` |
| `resource_type` | `String` | What was acted upon, e.g. `"challenge"`, `"credential"` |
| `resource_id` | `String` | Identifier of the affected resource |
| `request_id` | `String` | Trace ID for cross service correlation |
| `geo_country` | `String` | ISO 3166-1 alpha-2 country code from CF-IPCountry |
| `worker_version` | `String` | Version of the emitting worker |
| `details` | `String` | Supplementary JSON payload, PII stripped |
| `queue_message_id` | `String` | Set by the consumer after dequeue, empty at creation |
| `created_at` | `String` | ISO 8601 timestamp with millisecond precision |

### Deliberately excluded

Raw IP addresses, raw user agent strings, raw origin headers, dates of birth, email addresses, names, document identifiers. The `strip_pii` function in `sanitize.rs` performs a defence in depth pass over free text fields, replacing IPv4 addresses, IPv6 addresses, email addresses, and date of birth patterns (years 1920 through 2012) with `[REDACTED_*]` placeholders.

## Usage

Add the dependency in your `Cargo.toml`:

```toml
[dependencies]
provii-audit = { path = "../provii-audit/rust" }
```

Enable the `consumer` feature only in the audit consumer worker:

```toml
[dependencies]
provii-audit = { path = "../provii-audit/rust", features = ["consumer"] }
```

### Creating and dispatching an event

```rust
use std::sync::Arc;
use provii_audit::{AuditLogger, AuditParams, EventCategory, PrivacyContext, Severity};
use provii_audit::sinks::queue::QueueAuditSink;

// Initialise once per request context.
let privacy = Arc::new(PrivacyContext::new(salt_bytes)?);
let queue = env.queue("AUDIT_QUEUE")?;
let sink = Arc::new(QueueAuditSink::new(queue));
let logger = AuditLogger::with_sink(sink, privacy, "provii-verifier");

// Raw IP is HMAC hashed before it reaches the sink or console.
logger.log_event(AuditParams {
    event_type: "verification_success",
    severity: Severity::Info,
    message: "Verification succeeded",
    event_category: EventCategory::Verification,
    outcome: "success",
    raw_ip: "203.0.113.42",
    origin: "https://example.com",
    raw_user_agent: "Mozilla/5.0",
    challenge_id: "ch-abc-123",
    environment: "production",
    geo_country: "AU",
    resource_type: "challenge",
    resource_id: "ch-abc-123",
    ..Default::default()
}).await?;
```

The `AuditLogger` performs these steps in order:

1. Validates field lengths against upper bounds (128 bytes for `event_type`, 2048 for `message`, 16384 for `details`).
2. Hashes `raw_ip`, `raw_user_agent`, and `origin` through `PrivacyContext` using domain separated HMAC-SHA-256. Each field type gets a distinct domain tag so identical raw values produce different hashes across fields.
3. Writes a sanitised console line with truncated hash prefixes for Grafana.
4. Builds the `AuditEvent` through `AuditEventBuilder`, which runs `strip_pii` on `message` and `details`.
5. Dispatches to the configured `AuditSink` (Cloudflare Queue in production).

For non critical paths where audit failure should not propagate:

```rust
logger.log_event_best_effort(params).await;
```

### Building events directly

If you need an `AuditEvent` without the logger (e.g. for testing or batch construction):

```rust
use provii_audit::AuditEventBuilder;
use provii_audit::Severity;

let event = AuditEventBuilder::new(
    "credential_issued",
    Severity::Info,
    "Attestation created",
    "provii-issuer",
)
.challenge_id("ch-456")
.environment("production")
.event_category("CREDENTIAL_ISSUANCE".to_string())
.outcome("success")
.build()?;

// event.event_id, event.timestamp_ms, and event.created_at are auto-generated.
// event.message has been PII-stripped.
```

## Independent verification

The digest chain makes it possible to verify audit integrity without trusting the service that produced the records. All you need is the chain entries from the `audit_digests` table and the HMAC key.

Each digest row contains a `batch_hash` (SHA-256 of sorted, length prefixed event IDs in that batch), a `previous_hash` linking to the prior batch, a `key_id` identifying which HMAC key signed it, and a `signature` computed as `HMAC-SHA-256(key, batch_hash || "|" || previous_hash || "|" || key_id)`. Straightforward to recompute.

```rust
use provii_audit::{verify_chain, DigestEntry, ChainVerification, DIGEST_GENESIS_HASH};

let entries: Vec<DigestEntry> = load_digest_rows_from_d1();  // oldest first
let hmac_key: &[u8] = &load_hmac_key_from_secrets();

match verify_chain(&entries, hmac_key)? {
    ChainVerification::Valid { entries_verified } => {
        println!("{entries_verified} batches verified, chain intact");
    }
    ChainVerification::Invalid { first_mismatch_index, batch_hash } => {
        eprintln!("Chain broken at batch {first_mismatch_index}: {batch_hash}");
    }
}
```

`verify_chain` walks the chain from genesis, recomputing each entry's HMAC-SHA-256 signature and comparing it to the stored value using `hmac::Mac::verify_slice`, which performs a constant time comparison internally. It also verifies that each entry's `previous_hash` matches the `batch_hash` of its predecessor.

To recompute batch hashes from raw event IDs (e.g. to verify that the `batch_hash` stored in a digest row actually corresponds to the events in that batch):

```rust
use provii_audit::compute_batch_hash;

let event_ids: Vec<&str> = vec!["evt-001", "evt-002", "evt-003", "evt-004"];
let hash = compute_batch_hash(&event_ids);
// SHA-256 of sorted, length-prefixed IDs: "7:evt-0017:evt-0027:evt-0037:evt-004"
// Order of input does not matter. The result is deterministic.
```

## Integration with other Provii crates

### provii-verifier

The provii-verifier Worker is the primary producer of audit events. Every verification challenge creation, success, failure, and expiry is logged through `AuditLogger`. The verifier constructs a `PrivacyContext` from the deployment salt at startup and shares it across requests via `Arc`.

### provii-audit-consumer

A separate Cloudflare Worker that drains the `AUDIT_QUEUE`. It deserialises `AuditEvent` records from queue messages and batch inserts them into D1 using `INSERT OR IGNORE`, making queue redelivery idempotent. After insertion, it computes the SHA-256 batch hash via `compute_batch_hash` and signs it into the digest chain via `compute_digest_signature`. A 90 day retention cron deletes old events while preserving the digest chain. The consumer depends on this library with the `consumer` feature flag enabled.

## Licence

Proprietary. Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust. All rights reserved. See [LICENSE](./LICENSE) for details.
