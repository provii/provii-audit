// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![forbid(unsafe_code)]
// Test code may use unwrap/expect where production code must not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Shared audit logging library for all Provii backend services.
//!
//! Events are HMAC-hashed for PII protection, serialised as JSON, and dispatched
//! to a Cloudflare Queue via [`QueueAuditSink`](sinks::queue::QueueAuditSink).
//! The `provii-audit-consumer` worker drains the queue into D1 storage with a
//! tamper-evident SHA-256 digest chain. Rows older than 90 days are purged by
//! a consumer cron.
//!
//! ## Architecture
//!
//! | Component | Role |
//! |-----------|------|
//! | [`AuditLogger`] | Top-level API. Hashes IP addresses and user agents before any output. |
//! | [`AuditSink`](sinks::AuditSink) | Trait abstracting the output destination (queue, test stub). |
//! | [`AuditEvent`] | 23-field event structure carried through queue transport. |
//! | [`PrivacyContext`] | Domain-separated HMAC-SHA-256 hashing with zeroised key material. |
//! | [`EventCategory`] | Categorical label for routing and filtering downstream. |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use provii_audit::{AuditLogger, AuditParams, Environment, EventCategory, Outcome, PrivacyContext, Severity};
//! use provii_audit::sinks::queue::QueueAuditSink;
//!
//! let privacy = Arc::new(PrivacyContext::new(salt_bytes)?);
//! let queue = env.queue("AUDIT_QUEUE")?;
//! let sink = Arc::new(QueueAuditSink::new(queue));
//! let logger = AuditLogger::with_sink(sink, privacy, "provii-verifier");
//!
//! // Raw IP is HMAC-hashed before it reaches the sink.
//! logger.log_event(AuditParams {
//!     event_type: "verification_success",
//!     severity: Severity::Info,
//!     message: "Verification succeeded",
//!     event_category: EventCategory::Verification,
//!     raw_ip: "192.168.1.1",
//!     origin: "https://example.com",
//!     raw_user_agent: "Mozilla/5.0",
//!     challenge_id: "challenge-123",
//!     environment: Environment::Production,
//!     geo_country: "AU",
//!     worker_version: "1.0.0",
//!     request_id: "req-abc",
//!     outcome: Some(Outcome::Success),
//!     ..Default::default()
//! }).await?;
//! ```

#[cfg(feature = "consumer")]
pub mod consumer;
pub mod error;
pub mod event;
pub mod logger;
pub mod privacy;
pub mod sanitize;
pub mod severity;
pub mod sinks;

#[cfg(feature = "consumer")]
pub use consumer::{
    compute_batch_hash, compute_digest_signature, derive_key_id, verify_chain, BatchResult,
    ChainVerification, DigestEntry, DIGEST_GENESIS_HASH,
};
pub use error::AuditError;
pub use event::{
    format_iso8601, ActorType, AuditEvent, AuditEventBuilder, Environment, EventCategory, Outcome,
    MAX_ISO8601_TIMESTAMP_MS,
};
pub use logger::{AuditLogger, AuditParams};
pub use privacy::PrivacyContext;
pub use severity::Severity;
