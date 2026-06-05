// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Queue audit sink backed by Cloudflare Queues.
//!
//! Sends audit events to a Cloudflare Queue for asynchronous processing
//! by `provii-audit-consumer`, which batch inserts into D1.
//!
//! On wasm32, `worker::Queue` handles the actual dispatch. On native targets
//! (used by `cargo test`), only the serialisation logic is exercised because
//! the queue binding is unavailable outside the Workers runtime.

#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use async_trait::async_trait;
#[cfg(any(target_arch = "wasm32", test))]
use serde::Serialize;

#[cfg(any(target_arch = "wasm32", test))]
use crate::error::AuditError;
#[cfg(target_arch = "wasm32")]
use crate::event::AuditEvent;
#[cfg(target_arch = "wasm32")]
use crate::sinks::AuditSink;

/// Audit sink that dispatches events to a Cloudflare Queue.
///
/// Wraps a `worker::Queue` obtained from the Worker environment via
/// `env.queue("BINDING_NAME")`. Messages are serialised to JSON by the
/// Workers SDK before being enqueued.
///
/// The queue consumer parses each message and persists it into D1.
///
/// # Example
///
/// ```rust,ignore
/// use provii_audit::sinks::queue::QueueAuditSink;
///
/// let queue = env.queue("AUDIT_QUEUE")?;
/// let sink = QueueAuditSink::new(queue);
///
/// // Via the AuditSink trait:
/// sink.write(&audit_event).await?;
///
/// // Via direct send (accepts any Serialize type):
/// sink.send(&audit_event).await?;
/// ```
pub struct QueueAuditSink {
    #[cfg(target_arch = "wasm32")]
    queue: worker::Queue,
    // On native targets the struct is unconstructable (no public fields).
    // Tests exercise serialisation logic via `serialise_for_queue` instead.
    #[cfg(not(target_arch = "wasm32"))]
    _phantom: std::convert::Infallible,
}

#[cfg(target_arch = "wasm32")]
impl QueueAuditSink {
    /// Create a new queue audit sink from a `worker::Queue` binding.
    #[must_use]
    pub fn new(queue: worker::Queue) -> Self {
        Self { queue }
    }

    /// Send a serialisable value to the queue as a single message.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::QueueError`] if the queue send fails due to a
    /// binding error, capacity limit, or network issue.
    pub async fn send<T: Serialize>(&self, event: &T) -> Result<(), AuditError> {
        self.queue
            .send(event)
            .await
            .map_err(|e| AuditError::queue(format!("Queue send failed: {e}")))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl AuditSink for QueueAuditSink {
    /// Write an [`AuditEvent`] to the queue as a JSON message.
    async fn write(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.send(event).await
    }
}

/// Serialise a value to JSON suitable for queue dispatch.
///
/// Extracted as a standalone function so tests can validate serialisation
/// without requiring a live queue binding. Not part of the public API
/// because external callers use [`QueueAuditSink::send`] directly.
///
/// # Errors
///
/// Returns [`AuditError::SerialisationError`] if `serde_json` serialisation fails.
#[cfg(test)]
pub(crate) fn serialise_for_queue<T: Serialize>(event: &T) -> Result<String, AuditError> {
    serde_json::to_string(event)
        .map_err(|e| AuditError::serialisation(format!("Failed to serialise queue message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEventBuilder, Environment};
    use crate::severity::Severity;

    fn val_str<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(serde_json::Value::as_str)
    }

    fn val_u64(v: &serde_json::Value, key: &str) -> Option<u64> {
        v.get(key).and_then(serde_json::Value::as_u64)
    }

    #[test]
    fn audit_event_serialises_for_queue() {
        let event = AuditEventBuilder::new(
            "verification_success",
            Severity::Info,
            "Verification succeeded",
            "provii-verifier",
        )
        .challenge_id("ch-abc")
        .environment(Environment::Production)
        .build()
        .unwrap();

        let json = serialise_for_queue(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val_str(&parsed, "event_type"), Some("verification_success"));
        assert_eq!(val_str(&parsed, "severity"), Some("info"));
        assert_eq!(val_str(&parsed, "message"), Some("Verification succeeded"));
        assert_eq!(val_str(&parsed, "source_service"), Some("provii-verifier"));
        assert_eq!(val_str(&parsed, "challenge_id"), Some("ch-abc"));
        assert_eq!(val_str(&parsed, "environment"), Some("production"));
        assert!(val_str(&parsed, "event_id").is_some());
        assert!(val_u64(&parsed, "timestamp_ms").is_some());
        assert!(val_str(&parsed, "created_at").is_some());
    }

    #[test]
    fn audit_event_json_roundtrip() {
        let event = AuditEventBuilder::new(
            "challenge_created",
            Severity::Warning,
            "Challenge issued",
            "provii-verifier",
        )
        .client_ip_hash("deadbeef")
        .origin("https://example.com")
        .user_agent_hash("cafebabe")
        .geo_country("AU")
        .build()
        .unwrap();

        let json = serialise_for_queue(&event).unwrap();
        let restored: crate::event::AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.event_id, event.event_id);
        assert_eq!(restored.timestamp_ms, event.timestamp_ms);
        assert_eq!(restored.source_service, event.source_service);
        assert_eq!(restored.event_type, event.event_type);
        assert_eq!(restored.severity, event.severity);
        assert_eq!(restored.client_ip_hash(), event.client_ip_hash());
        assert_eq!(restored.origin, event.origin);
        assert_eq!(restored.user_agent_hash, event.user_agent_hash);
        assert_eq!(restored.geo_country, event.geo_country);
        assert_eq!(restored.created_at, event.created_at);
    }

    #[test]
    fn queue_error_variant_formats() {
        let err = AuditError::queue("test failure");
        assert_eq!(err.to_string(), "Queue error: test failure");
    }

    #[test]
    fn serialisation_error_variant_formats() {
        let err = AuditError::serialisation("bad json");
        assert_eq!(err.to_string(), "Serialisation error: bad json");
    }

    #[test]
    fn arbitrary_serialisable_type_produces_json() {
        #[derive(Serialize)]
        struct FutureEvent {
            event_type: String,
            timestamp_ms: u64,
            payload: serde_json::Value,
        }

        let event = FutureEvent {
            event_type: "age_check_passed".to_string(),
            timestamp_ms: 1_700_000_000_000,
            payload: serde_json::json!({"circuit": "groth16", "verified": true}),
        };

        let json = serialise_for_queue(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val_str(&parsed, "event_type"), Some("age_check_passed"));
        assert_eq!(val_u64(&parsed, "timestamp_ms"), Some(1_700_000_000_000));
        let circuit = parsed
            .get("payload")
            .and_then(|p| p.get("circuit"))
            .and_then(serde_json::Value::as_str);
        assert_eq!(circuit, Some("groth16"));
    }

    #[test]
    fn audit_event_has_expected_fields() {
        let event = AuditEventBuilder::new(
            "verification_success",
            Severity::Info,
            "Verification succeeded",
            "provii-verifier",
        )
        .build()
        .unwrap();

        let json = serialise_for_queue(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let required_keys = [
            "event_id",
            "source_service",
            "timestamp_ms",
            "created_at",
            "environment",
            "geo_country",
            "queue_message_id",
            "worker_version",
            "request_id",
        ];

        for key in &required_keys {
            assert!(parsed.get(key).is_some(), "missing field: {key}");
        }
    }
}
