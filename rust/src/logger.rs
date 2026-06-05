// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! High-level audit logger for emitting privacy-safe audit events.
//!
//! [`AuditLogger`] is the primary API surface of this crate. It accepts raw
//! request metadata, hashes PII (IP addresses, user agent strings) through
//! [`PrivacyContext`], constructs structured [`AuditEvent`](crate::event::AuditEvent)
//! records via [`AuditEventBuilder`], and dispatches them to the configured
//! [`AuditSink`]. Console output uses hashed values exclusively so that
//! Grafana log drains never capture raw PII.
//!
//! Callers construct an [`AuditParams`] with named fields and pass it to
//! [`AuditLogger::log_event`] or [`AuditLogger::log_event_best_effort`].

#![forbid(unsafe_code)]

use std::sync::Arc;

use crate::error::AuditError;
use crate::event::{ActorType, AuditEventBuilder, Environment, EventCategory, Outcome};
use crate::privacy::PrivacyContext;
use crate::sanitize::{validate_append_fields, validate_secondary_fields};
use crate::severity::Severity;
use crate::sinks::AuditSink;

#[cfg(target_arch = "wasm32")]
use worker::console_log;

/// No-op replacement for `worker::console_log!` in native test builds.
#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// Named parameters accepted by [`AuditLogger::log_event`].
///
/// `event_type` and `message` are required (empty strings are rejected by
/// validation). All other `&str` fields default to `""`, enums to their
/// baseline variant, and `Option` fields to `None`. Use struct update
/// syntax with `..Default::default()` for concise construction:
///
/// ```rust,ignore
/// use provii_audit::logger::AuditParams;
/// use provii_audit::{Severity, EventCategory, Environment, Outcome};
///
/// let params = AuditParams {
///     event_type: "verification_success",
///     severity: Severity::Info,
///     message: "Verification succeeded",
///     event_category: EventCategory::Verification,
///     outcome: Some(Outcome::Success),
///     resource_type: "challenge",
///     resource_id: "ch-123",
///     environment: Environment::Production,
///     ..Default::default()
/// };
/// ```
pub struct AuditParams<'a> {
    /// Machine-readable event type (e.g. `"verification_success"`).
    pub event_type: &'a str,
    /// Severity level for this event.
    pub severity: Severity,
    /// Human-readable description of what occurred.
    pub message: &'a str,
    /// High-level category grouping related event types.
    pub event_category: EventCategory,
    /// Outcome of the operation.
    pub outcome: Option<Outcome>,
    /// Raw client IP address. Hashed before any output.
    pub raw_ip: &'a str,
    /// Request origin header value.
    pub origin: &'a str,
    /// Raw user agent string. Hashed before any output.
    pub raw_user_agent: &'a str,
    /// Associated challenge identifier, if applicable.
    pub challenge_id: &'a str,
    /// Freeform detail payload (typically JSON).
    pub details: &'a str,
    /// Correlation identifier for the originating request.
    pub request_id: &'a str,
    /// Deployment environment.
    pub environment: Environment,
    /// ISO 3166-1 alpha-2 country code from geo lookup.
    pub geo_country: &'a str,
    /// Version string of the emitting worker.
    pub worker_version: &'a str,
    /// Identifier of the acting entity (user, service, API key).
    pub actor_id: &'a str,
    /// Type of actor.
    pub actor_type: Option<ActorType>,
    /// Type of the resource being acted upon.
    pub resource_type: &'a str,
    /// Identifier of the resource being acted upon.
    pub resource_id: &'a str,
}

impl Default for AuditParams<'_> {
    fn default() -> Self {
        Self {
            event_type: "",
            severity: Severity::Info,
            message: "",
            event_category: EventCategory::SecurityEvent,
            outcome: None,
            raw_ip: "",
            origin: "",
            raw_user_agent: "",
            challenge_id: "",
            details: "",
            request_id: "",
            environment: Environment::Production,
            geo_country: "",
            worker_version: "",
            actor_id: "",
            actor_type: None,
            resource_type: "",
            resource_id: "",
        }
    }
}

/// Replaces control characters (including newlines and tabs) with spaces.
///
/// Applied to externally-sourced values before console output to prevent
/// log injection via embedded newlines or ANSI escape sequences.
fn sanitise_for_console(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// High-level audit logger that hashes PII before any output.
///
/// Constructed once per request context and shared via [`Arc`]. All fields
/// are either `Arc` or `String`, so cloning is cheap. The logger validates
/// input lengths, hashes IP and user agent through [`PrivacyContext`], emits
/// a sanitised console line for Grafana, builds an [`AuditEvent`](crate::event::AuditEvent)
/// via the builder, and dispatches it to the configured [`AuditSink`].
#[derive(Clone)]
pub struct AuditLogger {
    sink: Option<Arc<dyn AuditSink>>,
    privacy: Arc<PrivacyContext>,
    source_service: String,
}

impl AuditLogger {
    /// Create a new audit logger with an optional sink.
    ///
    /// Pass `None` for console-only logging (useful in tests or when the
    /// queue binding is unavailable). The `source_service` value is embedded
    /// in every emitted event.
    #[must_use]
    pub fn new(
        sink: Option<Arc<dyn AuditSink>>,
        privacy: Arc<PrivacyContext>,
        source_service: impl Into<String>,
    ) -> Self {
        Self {
            sink,
            privacy,
            source_service: source_service.into(),
        }
    }

    /// Create a logger with a guaranteed sink.
    ///
    /// Convenience constructor that wraps the sink in `Some` internally,
    /// avoiding the need for callers to spell out `Some(sink)`.
    #[must_use]
    pub fn with_sink(
        sink: Arc<dyn AuditSink>,
        privacy: Arc<PrivacyContext>,
        source_service: impl Into<String>,
    ) -> Self {
        Self {
            sink: Some(sink),
            privacy,
            source_service: source_service.into(),
        }
    }

    /// Emit an audit event using named parameters.
    ///
    /// This is the primary method for audit logging. It validates
    /// input field lengths, hashes PII, writes a sanitised console line,
    /// builds the event through [`AuditEventBuilder`], and dispatches to the
    /// configured sink.
    ///
    /// Console output sanitises `origin`, `challenge_id`, `event_type`, and
    /// `outcome` to prevent log injection via control characters or embedded
    /// newlines.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if field validation, event construction, or
    /// sink dispatch fails.
    #[allow(clippy::future_not_send)]
    pub async fn log_event(&self, params: AuditParams<'_>) -> Result<(), AuditError> {
        validate_append_fields(
            params.event_type,
            params.severity.as_str(),
            params.message,
            Some(params.details),
        )?;
        validate_secondary_fields(
            params.raw_ip,
            params.origin,
            params.raw_user_agent,
            params.challenge_id,
        )?;

        let hashed_ip = if params.raw_ip.is_empty() {
            String::new()
        } else {
            self.privacy.hash_ip(params.raw_ip)?
        };
        let hashed_ua = if params.raw_user_agent.is_empty() {
            String::new()
        } else {
            self.privacy.hash_user_agent(params.raw_user_agent)?
        };
        // Hash the origin like IP and UA to avoid storing it verbatim.
        let hashed_origin = if params.origin.is_empty() {
            String::new()
        } else {
            self.privacy.hash_origin(params.origin)?
        };

        // Console log with hashed values only (Grafana-safe).
        // Sanitise origin and challenge_id to prevent log injection.
        #[allow(unused_variables)]
        let ip_prefix = if hashed_ip.is_empty() {
            "-".to_string()
        } else {
            hashed_ip.get(..16).unwrap_or(&hashed_ip).to_string()
        };
        #[allow(unused_variables)]
        let safe_origin = if hashed_origin.is_empty() {
            "-".to_string()
        } else {
            hashed_origin
                .get(..16)
                .unwrap_or(&hashed_origin)
                .to_string()
        };
        #[allow(unused_variables)]
        let safe_challenge = if params.challenge_id.is_empty() {
            "-".to_string()
        } else {
            sanitise_for_console(params.challenge_id)
        };
        #[allow(unused_variables)]
        let safe_event_type = sanitise_for_console(params.event_type);
        #[allow(unused_variables)]
        let safe_outcome = params
            .outcome
            .map_or_else(|| "-".to_string(), |oc| oc.to_string());
        console_log!(
            "[AUDIT][{}] {} severity={} ip={} origin={} challenge={} category={} outcome={}",
            self.source_service,
            safe_event_type,
            params.severity,
            ip_prefix,
            safe_origin,
            safe_challenge,
            params.event_category,
            safe_outcome
        );

        let mut builder = AuditEventBuilder::new(
            params.event_type,
            params.severity,
            params.message,
            &self.source_service,
        )
        .client_ip_hash(&hashed_ip)
        .origin(&hashed_origin)
        .user_agent_hash(&hashed_ua)
        .challenge_id(params.challenge_id)
        .details(params.details)
        .request_id(params.request_id)
        .environment(params.environment)
        .geo_country(params.geo_country)
        .worker_version(params.worker_version)
        .event_category(params.event_category)
        .actor_id(params.actor_id)
        .resource_type(params.resource_type)
        .resource_id(params.resource_id);

        if let Some(at) = params.actor_type {
            builder = builder.actor_type(at);
        }
        if let Some(oc) = params.outcome {
            builder = builder.outcome(oc);
        }

        let event = builder.build()?;

        if let Some(ref sink) = self.sink {
            sink.write(&event).await?;
        }

        Ok(())
    }

    /// Emit an audit event, discarding errors with a console warning.
    ///
    /// Use this instead of `let _ = log_event(...)` when audit failure must
    /// not propagate to the caller. Errors are logged to the console for
    /// observability rather than silently swallowed.
    #[allow(clippy::future_not_send)]
    pub async fn log_event_best_effort(&self, params: AuditParams<'_>) {
        #[allow(unused_variables)]
        if let Err(e) = self.log_event(params).await {
            console_log!(
                "[AUDIT][ERROR] log_event_best_effort: audit logging failed: {}",
                e
            );
        }
    }

    /// Returns a reference to the underlying [`PrivacyContext`].
    ///
    /// Useful when callers need to hash additional PII fields outside the
    /// standard `log_event` flow.
    #[must_use]
    pub fn privacy(&self) -> &PrivacyContext {
        &self.privacy
    }

    /// Returns the source service name embedded in all emitted events.
    #[must_use]
    pub fn source_service(&self) -> &str {
        &self.source_service
    }
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("source_service", &self.source_service)
            .field("has_sink", &self.sink.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEvent, Environment, Outcome};
    use crate::sinks::AuditSink;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Mock sink that captures all events written to it.
    struct MockSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl MockSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<AuditEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait(?Send)]
    impl AuditSink for MockSink {
        async fn write(&self, event: &AuditEvent) -> Result<(), AuditError> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    /// Mock sink that always returns an error on write.
    struct FailingSink;

    #[async_trait(?Send)]
    impl AuditSink for FailingSink {
        async fn write(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::queue("simulated failure"))
        }
    }

    fn test_privacy() -> Arc<PrivacyContext> {
        Arc::new(PrivacyContext::new(b"test-salt-minimum-32-bytes-long!!".to_vec()).unwrap())
    }

    #[tokio::test]
    async fn log_event_with_all_params() {
        let sink = Arc::new(MockSink::new());
        let logger = AuditLogger::with_sink(sink.clone(), test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "verification_success",
            severity: Severity::Info,
            message: "Verification succeeded",
            event_category: EventCategory::Verification,
            outcome: Some(Outcome::Success),
            raw_ip: "192.168.1.1",
            origin: "https://example.com",
            raw_user_agent: "Mozilla/5.0",
            challenge_id: "ch-123",
            details: r#"{"score":100}"#,
            request_id: "req-abc",
            environment: Environment::Production,
            geo_country: "AU",
            worker_version: "1.0.0",
            actor_id: "user-42",
            actor_type: Some(ActorType::User),
            resource_type: "challenge",
            resource_id: "ch-123",
        };

        logger.log_event(params).await.unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);

        let event = events.first().expect("expected at least one event");
        assert_eq!(event.event_type, "verification_success");
        assert_eq!(event.event_category, Some(EventCategory::Verification));
        assert_eq!(event.outcome, Some(Outcome::Success));
        assert_eq!(event.actor_id, "user-42");
        assert_eq!(event.actor_type, Some(ActorType::User));
        assert_eq!(event.resource_type, "challenge");
        assert_eq!(event.resource_id, "ch-123");
        // IP must be hashed, not raw
        assert_ne!(event.client_ip_hash(), "192.168.1.1");
        assert_eq!(event.client_ip_hash().len(), 64);
        // UA must be hashed, not raw
        assert_ne!(event.user_agent_hash, "Mozilla/5.0");
        assert_eq!(event.user_agent_hash.len(), 64);
        // Origin must be hashed, not raw
        assert_ne!(event.origin, "https://example.com");
        assert_eq!(event.origin.len(), 64);
    }

    #[tokio::test]
    async fn log_event_with_defaults() {
        let sink = Arc::new(MockSink::new());
        let logger = AuditLogger::with_sink(sink.clone(), test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "test_event",
            message: "Test message",
            ..Default::default()
        };

        logger.log_event(params).await.unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);

        let event = events.first().expect("expected at least one event");
        assert_eq!(event.event_type, "test_event");
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.event_category, Some(EventCategory::SecurityEvent));
        assert!(event.outcome.is_none());
        assert!(event.actor_id.is_empty());
        assert_eq!(event.client_ip_hash(), "");
        assert_eq!(event.environment, Environment::Production);
    }

    #[tokio::test]
    async fn log_event_rejects_empty_event_type() {
        let logger = AuditLogger::new(None, test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "",
            message: "msg",
            ..Default::default()
        };

        let result = logger.log_event(params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn log_event_propagates_sink_error() {
        let sink: Arc<dyn AuditSink> = Arc::new(FailingSink);
        let logger = AuditLogger::with_sink(sink, test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "test_event",
            message: "msg",
            ..Default::default()
        };

        let result = logger.log_event(params).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("simulated failure"));
    }

    #[tokio::test]
    async fn log_event_best_effort_succeeds_on_success() {
        let sink = Arc::new(MockSink::new());
        let logger = AuditLogger::with_sink(sink.clone(), test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "test_event",
            message: "msg",
            ..Default::default()
        };

        logger.log_event_best_effort(params).await;

        assert_eq!(sink.events().len(), 1);
    }

    #[tokio::test]
    async fn log_event_best_effort_does_not_panic_on_sink_error() {
        let sink: Arc<dyn AuditSink> = Arc::new(FailingSink);
        let logger = AuditLogger::with_sink(sink, test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "test_event",
            message: "msg",
            ..Default::default()
        };

        logger.log_event_best_effort(params).await;
    }

    #[test]
    fn sanitise_for_console_strips_control_chars() {
        assert_eq!(sanitise_for_console("foo\nbar"), "foo bar");
        assert_eq!(sanitise_for_console("foo\x1b[31mbar"), "foo [31mbar");
        assert_eq!(sanitise_for_console("clean"), "clean");
        assert_eq!(sanitise_for_console(""), "");
    }

    #[tokio::test]
    async fn log_event_best_effort_does_not_panic_on_validation_error() {
        let logger = AuditLogger::new(None, test_privacy(), "test-service");

        let params = AuditParams {
            event_type: "",
            message: "msg",
            ..Default::default()
        };

        logger.log_event_best_effort(params).await;
    }

    #[test]
    fn debug_impl_contains_service_name() {
        let logger = AuditLogger::new(None, test_privacy(), "provii-verifier");
        let debug = format!("{logger:?}");
        assert!(
            debug.contains("provii-verifier"),
            "Debug should include source_service, got: {debug}"
        );
        assert!(
            debug.contains("has_sink"),
            "Debug should include has_sink field, got: {debug}"
        );
    }

    #[test]
    fn privacy_accessor_returns_context() {
        let logger = AuditLogger::new(None, test_privacy(), "svc");
        // Verify the accessor works by hashing through it.
        let hash = logger.privacy().hash_ip("10.0.0.1").unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn source_service_accessor() {
        let logger = AuditLogger::new(None, test_privacy(), "my-service");
        assert_eq!(logger.source_service(), "my-service");
    }

    #[tokio::test]
    async fn log_event_succeeds_without_sink() {
        let logger = AuditLogger::new(None, test_privacy(), "console-only");
        let params = AuditParams {
            event_type: "test_event",
            message: "Console-only message",
            ..Default::default()
        };
        // Should succeed even with no sink (console-only path).
        logger.log_event(params).await.unwrap();
    }

    #[tokio::test]
    async fn log_event_rejects_oversized_message() {
        let logger = AuditLogger::new(None, test_privacy(), "svc");
        let long_msg = "x".repeat(2049);
        let params = AuditParams {
            event_type: "evt",
            message: &long_msg,
            ..Default::default()
        };
        let result = logger.log_event(params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn log_event_rejects_oversized_secondary_field() {
        let logger = AuditLogger::new(None, test_privacy(), "svc");
        let big = "x".repeat(8193);
        let params = AuditParams {
            event_type: "evt",
            message: "msg",
            raw_ip: &big,
            ..Default::default()
        };
        let result = logger.log_event(params).await;
        assert!(result.is_err());
    }
}
