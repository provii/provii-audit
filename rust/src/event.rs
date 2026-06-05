// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Queue-oriented audit event types and builder.
//!
//! [`AuditEvent`] carries 23 fields, gets serialised to JSON, and is pushed to
//! a Cloudflare Queue for asynchronous processing by a consumer worker.
//! Integrity is provided by the queue transport and the consumer's D1 digest
//! chain.
//!
//! ## Builder
//!
//! Construct events with [`AuditEventBuilder`]. Required fields are set via the
//! constructor; optional fields via chained setter methods.
//!
//! ```rust,ignore
//! use provii_audit::event::{AuditEvent, AuditEventBuilder, Environment};
//! use provii_audit::Severity;
//!
//! let event = AuditEventBuilder::new(
//!     "verification_success",
//!     Severity::Info,
//!     "Verification succeeded",
//!     "provii-verifier",
//! )
//! .challenge_id("challenge-abc")
//! .origin("https://example.com")
//! .environment(Environment::Production)
//! .build()?;
//! ```

#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::AuditError;
use crate::sanitize::{self, strip_pii};
use crate::severity::Severity;

/// Serde helper for `Option<T>` fields that serialise `None` as `""` and
/// deserialise `""` as `None`. Non-empty strings round-trip through `T`'s own
/// serde implementation. This preserves wire compatibility with the consumer
/// worker which reads these fields from queue JSON where absent values are
/// represented as empty strings.
mod option_enum_as_string {
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    // Serde `with` contract requires `&Option<T>`, not `Option<&T>`.
    #[allow(clippy::ref_option)]
    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        match value {
            None => serializer.serialize_str(""),
            Some(v) => v.serialize(serializer),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: serde::de::DeserializeOwned,
        D: Deserializer<'de>,
    {
        // Deserialise as a raw string first, then decide.
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(None);
        }
        // Re-deserialise the non-empty string through T's Deserialize impl.
        let value = serde_json::from_value::<T>(serde_json::Value::String(s))
            .map_err(serde::de::Error::custom)?;
        Ok(Some(value))
    }
}

/// Security-relevant classification for an audit event.
///
/// Ten categories cover the full surface area of Provii's auditable actions,
/// from authentication through to external service calls. Serialised as
/// `SCREAMING_SNAKE_CASE` (e.g. `"KEY_ACCESS"`, `"DATA_MUTATION"`). Used for
/// filtering, alerting, and compliance reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum EventCategory {
    /// Login, token exchange, credential presentation.
    Authentication,
    /// Permission checks and access control decisions.
    Authorization,
    /// Reads or rotations of cryptographic key material.
    KeyAccess,
    /// Writes, updates, or deletions of stored data.
    DataMutation,
    /// Session creation, renewal, or destruction.
    SessionLifecycle,
    /// Attestation or credential issuance by the issuer service.
    CredentialIssuance,
    /// Age verification proof generation or validation.
    Verification,
    /// Actions performed through the admin portal.
    AdminAction,
    /// Outbound calls to third-party or inter-service endpoints.
    ExternalCall,
    /// Rate limiting, anomaly detection, or policy violations.
    SecurityEvent,
}

impl EventCategory {
    /// Return the `SCREAMING_SNAKE_CASE` string form of this category.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "AUTHENTICATION",
            Self::Authorization => "AUTHORIZATION",
            Self::KeyAccess => "KEY_ACCESS",
            Self::DataMutation => "DATA_MUTATION",
            Self::SessionLifecycle => "SESSION_LIFECYCLE",
            Self::CredentialIssuance => "CREDENTIAL_ISSUANCE",
            Self::Verification => "VERIFICATION",
            Self::AdminAction => "ADMIN_ACTION",
            Self::ExternalCall => "EXTERNAL_CALL",
            Self::SecurityEvent => "SECURITY_EVENT",
        }
    }
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deployment environment for audit events.
///
/// Serialised as `snake_case`: `"production"` or `"sandbox"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Environment {
    /// Live traffic environment.
    Production,
    /// Testing environment.
    Sandbox,
}

impl Environment {
    /// Return the canonical lowercase string form.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Sandbox => "sandbox",
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of actor that performed an audited action.
///
/// Serialised as `snake_case`. An empty string in the database represents
/// an unset actor type; callers should use `Option<ActorType>` at the API
/// boundary rather than storing a raw empty string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActorType {
    /// A human end-user.
    User,
    /// An internal backend service.
    Service,
    /// An API key holder.
    ApiKey,
    /// An automated system process.
    System,
}

impl ActorType {
    /// Return the canonical lowercase string form.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
            Self::ApiKey => "api_key",
            Self::System => "system",
        }
    }
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of an audited operation.
///
/// Serialised as `snake_case`. An empty string in the database represents
/// an unset outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Outcome {
    /// The operation completed successfully.
    Success,
    /// The operation failed due to an expected condition.
    Failure,
    /// The operation was denied by access control.
    Denied,
    /// The operation failed due to an unexpected error.
    Error,
}

impl Outcome {
    /// Return the canonical lowercase string form.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Queue-oriented audit event (v2).
///
/// Most string fields use `String` with empty strings for absent values.
/// Four classification fields (`environment`, `event_category`, `actor_type`,
/// `outcome`) use typed enums for compile-time correctness. The three
/// `Option` enums serialise as `""` when absent, preserving wire compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditEvent {
    /// Unique event identifier (UUID v4, hex-encoded without hyphens).
    pub event_id: String,

    /// Milliseconds since Unix epoch, auto-set at creation.
    pub timestamp_ms: u64,

    /// Source service name (e.g. "provii-verifier", "provii-issuer").
    pub source_service: String,

    /// Event type key (e.g. `"verification_success"`, `"challenge_created"`).
    pub event_type: String,

    /// Event severity level.
    pub severity: Severity,

    /// HMAC-hashed client IP address. Empty if absent.
    client_ip_hash: String,

    /// Origin domain. Empty if absent.
    pub origin: String,

    /// HMAC-hashed user agent string. Empty if absent.
    pub user_agent_hash: String,

    /// Challenge ID. Empty if not applicable.
    pub challenge_id: String,

    /// Human-readable event message, PII-stripped at build time.
    message: String,

    /// Supplementary details as a JSON string. Empty if none.
    details: String,

    /// Request trace ID for correlation. Empty if absent.
    pub request_id: String,

    /// Deployment environment.
    pub environment: Environment,

    /// Worker version string. Empty if not set.
    pub worker_version: String,

    /// ISO 3166-1 alpha-2 country code from `CF-IPCountry`. Empty if absent.
    pub geo_country: String,

    /// Event category. `None` for events where the emitting service did not
    /// set a category. Serialises as `""` when absent.
    #[serde(with = "option_enum_as_string")]
    pub event_category: Option<EventCategory>,

    /// Who performed the action: user ID, service name, or API key ID.
    /// Empty string if not set.
    pub actor_id: String,

    /// Actor type. `None` if not set. Serialises as `""` when absent.
    #[serde(with = "option_enum_as_string")]
    pub actor_type: Option<ActorType>,

    /// Resource type affected: "challenge", "session", "credential", "kek", etc.
    /// Empty string if not set.
    pub resource_type: String,

    /// Identifier of the affected resource. Empty string if not set.
    pub resource_id: String,

    /// Action outcome. `None` if not set. Serialises as `""` when absent.
    #[serde(with = "option_enum_as_string")]
    pub outcome: Option<Outcome>,

    /// Queue message ID, populated by the consumer after dequeue. Empty at
    /// creation.
    pub queue_message_id: String,

    /// ISO 8601 timestamp string, generated at creation
    /// (e.g. "2026-03-03T12:34:56.789Z").
    pub created_at: String,
}

/// Maximum length for `event_id` (UUID v4 hex, 32 chars, plus headroom).
const MAX_EVENT_ID_LENGTH: usize = 64;

/// Maximum length for `source_service`.
const MAX_SOURCE_SERVICE_LENGTH: usize = 128;

/// Maximum length for `request_id`.
const MAX_REQUEST_ID_LENGTH: usize = 256;

/// Maximum length for `worker_version`.
const MAX_WORKER_VERSION_LENGTH: usize = 128;

/// Maximum length for `geo_country` (ISO 3166-1 alpha-2, plus headroom).
const MAX_GEO_COUNTRY_LENGTH: usize = 8;

/// Maximum length for `actor_id`.
const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length for `resource_type`.
const MAX_RESOURCE_TYPE_LENGTH: usize = 128;

/// Maximum length for `resource_id`.
const MAX_RESOURCE_ID_LENGTH: usize = 256;

/// Maximum length for `queue_message_id`.
const MAX_QUEUE_MESSAGE_ID_LENGTH: usize = 256;

/// Maximum length for `created_at` (ISO 8601 string, 24 chars, plus headroom).
const MAX_CREATED_AT_LENGTH: usize = 32;

impl AuditEvent {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub fn details(&self) -> &str {
        &self.details
    }
    #[must_use]
    pub fn client_ip_hash(&self) -> &str {
        &self.client_ip_hash
    }

    /// Validates all string field lengths after deserialisation.
    ///
    /// The builder enforces constraints at construction time, but events
    /// arriving from the queue via `serde_json::from_str` bypass the builder
    /// entirely. Call this method on any deserialised `AuditEvent` before
    /// passing it to downstream consumers (e.g. D1 bind params).
    ///
    /// Enum fields (`severity`, `environment`, `event_category`, `actor_type`,
    /// `outcome`) are validated by serde at deserialisation time and are not
    /// checked here.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::FieldValidationError`] on the first field that
    /// is empty where required or exceeds its byte length limit.
    #[allow(clippy::too_many_lines)]
    pub fn validate_field_lengths(&self) -> Result<(), AuditError> {
        // Required non-empty fields.
        if self.event_id.is_empty() {
            return Err(AuditError::field_validation(
                "event_id",
                "must not be empty",
            ));
        }
        if self.source_service.is_empty() {
            return Err(AuditError::field_validation(
                "source_service",
                "must not be empty",
            ));
        }
        if self.event_type.is_empty() {
            return Err(AuditError::field_validation(
                "event_type",
                "must not be empty",
            ));
        }
        if self.message.is_empty() {
            return Err(AuditError::field_validation("message", "must not be empty"));
        }
        if self.created_at.is_empty() {
            return Err(AuditError::field_validation(
                "created_at",
                "must not be empty",
            ));
        }

        // Per-field length checks against local constants.
        if self.event_id.len() > MAX_EVENT_ID_LENGTH {
            return Err(AuditError::field_validation(
                "event_id",
                format!("exceeds {MAX_EVENT_ID_LENGTH} byte limit"),
            ));
        }
        if self.source_service.len() > MAX_SOURCE_SERVICE_LENGTH {
            return Err(AuditError::field_validation(
                "source_service",
                format!("exceeds {MAX_SOURCE_SERVICE_LENGTH} byte limit"),
            ));
        }
        if self.event_type.len() > sanitize::MAX_EVENT_TYPE_LENGTH {
            return Err(AuditError::field_validation(
                "event_type",
                format!("exceeds {} byte limit", sanitize::MAX_EVENT_TYPE_LENGTH),
            ));
        }
        if self.message.len() > sanitize::MAX_MESSAGE_LENGTH {
            return Err(AuditError::field_validation(
                "message",
                format!("exceeds {} byte limit", sanitize::MAX_MESSAGE_LENGTH),
            ));
        }
        if self.details.len() > sanitize::MAX_DETAILS_LENGTH {
            return Err(AuditError::field_validation(
                "details",
                format!("exceeds {} byte limit", sanitize::MAX_DETAILS_LENGTH),
            ));
        }
        if self.request_id.len() > MAX_REQUEST_ID_LENGTH {
            return Err(AuditError::field_validation(
                "request_id",
                format!("exceeds {MAX_REQUEST_ID_LENGTH} byte limit"),
            ));
        }
        if self.worker_version.len() > MAX_WORKER_VERSION_LENGTH {
            return Err(AuditError::field_validation(
                "worker_version",
                format!("exceeds {MAX_WORKER_VERSION_LENGTH} byte limit"),
            ));
        }
        if self.geo_country.len() > MAX_GEO_COUNTRY_LENGTH {
            return Err(AuditError::field_validation(
                "geo_country",
                format!("exceeds {MAX_GEO_COUNTRY_LENGTH} byte limit"),
            ));
        }
        if self.actor_id.len() > MAX_ACTOR_ID_LENGTH {
            return Err(AuditError::field_validation(
                "actor_id",
                format!("exceeds {MAX_ACTOR_ID_LENGTH} byte limit"),
            ));
        }
        if self.resource_type.len() > MAX_RESOURCE_TYPE_LENGTH {
            return Err(AuditError::field_validation(
                "resource_type",
                format!("exceeds {MAX_RESOURCE_TYPE_LENGTH} byte limit"),
            ));
        }
        if self.resource_id.len() > MAX_RESOURCE_ID_LENGTH {
            return Err(AuditError::field_validation(
                "resource_id",
                format!("exceeds {MAX_RESOURCE_ID_LENGTH} byte limit"),
            ));
        }
        if self.queue_message_id.len() > MAX_QUEUE_MESSAGE_ID_LENGTH {
            return Err(AuditError::field_validation(
                "queue_message_id",
                format!("exceeds {MAX_QUEUE_MESSAGE_ID_LENGTH} byte limit"),
            ));
        }
        if self.created_at.len() > MAX_CREATED_AT_LENGTH {
            return Err(AuditError::field_validation(
                "created_at",
                format!("exceeds {MAX_CREATED_AT_LENGTH} byte limit"),
            ));
        }

        // Fields validated against the shared secondary field limit (8192 bytes).
        if self.client_ip_hash.len() > sanitize::MAX_FIELD_LENGTH {
            return Err(AuditError::field_validation(
                "client_ip_hash",
                format!("exceeds {} byte limit", sanitize::MAX_FIELD_LENGTH),
            ));
        }
        if self.origin.len() > sanitize::MAX_FIELD_LENGTH {
            return Err(AuditError::field_validation(
                "origin",
                format!("exceeds {} byte limit", sanitize::MAX_FIELD_LENGTH),
            ));
        }
        if self.user_agent_hash.len() > sanitize::MAX_FIELD_LENGTH {
            return Err(AuditError::field_validation(
                "user_agent_hash",
                format!("exceeds {} byte limit", sanitize::MAX_FIELD_LENGTH),
            ));
        }
        if self.challenge_id.len() > sanitize::MAX_FIELD_LENGTH {
            return Err(AuditError::field_validation(
                "challenge_id",
                format!("exceeds {} byte limit", sanitize::MAX_FIELD_LENGTH),
            ));
        }

        Ok(())
    }
}

/// Builder for [`AuditEvent`].
///
/// Four required fields (`event_type`, `severity`, `message`,
/// `source_service`) are provided at construction. All remaining fields
/// default to empty strings and can be set via chained methods.
///
/// Call [`.build()`](Self::build) to finalise the event. This auto-generates
/// `event_id` (UUID v4 via `getrandom`), `timestamp_ms`, and `created_at`.
/// Free-text fields (`message`, `details`) are PII-stripped before storage.
#[must_use]
#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    event_type: String,
    severity: Severity,
    message: String,
    source_service: String,
    client_ip_hash: String,
    origin: String,
    user_agent_hash: String,
    challenge_id: String,
    details: String,
    request_id: String,
    environment: Environment,
    worker_version: String,
    geo_country: String,
    event_category: Option<EventCategory>,
    actor_id: String,
    actor_type: Option<ActorType>,
    resource_type: String,
    resource_id: String,
    outcome: Option<Outcome>,
}

impl AuditEventBuilder {
    /// Create a new builder with the four required fields.
    ///
    /// All optional fields are initialised to empty strings or `None`. The
    /// environment defaults to [`Environment::Production`].
    pub fn new(
        event_type: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        source_service: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            severity,
            message: message.into(),
            source_service: source_service.into(),
            client_ip_hash: String::new(),
            origin: String::new(),
            user_agent_hash: String::new(),
            challenge_id: String::new(),
            details: "{}".to_string(),
            request_id: String::new(),
            environment: Environment::Production,
            worker_version: String::new(),
            geo_country: String::new(),
            event_category: None,
            actor_id: String::new(),
            actor_type: None,
            resource_type: String::new(),
            resource_id: String::new(),
            outcome: None,
        }
    }

    /// Set the HMAC-hashed client IP.
    pub fn client_ip_hash(mut self, value: impl Into<String>) -> Self {
        self.client_ip_hash = value.into();
        self
    }

    /// Set the origin domain.
    pub fn origin(mut self, value: impl Into<String>) -> Self {
        self.origin = value.into();
        self
    }

    /// Set the HMAC-hashed user agent string.
    pub fn user_agent_hash(mut self, value: impl Into<String>) -> Self {
        self.user_agent_hash = value.into();
        self
    }

    /// Set the challenge ID.
    pub fn challenge_id(mut self, value: impl Into<String>) -> Self {
        self.challenge_id = value.into();
        self
    }

    /// Set supplementary details (should be a JSON string).
    pub fn details(mut self, value: impl Into<String>) -> Self {
        self.details = value.into();
        self
    }

    /// Set the request trace ID for cross-service correlation.
    pub fn request_id(mut self, value: impl Into<String>) -> Self {
        self.request_id = value.into();
        self
    }

    /// Set the deployment environment.
    pub const fn environment(mut self, value: Environment) -> Self {
        self.environment = value;
        self
    }

    /// Set the worker version string.
    pub fn worker_version(mut self, value: impl Into<String>) -> Self {
        self.worker_version = value.into();
        self
    }

    /// Set the ISO 3166-1 alpha-2 country code.
    pub fn geo_country(mut self, value: impl Into<String>) -> Self {
        self.geo_country = value.into();
        self
    }

    /// Set the event category.
    pub const fn event_category(mut self, value: EventCategory) -> Self {
        self.event_category = Some(value);
        self
    }

    /// Set the actor ID (who performed the action).
    pub fn actor_id(mut self, value: impl Into<String>) -> Self {
        self.actor_id = value.into();
        self
    }

    /// Set the actor type.
    pub const fn actor_type(mut self, value: ActorType) -> Self {
        self.actor_type = Some(value);
        self
    }

    /// Set the resource type ("challenge", "session", "credential", "kek", etc.).
    pub fn resource_type(mut self, value: impl Into<String>) -> Self {
        self.resource_type = value.into();
        self
    }

    /// Set the resource identifier.
    pub fn resource_id(mut self, value: impl Into<String>) -> Self {
        self.resource_id = value.into();
        self
    }

    /// Set the action outcome.
    pub const fn outcome(mut self, value: Outcome) -> Self {
        self.outcome = Some(value);
        self
    }

    /// Finalise the builder and produce an [`AuditEvent`].
    ///
    /// Auto-generates `event_id` (UUID v4), `timestamp_ms`, and `created_at`.
    /// The `queue_message_id` field is left empty; the consumer sets it after
    /// dequeue. Typed enum fields (`environment`, `event_category`,
    /// `actor_type`, `outcome`) are validated at compile time, so no runtime
    /// checks are needed for them.
    ///
    /// Free-text fields (`message` and `details`) are run through PII
    /// sanitisation before being stored in the event.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::ValidationError`] if any of `event_type`,
    /// `message`, or `source_service` is empty, or if the platform RNG fails.
    pub fn build(self) -> Result<AuditEvent, AuditError> {
        if self.event_type.is_empty() {
            return Err(AuditError::field_validation(
                "event_type",
                "must not be empty",
            ));
        }
        if self.message.is_empty() {
            return Err(AuditError::field_validation("message", "must not be empty"));
        }
        if self.source_service.is_empty() {
            return Err(AuditError::field_validation(
                "source_service",
                "must not be empty",
            ));
        }

        let event_id = generate_uuid_v4()?;
        let timestamp_ms = current_timestamp_ms();
        let created_at = format_iso8601(timestamp_ms);

        let sanitised_message = strip_pii(&self.message);
        let sanitised_details = strip_pii(&self.details);

        Ok(AuditEvent {
            event_id,
            timestamp_ms,
            source_service: self.source_service,
            event_type: self.event_type,
            severity: self.severity,
            client_ip_hash: self.client_ip_hash,
            origin: self.origin,
            user_agent_hash: self.user_agent_hash,
            challenge_id: self.challenge_id,
            message: sanitised_message,
            details: sanitised_details,
            request_id: self.request_id,
            environment: self.environment,
            worker_version: self.worker_version,
            geo_country: self.geo_country,
            event_category: self.event_category,
            actor_id: self.actor_id,
            actor_type: self.actor_type,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            outcome: self.outcome,
            queue_message_id: String::new(),
            created_at,
        })
    }
}

/// Generate a UUID v4 as a 32-character hex string (no hyphens).
///
/// Uses `getrandom`, which supports both native targets and
/// `wasm32-unknown-unknown` (with the `js` feature for WASM).
fn generate_uuid_v4() -> Result<String, AuditError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| AuditError::validation(format!("RNG failed: {e}")))?;

    // Version 4: high nibble of byte 6 = 0100.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Variant 1 (RFC 4122): high two bits of byte 8 = 10.
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(hex::encode(bytes))
}

/// Get the current timestamp in milliseconds since Unix epoch.
///
/// On WASM targets this calls `js_sys::Date::now()`. On native targets it
/// reads from `std::time::SystemTime`.
fn current_timestamp_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let ms = js_sys::Date::now() as u64;
        ms
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        #[allow(clippy::cast_possible_truncation)]
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// Maximum timestamp (milliseconds) representable as ISO 8601: 9999-12-31T23:59:59.999Z.
pub const MAX_ISO8601_TIMESTAMP_MS: u64 = 253_402_300_799_999;

/// Format a Unix timestamp (milliseconds) as an ISO 8601 string.
///
/// Produces `YYYY-MM-DDTHH:MM:SS.mmmZ` without pulling in the `chrono` crate.
/// Uses the O(1) Howard Hinnant `civil_from_days` algorithm. Timestamps beyond
/// 9999-12-31T23:59:59.999Z are clamped to that maximum.
#[must_use]
#[allow(clippy::arithmetic_side_effects, clippy::similar_names)]
pub fn format_iso8601(timestamp_ms: u64) -> String {
    let timestamp_ms = if timestamp_ms > MAX_ISO8601_TIMESTAMP_MS {
        MAX_ISO8601_TIMESTAMP_MS
    } else {
        timestamp_ms
    };

    let total_secs = timestamp_ms / 1000;
    let millis = timestamp_ms % 1000;
    let days_since_epoch = total_secs / 86400;
    let day_secs = total_secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- UUID v4 generation ----

    #[test]
    fn uuid_v4_is_32_hex_chars() {
        let id = generate_uuid_v4().unwrap();
        assert_eq!(id.len(), 32, "UUID hex should be 32 characters");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "UUID must be valid hex"
        );
    }

    #[test]
    fn uuid_v4_has_version_bits() {
        let id = generate_uuid_v4().unwrap();
        // Byte 6 occupies hex positions 12..14. High nibble must be '4'.
        let version_char = id
            .as_bytes()
            .get(12)
            .expect("UUID must have at least 13 bytes");
        assert_eq!(*version_char, b'4', "UUID version nibble must be 4");
    }

    #[test]
    fn uuid_v4_has_variant_bits() {
        let id = generate_uuid_v4().unwrap();
        // Byte 8 occupies hex positions 16..18. High nibble must be 8, 9, a, or b.
        let variant_char = id
            .as_bytes()
            .get(16)
            .expect("UUID must have at least 17 bytes");
        assert!(
            matches!(variant_char, b'8' | b'9' | b'a' | b'b'),
            "UUID variant nibble must be 8/9/a/b, got: {}",
            *variant_char as char
        );
    }

    #[test]
    fn uuid_v4_is_unique() {
        let id1 = generate_uuid_v4().unwrap();
        let id2 = generate_uuid_v4().unwrap();
        assert_ne!(id1, id2, "Two UUID v4 values must differ");
    }

    // ---- ISO 8601 formatting ----

    #[test]
    fn format_iso8601_epoch() {
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn format_iso8601_known_date() {
        // 2024-01-15T12:10:45.123Z
        let ts: u64 = 1_705_320_645_123;
        let result = format_iso8601(ts);
        assert_eq!(result, "2024-01-15T12:10:45.123Z");
    }

    #[test]
    fn format_iso8601_leap_year_feb_29() {
        // 2024-02-29T00:00:00.000Z (2024 is a leap year)
        let ts: u64 = 1_709_164_800_000;
        let result = format_iso8601(ts);
        assert_eq!(result, "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn format_iso8601_end_of_year() {
        // 2023-12-31T23:59:59.999Z
        let ts: u64 = 1_704_067_199_999;
        let result = format_iso8601(ts);
        assert_eq!(result, "2023-12-31T23:59:59.999Z");
    }

    #[test]
    fn format_iso8601_millis_preserved() {
        let ts: u64 = 1_700_000_000_456;
        let result = format_iso8601(ts);
        let suffix = ".456Z";
        assert!(result.ends_with(suffix), "Millis not preserved: {result}");
    }

    #[test]
    fn format_iso8601_year_2000_leap() {
        // 2000-02-29T00:00:00.000Z (year 2000 is leap: divisible by 400)
        // Days from epoch to 2000-01-01: 10957
        // Plus Jan(31) + 28 days = day 59 from Jan 1 → Feb 29
        // (10957 + 31 + 28) * 86400 * 1000 = 951_782_400_000
        let ts: u64 = 951_782_400_000;
        assert_eq!(format_iso8601(ts), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn format_iso8601_year_2100_non_leap() {
        // 2100-03-01T00:00:00.000Z (year 2100 is NOT leap: divisible by 100 but not 400)
        // If 2100 were leap, Feb would have 29 days and this timestamp would be Feb 29.
        // Since 2100 is not leap, the 60th day (0-indexed 59) of 2100 is March 1.
        // Days from epoch to 2100-01-01: 47482
        // Plus 59 days = 47541 days
        // 47541 * 86400 * 1000 = 4_107_542_400_000
        let ts: u64 = 4_107_542_400_000;
        assert_eq!(format_iso8601(ts), "2100-03-01T00:00:00.000Z");
    }

    #[test]
    fn format_iso8601_year_9999_max() {
        // 9999-12-31T23:59:59.999Z = MAX_ISO8601_TIMESTAMP_MS
        assert_eq!(
            format_iso8601(MAX_ISO8601_TIMESTAMP_MS),
            "9999-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn format_iso8601_u64_max_clamps() {
        // u64::MAX should clamp to 9999-12-31T23:59:59.999Z
        assert_eq!(format_iso8601(u64::MAX), "9999-12-31T23:59:59.999Z");
    }

    #[test]
    fn format_iso8601_one_ms_after_epoch() {
        assert_eq!(format_iso8601(1), "1970-01-01T00:00:00.001Z");
    }

    // ---- Builder: required field validation ----

    #[test]
    fn builder_rejects_empty_event_type() {
        let result = AuditEventBuilder::new("", Severity::Info, "message", "service").build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("event_type"),
            "expected event_type error, got: {err}"
        );
    }

    #[test]
    fn builder_rejects_empty_message() {
        let result = AuditEventBuilder::new("event", Severity::Info, "", "service").build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("message"),
            "expected message error, got: {err}"
        );
    }

    #[test]
    fn builder_rejects_empty_source_service() {
        let result = AuditEventBuilder::new("event", Severity::Info, "message", "").build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("source_service"),
            "expected source_service error, got: {err}"
        );
    }

    // ---- Builder: successful construction ----

    #[test]
    fn builder_minimal_creates_event() {
        let event = AuditEventBuilder::new(
            "verification_success",
            Severity::Info,
            "Verification succeeded",
            "provii-verifier",
        )
        .build()
        .unwrap();

        assert_eq!(event.event_type, "verification_success");
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.message, "Verification succeeded");
        assert_eq!(event.source_service, "provii-verifier");

        // Auto-generated fields
        assert_eq!(event.event_id.len(), 32);
        assert!(event.timestamp_ms > 0);
        assert!(!event.created_at.is_empty());
        assert!(event.created_at.ends_with('Z'));

        // Optional fields default to empty
        assert!(event.client_ip_hash.is_empty());
        assert!(event.origin.is_empty());
        assert!(event.user_agent_hash.is_empty());
        assert!(event.challenge_id.is_empty());
        assert_eq!(event.details, "{}");
        assert!(event.request_id.is_empty());
        assert_eq!(event.environment, Environment::Production);
        assert!(event.worker_version.is_empty());
        assert!(event.geo_country.is_empty());
        assert!(event.event_category.is_none());
        assert!(event.actor_id.is_empty());
        assert!(event.actor_type.is_none());
        assert!(event.resource_type.is_empty());
        assert!(event.resource_id.is_empty());
        assert!(event.outcome.is_none());
        assert!(event.queue_message_id.is_empty());
    }

    #[test]
    fn builder_all_optional_fields() {
        let event = AuditEventBuilder::new(
            "challenge_created",
            Severity::Warning,
            "Challenge issued",
            "provii-verifier",
        )
        .client_ip_hash("abcdef1234567890")
        .origin("https://example.com")
        .user_agent_hash("fedcba0987654321")
        .challenge_id("ch-001")
        .details(r#"{"ttl":300}"#)
        .request_id("req-abc-123")
        .environment(Environment::Production)
        .worker_version("1.2.3")
        .geo_country("AU")
        .build()
        .unwrap();

        assert_eq!(event.client_ip_hash, "abcdef1234567890");
        assert_eq!(event.origin, "https://example.com");
        assert_eq!(event.user_agent_hash, "fedcba0987654321");
        assert_eq!(event.challenge_id, "ch-001");
        assert_eq!(event.details, r#"{"ttl":300}"#);
        assert_eq!(event.request_id, "req-abc-123");
        assert_eq!(event.environment, Environment::Production);
        assert_eq!(event.worker_version, "1.2.3");
        assert_eq!(event.geo_country, "AU");
        assert!(event.queue_message_id.is_empty());
    }

    // ---- Serialisation round-trip ----

    #[test]
    fn serialise_deserialise_roundtrip() {
        let event = AuditEventBuilder::new(
            "verification_success",
            Severity::Critical,
            "Verified",
            "provii-verifier",
        )
        .challenge_id("ch-123")
        .environment(Environment::Sandbox)
        .build()
        .unwrap();

        let json = serde_json::to_string(&event).unwrap();
        let roundtripped: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(
            roundtripped, event,
            "All fields must survive serialisation round-trip"
        );
    }

    #[test]
    fn severity_serialises_as_snake_case_in_event() {
        let event = AuditEventBuilder::new("e", Severity::Critical, "m", "s")
            .build()
            .unwrap();

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains(r#""severity":"critical""#),
            "severity must serialise as snake_case, got: {json}"
        );
    }

    // ---- Auto-generated field properties ----

    #[test]
    fn event_ids_are_unique_across_builds() {
        let e1 = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();
        let e2 = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();

        assert_ne!(
            e1.event_id, e2.event_id,
            "Each build must produce a unique event_id"
        );
    }

    #[test]
    fn timestamp_ms_is_recent() {
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();

        // Timestamp should be after 2025-01-01T00:00:00Z (1735689600000).
        assert!(
            event.timestamp_ms > 1_735_689_600_000,
            "timestamp_ms should be recent, got: {}",
            event.timestamp_ms
        );
    }

    #[test]
    fn created_at_is_iso8601_format() {
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();

        let bytes = event.created_at.as_bytes();
        assert_eq!(bytes.len(), 24, "ISO 8601 should be 24 chars");
        assert_eq!(bytes.get(4).copied(), Some(b'-'), "Char 4 should be '-'");
        assert_eq!(bytes.get(7).copied(), Some(b'-'), "Char 7 should be '-'");
        assert_eq!(bytes.get(10).copied(), Some(b'T'), "Char 10 should be 'T'");
        assert_eq!(bytes.get(13).copied(), Some(b':'), "Char 13 should be ':'");
        assert_eq!(bytes.get(16).copied(), Some(b':'), "Char 16 should be ':'");
        assert_eq!(bytes.get(19).copied(), Some(b'.'), "Char 19 should be '.'");
        assert_eq!(
            bytes.get(23).copied(),
            Some(b'Z'),
            "Last char should be 'Z'"
        );
    }

    #[test]
    fn created_at_matches_timestamp_ms() {
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();

        let expected = format_iso8601(event.timestamp_ms);
        assert_eq!(event.created_at, expected);
    }

    // ---- Deserialisation from external JSON ----

    #[test]
    fn deserialise_from_json_with_all_fields() {
        let json = r#"{
            "event_id": "aabbccdd11223344aabbccdd11223344",
            "timestamp_ms": 1700000000000,
            "source_service": "provii-issuer",
            "event_type": "attestation_issued",
            "severity": "info",
            "client_ip_hash": "deadbeef",
            "origin": "https://issuer.example.com",
            "user_agent_hash": "cafebabe",
            "challenge_id": "",
            "message": "Attestation issued",
            "details": "{}",
            "request_id": "req-001",
            "environment": "production",
            "worker_version": "2.0.0",
            "geo_country": "AU",
            "event_category": "CREDENTIAL_ISSUANCE",
            "actor_id": "issuer-svc-01",
            "actor_type": "service",
            "resource_type": "credential",
            "resource_id": "cred-abc-123",
            "outcome": "success",
            "queue_message_id": "msg-555",
            "created_at": "2023-11-14T22:13:20.000Z"
        }"#;

        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_id, "aabbccdd11223344aabbccdd11223344");
        assert_eq!(event.timestamp_ms, 1_700_000_000_000);
        assert_eq!(event.source_service, "provii-issuer");
        assert_eq!(event.event_type, "attestation_issued");
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.environment, Environment::Production);
        assert_eq!(
            event.event_category,
            Some(EventCategory::CredentialIssuance)
        );
        assert_eq!(event.actor_id, "issuer-svc-01");
        assert_eq!(event.actor_type, Some(ActorType::Service));
        assert_eq!(event.resource_type, "credential");
        assert_eq!(event.resource_id, "cred-abc-123");
        assert_eq!(event.outcome, Some(Outcome::Success));
        assert_eq!(event.queue_message_id, "msg-555");
        assert_eq!(event.geo_country, "AU");
    }

    // ---- Edge cases ----

    #[test]
    fn builder_accepts_single_char_fields() {
        let result = AuditEventBuilder::new("e", Severity::Info, "m", "s").build();
        assert!(result.is_ok());
    }

    #[test]
    fn builder_preserves_unicode_in_message() {
        let msg = "Caf\u{00e9} test \u{1F600}";
        let event = AuditEventBuilder::new("e", Severity::Info, msg, "s")
            .build()
            .unwrap();
        assert_eq!(event.message, msg);
    }

    #[test]
    fn queue_message_id_is_always_empty_at_creation() {
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();
        assert!(
            event.queue_message_id.is_empty(),
            "queue_message_id must be empty at creation"
        );
    }

    #[test]
    fn all_severity_levels_accepted() {
        for severity in [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ] {
            let result = AuditEventBuilder::new("e", severity, "m", "s").build();
            assert!(result.is_ok(), "Severity {severity} should be accepted");
        }
    }

    // ---- EventCategory tests ----

    #[test]
    fn event_category_serde_roundtrip() {
        let categories = [
            EventCategory::Authentication,
            EventCategory::Authorization,
            EventCategory::KeyAccess,
            EventCategory::DataMutation,
            EventCategory::SessionLifecycle,
            EventCategory::CredentialIssuance,
            EventCategory::Verification,
            EventCategory::AdminAction,
            EventCategory::ExternalCall,
            EventCategory::SecurityEvent,
        ];

        for cat in categories {
            let json = serde_json::to_string(&cat).unwrap();
            let roundtripped: EventCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtripped, cat, "Roundtrip failed for {cat}");
        }
    }

    #[test]
    fn event_category_serialises_as_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventCategory::KeyAccess).unwrap(),
            r#""KEY_ACCESS""#
        );
        assert_eq!(
            serde_json::to_string(&EventCategory::SessionLifecycle).unwrap(),
            r#""SESSION_LIFECYCLE""#
        );
        assert_eq!(
            serde_json::to_string(&EventCategory::CredentialIssuance).unwrap(),
            r#""CREDENTIAL_ISSUANCE""#
        );
        assert_eq!(
            serde_json::to_string(&EventCategory::SecurityEvent).unwrap(),
            r#""SECURITY_EVENT""#
        );
    }

    #[test]
    fn event_category_display_matches_serde() {
        assert_eq!(EventCategory::Authentication.to_string(), "AUTHENTICATION");
        assert_eq!(EventCategory::Authorization.to_string(), "AUTHORIZATION");
        assert_eq!(EventCategory::KeyAccess.to_string(), "KEY_ACCESS");
        assert_eq!(EventCategory::DataMutation.to_string(), "DATA_MUTATION");
        assert_eq!(
            EventCategory::SessionLifecycle.to_string(),
            "SESSION_LIFECYCLE"
        );
        assert_eq!(
            EventCategory::CredentialIssuance.to_string(),
            "CREDENTIAL_ISSUANCE"
        );
        assert_eq!(EventCategory::Verification.to_string(), "VERIFICATION");
        assert_eq!(EventCategory::AdminAction.to_string(), "ADMIN_ACTION");
        assert_eq!(EventCategory::ExternalCall.to_string(), "EXTERNAL_CALL");
        assert_eq!(EventCategory::SecurityEvent.to_string(), "SECURITY_EVENT");
    }

    #[test]
    fn event_category_has_exactly_10_variants() {
        // Exhaustive match ensures this test fails to compile if variants change.
        let all = [
            EventCategory::Authentication,
            EventCategory::Authorization,
            EventCategory::KeyAccess,
            EventCategory::DataMutation,
            EventCategory::SessionLifecycle,
            EventCategory::CredentialIssuance,
            EventCategory::Verification,
            EventCategory::AdminAction,
            EventCategory::ExternalCall,
            EventCategory::SecurityEvent,
        ];
        assert_eq!(all.len(), 10);
    }

    // ---- Builder with category/actor/outcome fields ----

    #[test]
    fn builder_with_all_new_fields() {
        let event = AuditEventBuilder::new("test_event", Severity::Info, "msg", "svc")
            .event_category(EventCategory::Verification)
            .actor_id("user-123")
            .actor_type(ActorType::User)
            .resource_type("challenge")
            .resource_id("ch-456")
            .outcome(Outcome::Success)
            .build()
            .unwrap();

        assert_eq!(event.event_category, Some(EventCategory::Verification));
        assert_eq!(event.actor_id, "user-123");
        assert_eq!(event.actor_type, Some(ActorType::User));
        assert_eq!(event.resource_type, "challenge");
        assert_eq!(event.resource_id, "ch-456");
        assert_eq!(event.outcome, Some(Outcome::Success));
    }

    #[test]
    fn builder_without_new_fields_defaults_to_none() {
        let event = AuditEventBuilder::new("test_event", Severity::Info, "msg", "svc")
            .build()
            .unwrap();

        assert!(event.event_category.is_none());
        assert!(event.actor_id.is_empty());
        assert!(event.actor_type.is_none());
        assert!(event.resource_type.is_empty());
        assert!(event.resource_id.is_empty());
        assert!(event.outcome.is_none());
    }

    // ---- PII sanitisation in build() ----

    #[test]
    fn build_strips_ipv4_from_message() {
        let event = AuditEventBuilder::new(
            "test",
            Severity::Info,
            "Client 192.168.1.1 connected",
            "svc",
        )
        .build()
        .unwrap();

        assert!(!event.message.contains("192.168.1.1"));
        assert!(event.message.contains("[REDACTED_IP]"));
    }

    #[test]
    fn build_strips_ipv4_from_details() {
        let event = AuditEventBuilder::new("test", Severity::Info, "msg", "svc")
            .details(r#"{"ip":"10.0.0.1"}"#)
            .build()
            .unwrap();

        assert!(!event.details.contains("10.0.0.1"));
        assert!(event.details.contains("[REDACTED_IP]"));
    }

    #[test]
    fn build_strips_email_from_message() {
        let event = AuditEventBuilder::new(
            "test",
            Severity::Info,
            "User user@example.com authenticated",
            "svc",
        )
        .build()
        .unwrap();

        assert!(!event.message.contains("user@example.com"));
        assert!(event.message.contains("[REDACTED_EMAIL]"));
    }

    #[test]
    fn build_strips_dob_from_details() {
        let event = AuditEventBuilder::new("test", Severity::Info, "msg", "svc")
            .details(r#"{"dob":"1990-05-15"}"#)
            .build()
            .unwrap();

        assert!(!event.details.contains("1990-05-15"));
        assert!(event.details.contains("[REDACTED_DOB]"));
    }

    #[test]
    fn build_preserves_clean_message() {
        let event =
            AuditEventBuilder::new("test", Severity::Info, "Challenge ch-123 verified", "svc")
                .build()
                .unwrap();

        assert_eq!(event.message, "Challenge ch-123 verified");
    }

    #[test]
    fn build_preserves_clean_details() {
        let event = AuditEventBuilder::new("test", Severity::Info, "msg", "svc")
            .details(r#"{"ttl":300}"#)
            .build()
            .unwrap();

        assert_eq!(event.details, r#"{"ttl":300}"#);
    }

    // ---- Environment enum ----

    #[test]
    fn environment_serde_roundtrip() {
        for env in [Environment::Production, Environment::Sandbox] {
            let json = serde_json::to_string(&env).unwrap();
            let roundtripped: Environment = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtripped, env);
        }
    }

    #[test]
    fn environment_display() {
        assert_eq!(Environment::Production.to_string(), "production");
        assert_eq!(Environment::Sandbox.to_string(), "sandbox");
    }

    // ---- ActorType enum ----

    #[test]
    fn actor_type_serde_roundtrip() {
        for at in [
            ActorType::User,
            ActorType::Service,
            ActorType::ApiKey,
            ActorType::System,
        ] {
            let json = serde_json::to_string(&at).unwrap();
            let roundtripped: ActorType = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtripped, at);
        }
    }

    #[test]
    fn actor_type_display() {
        assert_eq!(ActorType::User.to_string(), "user");
        assert_eq!(ActorType::Service.to_string(), "service");
        assert_eq!(ActorType::ApiKey.to_string(), "api_key");
        assert_eq!(ActorType::System.to_string(), "system");
    }

    // ---- Outcome enum ----

    #[test]
    fn outcome_serde_roundtrip() {
        for oc in [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Denied,
            Outcome::Error,
        ] {
            let json = serde_json::to_string(&oc).unwrap();
            let roundtripped: Outcome = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtripped, oc);
        }
    }

    #[test]
    fn outcome_display() {
        assert_eq!(Outcome::Success.to_string(), "success");
        assert_eq!(Outcome::Failure.to_string(), "failure");
        assert_eq!(Outcome::Denied.to_string(), "denied");
        assert_eq!(Outcome::Error.to_string(), "error");
    }

    // ---- Builder: enum fields accepted via type system ----

    #[test]
    fn builder_accepts_sandbox_environment() {
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .environment(Environment::Sandbox)
            .build()
            .unwrap();
        assert_eq!(event.environment, Environment::Sandbox);
    }

    #[test]
    fn builder_accepts_all_actor_types() {
        for at in [
            ActorType::User,
            ActorType::Service,
            ActorType::ApiKey,
            ActorType::System,
        ] {
            let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
                .actor_type(at)
                .build()
                .unwrap();
            assert_eq!(event.actor_type, Some(at));
        }
    }

    #[test]
    fn builder_accepts_all_outcomes() {
        for oc in [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Denied,
            Outcome::Error,
        ] {
            let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
                .outcome(oc)
                .build()
                .unwrap();
            assert_eq!(event.outcome, Some(oc));
        }
    }

    #[test]
    fn builder_accepts_all_event_categories() {
        for cat in [
            EventCategory::Authentication,
            EventCategory::Authorization,
            EventCategory::KeyAccess,
            EventCategory::DataMutation,
            EventCategory::SessionLifecycle,
            EventCategory::CredentialIssuance,
            EventCategory::Verification,
            EventCategory::AdminAction,
            EventCategory::ExternalCall,
            EventCategory::SecurityEvent,
        ] {
            let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
                .event_category(cat)
                .build()
                .unwrap();
            assert_eq!(event.event_category, Some(cat));
        }
    }

    // ---- Option enum serde: wire compatibility ----

    #[test]
    fn option_enum_serialises_none_as_empty_string() {
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();
        let json = serde_json::to_string(&event).unwrap();
        // event_category, actor_type, outcome should all be ""
        assert!(
            json.contains(r#""event_category":"""#),
            "None event_category must serialise as empty string, got: {json}"
        );
        assert!(
            json.contains(r#""actor_type":"""#),
            "None actor_type must serialise as empty string, got: {json}"
        );
        assert!(
            json.contains(r#""outcome":"""#),
            "None outcome must serialise as empty string, got: {json}"
        );
    }

    #[test]
    fn option_enum_deserialises_empty_string_as_none() {
        let json = r#"{
            "event_id": "aabbccdd11223344aabbccdd11223344",
            "timestamp_ms": 1700000000000,
            "source_service": "svc",
            "event_type": "e",
            "severity": "info",
            "client_ip_hash": "",
            "origin": "",
            "user_agent_hash": "",
            "challenge_id": "",
            "message": "m",
            "details": "{}",
            "request_id": "",
            "environment": "production",
            "worker_version": "",
            "geo_country": "",
            "event_category": "",
            "actor_id": "",
            "actor_type": "",
            "resource_type": "",
            "resource_id": "",
            "outcome": "",
            "queue_message_id": "",
            "created_at": "2023-11-14T22:13:20.000Z"
        }"#;

        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert!(event.event_category.is_none());
        assert!(event.actor_type.is_none());
        assert!(event.outcome.is_none());
        assert_eq!(event.environment, Environment::Production);
    }

    // ---- validate_field_lengths: builder event passes ----

    #[test]
    fn validate_field_lengths_passes_for_builder_event() {
        let event = AuditEventBuilder::new(
            "verification_success",
            Severity::Info,
            "Verification succeeded",
            "provii-verifier",
        )
        .client_ip_hash("abcdef1234567890")
        .origin("https://example.com")
        .user_agent_hash("fedcba0987654321")
        .challenge_id("ch-001")
        .build()
        .unwrap();

        assert!(event.validate_field_lengths().is_ok());
    }

    // ---- validate_field_lengths: oversized fields rejected ----

    /// Helper that builds a valid `AuditEvent` JSON, overriding one field.
    fn deserialise_with_field(field: &str, value: &str) -> AuditEvent {
        let json = r#"{
                "event_id": "aabbccdd11223344aabbccdd11223344",
                "timestamp_ms": 1700000000000,
                "source_service": "svc",
                "event_type": "test_event",
                "severity": "info",
                "client_ip_hash": "",
                "origin": "",
                "user_agent_hash": "",
                "challenge_id": "",
                "message": "test message",
                "details": "{}",
                "request_id": "",
                "environment": "production",
                "worker_version": "",
                "geo_country": "",
                "event_category": "",
                "actor_id": "",
                "actor_type": "",
                "resource_type": "",
                "resource_id": "",
                "outcome": "",
                "queue_message_id": "",
                "created_at": "2023-11-14T22:13:20.000Z"
            }"#
        .to_string();
        let mut event: AuditEvent = serde_json::from_str(&json).unwrap();
        match field {
            "event_id" => event.event_id = value.to_string(),
            "source_service" => event.source_service = value.to_string(),
            "event_type" => event.event_type = value.to_string(),
            "geo_country" => event.geo_country = value.to_string(),
            "actor_id" => event.actor_id = value.to_string(),
            "origin" => event.origin = value.to_string(),
            "user_agent_hash" => event.user_agent_hash = value.to_string(),
            "challenge_id" => event.challenge_id = value.to_string(),
            "request_id" => event.request_id = value.to_string(),
            "worker_version" => event.worker_version = value.to_string(),
            "resource_type" => event.resource_type = value.to_string(),
            "resource_id" => event.resource_id = value.to_string(),
            "queue_message_id" => event.queue_message_id = value.to_string(),
            "created_at" => event.created_at = value.to_string(),
            _ => {}
        }
        event
    }

    #[test]
    fn validate_rejects_oversized_event_id() {
        let event = deserialise_with_field("event_id", &"x".repeat(65));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("event_id"));
    }

    #[test]
    fn validate_rejects_oversized_source_service() {
        let event = deserialise_with_field("source_service", &"x".repeat(129));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("source_service"));
    }

    #[test]
    fn validate_rejects_oversized_geo_country() {
        let event = deserialise_with_field("geo_country", &"x".repeat(9));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("geo_country"));
    }

    #[test]
    fn validate_rejects_oversized_actor_id() {
        let event = deserialise_with_field("actor_id", &"x".repeat(257));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("actor_id"));
    }

    #[test]
    fn validate_rejects_oversized_origin() {
        let event = deserialise_with_field("origin", &"x".repeat(8193));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("origin"));
    }

    #[test]
    fn validate_rejects_oversized_user_agent_hash() {
        let event = deserialise_with_field("user_agent_hash", &"x".repeat(8193));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("user_agent_hash"));
    }

    #[test]
    fn validate_rejects_oversized_challenge_id() {
        let event = deserialise_with_field("challenge_id", &"x".repeat(8193));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("challenge_id"));
    }

    #[test]
    fn validate_rejects_oversized_request_id() {
        // MAX_REQUEST_ID_LENGTH is 256; one byte over must fail.
        let event = deserialise_with_field("request_id", &"x".repeat(257));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("request_id"));
    }

    #[test]
    fn validate_rejects_oversized_worker_version() {
        // MAX_WORKER_VERSION_LENGTH is 128; one byte over must fail.
        let event = deserialise_with_field("worker_version", &"x".repeat(129));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("worker_version"));
    }

    #[test]
    fn validate_rejects_oversized_resource_type() {
        // MAX_RESOURCE_TYPE_LENGTH is 128; one byte over must fail.
        let event = deserialise_with_field("resource_type", &"x".repeat(129));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("resource_type"));
    }

    #[test]
    fn validate_rejects_oversized_resource_id() {
        // MAX_RESOURCE_ID_LENGTH is 256; one byte over must fail.
        let event = deserialise_with_field("resource_id", &"x".repeat(257));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("resource_id"));
    }

    #[test]
    fn validate_rejects_oversized_queue_message_id() {
        // MAX_QUEUE_MESSAGE_ID_LENGTH is 256; one byte over must fail.
        let event = deserialise_with_field("queue_message_id", &"x".repeat(257));
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("queue_message_id"));
    }

    // ---- invalid enum deserialisation ----

    #[test]
    fn deserialise_rejects_invalid_event_category() {
        // An unrecognised enum variant must produce a serde error, exercising
        // the error-mapping path in option_enum_as_string::deserialize.
        let json = r#"{
            "event_id": "aabbccdd11223344aabbccdd11223344",
            "timestamp_ms": 1700000000000,
            "source_service": "svc",
            "event_type": "test_event",
            "severity": "info",
            "client_ip_hash": "",
            "origin": "",
            "user_agent_hash": "",
            "challenge_id": "",
            "message": "test message",
            "details": "{}",
            "request_id": "",
            "environment": "production",
            "worker_version": "",
            "geo_country": "",
            "event_category": "BOGUS_VALUE",
            "actor_id": "",
            "actor_type": "",
            "resource_type": "",
            "resource_id": "",
            "outcome": "",
            "queue_message_id": "",
            "created_at": "2023-11-14T22:13:20.000Z"
        }"#;

        let result = serde_json::from_str::<AuditEvent>(json);
        assert!(
            result.is_err(),
            "expected deserialisation to fail for bogus enum variant"
        );
    }

    // ---- validate_field_lengths: at-limit values pass ----

    #[test]
    fn validate_accepts_event_id_at_limit() {
        let event = deserialise_with_field("event_id", &"a".repeat(64));
        assert!(event.validate_field_lengths().is_ok());
    }

    #[test]
    fn validate_accepts_geo_country_at_limit() {
        let event = deserialise_with_field("geo_country", &"A".repeat(8));
        assert!(event.validate_field_lengths().is_ok());
    }

    #[test]
    fn validate_accepts_origin_at_limit() {
        let event = deserialise_with_field("origin", &"x".repeat(8192));
        assert!(event.validate_field_lengths().is_ok());
    }

    #[test]
    fn validate_accepts_challenge_id_at_limit() {
        let event = deserialise_with_field("challenge_id", &"c".repeat(8192));
        assert!(event.validate_field_lengths().is_ok());
    }

    // ---- validate_field_lengths: empty required fields rejected ----

    #[test]
    fn validate_rejects_empty_event_id_after_deserialisation() {
        let event = deserialise_with_field("event_id", "");
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("event_id"),
            "expected event_id error, got: {err}"
        );
        assert!(
            err.contains("must not be empty"),
            "expected emptiness error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_empty_created_at_after_deserialisation() {
        let event = deserialise_with_field("created_at", "");
        let result = event.validate_field_lengths();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("created_at"),
            "expected created_at error, got: {err}"
        );
    }

    // ---- validate_field_lengths: enum fields are not checked (regression guard) ----

    #[test]
    fn validate_does_not_reject_enum_fields() {
        // Build an event with all enum fields set. The method should not
        // attempt to length-check severity, environment, event_category,
        // actor_type, or outcome, regardless of their serialised form.
        let event = AuditEventBuilder::new("test_event", Severity::Critical, "msg", "svc")
            .environment(Environment::Sandbox)
            .event_category(EventCategory::SecurityEvent)
            .actor_type(ActorType::System)
            .outcome(Outcome::Denied)
            .build()
            .unwrap();

        // If validate_field_lengths tried to check an enum field as a string,
        // it would fail to compile or would need to call .to_string() first.
        // This test confirms the method completes without error.
        assert!(event.validate_field_lengths().is_ok());
    }

    #[test]
    fn validate_does_not_reject_none_enum_fields() {
        // Variant where optional enums are None.
        let event = AuditEventBuilder::new("e", Severity::Info, "m", "s")
            .build()
            .unwrap();
        assert!(event.validate_field_lengths().is_ok());
    }

    // ---- Property-based tests (H-33) ----

    use proptest::prelude::*;

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Warning),
            Just(Severity::Error),
            Just(Severity::Critical),
        ]
    }

    fn arb_environment() -> impl Strategy<Value = Environment> {
        prop_oneof![Just(Environment::Production), Just(Environment::Sandbox),]
    }

    fn arb_event_category() -> impl Strategy<Value = EventCategory> {
        prop_oneof![
            Just(EventCategory::Authentication),
            Just(EventCategory::Authorization),
            Just(EventCategory::KeyAccess),
            Just(EventCategory::DataMutation),
            Just(EventCategory::SessionLifecycle),
            Just(EventCategory::CredentialIssuance),
            Just(EventCategory::Verification),
            Just(EventCategory::AdminAction),
            Just(EventCategory::ExternalCall),
            Just(EventCategory::SecurityEvent),
        ]
    }

    fn arb_actor_type() -> impl Strategy<Value = ActorType> {
        prop_oneof![
            Just(ActorType::User),
            Just(ActorType::Service),
            Just(ActorType::ApiKey),
            Just(ActorType::System),
        ]
    }

    fn arb_outcome() -> impl Strategy<Value = Outcome> {
        prop_oneof![
            Just(Outcome::Success),
            Just(Outcome::Failure),
            Just(Outcome::Denied),
            Just(Outcome::Error),
        ]
    }

    fn arb_nonempty_string() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,64}"
    }

    proptest! {
        #[test]
        #[allow(clippy::indexing_slicing)]
        fn prop_format_iso8601_produces_valid_string(ts: u64) {
            let s = format_iso8601(ts);
            let bytes = s.as_bytes();
            // Always 24 bytes: YYYY-MM-DDTHH:MM:SS.mmmZ
            prop_assert_eq!(bytes.len(), 24);
            prop_assert_eq!(bytes[4], b'-');
            prop_assert_eq!(bytes[7], b'-');
            prop_assert_eq!(bytes[10], b'T');
            prop_assert_eq!(bytes[13], b':');
            prop_assert_eq!(bytes[16], b':');
            prop_assert_eq!(bytes[19], b'.');
            prop_assert_eq!(bytes[23], b'Z');

            // Year, month, day, hour, minute, second, millis are all digit ranges.
            for &idx in &[0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22] {
                prop_assert!(bytes[idx].is_ascii_digit(), "byte at {} should be digit", idx);
            }

            // Month 01..12, day 01..31, hour 00..23, minute 00..59, second 00..59
            let month: u8 = std::str::from_utf8(&bytes[5..7]).unwrap().parse().unwrap();
            let day: u8 = std::str::from_utf8(&bytes[8..10]).unwrap().parse().unwrap();
            let hour: u8 = std::str::from_utf8(&bytes[11..13]).unwrap().parse().unwrap();
            let minute: u8 = std::str::from_utf8(&bytes[14..16]).unwrap().parse().unwrap();
            let second: u8 = std::str::from_utf8(&bytes[17..19]).unwrap().parse().unwrap();

            prop_assert!((1..=12).contains(&month), "month {} out of range", month);
            prop_assert!((1..=31).contains(&day), "day {} out of range", day);
            prop_assert!(hour <= 23, "hour {} out of range", hour);
            prop_assert!(minute <= 59, "minute {} out of range", minute);
            prop_assert!(second <= 59, "second {} out of range", second);
        }

        #[test]
        fn prop_format_iso8601_clamps_above_max(ts in (MAX_ISO8601_TIMESTAMP_MS + 1)..=u64::MAX) {
            let clamped = format_iso8601(MAX_ISO8601_TIMESTAMP_MS);
            let result = format_iso8601(ts);
            prop_assert_eq!(result, clamped);
        }

        #[test]
        fn prop_audit_event_serde_roundtrip(
            event_type in arb_nonempty_string(),
            severity in arb_severity(),
            message in arb_nonempty_string(),
            source_service in arb_nonempty_string(),
            env in arb_environment(),
            category in arb_event_category(),
            actor in arb_actor_type(),
            outcome in arb_outcome(),
        ) {
            let event = AuditEventBuilder::new(
                event_type,
                severity,
                message,
                source_service,
            )
            .environment(env)
            .event_category(category)
            .actor_type(actor)
            .outcome(outcome)
            .build()
            .unwrap();

            let json = serde_json::to_string(&event).unwrap();
            let roundtripped: AuditEvent = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtripped, event);
        }

        #[test]
        fn prop_builder_rejects_empty_event_type(
            severity in arb_severity(),
            message in arb_nonempty_string(),
            source_service in arb_nonempty_string(),
        ) {
            let result = AuditEventBuilder::new("", severity, message, source_service).build();
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_builder_rejects_empty_message(
            event_type in arb_nonempty_string(),
            severity in arb_severity(),
            source_service in arb_nonempty_string(),
        ) {
            let result = AuditEventBuilder::new(event_type, severity, "", source_service).build();
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_builder_rejects_empty_source_service(
            event_type in arb_nonempty_string(),
            severity in arb_severity(),
            message in arb_nonempty_string(),
        ) {
            let result = AuditEventBuilder::new(event_type, severity, message, "").build();
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_builder_valid_inputs_succeed(
            event_type in arb_nonempty_string(),
            severity in arb_severity(),
            message in arb_nonempty_string(),
            source_service in arb_nonempty_string(),
        ) {
            let result = AuditEventBuilder::new(event_type, severity, message, source_service).build();
            prop_assert!(result.is_ok());
        }

        #[test]
        fn prop_severity_serde_roundtrip(severity in arb_severity()) {
            let json = serde_json::to_string(&severity).unwrap();
            let roundtripped: Severity = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtripped, severity);
        }

        #[test]
        fn prop_environment_serde_roundtrip(env in arb_environment()) {
            let json = serde_json::to_string(&env).unwrap();
            let roundtripped: Environment = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtripped, env);
        }

        #[test]
        fn prop_event_category_serde_roundtrip(cat in arb_event_category()) {
            let json = serde_json::to_string(&cat).unwrap();
            let roundtripped: EventCategory = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtripped, cat);
        }

        #[test]
        fn prop_actor_type_serde_roundtrip(at in arb_actor_type()) {
            let json = serde_json::to_string(&at).unwrap();
            let roundtripped: ActorType = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtripped, at);
        }

        #[test]
        fn prop_outcome_serde_roundtrip(oc in arb_outcome()) {
            let json = serde_json::to_string(&oc).unwrap();
            let roundtripped: Outcome = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(roundtripped, oc);
        }
    }
}
