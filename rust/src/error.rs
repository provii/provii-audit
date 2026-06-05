// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error types returned by audit logging operations.
//!
//! Every fallible function in this crate returns [`AuditError`]. The variants
//! map one-to-one with the failure domains: HMAC key construction, privacy
//! salt validation, serialisation, input validation, and queue dispatch.
//!
//! Structured variants carry typed context fields so callers can inspect
//! specific failure conditions without parsing display strings.

#![forbid(unsafe_code)]

/// Errors that can occur during audit logging.
///
/// # Security
///
/// The `Display` implementation echoes context strings verbatim. Callers
/// MUST NOT embed secret material (keys, tokens, salts, PII) in the context
/// string. These messages surface in console output, Grafana log drains,
/// Sentry breadcrumbs, and error HTTP responses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// HMAC key construction failed due to invalid length or format.
    #[error("HMAC key error: {context}")]
    HmacKeyError {
        /// Freeform description of the failure site.
        context: String,
    },

    /// Privacy salt is shorter than the required minimum.
    #[error("Privacy salt too short: expected at least {minimum} bytes, got {actual}")]
    PrivacySaltTooShort {
        /// Required minimum salt length in bytes.
        minimum: usize,
        /// Actual salt length supplied.
        actual: usize,
    },

    /// Privacy salt consists entirely of zero bytes.
    #[error("Privacy salt must not be all zeros")]
    PrivacySaltAllZeros,

    /// JSON serialisation or deserialisation failed.
    #[error("Serialisation error: {context}")]
    SerialisationError {
        /// Freeform description of where serialisation failed.
        context: String,
    },

    /// Input validation rejected a caller-supplied value.
    #[error("Validation error on field '{field}': {reason}")]
    FieldValidationError {
        /// Name of the field that failed validation.
        field: String,
        /// Why validation was rejected.
        reason: String,
    },

    /// Input validation rejected a caller-supplied value (unstructured).
    ///
    /// Prefer [`FieldValidationError`](Self::FieldValidationError) when the
    /// failing field name is known.
    #[error("Validation error: {context}")]
    ValidationError {
        /// Freeform description of the validation failure.
        context: String,
    },

    /// Cloudflare Queue dispatch failed. The event was not enqueued.
    #[error("Queue error: {context}")]
    QueueError {
        /// Freeform description of the queue dispatch failure.
        context: String,
    },
}

// ---------------------------------------------------------------------------
// Convenience constructors for internal use.
// Some are only referenced in wasm32 or test builds, which causes dead_code
// warnings on native library checks. Suppressed here because the full set
// is exercised across all target configurations.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
impl AuditError {
    /// Create an [`HmacKeyError`](Self::HmacKeyError) with context.
    pub(crate) fn hmac_key(context: impl Into<String>) -> Self {
        Self::HmacKeyError {
            context: context.into(),
        }
    }

    /// Create a [`SerialisationError`](Self::SerialisationError) with context.
    pub(crate) fn serialisation(context: impl Into<String>) -> Self {
        Self::SerialisationError {
            context: context.into(),
        }
    }

    /// Create a [`ValidationError`](Self::ValidationError) with context.
    pub(crate) fn validation(context: impl Into<String>) -> Self {
        Self::ValidationError {
            context: context.into(),
        }
    }

    /// Create a [`FieldValidationError`](Self::FieldValidationError).
    pub(crate) fn field_validation(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::FieldValidationError {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Create a [`QueueError`](Self::QueueError) with context.
    pub(crate) fn queue(context: impl Into<String>) -> Self {
        Self::QueueError {
            context: context.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_key_error_display() {
        let err = AuditError::hmac_key("invalid length");
        assert_eq!(err.to_string(), "HMAC key error: invalid length");
    }

    #[test]
    fn hmac_key_error_equality() {
        let a = AuditError::hmac_key("ctx");
        let b = AuditError::HmacKeyError {
            context: "ctx".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn privacy_salt_too_short_display() {
        let err = AuditError::PrivacySaltTooShort {
            minimum: 32,
            actual: 16,
        };
        assert_eq!(
            err.to_string(),
            "Privacy salt too short: expected at least 32 bytes, got 16"
        );
    }

    #[test]
    fn privacy_salt_all_zeros_display() {
        let err = AuditError::PrivacySaltAllZeros;
        assert_eq!(err.to_string(), "Privacy salt must not be all zeros");
    }

    #[test]
    fn serialisation_error_display() {
        let err = AuditError::serialisation("unexpected EOF");
        assert_eq!(err.to_string(), "Serialisation error: unexpected EOF");
    }

    #[test]
    fn validation_error_display() {
        let err = AuditError::validation("RNG failed: entropy exhausted");
        assert_eq!(
            err.to_string(),
            "Validation error: RNG failed: entropy exhausted"
        );
    }

    #[test]
    fn field_validation_error_display() {
        let err = AuditError::field_validation("event_type", "must not be empty");
        assert_eq!(
            err.to_string(),
            "Validation error on field 'event_type': must not be empty"
        );
    }

    #[test]
    fn queue_error_display() {
        let err = AuditError::queue("send timed out");
        assert_eq!(err.to_string(), "Queue error: send timed out");
    }

    #[test]
    fn error_clone_preserves_variant() {
        let original = AuditError::field_validation("field", "reason");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn error_debug_contains_variant_name() {
        let err = AuditError::hmac_key("test");
        let debug = format!("{err:?}");
        assert!(
            debug.contains("HmacKeyError"),
            "Debug should contain variant name, got: {debug}"
        );
    }
}
