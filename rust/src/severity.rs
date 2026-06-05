// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Severity levels attached to every audit event.
//!
//! Serialises as `snake_case` for JSON output. The ordering derived on the
//! enum (`Info < Warning < Error < Critical`) lets callers filter by minimum
//! severity with a simple comparison.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity of a single audit log entry.
///
/// Variants are ordered from least to most severe. Serde serialises them as
/// `snake_case`: `"info"`, `"warning"`, `"error"`, `"critical"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    /// Normal operations. Nothing requires attention.
    Info,
    /// Unusual condition that is not yet harmful.
    Warning,
    /// An operation failed. Requires investigation.
    Error,
    /// Security violation or data integrity failure. Requires immediate action.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Severity {
    /// Returns the canonical lowercase string without allocating.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Parses a severity from a case-insensitive string, accepting common
    /// aliases that serde strict deserialisation would reject.
    ///
    /// Accepted aliases per level:
    ///
    /// | Level | Aliases |
    /// |---|---|
    /// | `Info` | `info`, `information`, `debug` (no separate debug level exists) |
    /// | `Warning` | `warning`, `warn` |
    /// | `Error` | `error`, `err` |
    /// | `Critical` | `critical`, `crit`, `fatal` |
    ///
    /// Returns `None` when the input does not match any known alias.
    #[cfg(test)]
    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" | "information" | "debug" => Some(Self::Info),
            "warning" | "warn" => Some(Self::Warning),
            "error" | "err" => Some(Self::Error),
            "critical" | "crit" | "fatal" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_as_snake_case() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), r#""info""#);
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            r#""warning""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            r#""error""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            r#""critical""#
        );
    }

    #[test]
    fn deserialises_from_snake_case() {
        assert_eq!(
            serde_json::from_str::<Severity>(r#""info""#).unwrap(),
            Severity::Info
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""critical""#).unwrap(),
            Severity::Critical
        );
    }

    #[test]
    fn display_matches_serde() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn deserialise_rejects_warn() {
        let result: Result<Severity, _> = serde_json::from_str("\"warn\"");
        assert!(result.is_err());
    }

    #[test]
    fn deserialise_rejects_debug() {
        let result: Result<Severity, _> = serde_json::from_str("\"debug\"");
        assert!(result.is_err());
    }

    #[test]
    fn deserialise_rejects_uppercase() {
        let result: Result<Severity, _> = serde_json::from_str("\"CRITICAL\"");
        assert!(result.is_err());
    }

    #[test]
    fn deserialise_rejects_mixed_case() {
        let result: Result<Severity, _> = serde_json::from_str("\"Info\"");
        assert!(result.is_err());
    }

    #[test]
    fn from_str_loose_handles_variants() {
        assert_eq!(Severity::from_str_loose("info"), Some(Severity::Info));
        assert_eq!(Severity::from_str_loose("INFO"), Some(Severity::Info));
        assert_eq!(Severity::from_str_loose("debug"), Some(Severity::Info));
        assert_eq!(Severity::from_str_loose("warn"), Some(Severity::Warning));
        assert_eq!(Severity::from_str_loose("err"), Some(Severity::Error));
        assert_eq!(Severity::from_str_loose("fatal"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_loose("unknown"), None);
    }
}
