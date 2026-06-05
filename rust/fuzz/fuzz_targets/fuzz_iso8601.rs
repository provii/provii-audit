// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Fuzzes the ISO 8601 formatting with arbitrary timestamp values.
//! Passes the fuzzed timestamp directly to format_iso8601 and verifies
//! structural invariants and numeric consistency on the output.

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_audit::event::AuditEventBuilder;
use provii_audit::{format_iso8601, Severity, MAX_ISO8601_TIMESTAMP_MS};

fuzz_target!(|ts: u64| {
    let output = format_iso8601(ts);

    // The effective timestamp after clamping.
    let effective = ts.min(MAX_ISO8601_TIMESTAMP_MS);

    // Structural invariants: exactly 24 bytes, fixed punctuation positions.
    assert_eq!(output.len(), 24);
    let b = output.as_bytes();
    assert_eq!(b[4], b'-');
    assert_eq!(b[7], b'-');
    assert_eq!(b[10], b'T');
    assert_eq!(b[13], b':');
    assert_eq!(b[16], b':');
    assert_eq!(b[19], b'.');
    assert_eq!(b[23], b'Z');

    // Parse numeric fields. Panics on non-digits (desired: catches malformed output).
    let year: u64 = output[0..4].parse().unwrap();
    let month: u64 = output[5..7].parse().unwrap();
    let day: u64 = output[8..10].parse().unwrap();
    let hours: u64 = output[11..13].parse().unwrap();
    let minutes: u64 = output[14..16].parse().unwrap();
    let seconds: u64 = output[17..19].parse().unwrap();
    let millis: u64 = output[20..23].parse().unwrap();

    // Value range checks.
    assert!(year >= 1970);
    assert!(year <= 9999);
    assert!((1..=12).contains(&month));
    assert!((1..=31).contains(&day));
    assert!(hours <= 23);
    assert!(minutes <= 59);
    assert!(seconds <= 59);
    assert!(millis <= 999);

    // Numeric consistency against effective (clamped) timestamp.
    assert_eq!(millis, effective % 1000);
    assert_eq!(seconds, (effective / 1000) % 60);
    assert_eq!(minutes, ((effective / 1000) % 3600) / 60);
    assert_eq!(hours, ((effective / 1000) % 86400) / 3600);

    // Builder path (retained, exercises full pipeline with system clock).
    let _ = AuditEventBuilder::new("fuzz", Severity::Info, "fuzz-msg", "fuzz-svc").build();
});
