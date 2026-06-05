// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_audit::AuditEvent;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialise arbitrary bytes as an AuditEvent.
    // Must never panic, regardless of input shape.
    if let Ok(event) = serde_json::from_slice::<AuditEvent>(data) {
        // Roundtrip: serialise back and re-deserialise.
        // Both directions must succeed without panic.
        if let Ok(json) = serde_json::to_vec(&event) {
            if let Ok(roundtripped) = serde_json::from_slice::<AuditEvent>(&json) {
                assert_eq!(event, roundtripped, "Serde roundtrip produced different event");
            }
        }
    }
});
