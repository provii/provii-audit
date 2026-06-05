// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use provii_audit::sanitize::{validate_append_fields, validate_secondary_fields};

#[derive(Arbitrary, Debug)]
struct ValidateInput<'a> {
    event_type: &'a str,
    severity: &'a str,
    message: &'a str,
    details: Option<&'a str>,
    client_ip: &'a str,
    origin: &'a str,
    user_agent: &'a str,
    challenge_id: &'a str,
}

fuzz_target!(|input: ValidateInput| {
    match validate_append_fields(
        input.event_type,
        input.severity,
        input.message,
        input.details,
    ) {
        Ok(()) => {
            // If validation passed, the fields must satisfy all documented
            // invariants enforced by validate_append_fields.
            assert!(
                !input.event_type.is_empty(),
                "Ok result but event_type is empty"
            );
            assert!(
                !input.event_type.starts_with("[TOMBSTONE:"),
                "Ok result but event_type has reserved tombstone prefix"
            );
            assert!(
                input.event_type.len() <= 128,
                "Ok result but event_type exceeds 128 bytes: {}",
                input.event_type.len()
            );
            assert!(
                input.severity.len() <= 64,
                "Ok result but severity exceeds 64 bytes: {}",
                input.severity.len()
            );
            assert!(
                input.message.len() <= 2048,
                "Ok result but message exceeds 2048 bytes: {}",
                input.message.len()
            );
            if let Some(d) = input.details {
                assert!(
                    d.len() <= 16384,
                    "Ok result but details exceeds 16384 bytes: {}",
                    d.len()
                );
            }
        }
        Err(_) => {
            // Err is the expected path for invalid input. cargo-fuzz
            // catches panics; the value of this target is the Ok arm.
        }
    }

    match validate_secondary_fields(
        input.client_ip,
        input.origin,
        input.user_agent,
        input.challenge_id,
    ) {
        Ok(()) => {
            // All four fields must be within the 8192-byte limit.
            assert!(
                input.client_ip.len() <= 8192,
                "Ok result but client_ip exceeds 8192 bytes: {}",
                input.client_ip.len()
            );
            assert!(
                input.origin.len() <= 8192,
                "Ok result but origin exceeds 8192 bytes: {}",
                input.origin.len()
            );
            assert!(
                input.user_agent.len() <= 8192,
                "Ok result but user_agent exceeds 8192 bytes: {}",
                input.user_agent.len()
            );
            assert!(
                input.challenge_id.len() <= 8192,
                "Ok result but challenge_id exceeds 8192 bytes: {}",
                input.challenge_id.len()
            );
        }
        Err(_) => {
            // Err is the expected path for invalid input.
        }
    }
});
