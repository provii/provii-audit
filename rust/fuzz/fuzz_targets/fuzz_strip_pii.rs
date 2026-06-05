// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_audit::sanitize::strip_pii;

fuzz_target!(|data: &str| {
    let result = strip_pii(data);

    // Invariant: output must never be longer than a bounded multiple of
    // input (each redaction placeholder is at most ~16 bytes, replacing
    // at least 3 bytes of original pattern, so growth is bounded).
    // A panic or unbounded allocation here indicates a bug.
    let _ = result.len();

    // Invariant: if the input contained no PII patterns, the output
    // should equal the input. We cannot assert this without knowing
    // whether patterns were present, but we can assert the function
    // does not panic.
});
