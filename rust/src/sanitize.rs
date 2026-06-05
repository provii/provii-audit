// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Input validation and PII stripping for audit log entries.
//!
//! Field length validation enforces upper bounds on all append request fields
//! before they reach the queue sink. PII pattern redaction is a best-effort
//! defence-in-depth pass that replaces IP addresses, email addresses, and
//! date-of-birth patterns in free-text fields with `[REDACTED_*]` placeholders.
//!
//! PII hashing (IP, User-Agent) is handled separately in [`crate::privacy`].

#![forbid(unsafe_code)]

use crate::error::AuditError;

/// Maximum length for a single secondary field value in bytes.
pub(crate) const MAX_FIELD_LENGTH: usize = 8192;

/// Maximum length for the details JSON field in bytes.
pub(crate) const MAX_DETAILS_LENGTH: usize = 16384;

/// Maximum length for the severity field.
///
/// The longest valid canonical value is "critical" (8 bytes). This limit is
/// generous but prevents processing a megabyte-sized severity string.
pub(crate) const MAX_SEVERITY_LENGTH: usize = 64;

/// Maximum length for the event type field.
pub(crate) const MAX_EVENT_TYPE_LENGTH: usize = 128;

/// Lower bound (inclusive) for the year component of date-of-birth patterns.
///
/// Dates with a year below this are unlikely to be birth dates and are left
/// unredacted to reduce false positives on historical dates.
pub(crate) const DOB_YEAR_LOWER: u16 = 1920;

/// Upper bound (inclusive) for the year component of date-of-birth patterns.
///
/// Set to 2013 so that individuals born in 2013 (aged 13 in 2026) are covered.
/// Dates with a year above this are left unredacted to avoid false positives on
/// recent event timestamps, release dates, and version dates.
pub(crate) const DOB_YEAR_UPPER: u16 = 2013;

/// Maximum length for the message field.
pub(crate) const MAX_MESSAGE_LENGTH: usize = 2048;

/// Validates and sanitises the primary fields of an append request.
///
/// Called before queue dispatch. Checks `event_type`, `severity`, `message`,
/// and optionally `details` against their respective byte-length limits. Also
/// rejects empty event types and the reserved `[TOMBSTONE:` prefix used by
/// the erasure subsystem.
///
/// # Errors
///
/// Returns [`AuditError::ValidationError`] if any field is empty where required,
/// uses a reserved prefix, or exceeds its length limit.
pub fn validate_append_fields(
    event_type: &str,
    severity: &str,
    message: &str,
    details: Option<&str>,
) -> Result<(), AuditError> {
    if event_type.is_empty() {
        return Err(AuditError::field_validation(
            "event_type",
            "must not be empty",
        ));
    }
    if event_type.starts_with("[TOMBSTONE:") {
        return Err(AuditError::field_validation(
            "event_type",
            "must not use reserved tombstone prefix",
        ));
    }
    if event_type.len() > MAX_EVENT_TYPE_LENGTH {
        return Err(AuditError::field_validation(
            "event_type",
            format!("exceeds {MAX_EVENT_TYPE_LENGTH} byte limit"),
        ));
    }
    if severity.len() > MAX_SEVERITY_LENGTH {
        return Err(AuditError::field_validation(
            "severity",
            format!("exceeds {MAX_SEVERITY_LENGTH} byte limit"),
        ));
    }
    if message.len() > MAX_MESSAGE_LENGTH {
        return Err(AuditError::field_validation(
            "message",
            format!("exceeds {MAX_MESSAGE_LENGTH} byte limit"),
        ));
    }
    if let Some(d) = details {
        if d.len() > MAX_DETAILS_LENGTH {
            return Err(AuditError::field_validation(
                "details",
                format!("exceeds {MAX_DETAILS_LENGTH} byte limit"),
            ));
        }
    }
    Ok(())
}

/// Validates secondary field lengths for an append request.
///
/// Called after deserialisation in the consumer worker. Rejects oversized
/// `client_ip`, `origin`, `user_agent`, and `challenge_id` fields. These
/// share a uniform 8,192-byte limit and are validated separately from the
/// primary fields handled by [`validate_append_fields`].
///
/// # Errors
///
/// Returns [`AuditError::ValidationError`] if any field exceeds the limit.
pub fn validate_secondary_fields(
    client_ip: &str,
    origin: &str,
    user_agent: &str,
    challenge_id: &str,
) -> Result<(), AuditError> {
    for (name, value) in [
        ("client_ip", client_ip),
        ("origin", origin),
        ("user_agent", user_agent),
        ("challenge_id", challenge_id),
    ] {
        if value.len() > MAX_FIELD_LENGTH {
            return Err(AuditError::field_validation(
                name,
                format!("exceeds {MAX_FIELD_LENGTH} byte limit"),
            ));
        }
    }
    Ok(())
}

/// Redaction placeholder for stripped IP addresses.
const REDACTED_IP: &str = "[REDACTED_IP]";

/// Redaction placeholder for stripped email addresses.
const REDACTED_EMAIL: &str = "[REDACTED_EMAIL]";

/// Redaction placeholder for stripped date-of-birth patterns.
const REDACTED_DOB: &str = "[REDACTED_DOB]";

/// Strips PII patterns from a free-text field.
///
/// Scans the input and replaces recognised patterns with redaction placeholders:
///
/// - IPv4 addresses (e.g. `192.168.1.1`) become `[REDACTED_IP]`
/// - IPv6 addresses (e.g. `2001:db8::1`, `::1`, `::ffff:192.168.1.1`) become `[REDACTED_IP]`
/// - Email addresses (e.g. `user@example.com`) become `[REDACTED_EMAIL]`
/// - Date-of-birth patterns (`YYYY-MM-DD`, `DD/MM/YYYY`, `MM/DD/YYYY`, `DD.MM.YYYY`, years 1920-2013) become `[REDACTED_DOB]`
///
/// This is a best-effort defence-in-depth measure. Callers should avoid placing
/// PII into `message` and `details` fields in the first place.
#[must_use]
pub fn strip_pii(input: &str) -> String {
    // IPv6 must run before IPv4 so that IPv4-mapped addresses like
    // ::ffff:192.168.1.1 are matched as a single IPv6 address rather
    // than having their embedded IPv4 portion stripped first.
    let mut result = strip_ipv6(input);
    result = strip_ipv4(&result);
    result = strip_emails(&result);
    result = strip_dob_patterns(&result);
    result
}

/// Replaces IPv4 address patterns (four dot-separated octets, each 0-255).
fn strip_ipv4(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i: usize = 0;

    while i < len {
        if let Some((end, valid)) = try_parse_ipv4(bytes, i) {
            if valid {
                let before_ok = i == 0
                    || !bytes
                        .get(i.wrapping_sub(1))
                        .copied()
                        .is_some_and(is_ipv4_adjacent);
                let after_ok = end >= len || !bytes.get(end).copied().is_some_and(is_ipv4_adjacent);
                if before_ok && after_ok {
                    result.push_str(REDACTED_IP);
                    // max(i + 1) guarantees forward progress: a redaction must
                    // consume at least one byte, so the loop can never spin in
                    // place even if the parser returns a non-advancing end.
                    i = end.max(i.wrapping_add(1));
                    continue;
                }
            }
        }
        // Advance one UTF-8 character at a time.
        if let Some(ch) = input.get(i..).and_then(|s| s.chars().next()) {
            result.push(ch);
            i = i.wrapping_add(ch.len_utf8());
        } else {
            i = i.wrapping_add(1);
        }
    }

    result
}

/// Returns `true` if the byte would make an IPv4 match part of a larger token
/// (e.g. version strings like `1.2.3.4.5`).
const fn is_ipv4_adjacent(b: u8) -> bool {
    b.is_ascii_digit() || b == b'.'
}

/// Attempts to parse an IPv4 address starting at `start`.
///
/// Returns `(end_position, is_valid)` on a structural match, or `None` if the
/// bytes at `start` do not resemble an IPv4 address at all.
fn try_parse_ipv4(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    let mut pos = start;
    let mut octets = 0u8;

    while octets < 4 {
        let octet_start = pos;
        while pos < bytes.len() && bytes.get(pos).copied().is_some_and(|b| b.is_ascii_digit()) {
            pos = pos.wrapping_add(1);
        }
        let digit_count = pos.wrapping_sub(octet_start);
        if digit_count == 0 || digit_count > 3 {
            return None;
        }
        let octet_str = std::str::from_utf8(bytes.get(octet_start..pos)?).ok()?;
        let val: u16 = octet_str.parse().ok()?;
        if val > 255 {
            return None;
        }
        octets = octets.wrapping_add(1);
        if octets < 4 {
            if pos >= bytes.len() || bytes.get(pos).copied() != Some(b'.') {
                return None;
            }
            pos = pos.wrapping_add(1);
        }
    }

    Some((pos, octets == 4))
}

/// Replaces IPv6 address patterns.
///
/// Matches sequences of hex groups separated by colons, including compressed
/// forms (`::`) and mixed IPv4-mapped addresses. Requires at least two colons
/// to reduce false positives on timestamps and other colon-delimited values.
fn strip_ipv6(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i: usize = 0;

    while i < len {
        if let Some(end) = try_parse_ipv6(bytes, i) {
            let segment = input.get(i..end).unwrap_or("");
            let colon_count = segment.bytes().filter(|&b| b == b':').count();
            if colon_count >= 2 {
                let before_ok = i == 0
                    || !bytes
                        .get(i.wrapping_sub(1))
                        .copied()
                        .is_some_and(|b| b.is_ascii_hexdigit() || b == b':');
                let after_ok = end >= len
                    || !bytes
                        .get(end)
                        .copied()
                        .is_some_and(|b| b.is_ascii_hexdigit() || b == b':');
                if before_ok && after_ok {
                    result.push_str(REDACTED_IP);
                    // max(i + 1) guarantees forward progress: a redaction must
                    // consume at least one byte, so the loop can never spin in
                    // place even if the parser returns a non-advancing end.
                    i = end.max(i.wrapping_add(1));
                    continue;
                }
            }
        }
        if let Some(ch) = input.get(i..).and_then(|s| s.chars().next()) {
            result.push(ch);
            i = i.wrapping_add(ch.len_utf8());
        } else {
            i = i.wrapping_add(1);
        }
    }

    result
}

/// Attempts to parse an IPv6 address starting at `start`.
///
/// Returns the end position on a structural match (at least one hex group or
/// `::` prefix), or `None` if no IPv6 pattern is found.
fn try_parse_ipv6(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut groups: u8 = 0;
    let mut saw_double_colon = false;

    // Handle leading ::
    if bytes.get(pos).copied() == Some(b':')
        && bytes.get(pos.wrapping_add(1)).copied() == Some(b':')
    {
        saw_double_colon = true;
        pos = pos.wrapping_add(2);
        if pos >= bytes.len()
            || !bytes
                .get(pos)
                .copied()
                .is_some_and(|b| b.is_ascii_hexdigit())
        {
            return Some(pos);
        }
    }

    loop {
        let group_start = pos;
        let mut digit_count: u8 = 0;
        while pos < bytes.len()
            && digit_count < 4
            && bytes
                .get(pos)
                .copied()
                .is_some_and(|b| b.is_ascii_hexdigit())
        {
            pos = pos.wrapping_add(1);
            digit_count = digit_count.wrapping_add(1);
        }

        if digit_count == 0 {
            break;
        }
        groups = groups.wrapping_add(1);

        // Check for an IPv4 suffix (e.g. ::ffff:192.168.1.1)
        if bytes.get(pos).copied() == Some(b'.') && digit_count <= 3 {
            if let Some((ipv4_end, true)) = try_parse_ipv4(bytes, group_start) {
                return Some(ipv4_end);
            }
        }

        if bytes.get(pos).copied() != Some(b':') {
            break;
        }

        // Double colon
        if bytes.get(pos.wrapping_add(1)).copied() == Some(b':') {
            if saw_double_colon {
                break;
            }
            saw_double_colon = true;
            pos = pos.wrapping_add(2);
            if pos >= bytes.len()
                || !bytes
                    .get(pos)
                    .copied()
                    .is_some_and(|b| b.is_ascii_hexdigit())
            {
                break;
            }
        } else {
            pos = pos.wrapping_add(1);
            if pos >= bytes.len()
                || !bytes
                    .get(pos)
                    .copied()
                    .is_some_and(|b| b.is_ascii_hexdigit())
            {
                // Trailing colon with no following hex group; back up.
                pos = pos.wrapping_sub(1);
                break;
            }
        }

        if groups >= 8 {
            break;
        }
    }

    if groups >= 1 || saw_double_colon {
        Some(pos)
    } else {
        None
    }
}

/// Replaces email address patterns.
///
/// Matches `local@domain.tld` where the local part is
/// `[a-zA-Z0-9._%+-]+` and the domain is `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`.
fn strip_emails(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i: usize = 0;

    while i < len {
        if bytes.get(i).copied() == Some(b'@') {
            let local_start = scan_email_local_back(bytes, i);
            if let Some(domain_end) = scan_email_domain_forward(bytes, i.wrapping_add(1)) {
                if local_start < i {
                    // Remove local-part characters already appended to result.
                    let local_len = i.wrapping_sub(local_start);
                    for _ in 0..local_len {
                        result.pop();
                    }
                    result.push_str(REDACTED_EMAIL);
                    // max(i + 1) guarantees forward progress (see strip_ipv4).
                    i = domain_end.max(i.wrapping_add(1));
                    continue;
                }
            }
        }
        if let Some(ch) = input.get(i..).and_then(|s| s.chars().next()) {
            result.push(ch);
            i = i.wrapping_add(ch.len_utf8());
        } else {
            i = i.wrapping_add(1);
        }
    }

    result
}

/// Returns `true` if the byte is valid in an email local part.
const fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'%' || b == b'+' || b == b'-'
}

/// Scans backwards from `at_pos` to find the start of the email local part.
fn scan_email_local_back(bytes: &[u8], at_pos: usize) -> usize {
    let mut pos = at_pos;
    while pos > 0
        && bytes
            .get(pos.wrapping_sub(1))
            .copied()
            .is_some_and(is_email_local_char)
    {
        pos = pos.wrapping_sub(1);
    }
    pos
}

/// Scans forward from the byte after `@` to find the end of the email domain.
///
/// Returns `Some(end)` if a valid domain with a TLD of at least two alphabetic
/// characters is found, or `None` otherwise.
fn scan_email_domain_forward(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut saw_dot = false;
    let mut last_dot_pos: usize = 0;

    while pos < bytes.len() {
        let b = bytes.get(pos).copied()?;
        if b.is_ascii_alphanumeric() || b == b'-' {
            pos = pos.wrapping_add(1);
        } else if b == b'.' {
            saw_dot = true;
            last_dot_pos = pos;
            pos = pos.wrapping_add(1);
        } else {
            break;
        }
    }

    if !saw_dot {
        return None;
    }

    // TLD must be at least 2 alphabetic characters after the last dot.
    let tld_len = pos.wrapping_sub(last_dot_pos.wrapping_add(1));
    if tld_len < 2 {
        return None;
    }
    for j in (last_dot_pos.wrapping_add(1))..pos {
        if !bytes
            .get(j)
            .copied()
            .is_some_and(|b| b.is_ascii_alphabetic())
        {
            return None;
        }
    }

    Some(pos)
}

/// Replaces date-of-birth patterns with `[REDACTED_DOB]`.
///
/// Recognised formats (years 1920 through 2013 only):
///
/// - `YYYY-MM-DD` (ISO 8601 date, not followed by a time separator)
/// - `DD/MM/YYYY` (AU/UK)
/// - `MM/DD/YYYY` (US)
/// - `DD.MM.YYYY` (European dot-delimited, not `YYYY.MM.DD` to avoid version string collisions)
///
/// The year range is narrowed to plausible birth dates to avoid false
/// positives on recent event timestamps, release dates, and version dates.
/// Dates followed by `T` or ` HH:` are excluded as they indicate timestamps.
///
/// Only matches when the pattern is word-bounded, not embedded in a longer
/// number or identifier.
fn strip_dob_patterns(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i: usize = 0;

    while i < len {
        let b = bytes.get(i).copied().unwrap_or(0);

        if b.is_ascii_digit() {
            // Try YYYY-MM-DD first.
            if let Some(end) = try_parse_iso_date(bytes, i) {
                let before_ok = i == 0
                    || !bytes
                        .get(i.wrapping_sub(1))
                        .copied()
                        .is_some_and(|b| b.is_ascii_alphanumeric());
                let after_ok = end >= len
                    || !bytes
                        .get(end)
                        .copied()
                        .is_some_and(|b| b.is_ascii_alphanumeric());
                if before_ok && after_ok {
                    result.push_str(REDACTED_DOB);
                    // max(i + 1) guarantees forward progress: a redaction must
                    // consume at least one byte, so the loop can never spin in
                    // place even if the parser returns a non-advancing end.
                    i = end.max(i.wrapping_add(1));
                    continue;
                }
            }
            // Try DD/MM/YYYY or MM/DD/YYYY.
            if let Some(end) = try_parse_slash_date(bytes, i) {
                let before_ok = i == 0
                    || !bytes
                        .get(i.wrapping_sub(1))
                        .copied()
                        .is_some_and(|b| b.is_ascii_alphanumeric());
                let after_ok = end >= len
                    || !bytes
                        .get(end)
                        .copied()
                        .is_some_and(|b| b.is_ascii_alphanumeric());
                if before_ok && after_ok {
                    result.push_str(REDACTED_DOB);
                    // max(i + 1) guarantees forward progress: a redaction must
                    // consume at least one byte, so the loop can never spin in
                    // place even if the parser returns a non-advancing end.
                    i = end.max(i.wrapping_add(1));
                    continue;
                }
            }
            // Try DD.MM.YYYY (European dot-delimited).
            if let Some(end) = try_parse_dot_date(bytes, i) {
                let before_ok = i == 0
                    || !bytes
                        .get(i.wrapping_sub(1))
                        .copied()
                        .is_some_and(|b| b.is_ascii_alphanumeric());
                let after_ok = end >= len
                    || !bytes
                        .get(end)
                        .copied()
                        .is_some_and(|b| b.is_ascii_alphanumeric());
                if before_ok && after_ok {
                    result.push_str(REDACTED_DOB);
                    // max(i + 1) guarantees forward progress: a redaction must
                    // consume at least one byte, so the loop can never spin in
                    // place even if the parser returns a non-advancing end.
                    i = end.max(i.wrapping_add(1));
                    continue;
                }
            }
        }

        if let Some(ch) = input.get(i..).and_then(|s| s.chars().next()) {
            result.push(ch);
            i = i.wrapping_add(ch.len_utf8());
        } else {
            i = i.wrapping_add(1);
        }
    }

    result
}

/// Attempts to parse a date-of-birth in `YYYY-MM-DD` format at `start`.
///
/// Year is restricted to [`DOB_YEAR_LOWER`] through [`DOB_YEAR_UPPER`] to
/// target plausible birth dates and avoid false positives on recent event
/// timestamps, release dates, and version dates. Dates followed by a time
/// separator (`T` or ` HH:`) are rejected as they indicate ISO 8601 or log
/// timestamps rather than DOBs.
fn try_parse_iso_date(bytes: &[u8], start: usize) -> Option<usize> {
    if start.wrapping_add(10) > bytes.len() {
        return None;
    }
    let segment = bytes.get(start..start.wrapping_add(10))?;

    if !segment.first()?.is_ascii_digit()
        || !segment.get(1)?.is_ascii_digit()
        || !segment.get(2)?.is_ascii_digit()
        || !segment.get(3)?.is_ascii_digit()
        || *segment.get(4)? != b'-'
        || !segment.get(5)?.is_ascii_digit()
        || !segment.get(6)?.is_ascii_digit()
        || *segment.get(7)? != b'-'
        || !segment.get(8)?.is_ascii_digit()
        || !segment.get(9)?.is_ascii_digit()
    {
        return None;
    }

    let year_str = std::str::from_utf8(segment.get(0..4)?).ok()?;
    let month_str = std::str::from_utf8(segment.get(5..7)?).ok()?;
    let day_str = std::str::from_utf8(segment.get(8..10)?).ok()?;

    let year: u16 = year_str.parse().ok()?;
    let month: u8 = month_str.parse().ok()?;
    let day: u8 = day_str.parse().ok()?;

    // Restrict to plausible DOB range. Dates outside this range are far
    // more likely to be event timestamps, release dates, or version dates.
    if !(DOB_YEAR_LOWER..=DOB_YEAR_UPPER).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }

    let end = start.wrapping_add(10);

    // Reject if followed by a time separator, indicating a timestamp.
    // Covers `YYYY-MM-DDT...` (ISO 8601) and `YYYY-MM-DD HH:` (log timestamps).
    if let Some(&next_byte) = bytes.get(end) {
        if next_byte == b'T' {
            return None;
        }
        if next_byte == b' ' {
            // Check for ` HH:` pattern (space, digit, digit, colon).
            if bytes
                .get(end.wrapping_add(1))
                .copied()
                .is_some_and(|b| b.is_ascii_digit())
                && bytes
                    .get(end.wrapping_add(2))
                    .copied()
                    .is_some_and(|b| b.is_ascii_digit())
                && bytes.get(end.wrapping_add(3)).copied() == Some(b':')
            {
                return None;
            }
        }
    }

    Some(end)
}

/// Attempts to parse `DD/MM/YYYY` or `MM/DD/YYYY` at `start`.
///
/// Year is restricted to [`DOB_YEAR_LOWER`] through [`DOB_YEAR_UPPER`] to
/// match plausible birth dates, consistent with the ISO date parser.
fn try_parse_slash_date(bytes: &[u8], start: usize) -> Option<usize> {
    if start.wrapping_add(10) > bytes.len() {
        return None;
    }
    let segment = bytes.get(start..start.wrapping_add(10))?;

    if !segment.first()?.is_ascii_digit()
        || !segment.get(1)?.is_ascii_digit()
        || *segment.get(2)? != b'/'
        || !segment.get(3)?.is_ascii_digit()
        || !segment.get(4)?.is_ascii_digit()
        || *segment.get(5)? != b'/'
        || !segment.get(6)?.is_ascii_digit()
        || !segment.get(7)?.is_ascii_digit()
        || !segment.get(8)?.is_ascii_digit()
        || !segment.get(9)?.is_ascii_digit()
    {
        return None;
    }

    let first_str = std::str::from_utf8(segment.get(0..2)?).ok()?;
    let second_str = std::str::from_utf8(segment.get(3..5)?).ok()?;
    let year_str = std::str::from_utf8(segment.get(6..10)?).ok()?;

    let first: u8 = first_str.parse().ok()?;
    let second: u8 = second_str.parse().ok()?;
    let year: u16 = year_str.parse().ok()?;

    if !(DOB_YEAR_LOWER..=DOB_YEAR_UPPER).contains(&year) {
        return None;
    }

    // Accept as DD/MM/YYYY (day 1-31, month 1-12)
    // or MM/DD/YYYY (month 1-12, day 1-31).
    let is_dmy = (1..=31).contains(&first) && (1..=12).contains(&second);
    let is_mdy = (1..=12).contains(&first) && (1..=31).contains(&second);

    if is_dmy || is_mdy {
        Some(start.wrapping_add(10))
    } else {
        None
    }
}

/// Attempts to parse `DD.MM.YYYY` (European dot-delimited) at `start`.
///
/// Only the `DD.MM.YYYY` order is recognised. The reverse `YYYY.MM.DD` format
/// is deliberately excluded because it collides too aggressively with version
/// strings (e.g. `2001.01.15`).
///
/// Year is restricted to [`DOB_YEAR_LOWER`] through [`DOB_YEAR_UPPER`].
/// Dates followed by a time separator (`T` or ` HH:`) are rejected as
/// timestamps, matching the behaviour of [`try_parse_iso_date`].
fn try_parse_dot_date(bytes: &[u8], start: usize) -> Option<usize> {
    if start.wrapping_add(10) > bytes.len() {
        return None;
    }
    let segment = bytes.get(start..start.wrapping_add(10))?;

    // Expect DD.MM.YYYY layout.
    if !segment.first()?.is_ascii_digit()
        || !segment.get(1)?.is_ascii_digit()
        || *segment.get(2)? != b'.'
        || !segment.get(3)?.is_ascii_digit()
        || !segment.get(4)?.is_ascii_digit()
        || *segment.get(5)? != b'.'
        || !segment.get(6)?.is_ascii_digit()
        || !segment.get(7)?.is_ascii_digit()
        || !segment.get(8)?.is_ascii_digit()
        || !segment.get(9)?.is_ascii_digit()
    {
        return None;
    }

    let day_str = std::str::from_utf8(segment.get(0..2)?).ok()?;
    let month_str = std::str::from_utf8(segment.get(3..5)?).ok()?;
    let year_str = std::str::from_utf8(segment.get(6..10)?).ok()?;

    let day: u8 = day_str.parse().ok()?;
    let month: u8 = month_str.parse().ok()?;
    let year: u16 = year_str.parse().ok()?;

    if !(DOB_YEAR_LOWER..=DOB_YEAR_UPPER).contains(&year) {
        return None;
    }

    if !(1..=31).contains(&day) || !(1..=12).contains(&month) {
        return None;
    }

    let end = start.wrapping_add(10);

    // Reject if followed by a time separator, indicating a timestamp.
    if let Some(&next_byte) = bytes.get(end) {
        if next_byte == b'T' {
            return None;
        }
        if next_byte == b' '
            && bytes
                .get(end.wrapping_add(1))
                .copied()
                .is_some_and(|b| b.is_ascii_digit())
            && bytes
                .get(end.wrapping_add(2))
                .copied()
                .is_some_and(|b| b.is_ascii_digit())
            && bytes.get(end.wrapping_add(3)).copied() == Some(b':')
        {
            return None;
        }
    }

    Some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty_event_type() {
        let result = validate_append_fields("", "info", "msg", None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_long_event_type() {
        let long = "x".repeat(MAX_EVENT_TYPE_LENGTH + 1);
        let result = validate_append_fields(&long, "info", "msg", None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_long_message() {
        let long = "x".repeat(MAX_MESSAGE_LENGTH + 1);
        let result = validate_append_fields("event", "info", &long, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_long_details() {
        let long = "x".repeat(MAX_DETAILS_LENGTH + 1);
        let result = validate_append_fields("event", "info", "msg", Some(&long));
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_tombstone_prefix() {
        let result = validate_append_fields("[TOMBSTONE:GDPR_ERASURE]", "info", "msg", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("reserved tombstone prefix"),
            "expected tombstone prefix error, got: {err}"
        );

        let result2 = validate_append_fields("[TOMBSTONE:ANYTHING]", "info", "msg", None);
        assert!(result2.is_err());
    }

    #[test]
    fn validate_accepts_valid_input() {
        let result = validate_append_fields("test_event", "info", "Test message", Some("{}"));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_secondary_rejects_oversized_client_ip() {
        let big = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = validate_secondary_fields(&big, "", "", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("client_ip"));
    }

    #[test]
    fn validate_secondary_rejects_oversized_origin() {
        let big = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = validate_secondary_fields("", &big, "", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("origin"));
    }

    #[test]
    fn validate_secondary_rejects_oversized_user_agent() {
        let big = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = validate_secondary_fields("", "", &big, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("user_agent"));
    }

    #[test]
    fn validate_secondary_rejects_oversized_challenge_id() {
        let big = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = validate_secondary_fields("", "", "", &big);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("challenge_id"));
    }

    #[test]
    fn validate_secondary_accepts_valid_fields() {
        let result = validate_secondary_fields(
            "192.168.1.1",
            "https://example.com",
            "Mozilla/5.0",
            "challenge-123",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_secondary_accepts_at_limit() {
        let at_limit = "x".repeat(MAX_FIELD_LENGTH);
        let result = validate_secondary_fields(&at_limit, "", "", "");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_event_type_at_exact_limit() {
        let at_limit = "x".repeat(MAX_EVENT_TYPE_LENGTH);
        assert!(validate_append_fields(&at_limit, "info", "msg", None).is_ok());
    }

    #[test]
    fn validate_event_type_one_over_limit() {
        let over = "x".repeat(MAX_EVENT_TYPE_LENGTH + 1);
        assert!(validate_append_fields(&over, "info", "msg", None).is_err());
    }

    #[test]
    fn validate_message_at_exact_limit() {
        let at_limit = "x".repeat(MAX_MESSAGE_LENGTH);
        assert!(validate_append_fields("event", "info", &at_limit, None).is_ok());
    }

    #[test]
    fn validate_message_one_over_limit() {
        let over = "x".repeat(MAX_MESSAGE_LENGTH + 1);
        assert!(validate_append_fields("event", "info", &over, None).is_err());
    }

    #[test]
    fn validate_details_at_exact_limit() {
        let at_limit = "x".repeat(MAX_DETAILS_LENGTH);
        assert!(validate_append_fields("event", "info", "msg", Some(&at_limit)).is_ok());
    }

    #[test]
    fn validate_details_one_over_limit() {
        let over = "x".repeat(MAX_DETAILS_LENGTH + 1);
        assert!(validate_append_fields("event", "info", "msg", Some(&over)).is_err());
    }

    #[test]
    fn validate_rejects_long_severity() {
        let long = "x".repeat(MAX_SEVERITY_LENGTH + 1);
        let result = validate_append_fields("event", &long, "msg", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("severity"));
    }

    #[test]
    fn validate_severity_at_exact_limit() {
        let at_limit = "x".repeat(MAX_SEVERITY_LENGTH);
        assert!(validate_append_fields("event", &at_limit, "msg", None).is_ok());
    }

    #[test]
    fn strip_pii_removes_ipv4() {
        assert_eq!(
            strip_pii("Client 192.168.1.1 connected"),
            "Client [REDACTED_IP] connected"
        );
    }

    #[test]
    fn strip_pii_removes_multiple_ipv4() {
        assert_eq!(
            strip_pii("From 10.0.0.1 to 10.0.0.2"),
            "From [REDACTED_IP] to [REDACTED_IP]"
        );
    }

    #[test]
    fn strip_pii_removes_ipv6_loopback() {
        assert_eq!(
            strip_pii("Client ::1 connected"),
            "Client [REDACTED_IP] connected"
        );
    }

    #[test]
    fn strip_pii_removes_ipv6_full() {
        assert_eq!(
            strip_pii("Client 2001:0db8:85a3:0000:0000:8a2e:0370:7334 connected"),
            "Client [REDACTED_IP] connected"
        );
    }

    #[test]
    fn strip_pii_removes_ipv6_compressed() {
        assert_eq!(
            strip_pii("Client 2001:db8::1 connected"),
            "Client [REDACTED_IP] connected"
        );
    }

    #[test]
    fn strip_pii_removes_email() {
        assert_eq!(
            strip_pii("Contact user@example.com for info"),
            "Contact [REDACTED_EMAIL] for info"
        );
    }

    #[test]
    fn strip_pii_removes_email_with_plus() {
        assert_eq!(
            strip_pii("Email: test+tag@sub.domain.co.uk done"),
            "Email: [REDACTED_EMAIL] done"
        );
    }

    #[test]
    fn strip_pii_removes_iso_date() {
        assert_eq!(
            strip_pii("DOB is 1990-05-15 recorded"),
            "DOB is [REDACTED_DOB] recorded"
        );
    }

    #[test]
    fn strip_pii_removes_slash_date_dmy() {
        assert_eq!(
            strip_pii("Born 15/05/1990 in AU"),
            "Born [REDACTED_DOB] in AU"
        );
    }

    #[test]
    fn strip_pii_removes_slash_date_mdy() {
        assert_eq!(
            strip_pii("Born 05/15/1990 in US"),
            "Born [REDACTED_DOB] in US"
        );
    }

    #[test]
    fn strip_pii_preserves_normal_text() {
        let input = "Challenge ch-123 verified successfully";
        assert_eq!(strip_pii(input), input);
    }

    #[test]
    fn strip_pii_preserves_empty_string() {
        assert_eq!(strip_pii(""), "");
    }

    #[test]
    fn strip_pii_combined() {
        let input = "User user@test.com from 192.168.1.1 born 1985-03-22";
        let result = strip_pii(input);
        assert!(!result.contains("user@test.com"));
        assert!(!result.contains("192.168.1.1"));
        assert!(!result.contains("1985-03-22"));
        assert!(result.contains("[REDACTED_IP]"));
        assert!(result.contains("[REDACTED_EMAIL]"));
        assert!(result.contains("[REDACTED_DOB]"));
    }

    #[test]
    fn strip_pii_does_not_match_version_strings() {
        let input = "version 2.0.0 release";
        assert_eq!(strip_pii(input), input);
    }

    #[test]
    fn strip_pii_rejects_invalid_ipv4_octets() {
        let input = "address 999.999.999.999 invalid";
        assert_eq!(strip_pii(input), input);
    }

    #[test]
    fn strip_pii_does_not_match_dates_outside_range() {
        let input = "date 2100-01-01 future";
        assert_eq!(strip_pii(input), input);
    }

    #[test]
    fn strip_pii_ipv4_at_string_boundaries() {
        assert_eq!(strip_pii("10.0.0.1"), "[REDACTED_IP]");
        assert_eq!(strip_pii("10.0.0.1 start"), "[REDACTED_IP] start");
        assert_eq!(strip_pii("end 10.0.0.1"), "end [REDACTED_IP]");
    }

    #[test]
    fn strip_pii_handles_ipv4_mapped_ipv6() {
        let result = strip_pii("Client ::ffff:192.168.1.1 connected");
        assert!(
            !result.contains("::ffff:"),
            "IPv6 prefix must be fully redacted"
        );
        assert!(
            !result.contains("192.168.1.1"),
            "Embedded IPv4 must be fully redacted"
        );
        assert_eq!(result, "Client [REDACTED_IP] connected");
    }

    // ---- Port-suffix behaviour tests ----

    #[test]
    fn strip_pii_handles_ip_with_port() {
        let result = strip_pii("from 192.168.1.1:8080 connection");
        assert!(!result.contains("192.168.1.1"), "IP should be redacted");
        assert!(
            result.contains("[REDACTED_IP]:8080"),
            "Port should remain after redacted IP"
        );
    }

    #[test]
    fn strip_pii_handles_ipv6_bracket_port() {
        let result = strip_pii("[2001:db8::1]:443 connected");
        assert!(!result.contains("2001:db8::1"), "IPv6 should be redacted");
    }

    // ---- DOB false positive regression tests ----

    #[test]
    fn strip_dob_rejects_iso8601_timestamp_with_t() {
        // Test the DOB parser directly (not strip_pii, which also runs
        // the IPv6 parser that matches time components with colons).
        let input = b"Event at 2000-03-15T12:34:56.789Z";
        let result = try_parse_iso_date(input, 9);
        assert!(
            result.is_none(),
            "ISO 8601 timestamp should not match DOB pattern"
        );
    }

    #[test]
    fn strip_dob_rejects_log_timestamp_with_space() {
        // Test the DOB parser directly to verify the space+time rejection.
        let input = b"Event at 2000-03-15 12:34:56";
        let result = try_parse_iso_date(input, 9);
        assert!(
            result.is_none(),
            "Log timestamp should not match DOB pattern"
        );
    }

    #[test]
    fn strip_pii_preserves_recent_date() {
        // 2024 is outside the DOB year range.
        let input = "deployed on 2024-01-15";
        assert_eq!(
            strip_pii(input),
            input,
            "Recent date should not be redacted as DOB"
        );
    }

    #[test]
    fn strip_pii_preserves_future_date() {
        let input = "scheduled for 2026-05-21";
        assert_eq!(
            strip_pii(input),
            input,
            "Future date should not be redacted as DOB"
        );
    }

    #[test]
    fn strip_pii_preserves_very_old_date() {
        // 1900 is outside the DOB year range.
        let input = "founded in 1900-01-01";
        assert_eq!(
            strip_pii(input),
            input,
            "Historical date should not be redacted as DOB"
        );
    }

    #[test]
    fn strip_pii_preserves_recent_slash_date() {
        let input = "filed on 15/05/2024";
        assert_eq!(
            strip_pii(input),
            input,
            "Recent slash date should not be redacted"
        );
    }

    #[test]
    fn strip_pii_still_redacts_plausible_dob() {
        let input = "born 1985-07-23 in AU";
        let result = strip_pii(input);
        assert!(!result.contains("1985-07-23"));
        assert!(result.contains("[REDACTED_DOB]"));
    }

    #[test]
    fn strip_pii_still_redacts_boundary_year_1920() {
        let input = "dob 1920-01-01 noted";
        let result = strip_pii(input);
        assert!(result.contains("[REDACTED_DOB]"));
    }

    #[test]
    fn strip_pii_still_redacts_boundary_year_2012() {
        let input = "dob 2012-12-31 noted";
        let result = strip_pii(input);
        assert!(result.contains("[REDACTED_DOB]"));
    }

    #[test]
    fn strip_pii_still_redacts_boundary_year_2013() {
        let input = "dob 2013-06-15 noted";
        let result = strip_pii(input);
        assert!(
            result.contains("[REDACTED_DOB]"),
            "2013 should be inside DOB range"
        );
    }

    #[test]
    fn strip_pii_excludes_boundary_year_2014() {
        let input = "date 2014-01-01 recorded";
        assert_eq!(strip_pii(input), input, "2014 is outside DOB range");
    }

    #[test]
    fn strip_pii_excludes_boundary_year_1919() {
        let input = "date 1919-12-31 recorded";
        assert_eq!(strip_pii(input), input, "1919 is outside DOB range");
    }

    // ---- M-3: Dot-delimited date tests ----

    #[test]
    fn strip_pii_handles_dot_date() {
        assert_eq!(
            strip_pii("born 15.06.1990 in DE"),
            "born [REDACTED_DOB] in DE"
        );
    }

    #[test]
    fn strip_pii_dot_date_boundary() {
        // 1919 is below DOB_YEAR_LOWER, should not be redacted.
        let input_1919 = "date 31.12.1919 noted";
        assert_eq!(strip_pii(input_1919), input_1919, "1919 below DOB range");

        // 1920 is at DOB_YEAR_LOWER, should be redacted.
        let result_1920 = strip_pii("date 01.01.1920 noted");
        assert!(
            result_1920.contains("[REDACTED_DOB]"),
            "1920 at lower bound"
        );

        // 2013 is at DOB_YEAR_UPPER, should be redacted.
        let result_2013 = strip_pii("date 15.06.2013 noted");
        assert!(
            result_2013.contains("[REDACTED_DOB]"),
            "2013 at upper bound"
        );

        // 2014 is above DOB_YEAR_UPPER, should not be redacted.
        let input_2014 = "date 01.01.2014 noted";
        assert_eq!(strip_pii(input_2014), input_2014, "2014 above DOB range");
    }

    #[test]
    fn strip_pii_dot_date_rejects_version() {
        // The leading `v` is alphanumeric so the boundary check rejects this.
        let input = "version v2001.01.15 released";
        assert_eq!(
            strip_pii(input),
            input,
            "version string should not be redacted"
        );
    }

    #[test]
    fn strip_pii_dot_date_rejects_ipv4() {
        // 192.168.1.1 has octets outside the day (1-31) or month (1-12) range,
        // so try_parse_dot_date will reject it. The IPv4 parser handles it instead.
        let result = strip_pii("address 192.168.1.1 here");
        assert!(
            !result.contains("[REDACTED_DOB]"),
            "IPv4 should not become a DOB"
        );
        assert!(
            result.contains("[REDACTED_IP]"),
            "IPv4 should be redacted as IP"
        );
    }

    // ---- H-35: Unicode tests ----

    #[test]
    fn strip_pii_cjk_surrounding_ipv4() {
        let input = "\u{4F60}\u{597D} 192.168.1.1 \u{4E16}\u{754C}";
        let result = strip_pii(input);
        assert!(!result.contains("192.168.1.1"));
        assert!(result.contains("[REDACTED_IP]"));
        assert!(result.contains('\u{4F60}'));
        assert!(result.contains('\u{754C}'));
    }

    #[test]
    fn strip_pii_cjk_surrounding_email() {
        let input = "\u{6D4B}\u{8BD5} user@example.com \u{5B8C}\u{6210}";
        let result = strip_pii(input);
        assert!(!result.contains("user@example.com"));
        assert!(result.contains("[REDACTED_EMAIL]"));
        assert!(result.contains('\u{6D4B}'));
        assert!(result.contains('\u{5B8C}'));
    }

    #[test]
    fn strip_pii_emoji_surrounding_ipv4() {
        let result = strip_pii("\u{1F30D} Client 10.0.0.1 \u{1F680}");
        assert!(!result.contains("10.0.0.1"));
        assert!(result.contains("[REDACTED_IP]"));
        assert!(result.contains('\u{1F30D}'));
        assert!(result.contains('\u{1F680}'));
    }

    #[test]
    fn strip_pii_emoji_adjacent_to_dob() {
        // Emoji bytes are not alphanumeric so the boundary check passes.
        let result = strip_pii("\u{1F382}1990-06-15\u{1F389}");
        assert!(!result.contains("1990-06-15"));
        assert!(result.contains("[REDACTED_DOB]"));
    }

    #[test]
    fn strip_pii_arabic_surrounding_ipv6() {
        let input = "\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} 2001:db8::1 \u{0627}\u{0644}\u{0639}\u{0631}\u{0628}";
        let result = strip_pii(input);
        assert!(!result.contains("2001:db8::1"));
        assert!(result.contains("[REDACTED_IP]"));
        // Arabic characters preserved.
        assert!(result.contains('\u{0645}'));
    }

    #[test]
    fn strip_pii_hebrew_surrounding_email() {
        let input = "\u{05E9}\u{05DC}\u{05D5}\u{05DD} admin@test.org \u{05D8}\u{05E1}\u{05D8}";
        let result = strip_pii(input);
        assert!(!result.contains("admin@test.org"));
        assert!(result.contains("[REDACTED_EMAIL]"));
        assert!(result.contains('\u{05E9}'));
    }

    #[test]
    fn strip_pii_combining_diacritical_near_ip() {
        // "cafe\u{0301}" is "cafe" + combining acute accent.
        let input = "cafe\u{0301} at 172.16.0.1 here";
        let result = strip_pii(input);
        assert!(!result.contains("172.16.0.1"));
        assert!(result.contains("[REDACTED_IP]"));
        assert!(result.contains("caf"));
    }

    #[test]
    fn strip_pii_combining_marks_in_email_boundary() {
        // Combining mark before the email local part (not part of the local part).
        let input = "name\u{0300} user@example.com end";
        let result = strip_pii(input);
        assert!(!result.contains("user@example.com"));
        assert!(result.contains("[REDACTED_EMAIL]"));
    }

    #[test]
    fn strip_pii_mixed_scripts_all_pattern_types() {
        let input = "\u{65E5}\u{672C}\u{8A9E} 192.168.0.1 admin@test.org 1985-03-22 \u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}";
        let result = strip_pii(input);
        assert!(!result.contains("192.168.0.1"));
        assert!(!result.contains("admin@test.org"));
        assert!(!result.contains("1985-03-22"));
        assert!(result.contains("[REDACTED_IP]"));
        assert!(result.contains("[REDACTED_EMAIL]"));
        assert!(result.contains("[REDACTED_DOB]"));
        // Japanese and Cyrillic preserved.
        assert!(result.contains('\u{65E5}'));
        assert!(result.contains('\u{041F}'));
    }

    #[test]
    fn strip_pii_zwj_emoji_sequence_preserved() {
        // Family emoji: 👨\u{200D}👩\u{200D}👧\u{200D}👦 with an IP address.
        let input = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} ip 10.0.0.1";
        let result = strip_pii(input);
        assert!(!result.contains("10.0.0.1"));
        assert!(result.contains("[REDACTED_IP]"));
        // ZWJ sequence should be preserved intact.
        assert!(result.contains('\u{1F468}'));
        assert!(result.contains('\u{200D}'));
        assert!(result.contains('\u{1F466}'));
    }

    // ---- H-36: Idempotency test ----

    #[test]
    fn strip_pii_is_idempotent() {
        let input = "User user@test.com from 192.168.1.1 ipv6 2001:db8::1 born 1985-03-22 end";
        let once = strip_pii(input);
        let twice = strip_pii(&once);
        assert_eq!(once, twice, "strip_pii must be idempotent");
    }

    // ---- H-37: Property-based tests ----

    use proptest::prelude::*;

    /// Strategy that generates strings with embedded PII patterns mixed with Unicode.
    fn pii_bearing_string() -> impl Strategy<Value = String> {
        let ipv4 = (0..=255u8, 0..=255u8, 0..=255u8, 0..=255u8)
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"));
        let email = ("[a-z]{1,8}", "[a-z]{2,6}", "[a-z]{2,4}")
            .prop_map(|(local, domain, tld)| format!("{local}@{domain}.{tld}"));
        let dob = (DOB_YEAR_LOWER..=DOB_YEAR_UPPER, 1..=12u8, 1..=28u8)
            .prop_map(|(y, m, d)| format!("{y:04}-{m:02}-{d:02}"));
        let filler = prop_oneof![
            Just("hello ".to_string()),
            Just(" \u{4F60}\u{597D} ".to_string()),
            Just(" \u{1F600} ".to_string()),
            Just(" text ".to_string()),
            Just(" ".to_string()),
        ];

        (
            filler.clone(),
            ipv4,
            filler.clone(),
            email,
            filler.clone(),
            dob,
            filler,
        )
            .prop_map(|(f1, ip, f2, em, f3, db, f4)| format!("{f1}{ip}{f2}{em}{f3}{db}{f4}"))
    }

    proptest! {
        #[test]
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        fn proptest_strip_pii_removes_all_ipv4(input in pii_bearing_string()) {
            let result = strip_pii(&input);
            // Check that no unredacted digit.digit.digit.digit pattern survives.
            // Simple heuristic: scan for any 4-octet pattern outside redaction markers.
            let cleaned = result.replace("[REDACTED_IP]", "");
            let bytes = cleaned.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i].is_ascii_digit() {
                    if let Some((end, true)) = try_parse_ipv4(bytes, i) {
                        let before_ok = i == 0 || !bytes.get(i.wrapping_sub(1)).copied().is_some_and(|b| b.is_ascii_digit() || b == b'.');
                        let after_ok = end >= bytes.len() || !bytes.get(end).copied().is_some_and(|b| b.is_ascii_digit() || b == b'.');
                        prop_assert!(!before_ok || !after_ok, "found unredacted IPv4 in: {}", result);
                    }
                }
                i += 1;
            }
        }

        #[test]
        fn proptest_strip_pii_preserves_utf8(input in ".*") {
            let result = strip_pii(&input);
            // In safe Rust this is trivially true, but validates no byte corruption.
            prop_assert!(std::str::from_utf8(result.as_bytes()).is_ok());
        }

        #[test]
        fn proptest_strip_pii_idempotent(input in pii_bearing_string()) {
            let once = strip_pii(&input);
            let twice = strip_pii(&once);
            prop_assert_eq!(once, twice, "strip_pii must be idempotent");
        }

        #[test]
        fn proptest_strip_pii_output_length_bounded(input in pii_bearing_string()) {
            let result = strip_pii(&input);
            // Adversarial analysis: pathological "::" IPv6 expansion to [REDACTED_IP]
            // (2 bytes -> 13 bytes, ratio ~7x). Adding a constant covers edge cases.
            let bound = input.len().saturating_mul(7).saturating_add(100);
            prop_assert!(
                result.len() <= bound,
                "output {} bytes exceeds bound {} for input {} bytes",
                result.len(),
                bound,
                input.len()
            );
        }
    }
}
