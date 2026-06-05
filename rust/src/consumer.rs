// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Consumer-side batch processing for the D1 audit store.
//!
//! This module provides pure logic functions used by the `provii-audit-consumer`
//! worker to batch-insert [`AuditEvent`] records into D1, compute SHA-256 batch
//! digests with HMAC-SHA256 chain signatures, and run retention cleanup.
//!
//! No `worker` crate types are imported here. The consumer worker calls these
//! functions with D1 results, keeping all platform-specific I/O at the edge.
//!
//! ## Digest Chain
//!
//! Each batch of inserted events produces a [`BatchResult`] containing:
//!
//! - A deterministic `batch_hash` (SHA-256 of sorted, length-prefixed event IDs)
//! - A `signature` (HMAC-SHA256 over `batch_hash || "|" || previous_hash || "|" || key_id`)
//! - The `previous_hash` linking back to the prior batch
//! - A `key_id` identifying which HMAC key produced the signature
//!
//! The first batch in the chain uses [`DIGEST_GENESIS_HASH`] as its previous hash.

#![forbid(unsafe_code)]

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::error::AuditError;
use crate::event::AuditEvent;

type HmacSha256 = Hmac<Sha256>;

/// Number of bind parameters per row in the INSERT statement.
///
/// Matches the 23 columns in `audit_events`. Used by tests to validate
/// that [`event_bind_params`] output and INSERT SQL stay in sync.
#[cfg(test)]
pub(crate) const BIND_PARAMS_PER_ROW: usize = 23;

/// Genesis hash anchoring the first entry in the digest chain.
///
/// The very first batch uses this value as its `previous_hash`. The trailing
/// zeroes are 64 hex characters (matching SHA-256 output length) to keep
/// format consistency with real batch hashes.
pub const DIGEST_GENESIS_HASH: &str =
    "provii-audit-digest-genesis-0000000000000000000000000000000000000000000000000000000000000000";

/// Minimum acceptable length, in bytes, for the digest-chain HMAC key.
///
/// Set to 32 bytes (256 bits), matching the SHA-256 output width and the
/// privacy salt minimum in [`crate::privacy`]. HMAC-SHA256 itself accepts a
/// key of any length, including an empty one (it hashes over-long keys and
/// zero-pads short ones), so a misconfigured empty or truncated key would
/// otherwise produce structurally valid signatures with far less than the
/// intended entropy, silently weakening the tamper-evidence of the chain.
const MIN_DIGEST_KEY_LENGTH: usize = 32;

/// Validates digest-chain HMAC key material before it is used to sign or
/// verify a chain entry.
///
/// HMAC-SHA256 never rejects a key on length grounds, so this guard is the
/// only place an empty, truncated, or trivially-guessable key is caught. It
/// rejects keys shorter than [`MIN_DIGEST_KEY_LENGTH`] (which covers the
/// empty-key case) and all-zero keys, mirroring the salt validation in
/// [`crate::privacy::PrivacyContext::new`].
///
/// # Errors
///
/// Returns [`AuditError::HmacKeyError`] if the key is shorter than
/// [`MIN_DIGEST_KEY_LENGTH`] or consists entirely of zero bytes. The error
/// context reports lengths only, never key bytes.
fn validate_digest_key(hmac_key: &[u8]) -> Result<(), AuditError> {
    if hmac_key.len() < MIN_DIGEST_KEY_LENGTH {
        return Err(AuditError::hmac_key(format!(
            "digest HMAC key too short: expected at least {MIN_DIGEST_KEY_LENGTH} bytes, got {}",
            hmac_key.len()
        )));
    }
    if hmac_key.iter().all(|&b| b == 0) {
        return Err(AuditError::hmac_key(
            "digest HMAC key must not be all zeros",
        ));
    }
    Ok(())
}

/// Returns the INSERT SQL for a single audit event row.
///
/// Uses `INSERT OR IGNORE` so duplicate `event_id` values (from queue
/// redelivery) are silently skipped rather than causing a constraint error.
///
/// The 23 bind parameters correspond to the columns in `audit_events`:
/// `event_id`, `timestamp_ms`, `source_service`, `event_type`, `severity`,
/// `client_ip_hash`, `origin`, `user_agent_hash`, `challenge_id`, `message`,
/// `details`, `request_id`, `environment`, `worker_version`, `geo_country`,
/// `event_category`, `actor_id`, `actor_type`, `resource_type`, `resource_id`,
/// `outcome`, `queue_message_id`, `created_at`.
#[must_use]
pub const fn insert_sql() -> &'static str {
    "INSERT OR IGNORE INTO audit_events (event_id, timestamp_ms, source_service, event_type, severity, client_ip_hash, origin, user_agent_hash, challenge_id, message, details, request_id, environment, worker_version, geo_country, event_category, actor_id, actor_type, resource_type, resource_id, outcome, queue_message_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)"
}

/// Returns the INSERT SQL for a digest chain entry.
///
/// The 10 bind parameters correspond to: `batch_id`, `timestamp_ms`,
/// `event_count`, `first_event_id`, `last_event_id`, `batch_hash`,
/// `previous_hash`, `signature`, `key_id`, `created_at`.
///
/// The `key_id` column identifies which HMAC key produced the signature,
/// enabling key rotation without breaking chain verification.
///
#[must_use]
pub const fn digest_insert_sql() -> &'static str {
    "INSERT INTO audit_digests (batch_id, timestamp_ms, event_count, first_event_id, last_event_id, batch_hash, previous_hash, signature, key_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
}

/// Returns the bounded retention DELETE SQL.
///
/// Removes at most `?2` events whose `timestamp_ms` is strictly less than
/// `?1`. The caller computes the cutoff timestamp (`?1`, e.g. now minus 90
/// days in milliseconds) and the per-iteration row cap (`?2`,
/// `RETENTION_BATCH_SIZE`), then re-runs this statement in a loop until a
/// run deletes fewer than `?2` rows (or a per-invocation budget is hit) so
/// the DELETE cannot grow into a single un-paced statement that times out
/// under D1's 30s query cap and lets `audit_events` grow toward the
/// un-raisable 10GB write-fail cap.
///
/// The `WHERE` predicate is identical to the previous unbounded form; the
/// `LIMIT ?2` only paces deletion across iterations, so a full sweep removes
/// the same rows (those strictly older than the cutoff), never more.
///
/// `DELETE ... LIMIT` requires `SQLite` to be built with
/// `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`; Cloudflare D1 enables it, so no
/// `ORDER BY` is used (the row choice within the cutoff is irrelevant
/// because every matching row is eventually deleted). If a future D1 build
/// rejects `DELETE ... LIMIT`, fall back to
/// `DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE timestamp_ms < ?1 LIMIT ?2)`.
#[must_use]
pub const fn retention_delete_sql() -> &'static str {
    "DELETE FROM audit_events WHERE timestamp_ms < ?1 LIMIT ?2"
}

/// Computes a deterministic batch hash from a set of event IDs.
///
/// The IDs are sorted lexicographically, then each ID is length-prefixed
/// (`len:value`) and concatenated before hashing with SHA-256. Sorting
/// ensures that the same set of events always produces the same hash
/// regardless of insertion or queue delivery order. Length-prefixing
/// prevents ambiguity between IDs containing the delimiter character
/// (e.g. `["a|b", "c"]` vs `["a", "b|c"]` would collide under naive
/// pipe-delimited joining).
///
/// Returns a lowercase hex-encoded SHA-256 digest (64 characters).
///
/// An empty slice produces the SHA-256 of the empty string, which is a
/// valid (if degenerate) hash. Callers should avoid creating empty batches.
#[must_use]
pub fn compute_batch_hash(event_ids: &[&str]) -> String {
    let mut sorted = event_ids.to_vec();
    sorted.sort_unstable();
    let mut encoded = String::new();
    for id in &sorted {
        encoded.push_str(&id.len().to_string());
        encoded.push(':');
        encoded.push_str(id);
    }
    let hash = Sha256::digest(encoded.as_bytes());
    hex::encode(hash)
}

/// Computes the HMAC-SHA256 signature for a digest chain entry.
///
/// Signs the concatenation `batch_hash || "|" || previous_hash || "|" || key_id`
/// with the supplied HMAC key. Including `key_id` in the signed data binds the
/// signature to a specific key identity, preventing an attacker from replaying
/// a signature computed under a different key.
///
/// Returns a lowercase hex-encoded HMAC-SHA256 tag (64 characters).
///
/// # Zeroisation
///
/// The caller owns the key bytes and MUST zeroise them after use (e.g. by
/// holding the key in a `Zeroizing<Vec<u8>>`). Neither hmac 0.12 nor 0.13
/// implements Zeroize/ZeroizeOnDrop for Mac types. This is an upstream gap
/// in digest's `buffer_fixed!` macro: `MacTraits` does not include
/// `ZeroizeOnDrop`, only `FixedHashTraits` does. `finalize_reset()` clears
/// message-derived state; the ipad/opad key schedule persists until drop.
/// In WASM, function-local data remains in linear memory after the stack
/// frame returns until overwritten.
///
/// # Errors
///
/// Returns [`AuditError::HmacKeyError`] if the key is empty, shorter than the
/// 32-byte minimum, all zeros, or otherwise rejected by the HMAC
/// implementation.
pub fn compute_digest_signature(
    batch_hash: &str,
    previous_hash: &str,
    hmac_key: &[u8],
    key_id: &str,
) -> Result<String, AuditError> {
    // Guard the key before it is used: HMAC-SHA256 accepts a key of any
    // length (including empty), so a misconfigured key would otherwise yield
    // a structurally valid but worthless signature, silently undermining the
    // chain's tamper-evidence.
    validate_digest_key(hmac_key)?;
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|e| AuditError::hmac_key(format!("Invalid HMAC key: {e}")))?;
    mac.update(batch_hash.as_bytes());
    mac.update(b"|");
    mac.update(previous_hash.as_bytes());
    mac.update(b"|");
    mac.update(key_id.as_bytes());
    // Neither hmac 0.12 nor 0.13 implements Zeroize/ZeroizeOnDrop for Mac
    // types (upstream gap in digest's buffer_fixed! macro). finalize()
    // consumes the MAC, dropping message-derived state; ipad/opad key schedule
    // persists until drop. In WASM, function-local data remains in linear memory
    // after the stack frame returns until overwritten. The HMAC is function-scoped.
    // Callers MUST zeroise the key bytes they own (see provii-audit-consumer).
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

/// Derives a short key identifier from raw HMAC key material.
///
/// Returns the first 8 hex characters of the SHA-256 hash of the key.
/// This is a non-secret, deterministic identifier stored alongside digest
/// rows to indicate which key produced the signature.
///
/// The truncated hash is not reversible and does not leak key material.
/// Collisions are cosmetically confusing but not a security risk since
/// chain verification uses the actual key, not the `key_id`.
#[must_use]
pub fn derive_key_id(key: &[u8]) -> String {
    let hash = Sha256::digest(key);
    let full_hex = hex::encode(hash);
    full_hex.get(..8).unwrap_or(&full_hex).to_string()
}

/// A single entry in the digest chain, passed to [`verify_chain`] for
/// recomputation and comparison.
///
/// Constructed by the consumer worker from D1 digest rows. Each entry
/// carries the stored signature so `verify_chain` can recompute and compare.
#[derive(Debug, Clone)]
pub struct DigestEntry {
    /// SHA-256 hash of the batch's sorted, length-prefixed event IDs.
    pub batch_hash: String,

    /// Hash of the previous batch in the chain (or [`DIGEST_GENESIS_HASH`]
    /// for the first entry).
    pub previous_hash: String,

    /// HMAC-SHA256 signature stored alongside the digest row.
    pub digest_signature: String,

    /// Identifier of the HMAC key that produced the signature.
    pub key_id: String,
}

/// Result of [`verify_chain`] indicating whether the digest chain is intact.
///
/// `Valid` means every stored signature matched its recomputed value.
/// `Invalid` identifies the first entry where they diverged, signalling
/// possible tampering or data corruption.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainVerification {
    /// Every entry's recomputed signature matches the stored signature.
    Valid {
        /// Number of entries verified.
        entries_verified: usize,
    },

    /// The chain is broken at the specified index (zero-based). The
    /// `batch_hash` of the failing entry is included for diagnostics.
    Invalid {
        /// Zero-based index of the first entry whose signature did not
        /// match the recomputed value.
        first_mismatch_index: usize,

        /// `batch_hash` of the entry at `first_mismatch_index`.
        batch_hash: String,
    },
}

/// Verifies the integrity of an HMAC-SHA256 digest chain.
///
/// Walks the chain from genesis, recomputing each entry's signature using
/// `batch_hash`, `previous_hash`, `key_id`, and the supplied `hmac_key`.
/// Each recomputed tag is compared to the stored `digest_signature` using
/// `hmac::Mac::verify_slice`, which performs a constant-time comparison
/// internally (via `subtle::ConstantTimeEq`).
///
/// The `entries` slice MUST be ordered from oldest to newest (i.e. the
/// first element should have `previous_hash == DIGEST_GENESIS_HASH`).
///
/// An empty slice is considered valid (zero entries verified).
///
/// # Key rotation
///
/// If the HMAC key was rotated during the chain's lifetime, entries signed
/// with the old key will fail verification against the new key. The caller
/// must either supply the correct key per segment or accept that
/// verification covers only the entries signed with the supplied key.
///
/// # Errors
///
/// Returns [`AuditError::HmacKeyError`] if the HMAC key is empty, shorter
/// than the 32-byte minimum, all zeros, or otherwise rejected by the
/// underlying implementation. An empty `entries` slice is a no-op and does
/// not require a valid key.
pub fn verify_chain(
    entries: &[DigestEntry],
    hmac_key: &[u8],
) -> Result<ChainVerification, AuditError> {
    if entries.is_empty() {
        return Ok(ChainVerification::Valid {
            entries_verified: 0,
        });
    }

    // Guard the key before any entry is verified. Without this, an empty or
    // truncated key would silently recompute tags and could mark a chain
    // "Invalid" for the wrong reason (key misconfiguration, not tampering),
    // or, paired with the same broken key at sign time, mask real tampering.
    validate_digest_key(hmac_key)?;

    let mut expected_previous = DIGEST_GENESIS_HASH.to_string();

    for (idx, entry) in entries.iter().enumerate() {
        // Verify linkage: each entry's previous_hash must match the
        // batch_hash of the preceding entry (or genesis for the first).
        if entry.previous_hash != expected_previous {
            return Ok(ChainVerification::Invalid {
                first_mismatch_index: idx,
                batch_hash: entry.batch_hash.clone(),
            });
        }

        // Recompute the HMAC tag over the same message that was signed
        // at write time: batch_hash || "|" || previous_hash || "|" || key_id.
        // See sign_digest_entry for the HMAC zeroisation gap note (hmac
        // 0.12/0.13 Mac types lack ZeroizeOnDrop, WASM linear memory
        // persistence). The HMAC is loop-scoped; caller owns key bytes.
        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .map_err(|e| AuditError::hmac_key(format!("Invalid HMAC key: {e}")))?;
        mac.update(entry.batch_hash.as_bytes());
        mac.update(b"|");
        mac.update(entry.previous_hash.as_bytes());
        mac.update(b"|");
        mac.update(entry.key_id.as_bytes());

        // Decode the stored hex signature to raw bytes for verify_slice.
        let stored_tag = hex::decode(&entry.digest_signature).map_err(|e| {
            AuditError::field_validation(
                "digest_signature",
                format!("invalid hex at chain index {idx}: {e}"),
            )
        })?;

        // SECURITY: verify_slice uses subtle::ConstantTimeEq internally.
        // This prevents timing side-channels when comparing the recomputed
        // tag against the stored tag.
        if mac.verify_slice(&stored_tag).is_err() {
            return Ok(ChainVerification::Invalid {
                first_mismatch_index: idx,
                batch_hash: entry.batch_hash.clone(),
            });
        }

        expected_previous.clone_from(&entry.batch_hash);
    }

    Ok(ChainVerification::Valid {
        entries_verified: entries.len(),
    })
}

/// Returns bind parameters for a single [`AuditEvent`] row as strings for D1.
///
/// Produces a `Vec` of exactly `BIND_PARAMS_PER_ROW` (23) string values in
/// the same column order as [`insert_sql`]. Numeric fields (`timestamp_ms`)
/// are converted to their decimal string representation.
///
/// This function does not validate field lengths. Callers MUST call
/// [`AuditEvent::validate_field_lengths`] on deserialised events before
/// passing them here, to reject oversized or empty required fields that
/// bypassed the builder.
#[must_use]
pub fn event_bind_params(event: &AuditEvent) -> Vec<String> {
    vec![
        event.event_id.clone(),
        event.timestamp_ms.to_string(),
        event.source_service.clone(),
        event.event_type.clone(),
        event.severity.as_str().to_string(),
        event.client_ip_hash().to_string(),
        event.origin.clone(),
        event.user_agent_hash.clone(),
        event.challenge_id.clone(),
        event.message().to_string(),
        event.details().to_string(),
        event.request_id.clone(),
        event.environment.to_string(),
        event.worker_version.clone(),
        event.geo_country.clone(),
        event
            .event_category
            .map_or_else(String::new, |v| v.to_string()),
        event.actor_id.clone(),
        event.actor_type.map_or_else(String::new, |v| v.to_string()),
        event.resource_type.clone(),
        event.resource_id.clone(),
        event.outcome.map_or_else(String::new, |v| v.to_string()),
        event.queue_message_id.clone(),
        event.created_at.clone(),
    ]
}

/// Result of processing a batch of queue messages into D1.
///
/// The consumer worker constructs this after a successful batch insert,
/// then uses it to write the corresponding digest chain row. Fields are
/// derived from the sorted event IDs in the batch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BatchResult {
    /// Unique identifier for this batch (UUID v4 hex, 32 chars).
    pub batch_id: String,

    /// Number of events in the batch.
    pub event_count: usize,

    /// Event ID of the first event (by sorted order).
    pub first_event_id: String,

    /// Event ID of the last event (by sorted order).
    pub last_event_id: String,

    /// SHA-256 hash of sorted, length-prefixed event IDs.
    pub batch_hash: String,

    /// Hash of the previous batch in the chain (or [`DIGEST_GENESIS_HASH`]).
    pub previous_hash: String,

    /// HMAC-SHA256 signature binding this batch to its predecessor.
    pub signature: String,

    /// Identifier of the HMAC key that produced the signature.
    ///
    /// First 8 hex characters of SHA-256(key). Used to select the correct
    /// key during chain verification after key rotation.
    pub key_id: String,

    /// Timestamp in milliseconds when the batch was processed.
    pub timestamp_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ActorType, AuditEventBuilder, Environment, EventCategory, Outcome};
    use crate::severity::Severity;

    // ---- compute_batch_hash: determinism ----

    #[test]
    fn batch_hash_is_deterministic() {
        let ids = &["aaa", "bbb", "ccc", "ddd"];
        let h1 = compute_batch_hash(ids);
        let h2 = compute_batch_hash(ids);
        assert_eq!(h1, h2, "Same input must produce identical hash");
    }

    #[test]
    fn batch_hash_is_64_hex_chars() {
        let hash = compute_batch_hash(&["event-1", "event-2"]);
        assert_eq!(hash.len(), 64, "SHA-256 hex digest must be 64 chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must be valid hex: {hash}"
        );
    }

    // ---- compute_batch_hash: ordering independence ----

    #[test]
    fn batch_hash_order_independent() {
        let forward = compute_batch_hash(&["alpha", "bravo", "charlie", "delta"]);
        let reverse = compute_batch_hash(&["delta", "charlie", "bravo", "alpha"]);
        let shuffled = compute_batch_hash(&["charlie", "alpha", "delta", "bravo"]);

        assert_eq!(forward, reverse, "Order must not affect hash");
        assert_eq!(forward, shuffled, "Order must not affect hash");
    }

    #[test]
    fn batch_hash_differs_for_different_ids() {
        let h1 = compute_batch_hash(&["aaa", "bbb"]);
        let h2 = compute_batch_hash(&["aaa", "ccc"]);
        assert_ne!(h1, h2, "Different IDs must produce different hashes");
    }

    // ---- compute_batch_hash: empty input ----

    #[test]
    fn batch_hash_empty_input() {
        let hash = compute_batch_hash(&[]);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Empty input must produce SHA-256 of empty string"
        );
        assert_eq!(hash.len(), 64);
    }

    // ---- compute_batch_hash: single element ----

    #[test]
    fn batch_hash_single_element() {
        let hash = compute_batch_hash(&["only-one"]);
        // Length-prefixed: "8:only-one"
        let expected = hex::encode(Sha256::digest(b"8:only-one"));
        assert_eq!(hash, expected);
    }

    // ---- compute_batch_hash: known test vector ----

    #[test]
    fn batch_hash_known_vector() {
        // Sorted: ["aaa", "bbb"] => length-prefixed: "3:aaa3:bbb"
        let hash = compute_batch_hash(&["bbb", "aaa"]);
        let expected = hex::encode(Sha256::digest(b"3:aaa3:bbb"));
        assert_eq!(hash, expected, "Known vector mismatch");
    }

    // ---- compute_digest_signature: known test vector ----

    #[test]
    fn digest_signature_known_vector() {
        let key = b"test-hmac-key-for-audit-digest-chain";
        let batch_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let previous_hash = DIGEST_GENESIS_HASH;
        let key_id = derive_key_id(key);

        let sig = compute_digest_signature(batch_hash, previous_hash, key, &key_id).unwrap();

        assert_eq!(sig.len(), 64, "HMAC-SHA256 hex must be 64 chars");
        assert!(
            sig.chars().all(|c| c.is_ascii_hexdigit()),
            "Signature must be valid hex"
        );

        // Recompute to verify determinism.
        let sig2 = compute_digest_signature(batch_hash, previous_hash, key, &key_id).unwrap();
        assert_eq!(sig, sig2, "Signature must be deterministic");
    }

    #[test]
    fn digest_signature_changes_with_different_batch_hash() {
        let key = b"some-key-padded-to-32-bytes-min!";
        let prev = DIGEST_GENESIS_HASH;
        let key_id = derive_key_id(key);

        let s1 = compute_digest_signature("hash-a", prev, key, &key_id).unwrap();
        let s2 = compute_digest_signature("hash-b", prev, key, &key_id).unwrap();
        assert_ne!(
            s1, s2,
            "Different batch_hash must yield different signature"
        );
    }

    #[test]
    fn digest_signature_changes_with_different_previous_hash() {
        let key = b"some-key-padded-to-32-bytes-min!";
        let batch = "same-batch-hash";
        let key_id = derive_key_id(key);

        let s1 = compute_digest_signature(batch, "prev-a", key, &key_id).unwrap();
        let s2 = compute_digest_signature(batch, "prev-b", key, &key_id).unwrap();
        assert_ne!(
            s1, s2,
            "Different previous_hash must yield different signature"
        );
    }

    #[test]
    fn digest_signature_changes_with_different_key() {
        let batch = "batch";
        let prev = "prev";

        let key_one = b"key-one-padded-to-at-least-32byt";
        let key_two = b"key-two-padded-to-at-least-32byt";
        let kid1 = derive_key_id(key_one);
        let kid2 = derive_key_id(key_two);

        let s1 = compute_digest_signature(batch, prev, key_one, &kid1).unwrap();
        let s2 = compute_digest_signature(batch, prev, key_two, &kid2).unwrap();
        assert_ne!(s1, s2, "Different HMAC key must yield different signature");
    }

    #[test]
    fn digest_signature_changes_with_different_key_id() {
        let key = b"same-key-padded-to-32-bytes-min!";
        let batch = "batch";
        let prev = "prev";

        let s1 = compute_digest_signature(batch, prev, key, "kid-aaa").unwrap();
        let s2 = compute_digest_signature(batch, prev, key, "kid-bbb").unwrap();
        assert_ne!(s1, s2, "Different key_id must yield different signature");
    }

    // ---- compute_digest_signature: manual HMAC verification ----

    #[test]
    fn digest_signature_matches_manual_hmac() {
        let key = b"manual-verification-key-32-bytes";
        let batch_hash = "deadbeef";
        let previous_hash = "cafebabe";
        let key_id = "abcd1234";

        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(b"deadbeef");
        mac.update(b"|");
        mac.update(b"cafebabe");
        mac.update(b"|");
        mac.update(b"abcd1234");
        let expected = hex::encode(mac.finalize().into_bytes());

        let actual = compute_digest_signature(batch_hash, previous_hash, key, key_id).unwrap();
        assert_eq!(actual, expected, "Must match hand-computed HMAC");
    }

    // ---- digest HMAC key-length guard (L4) ----
    //
    // HMAC-SHA256 accepts a key of any length, including empty, so without an
    // explicit guard a misconfigured (empty, truncated, or all-zero) key would
    // produce structurally valid signatures that silently weaken the chain's
    // tamper-evidence. These tests assert the guard rejects such keys at both
    // entry points (signing and verification) before the key is used.

    #[test]
    fn min_digest_key_length_is_32() {
        // The guard threshold matches the SHA-256 output width and the privacy
        // salt minimum. If this constant is lowered, the security rationale in
        // the L4 finding no longer holds, so pin it explicitly.
        assert_eq!(MIN_DIGEST_KEY_LENGTH, 32);
    }

    #[test]
    fn compute_digest_signature_rejects_empty_key() {
        let key_id = derive_key_id(b"");
        let err = compute_digest_signature("batch", DIGEST_GENESIS_HASH, b"", &key_id)
            .expect_err("empty HMAC key must be rejected");
        assert!(
            matches!(err, AuditError::HmacKeyError { .. }),
            "expected HmacKeyError, got {err:?}"
        );
    }

    #[test]
    fn compute_digest_signature_rejects_short_key() {
        // 31 bytes: one short of the 32-byte minimum.
        let short_key = vec![0xAB_u8; MIN_DIGEST_KEY_LENGTH - 1];
        let key_id = derive_key_id(&short_key);
        let err = compute_digest_signature("batch", DIGEST_GENESIS_HASH, &short_key, &key_id)
            .expect_err("short HMAC key must be rejected");
        assert!(
            matches!(err, AuditError::HmacKeyError { .. }),
            "expected HmacKeyError, got {err:?}"
        );
        let AuditError::HmacKeyError { context } = err else {
            unreachable!("variant asserted above")
        };
        assert!(
            context.contains("too short"),
            "context should explain the length failure: {context}"
        );
        // The error must never echo key bytes, only lengths.
        assert!(
            context.contains("31") && context.contains("32"),
            "context should report actual and minimum lengths: {context}"
        );
    }

    #[test]
    fn compute_digest_signature_rejects_all_zero_key() {
        let zero_key = vec![0x00_u8; MIN_DIGEST_KEY_LENGTH];
        let key_id = derive_key_id(&zero_key);
        let err = compute_digest_signature("batch", DIGEST_GENESIS_HASH, &zero_key, &key_id)
            .expect_err("all-zero HMAC key must be rejected");
        assert!(
            matches!(err, AuditError::HmacKeyError { .. }),
            "expected HmacKeyError, got {err:?}"
        );
        let AuditError::HmacKeyError { context } = err else {
            unreachable!("variant asserted above")
        };
        assert!(
            context.contains("all zeros"),
            "context should explain the all-zero failure: {context}"
        );
    }

    #[test]
    fn compute_digest_signature_accepts_exact_minimum_key() {
        // Exactly 32 non-zero bytes must be accepted (boundary check).
        let key = vec![0xAB_u8; MIN_DIGEST_KEY_LENGTH];
        let key_id = derive_key_id(&key);
        let sig = compute_digest_signature("batch", DIGEST_GENESIS_HASH, &key, &key_id)
            .expect("32-byte non-zero key must be accepted");
        assert_eq!(sig.len(), 64, "HMAC-SHA256 hex must be 64 chars");
    }

    #[test]
    fn verify_chain_rejects_empty_key() {
        // A non-empty chain must require a valid key. Build a valid chain with
        // a good key, then verify it with an empty key: this must Err, not
        // silently report Invalid (which would mask the misconfiguration).
        let chain = build_chain(b"valid-key-material-exactly-32byt", 2);
        let err = verify_chain(&chain, b"").expect_err("empty HMAC key must be rejected");
        assert!(
            matches!(err, AuditError::HmacKeyError { .. }),
            "expected HmacKeyError, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_rejects_short_key() {
        let chain = build_chain(b"valid-key-material-exactly-32byt", 1);
        let short_key = vec![0x11_u8; MIN_DIGEST_KEY_LENGTH - 1];
        let err = verify_chain(&chain, &short_key).expect_err("short HMAC key must be rejected");
        assert!(
            matches!(err, AuditError::HmacKeyError { .. }),
            "expected HmacKeyError, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_rejects_all_zero_key() {
        let chain = build_chain(b"valid-key-material-exactly-32byt", 1);
        let zero_key = vec![0x00_u8; MIN_DIGEST_KEY_LENGTH];
        let err = verify_chain(&chain, &zero_key).expect_err("all-zero HMAC key must be rejected");
        assert!(
            matches!(err, AuditError::HmacKeyError { .. }),
            "expected HmacKeyError, got {err:?}"
        );
    }

    #[test]
    fn verify_chain_empty_entries_skips_key_guard() {
        // An empty chain is a no-op and must remain valid even with a key that
        // would otherwise be rejected, preserving the documented contract.
        let result = verify_chain(&[], b"").expect("empty chain must be a no-op");
        assert_eq!(
            result,
            ChainVerification::Valid {
                entries_verified: 0
            }
        );
    }

    // ---- event_bind_params: count ----

    #[test]
    fn bind_params_has_correct_count() {
        let event = AuditEventBuilder::new("test_event", Severity::Info, "msg", "svc")
            .build()
            .unwrap();
        let params = event_bind_params(&event);
        assert_eq!(
            params.len(),
            BIND_PARAMS_PER_ROW,
            "Must produce exactly {BIND_PARAMS_PER_ROW} params"
        );
    }

    // ---- event_bind_params: order matches INSERT columns ----

    #[test]
    fn bind_params_order_matches_insert() {
        // Build a known event via the builder, then override public fields
        // for deterministic position checks. Private fields (client_ip_hash,
        // message, details) are set through builder methods.
        let mut event = AuditEventBuilder::new("etype", Severity::Warning, "msg", "svc")
            .client_ip_hash("iph")
            .origin("orig")
            .user_agent_hash("uah")
            .challenge_id("cid")
            .details("det")
            .request_id("rid")
            .environment(Environment::Sandbox)
            .worker_version("wv")
            .geo_country("AU")
            .event_category(EventCategory::Verification)
            .actor_id("actor-1")
            .actor_type(ActorType::Service)
            .resource_type("challenge")
            .resource_id("res-1")
            .outcome(Outcome::Success)
            .build()
            .unwrap();

        // Override auto-generated fields for deterministic assertions.
        event.event_id = "eid".into();
        event.timestamp_ms = 1_700_000_000_000;
        event.queue_message_id = "qmid".into();
        event.created_at = "2026-03-03T00:00:00.000Z".into();

        let params = event_bind_params(&event);

        // Verify each position matches the INSERT column order.
        assert_eq!(params.first().unwrap(), "eid", "?1 = event_id");
        assert_eq!(params.get(1).unwrap(), "1700000000000", "?2 = timestamp_ms");
        assert_eq!(params.get(2).unwrap(), "svc", "?3 = source_service");
        assert_eq!(params.get(3).unwrap(), "etype", "?4 = event_type");
        assert_eq!(params.get(4).unwrap(), "warning", "?5 = severity");
        assert_eq!(params.get(5).unwrap(), "iph", "?6 = client_ip_hash");
        assert_eq!(params.get(6).unwrap(), "orig", "?7 = origin");
        assert_eq!(params.get(7).unwrap(), "uah", "?8 = user_agent_hash");
        assert_eq!(params.get(8).unwrap(), "cid", "?9 = challenge_id");
        assert_eq!(params.get(9).unwrap(), "msg", "?10 = message");
        assert_eq!(params.get(10).unwrap(), "det", "?11 = details");
        assert_eq!(params.get(11).unwrap(), "rid", "?12 = request_id");
        assert_eq!(params.get(12).unwrap(), "sandbox", "?13 = environment");
        assert_eq!(params.get(13).unwrap(), "wv", "?14 = worker_version");
        assert_eq!(params.get(14).unwrap(), "AU", "?15 = geo_country");
        assert_eq!(
            params.get(15).unwrap(),
            "VERIFICATION",
            "?16 = event_category"
        );
        assert_eq!(params.get(16).unwrap(), "actor-1", "?17 = actor_id");
        assert_eq!(params.get(17).unwrap(), "service", "?18 = actor_type");
        assert_eq!(params.get(18).unwrap(), "challenge", "?19 = resource_type");
        assert_eq!(params.get(19).unwrap(), "res-1", "?20 = resource_id");
        assert_eq!(params.get(20).unwrap(), "success", "?21 = outcome");
        assert_eq!(params.get(21).unwrap(), "qmid", "?22 = queue_message_id");
        assert_eq!(
            params.get(22).unwrap(),
            "2026-03-03T00:00:00.000Z",
            "?23 = created_at"
        );
    }

    // ---- SQL strings: structural validity ----

    #[test]
    fn insert_sql_has_23_placeholders() {
        let sql = insert_sql();
        let count = (1..=23).filter(|i| sql.contains(&format!("?{i}"))).count();
        assert_eq!(count, 23, "INSERT must reference ?1 through ?23");
    }

    #[test]
    fn insert_sql_uses_insert_or_ignore() {
        let sql = insert_sql();
        assert!(
            sql.starts_with("INSERT OR IGNORE"),
            "Must use INSERT OR IGNORE for idempotent redelivery"
        );
    }

    #[test]
    fn insert_sql_targets_audit_events() {
        let sql = insert_sql();
        assert!(
            sql.contains("audit_events"),
            "Must target audit_events table"
        );
    }

    #[test]
    fn digest_insert_sql_has_10_placeholders() {
        let sql = digest_insert_sql();
        let count = (1..=10).filter(|i| sql.contains(&format!("?{i}"))).count();
        assert_eq!(count, 10, "Digest INSERT must reference ?1 through ?10");
    }

    #[test]
    fn digest_insert_sql_targets_audit_digests() {
        let sql = digest_insert_sql();
        assert!(
            sql.contains("audit_digests"),
            "Must target audit_digests table"
        );
    }

    #[test]
    fn retention_delete_sql_targets_audit_events() {
        let sql = retention_delete_sql();
        assert!(sql.contains("DELETE"), "Must be a DELETE statement");
        assert!(
            sql.contains("audit_events"),
            "Must target audit_events table"
        );
        assert!(
            sql.contains("timestamp_ms < ?1"),
            "Must filter on timestamp_ms"
        );
        // R4: the DELETE is paced with a bound LIMIT (?2 = RETENTION_BATCH_SIZE)
        // so it cannot run as one un-paced statement that times out under D1's
        // 30s query cap. The WHERE predicate is unchanged, so a full sweep
        // removes the same rows, never more.
        assert!(
            sql.contains("LIMIT ?2"),
            "Must bound each iteration with LIMIT ?2"
        );
        // No ORDER BY: every matching row is eventually deleted, so row choice
        // within the cutoff is irrelevant, and ORDER BY would force a sort.
        assert!(
            !sql.to_ascii_uppercase().contains("ORDER BY"),
            "Must not use ORDER BY (unnecessary sort on a full-sweep delete)"
        );
    }

    // ---- BatchResult: serialisation roundtrip ----

    #[test]
    fn batch_result_serialise_roundtrip() {
        let br = BatchResult {
            batch_id: "aabbccdd11223344aabbccdd11223344".into(),
            event_count: 42,
            first_event_id: "first-id".into(),
            last_event_id: "last-id".into(),
            batch_hash: "abcd".repeat(16),
            previous_hash: DIGEST_GENESIS_HASH.into(),
            signature: "ef01".repeat(16),
            key_id: "abcd1234".into(),
            timestamp_ms: 1_700_000_000_000,
        };

        let json = serde_json::to_string(&br).unwrap();
        let roundtripped: BatchResult = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.batch_id, br.batch_id);
        assert_eq!(roundtripped.event_count, br.event_count);
        assert_eq!(roundtripped.first_event_id, br.first_event_id);
        assert_eq!(roundtripped.last_event_id, br.last_event_id);
        assert_eq!(roundtripped.batch_hash, br.batch_hash);
        assert_eq!(roundtripped.previous_hash, br.previous_hash);
        assert_eq!(roundtripped.signature, br.signature);
        assert_eq!(roundtripped.key_id, br.key_id);
        assert_eq!(roundtripped.timestamp_ms, br.timestamp_ms);
    }

    #[test]
    fn batch_result_deserialise_from_json() {
        let json = r#"{
            "batch_id": "deadbeefdeadbeefdeadbeefdeadbeef",
            "event_count": 7,
            "first_event_id": "aaa",
            "last_event_id": "zzz",
            "batch_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "previous_hash": "prev",
            "signature": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "key_id": "ef567890",
            "timestamp_ms": 1234567890123
        }"#;

        let br: BatchResult = serde_json::from_str(json).unwrap();
        assert_eq!(br.batch_id, "deadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(br.event_count, 7);
        assert_eq!(br.key_id, "ef567890");
        assert_eq!(br.timestamp_ms, 1_234_567_890_123);
    }

    // ---- Genesis hash ----

    #[test]
    fn genesis_hash_has_expected_prefix() {
        assert!(
            DIGEST_GENESIS_HASH.starts_with("provii-audit-digest-genesis-"),
            "Genesis hash must start with known prefix"
        );
    }

    #[test]
    fn genesis_hash_has_consistent_length() {
        let prefix = "provii-audit-digest-genesis-";
        assert!(DIGEST_GENESIS_HASH.starts_with(prefix));
        // Prefix is entirely ASCII, so byte length equals char count.
        let suffix = DIGEST_GENESIS_HASH
            .get(prefix.len()..)
            .expect("suffix must exist");
        assert_eq!(
            suffix.len(),
            64,
            "Trailing portion must be 64 chars (matching SHA-256 hex output)"
        );
        assert!(
            suffix.chars().all(|c| c == '0'),
            "Trailing portion must be all zeroes"
        );
    }

    // ---- BIND_PARAMS_PER_ROW ----

    #[test]
    fn bind_params_per_row_matches_sql() {
        let sql = insert_sql();
        // Extract the column list between the first '(' and the first ')'.
        let open = sql.find('(').expect("INSERT SQL must contain '('");
        let close = sql.find(')').expect("INSERT SQL must contain ')'");
        // Column list is ASCII, so byte slicing is safe here.
        let columns = sql
            .get(open + 1..close)
            .expect("column range must be valid");
        let col_count = columns.split(',').count();
        assert_eq!(
            col_count, BIND_PARAMS_PER_ROW,
            "BIND_PARAMS_PER_ROW must match column count in INSERT SQL"
        );
    }

    // ---- Digest chain simulation ----

    #[test]
    fn digest_chain_two_batches() {
        let key = b"chain-test-key-32-bytes-exactly!";
        let key_id = derive_key_id(key);

        // Batch 1: genesis.
        let ids_1 = &["evt-001", "evt-002", "evt-003"];
        let hash_1 = compute_batch_hash(ids_1);
        let sig_1 = compute_digest_signature(&hash_1, DIGEST_GENESIS_HASH, key, &key_id).unwrap();

        // Batch 2: chains to batch 1.
        let ids_2 = &["evt-004", "evt-005"];
        let hash_2 = compute_batch_hash(ids_2);
        let sig_2 = compute_digest_signature(&hash_2, &hash_1, key, &key_id).unwrap();

        assert_ne!(hash_1, hash_2);
        assert_ne!(sig_1, sig_2);

        // Signatures are deterministic when recomputed.
        let sig_1_again =
            compute_digest_signature(&hash_1, DIGEST_GENESIS_HASH, key, &key_id).unwrap();
        assert_eq!(sig_1, sig_1_again);

        let sig_2_again = compute_digest_signature(&hash_2, &hash_1, key, &key_id).unwrap();
        assert_eq!(sig_2, sig_2_again);
    }

    // ---- derive_key_id ----

    #[test]
    fn derive_key_id_is_8_hex_chars() {
        let kid = derive_key_id(b"some-key-material");
        assert_eq!(kid.len(), 8, "key_id must be 8 hex chars");
        assert!(
            kid.chars().all(|c| c.is_ascii_hexdigit()),
            "key_id must be valid hex: {kid}"
        );
    }

    #[test]
    fn derive_key_id_is_deterministic() {
        let k1 = derive_key_id(b"deterministic-key");
        let k2 = derive_key_id(b"deterministic-key");
        assert_eq!(k1, k2, "Same key must produce same key_id");
    }

    #[test]
    fn derive_key_id_differs_for_different_keys() {
        let k1 = derive_key_id(b"key-alpha");
        let k2 = derive_key_id(b"key-bravo");
        assert_ne!(k1, k2, "Different keys must produce different key_ids");
    }

    #[test]
    fn derive_key_id_known_vector() {
        // SHA-256(b"test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        // First 8 hex chars = "9f86d081"
        let kid = derive_key_id(b"test");
        assert_eq!(kid, "9f86d081", "Known vector mismatch for derive_key_id");
    }

    // ---- event_bind_params: empty optional fields ----

    #[test]
    fn bind_params_handles_empty_optional_fields() {
        let event = AuditEventBuilder::new("test", Severity::Error, "err msg", "svc")
            .build()
            .unwrap();

        let params = event_bind_params(&event);

        assert!(
            params.get(5).unwrap().is_empty(),
            "client_ip_hash should be empty"
        );
        assert!(params.get(6).unwrap().is_empty(), "origin should be empty");
        assert!(
            params.get(7).unwrap().is_empty(),
            "user_agent_hash should be empty"
        );
        assert!(
            params.get(8).unwrap().is_empty(),
            "challenge_id should be empty"
        );
        assert_eq!(
            params.get(10).unwrap(),
            "{}",
            "details should default to '{{}}'"
        );
        assert!(
            params.get(11).unwrap().is_empty(),
            "request_id should be empty"
        );
        assert_eq!(
            params.get(12).unwrap(),
            "production",
            "environment should default to production"
        );
        assert!(
            params.get(13).unwrap().is_empty(),
            "worker_version should be empty"
        );
        assert!(
            params.get(14).unwrap().is_empty(),
            "geo_country should be empty"
        );
        assert!(
            params.get(15).unwrap().is_empty(),
            "event_category None should produce empty string"
        );
        assert!(
            params.get(16).unwrap().is_empty(),
            "actor_id should be empty"
        );
        assert!(
            params.get(17).unwrap().is_empty(),
            "actor_type None should produce empty string"
        );
        assert!(
            params.get(18).unwrap().is_empty(),
            "resource_type should be empty"
        );
        assert!(
            params.get(19).unwrap().is_empty(),
            "resource_id should be empty"
        );
        assert!(
            params.get(20).unwrap().is_empty(),
            "outcome None should produce empty string"
        );
        assert!(
            params.get(21).unwrap().is_empty(),
            "queue_message_id should be empty"
        );
    }

    // ---- compute_batch_hash: duplicates ----

    #[test]
    fn batch_hash_with_duplicate_ids() {
        let with_dup = compute_batch_hash(&["aaa", "aaa", "bbb"]);
        let without_dup = compute_batch_hash(&["aaa", "bbb"]);
        // Duplicates change the encoded string ("3:aaa3:aaa3:bbb" vs "3:aaa3:bbb"),
        // so the hashes must differ. The caller is responsible for deduplication.
        assert_ne!(
            with_dup, without_dup,
            "Duplicates must produce a different hash"
        );
    }

    #[test]
    fn batch_hash_no_delimiter_collision() {
        // Length-prefixing prevents ["a|b", "c"] and ["a", "b|c"] from colliding.
        // Under naive pipe-joining both would produce "a|b|c".
        let hash1 = compute_batch_hash(&["a|b", "c"]);
        let hash2 = compute_batch_hash(&["a", "b|c"]);
        assert_ne!(
            hash1, hash2,
            "IDs containing the old delimiter must not collide"
        );
    }

    // ---- verify_chain: valid chain ----

    fn build_chain(key: &[u8], batch_count: usize) -> Vec<DigestEntry> {
        let key_id = derive_key_id(key);
        let mut entries = Vec::with_capacity(batch_count);
        let mut prev = DIGEST_GENESIS_HASH.to_string();

        for i in 0..batch_count {
            let batch_hash = compute_batch_hash(&[&format!("evt-{i}-a"), &format!("evt-{i}-b")]);
            let sig = compute_digest_signature(&batch_hash, &prev, key, &key_id).unwrap();
            entries.push(DigestEntry {
                batch_hash: batch_hash.clone(),
                previous_hash: prev.clone(),
                digest_signature: sig,
                key_id: key_id.clone(),
            });
            prev = batch_hash;
        }

        entries
    }

    #[test]
    fn verify_chain_empty_is_valid() {
        let result = verify_chain(&[], b"any-key").unwrap();
        assert_eq!(
            result,
            ChainVerification::Valid {
                entries_verified: 0
            }
        );
    }

    #[test]
    fn verify_chain_single_entry_valid() {
        let key = b"single-entry-key-material-32byte";
        let chain = build_chain(key, 1);
        let result = verify_chain(&chain, key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Valid {
                entries_verified: 1
            }
        );
    }

    #[test]
    fn verify_chain_five_entries_valid() {
        let key = b"five-entries-key-material-32byte";
        let chain = build_chain(key, 5);
        let result = verify_chain(&chain, key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Valid {
                entries_verified: 5
            }
        );
    }

    // ---- verify_chain: tampered signature ----

    #[test]
    fn verify_chain_tampered_signature_detected() {
        let key = b"tamper-detect-key-material-32byt";
        let mut chain = build_chain(key, 4);

        // Tamper with the third entry's signature (index 2).
        chain.get_mut(2).unwrap().digest_signature = "ff".repeat(32); // 64 hex chars, wrong value

        let result = verify_chain(&chain, key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Invalid {
                first_mismatch_index: 2,
                batch_hash: chain.get(2).unwrap().batch_hash.clone(),
            }
        );
    }

    // ---- verify_chain: tampered batch_hash ----

    #[test]
    fn verify_chain_tampered_batch_hash_detected() {
        let key = b"batch-tamper-key-material-32byte";
        let mut chain = build_chain(key, 4);

        // Tamper with the second entry's batch_hash. This makes the
        // signature fail AND breaks the linkage to entry 3.
        chain.get_mut(1).unwrap().batch_hash = "00".repeat(32);

        let result = verify_chain(&chain, key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Invalid {
                first_mismatch_index: 1,
                batch_hash: "00".repeat(32),
            }
        );
    }

    // ---- verify_chain: broken linkage ----

    #[test]
    fn verify_chain_broken_linkage_detected() {
        let key = b"linkage-test-key-material-32byte";
        let mut chain = build_chain(key, 4);

        // Corrupt previous_hash of entry 2 so it no longer links to entry 1.
        chain.get_mut(2).unwrap().previous_hash = "bad-link".to_string();

        let result = verify_chain(&chain, key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Invalid {
                first_mismatch_index: 2,
                batch_hash: chain.get(2).unwrap().batch_hash.clone(),
            }
        );
    }

    // ---- verify_chain: wrong key ----

    #[test]
    fn verify_chain_wrong_key_detected() {
        let key = b"correct-key-material-exactly-32b";
        let wrong_key = b"wrong-key-material-nope-32bytes!";
        let chain = build_chain(key, 2);

        let result = verify_chain(&chain, wrong_key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Invalid {
                first_mismatch_index: 0,
                batch_hash: chain.first().unwrap().batch_hash.clone(),
            }
        );
    }

    // ---- verify_chain: invalid hex in stored signature ----

    #[test]
    fn verify_chain_invalid_hex_signature() {
        let key = b"hex-error-key-material-32-bytes!";
        let mut chain = build_chain(key, 1);
        chain.first_mut().unwrap().digest_signature = "not-valid-hex!!".to_string();

        let result = verify_chain(&chain, key);
        assert!(result.is_err(), "Invalid hex must return Err");
    }

    // ---- verify_chain: first entry has wrong previous_hash ----

    #[test]
    fn verify_chain_wrong_genesis() {
        let key = b"genesis-mismatch-key-32-bytes!!!";
        let mut chain = build_chain(key, 1);
        chain.first_mut().unwrap().previous_hash = "not-genesis".to_string();

        let result = verify_chain(&chain, key).unwrap();
        assert_eq!(
            result,
            ChainVerification::Invalid {
                first_mismatch_index: 0,
                batch_hash: chain.first().unwrap().batch_hash.clone(),
            }
        );
    }

    // ---- Property-based tests (H-34) ----

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_batch_hash_deterministic(
            ids in prop::collection::vec("[a-zA-Z0-9]{1,16}", 1..8),
        ) {
            let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
            let h1 = compute_batch_hash(&refs);
            let h2 = compute_batch_hash(&refs);
            prop_assert_eq!(h1, h2, "same input must produce identical hash");
        }

        #[test]
        fn prop_batch_hash_permutation_invariant(
            ids in prop::collection::vec("[a-zA-Z0-9]{1,16}", 2..8),
        ) {
            let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
            let mut reversed = refs.clone();
            reversed.reverse();
            let h_fwd = compute_batch_hash(&refs);
            let h_rev = compute_batch_hash(&reversed);
            prop_assert_eq!(h_fwd, h_rev, "reversed input must produce identical hash");
        }

        #[test]
        fn prop_batch_hash_is_64_hex(
            ids in prop::collection::vec("[a-zA-Z0-9]{1,16}", 0..8),
        ) {
            let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
            let hash = compute_batch_hash(&refs);
            prop_assert_eq!(hash.len(), 64, "SHA-256 hex digest must be 64 chars");
            prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "must be valid hex");
        }

        #[test]
        fn prop_batch_hash_distinct_inputs_differ(
            a in prop::collection::vec("[a-z]{1,8}", 1..5),
            b in prop::collection::vec("[a-z]{1,8}", 1..5),
        ) {
            let mut a_sorted = a.clone();
            let mut b_sorted = b.clone();
            a_sorted.sort();
            b_sorted.sort();
            // Only assert different hashes when the sorted sets actually differ.
            if a_sorted != b_sorted {
                let refs_a: Vec<&str> = a.iter().map(String::as_str).collect();
                let refs_b: Vec<&str> = b.iter().map(String::as_str).collect();
                let ha = compute_batch_hash(&refs_a);
                let hb = compute_batch_hash(&refs_b);
                prop_assert_ne!(ha, hb, "different sorted inputs must produce different hashes");
            }
        }

        #[test]
        fn prop_sign_verify_roundtrip(
            // Keys are at least MIN_DIGEST_KEY_LENGTH (32) bytes so they pass
            // the key-length guard; the property under test is the roundtrip,
            // not sub-minimum key acceptance.
            key in prop::collection::vec(any::<u8>(), 32..64),
        ) {
            let key_id = derive_key_id(&key);
            let batch_hash = compute_batch_hash(&["roundtrip-evt-a", "roundtrip-evt-b"]);
            let sig = compute_digest_signature(&batch_hash, DIGEST_GENESIS_HASH, &key, &key_id).unwrap();

            // Build a single-entry chain and verify.
            let chain = vec![DigestEntry {
                batch_hash,
                previous_hash: DIGEST_GENESIS_HASH.to_string(),
                digest_signature: sig,
                key_id,
            }];
            let result = verify_chain(&chain, &key).unwrap();
            prop_assert_eq!(result, ChainVerification::Valid { entries_verified: 1 });
        }

        #[test]
        fn prop_digest_signature_deterministic(
            key in prop::collection::vec(any::<u8>(), 32..64),
            batch_hash in "[a-f0-9]{64}",
            prev_hash in "[a-f0-9]{64}",
        ) {
            let key_id = derive_key_id(&key);
            let s1 = compute_digest_signature(&batch_hash, &prev_hash, &key, &key_id).unwrap();
            let s2 = compute_digest_signature(&batch_hash, &prev_hash, &key, &key_id).unwrap();
            prop_assert_eq!(s1, s2, "same inputs must produce identical signature");
        }

        #[test]
        fn prop_digest_signature_is_64_hex(
            key in prop::collection::vec(any::<u8>(), 32..64),
            batch_hash in "[a-f0-9]{16,64}",
        ) {
            let key_id = derive_key_id(&key);
            let sig = compute_digest_signature(&batch_hash, DIGEST_GENESIS_HASH, &key, &key_id).unwrap();
            prop_assert_eq!(sig.len(), 64, "HMAC-SHA256 hex must be 64 chars");
            prop_assert!(sig.chars().all(|c| c.is_ascii_hexdigit()), "must be valid hex");
        }

        #[test]
        fn prop_derive_key_id_deterministic_and_valid(
            key in prop::collection::vec(any::<u8>(), 1..128),
        ) {
            let kid1 = derive_key_id(&key);
            let kid2 = derive_key_id(&key);
            prop_assert_eq!(&kid1, &kid2, "same key must produce same key_id");
            prop_assert_eq!(kid1.len(), 8, "key_id must be 8 hex chars");
            prop_assert!(kid1.chars().all(|c| c.is_ascii_hexdigit()), "key_id must be valid hex");
        }

        #[test]
        fn prop_chain_roundtrip_valid(batch_count in 1..8_usize) {
            let key = b"proptest-chain-key-material-32b!";
            let chain = build_chain(key, batch_count);
            let result = verify_chain(&chain, key).unwrap();
            prop_assert_eq!(
                result,
                ChainVerification::Valid { entries_verified: batch_count },
                "valid chain with {} batches must verify", batch_count
            );
        }

        #[test]
        fn prop_wrong_key_fails_verification(
            correct_key in prop::collection::vec(any::<u8>(), 32..64),
            wrong_key in prop::collection::vec(any::<u8>(), 32..64),
        ) {
            // Only test when keys actually differ.
            if correct_key != wrong_key {
                let chain = build_chain(&correct_key, 1);
                let result = verify_chain(&chain, &wrong_key).unwrap();
                prop_assert_eq!(
                    result,
                    ChainVerification::Invalid {
                        first_mismatch_index: 0,
                        batch_hash: chain.first().unwrap().batch_hash.clone(),
                    }
                );
            }
        }
    }
}
