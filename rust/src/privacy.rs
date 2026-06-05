// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Privacy-preserving hashing for audit log entries.
//!
//! All IP addresses and user agents are hashed with domain-separated,
//! keyed HMAC-SHA-256 before persistence. Persisted audit events never
//! contain raw PII.
//!
//! `hash_*` functions in this module perform HMAC-SHA-256 with domain
//! separation for PII fields. The `consumer` module's `compute_*`
//! functions serve a different purpose: SHA-256 digests and HMAC
//! signatures for the tamper-detection chain.
//!
//! Domain separation prevents cross-use collisions. An IP hash cannot be
//! mistaken for a UA hash because each uses a distinct domain tag prefix
//! fed as message content to the HMAC. The construction is
//! `HMAC-SHA-256(salt, domain_tag || input)`, where the deployment salt
//! is used as the HMAC key.
//!
//! The salt is loaded from Cloudflare Secrets Store at startup and held
//! in a [`PrivacyContext`] that zeroises the key material on drop.

#![forbid(unsafe_code)]

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::AuditError;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag for IP address hashing.
const IP_DOMAIN_TAG: &[u8] = b"provii-ip-v0";

/// Domain separation tag for user agent hashing.
const UA_DOMAIN_TAG: &[u8] = b"provii-ua-v0";

/// Domain separation tag for origin hashing.
const ORIGIN_DOMAIN_TAG: &[u8] = b"provii-origin-v0";

/// Minimum acceptable salt length in bytes.
const MIN_SALT_LENGTH: usize = 32;

/// Hash an IP address with domain separation.
///
/// Computes `HMAC-SHA-256(salt, IP_DOMAIN_TAG || ip)`.
/// The salt is the HMAC key. The domain tag is fed as message content,
/// preventing collisions with UA hashes even when the same key and
/// input value are used.
///
/// # Arguments
///
/// * `ip` -- The raw IP address string (IPv4 or IPv6).
/// * `salt` -- A secret salt used as the HMAC key, at least 32 bytes.
///
/// # Returns
///
/// A deterministic 64-character lowercase hex string.
///
/// # Errors
///
/// Returns [`AuditError::HmacKeyError`] if the HMAC key is rejected.
pub(crate) fn hash_ip(ip: &str, salt: &[u8]) -> Result<String, AuditError> {
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|e| AuditError::hmac_key(format!("HMAC key rejected: {e}")))?;
    mac.update(IP_DOMAIN_TAG);
    mac.update(ip.as_bytes());
    // Neither hmac 0.12 nor 0.13 implements Zeroize/ZeroizeOnDrop for Mac
    // types. This is an upstream gap: digest's buffer_fixed! macro backs
    // FixedHashTraits (which includes ZeroizeOnDrop) but MacTraits does not.
    // finalize() consumes the MAC, dropping message-derived state; the ipad/opad key
    // schedule persists in memory until drop. In WASM, function-local data
    // remains in linear memory after the stack frame returns until overwritten.
    // The HMAC is function-scoped and lives only for the duration of this call.
    // Source key material is owned by PrivacyContext which zeroises on drop.
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

/// Hash a user agent with domain separation.
///
/// Computes `HMAC-SHA-256(salt, UA_DOMAIN_TAG || ua)`.
/// The salt is the HMAC key. The domain tag is fed as message content.
///
/// # Arguments
///
/// * `ua` -- The raw user agent string.
/// * `salt` -- A secret salt used as the HMAC key, at least 32 bytes.
///
/// # Returns
///
/// A deterministic 64-character lowercase hex string.
///
/// # Errors
///
/// Returns [`AuditError::HmacKeyError`] if the HMAC key is rejected.
pub(crate) fn hash_user_agent(ua: &str, salt: &[u8]) -> Result<String, AuditError> {
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|e| AuditError::hmac_key(format!("HMAC key rejected: {e}")))?;
    mac.update(UA_DOMAIN_TAG);
    mac.update(ua.as_bytes());
    // See hash_ip for HMAC zeroisation gap note (hmac 0.12/0.13, WASM linear memory).
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

/// Hash an origin with domain separation.
///
/// Computes `HMAC-SHA-256(salt, ORIGIN_DOMAIN_TAG || origin)`.
/// The salt is the HMAC key. The domain tag prevents collisions with
/// IP and UA hashes.
///
/// # Arguments
///
/// * `origin` -- The request origin header value.
/// * `salt` -- A secret salt used as the HMAC key, at least 32 bytes.
///
/// # Returns
///
/// A deterministic 64-character lowercase hex string.
///
/// # Errors
///
/// Returns [`AuditError::HmacKeyError`] if the HMAC key is rejected.
pub(crate) fn hash_origin(origin: &str, salt: &[u8]) -> Result<String, AuditError> {
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|e| AuditError::hmac_key(format!("HMAC key rejected: {e}")))?;
    mac.update(ORIGIN_DOMAIN_TAG);
    mac.update(origin.as_bytes());
    // See hash_ip for HMAC zeroisation gap note (hmac 0.12/0.13, WASM linear memory).
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

/// Holds the HMAC key (salt) for IP and UA hashing.
///
/// The key material is zeroised when the context is dropped. Construction
/// rejects keys shorter than 32 bytes and all-zero keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivacyContext {
    salt: Box<[u8]>,
}

impl PrivacyContext {
    /// Create a new privacy context from a salt.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::PrivacySaltTooShort`] if the salt is shorter
    /// than 32 bytes, or [`AuditError::PrivacySaltAllZeros`] if every byte
    /// is zero (trivially reversible hashes).
    pub fn new(mut salt: Vec<u8>) -> Result<Self, AuditError> {
        if salt.len() < MIN_SALT_LENGTH {
            let actual = salt.len();
            salt.zeroize();
            return Err(AuditError::PrivacySaltTooShort {
                minimum: MIN_SALT_LENGTH,
                actual,
            });
        }
        if salt.iter().all(|&b| b == 0) {
            salt.zeroize();
            return Err(AuditError::PrivacySaltAllZeros);
        }
        Ok(Self {
            salt: salt.into_boxed_slice(),
        })
    }

    /// Hash an IP address using this context's salt.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::HmacKeyError`] if the HMAC key is rejected.
    pub fn hash_ip(&self, ip: &str) -> Result<String, AuditError> {
        hash_ip(ip, &self.salt)
    }

    /// Hash a user agent using this context's salt.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::HmacKeyError`] if the HMAC key is rejected.
    pub fn hash_user_agent(&self, ua: &str) -> Result<String, AuditError> {
        hash_user_agent(ua, &self.salt)
    }

    /// Hash an origin using this context's salt.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::HmacKeyError`] if the HMAC key is rejected.
    pub fn hash_origin(&self, origin: &str) -> Result<String, AuditError> {
        hash_origin(origin, &self.salt)
    }
}

impl std::fmt::Debug for PrivacyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyContext")
            .field("salt", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> Vec<u8> {
        b"test-salt-minimum-32-bytes-long!!".to_vec()
    }

    #[test]
    fn hash_ip_is_deterministic() {
        let salt = test_salt();
        assert_eq!(
            hash_ip("192.168.1.1", &salt).unwrap(),
            hash_ip("192.168.1.1", &salt).unwrap()
        );
    }

    #[test]
    fn different_ips_different_hashes() {
        let salt = test_salt();
        assert_ne!(
            hash_ip("192.168.1.1", &salt).unwrap(),
            hash_ip("192.168.1.2", &salt).unwrap()
        );
    }

    #[test]
    fn different_salts_different_hashes() {
        let salt_a = b"salt-aaaa-32-bytes-long-padding!!".to_vec();
        let salt_b = b"salt-bbbb-32-bytes-long-padding!!".to_vec();
        assert_ne!(
            hash_ip("10.0.0.1", &salt_a).unwrap(),
            hash_ip("10.0.0.1", &salt_b).unwrap()
        );
    }

    #[test]
    fn output_is_64_hex_chars() {
        let h = hash_ip("::1", &test_salt()).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ua_hash_is_deterministic() {
        let salt = test_salt();
        assert_eq!(
            hash_user_agent("Mozilla/5.0", &salt).unwrap(),
            hash_user_agent("Mozilla/5.0", &salt).unwrap()
        );
    }

    #[test]
    fn origin_hash_is_deterministic() {
        let salt = test_salt();
        assert_eq!(
            hash_origin("https://example.com", &salt).unwrap(),
            hash_origin("https://example.com", &salt).unwrap()
        );
    }

    #[test]
    fn origin_hash_is_64_hex_chars() {
        let h = hash_origin("https://example.com", &test_salt()).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn origin_hash_differs_from_ip_and_ua() {
        let salt = test_salt();
        let val = "https://example.com";
        let origin_h = hash_origin(val, &salt).unwrap();
        let ip_h = hash_ip(val, &salt).unwrap();
        let ua_h = hash_user_agent(val, &salt).unwrap();
        assert_ne!(origin_h, ip_h);
        assert_ne!(origin_h, ua_h);
    }

    #[test]
    fn privacy_context_hash_origin() {
        let ctx = PrivacyContext::new(test_salt()).unwrap();
        let h = ctx.hash_origin("https://example.com").unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn ip_and_ua_hashes_differ_for_same_input() {
        let salt = test_salt();
        assert_ne!(
            hash_ip("test-value", &salt).unwrap(),
            hash_user_agent("test-value", &salt).unwrap()
        );
    }

    #[test]
    fn privacy_context_rejects_short_salt() {
        let result = PrivacyContext::new(b"too-short".to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn privacy_context_accepts_valid_salt() {
        let ctx = PrivacyContext::new(test_salt());
        assert!(ctx.is_ok());
    }

    #[test]
    fn privacy_context_methods() {
        let ctx = PrivacyContext::new(test_salt()).unwrap();
        let ip_hash = ctx.hash_ip("192.168.1.1").unwrap();
        let ua_hash = ctx.hash_user_agent("Mozilla/5.0").unwrap();

        assert_eq!(ip_hash.len(), 64);
        assert_eq!(ua_hash.len(), 64);
        assert_ne!(ip_hash, ua_hash);
    }

    #[test]
    fn handles_ipv6() {
        let salt = test_salt();
        let h = hash_ip("2001:0db8:85a3::8a2e:0370:7334", &salt).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_ip("2001:0db8:85a3::8a2e:0370:7334", &salt).unwrap());
    }

    #[test]
    fn handles_unknown_ip() {
        let h = hash_ip("unknown", &test_salt()).unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn rejects_31_byte_salt() {
        let short_salt = vec![0xAB; 31];
        let result = PrivacyContext::new(short_salt);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_32_byte_salt() {
        let exact_salt = vec![0xAB; 32];
        let result = PrivacyContext::new(exact_salt);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_all_zero_32_byte_salt() {
        let zero_salt = vec![0x00; 32];
        let result = PrivacyContext::new(zero_salt);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("all zeros"),
            "expected all-zeros error, got: {err}"
        );
    }

    #[test]
    fn rejects_all_zero_64_byte_salt() {
        let zero_salt = vec![0x00; 64];
        let result = PrivacyContext::new(zero_salt);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_salt_with_single_nonzero_byte() {
        let mut salt = vec![0x00; 32];
        if let Some(byte) = salt.get_mut(31) {
            *byte = 0x01;
        }
        let result = PrivacyContext::new(salt);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_longer_salt() {
        let long_salt = vec![0xAB; 64];
        let result = PrivacyContext::new(long_salt);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_ip_produces_valid_hash() {
        let salt = test_salt();
        let h = hash_ip("", &salt).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn empty_ua_produces_valid_hash() {
        let salt = test_salt();
        let h = hash_user_agent("", &salt).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn empty_ip_and_ua_differ() {
        let salt = test_salt();
        assert_ne!(
            hash_ip("", &salt).unwrap(),
            hash_user_agent("", &salt).unwrap()
        );
    }

    /// Known-answer test for IP hashing.
    ///
    /// Computed with salt = `b"test-salt-minimum-32-bytes-long!!"` and
    /// input `"192.168.1.1"`. Catches construction drift: a changed
    /// domain tag, reordered concatenation, or altered formatting would
    /// break this assertion.
    #[test]
    fn known_answer_ip_hash() {
        let salt = test_salt();
        let result = hash_ip("192.168.1.1", &salt).unwrap();
        assert_eq!(
            result,
            "4aaadcd1c06ba477c05782ff45ca35241f708f8f79693f58b2839e06d2c4302b"
        );
    }

    /// Known-answer test for UA hashing.
    ///
    /// Computed with salt = `b"test-salt-minimum-32-bytes-long!!"` and
    /// input `"Mozilla/5.0"`.
    #[test]
    fn known_answer_ua_hash() {
        let salt = test_salt();
        let result = hash_user_agent("Mozilla/5.0", &salt).unwrap();
        assert_eq!(
            result,
            "24952a1f7652d958c67cdf97c5ccb8c35cf93f8590030ad2022de3abc87643df"
        );
    }

    /// The custom `Debug` impl on `PrivacyContext` must not leak the
    /// salt value or its length. A regression here would expose secret
    /// key material in any log line that debug-prints the context.
    #[test]
    fn debug_output_does_not_leak_salt() {
        let salt = b"super-secret-salt-32-bytes-long!".to_vec();
        let ctx = PrivacyContext::new(salt).unwrap();
        let debug_output = format!("{ctx:?}");

        assert!(
            !debug_output.contains("super-secret"),
            "Debug output leaked salt: {debug_output}"
        );
        assert!(
            !debug_output.contains("32"),
            "Debug output leaked salt length: {debug_output}"
        );
        assert!(
            debug_output.contains("REDACTED"),
            "Debug output missing redaction: {debug_output}"
        );
    }
}
