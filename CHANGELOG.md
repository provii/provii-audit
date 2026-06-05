# Changelog

All notable changes to provii-audit.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow [0ver](https://0ver.org/): the major version stays at zero.

## [v0.1.0] (unreleased)

First Provii release of the audit logging library.

- Privacy-preserving HMAC-SHA-256 hashing of IP addresses, user agents, and origin headers with domain-separated tags.
- 23-field `AuditEvent` record format with typed enums for severity, environment, event category, actor type, and outcome.
- Cloudflare Queue dispatch via `QueueAuditSink` for asynchronous D1 persistence.
- SHA-256 digest chain with HMAC-SHA-256 signed entries for tamper-evident batch verification.
- Defence-in-depth PII stripping of IPv4, IPv6, email, and date-of-birth patterns from free-text fields.
