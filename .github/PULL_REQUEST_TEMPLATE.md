## What changed

<!-- Describe the change in 1-2 sentences. Link to related issues if applicable. -->

## Why

<!-- What problem does this solve or what requirement does it address? -->

## How to test

<!-- Steps for the reviewer to verify the change works correctly. -->

## Checklist

- [ ] `cargo test --all-features --locked` passes
- [ ] `cargo clippy --all-features -- -D warnings` passes
- [ ] `cargo build --target wasm32-unknown-unknown --locked` compiles
- [ ] No new `unwrap()` or `expect()` in library code
- [ ] PII-sensitive fields go through `PrivacyContext` or `strip_pii`
