# Contributing

Thank you for considering a contribution to provii-audit. Changes come in by pull request. The library ships inside security-critical Cloudflare Workers, so the bar for correctness is high.

## Before you start

Open an issue describing the problem or improvement before writing code. This avoids wasted effort on changes that conflict with the project's direction or are already in progress.

## Development setup

You need a stable Rust toolchain (1.75 or later) and the `wasm32-unknown-unknown` target.

```sh
rustup target add wasm32-unknown-unknown
```

## Pull request flow

1. Fork the repository and create a branch from `main`.
2. Make your changes in `rust/src/` or `rust/fuzz/`.
4. Run the full check suite locally before pushing.
5. Open a pull request against `main` with a clear description of what changed and why.

## Required checks

Every PR must pass these before review:

```sh
cd rust
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo build --target wasm32-unknown-unknown --all-features --locked
```

## Code standards

- No `unwrap()` or `expect()` in library code. Use `Result` and `thiserror`.
- No `unsafe` without a documented safety invariant.
- All secret material must use `zeroize`. Comparisons of secret data must use constant time primitives.
- PII-sensitive fields go through `PrivacyContext` or `strip_pii`.
- Australian English in comments and documentation.

## Contributor Licence Agreement

First-time contributors are asked to sign the [CLA](./CLA.md) by replying to the automated comment on their pull request.
