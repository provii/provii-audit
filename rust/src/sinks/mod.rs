// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Audit sink trait and implementations.
//!
//! Sinks are the output destinations for audit events. The [`AuditSink`] trait
//! abstracts dispatch so that production code writes to a Cloudflare Queue
//! while test code can substitute a stub.

#![forbid(unsafe_code)]

pub mod queue;

pub use queue::QueueAuditSink;

use async_trait::async_trait;

use crate::error::AuditError;
use crate::event::AuditEvent;

/// Trait for audit event output destinations.
///
/// `Send + Sync` supertraits are required so `Arc<dyn AuditSink>` can live
/// inside `AppState`, which must itself be `Send + Sync` for static storage.
/// Cloudflare Workers are single threaded; the `worker` crate provides the
/// blanket `unsafe impl Send/Sync` for its types.
///
/// The `?Send` bound on `async_trait` produces a `!Send` future, which is
/// correct for WASM where no thread spawning occurs.
#[async_trait(?Send)]
pub trait AuditSink: Send + Sync {
    /// Write an audit event to this sink.
    ///
    /// Implementations should tolerate transient failures without panicking.
    async fn write(&self, event: &AuditEvent) -> Result<(), AuditError>;
}
