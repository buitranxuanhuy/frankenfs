#![forbid(unsafe_code)]
//! FrankenFS public API facade.
//!
//! Re-exports core functionality from `ffs-core` through a stable external
//! interface. This is the crate that downstream consumers (CLI, TUI, harness)
//! depend on.

pub use ffs_core::*;
