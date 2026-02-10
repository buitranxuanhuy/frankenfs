#![forbid(unsafe_code)]
//! JBD2-compatible journal replay and native COW journal.
//!
//! Handles transaction lifecycle (running → committing → committed),
//! descriptor blocks, commit blocks, revoke blocks, and the native
//! copy-on-write journal for FrankenFS's MVCC mode.
