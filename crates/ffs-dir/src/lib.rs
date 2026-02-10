#![forbid(unsafe_code)]
//! Directory operations.
//!
//! Linear directory entry scan, htree (hashed B-tree) lookup with
//! dx_hash computation (half-MD4 and TEA), directory entry creation
//! and deletion, and `..`/`.` management.
