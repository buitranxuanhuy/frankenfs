#![forbid(unsafe_code)]
//! Extended attributes (xattr).
//!
//! Inline xattr storage (after inode extra fields within the inode table
//! entry) and external xattr block storage. Namespace routing for user,
//! system, security, and trusted attribute namespaces.
