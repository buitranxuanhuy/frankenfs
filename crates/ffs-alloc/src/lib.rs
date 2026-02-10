#![forbid(unsafe_code)]
//! Block and inode allocation.
//!
//! mballoc-style multi-block allocator (buddy system, best-fit,
//! per-inode and per-locality-group preallocation) and Orlov
//! inode allocator for directory spreading.
