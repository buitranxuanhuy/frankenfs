#![forbid(unsafe_code)]
//! Inode management.
//!
//! Read, write, create, and delete inodes. Permission checks,
//! timestamp management (atime/ctime/mtime/crtime), flag handling,
//! and inode table I/O.
