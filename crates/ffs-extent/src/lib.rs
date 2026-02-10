#![forbid(unsafe_code)]
//! Extent mapping: logical block to physical block resolution.
//!
//! Resolves file logical offsets to physical block addresses via the
//! extent B+tree, allocates new extents, and detects holes (unwritten
//! regions) in file mappings.
