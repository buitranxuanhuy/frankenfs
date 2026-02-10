#![forbid(unsafe_code)]
//! ext4 extent B+tree operations.
//!
//! Search, insert, split, merge, and tree walk over the extent tree
//! stored in inode `i_block[15]` fields and internal/leaf nodes.
