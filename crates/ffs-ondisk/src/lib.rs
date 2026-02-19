#![forbid(unsafe_code)]
//! On-disk format parsing for ext4 and btrfs structures.
//!
//! Pure parsing crate — no I/O, no side effects. Parses byte slices into
//! typed Rust structures representing ext4 superblocks, group descriptors,
//! inodes, extent trees, directory entries, JBD2 journal structures, and
//! btrfs superblocks, headers, leaf item tables, and internal node key-pointers.

pub mod btrfs;
pub mod ext4;

pub use btrfs::{
    BtrfsChunkEntry, BtrfsHeader, BtrfsItem, BtrfsKey, BtrfsKeyPtr, BtrfsPhysicalMapping,
    BtrfsStripe, BtrfsSuperblock, map_logical_to_physical, parse_internal_items, parse_leaf_items,
    parse_sys_chunk_array, verify_superblock_checksum as verify_btrfs_superblock_checksum,
    verify_tree_block_checksum as verify_btrfs_tree_block_checksum,
};
pub use ext4::{
    DirBlockIter, EXT4_ERROR_FS, EXT4_ORPHAN_FS, EXT4_VALID_FS, Ext4CompatFeatures, Ext4DirEntry,
    Ext4DirEntryRef, Ext4DirEntryTail, Ext4DxEntry, Ext4DxRoot, Ext4Extent, Ext4ExtentHeader,
    Ext4ExtentIndex, Ext4FileType, Ext4GroupDesc, Ext4ImageReader, Ext4IncompatFeatures, Ext4Inode,
    Ext4RoCompatFeatures, Ext4Superblock, Ext4Xattr, ExtentTree, FeatureDiagnostics, InodeLocation,
    dx_hash, ext4_chksum, iter_dir_block, lookup_in_dir_block, parse_dir_block, parse_dx_root,
    parse_extent_tree, parse_ibody_xattrs, parse_inode_extent_tree, parse_xattr_block,
    verify_dir_block_checksum, verify_extent_block_checksum, verify_group_desc_checksum,
    verify_inode_checksum,
};
