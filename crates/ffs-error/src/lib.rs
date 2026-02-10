#![forbid(unsafe_code)]
//! Error types for FrankenFS.
//!
//! Defines `FfsError` and a `Result<T>` alias used throughout the workspace.
//! Includes errno mappings for FUSE response codes.

use thiserror::Error;

/// Unified error type for all FrankenFS operations.
#[derive(Debug, Error)]
pub enum FfsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupt metadata at block {block}: {detail}")]
    Corruption { block: u64, detail: String },

    #[error("invalid on-disk format: {0}")]
    Format(String),

    #[error("MVCC conflict: transaction {tx} conflicts on block {block}")]
    MvccConflict { tx: u64, block: u64 },

    #[error("operation cancelled")]
    Cancelled,

    #[error("no space left on device")]
    NoSpace,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied")]
    PermissionDenied,

    #[error("not a directory")]
    NotDirectory,

    #[error("is a directory")]
    IsDirectory,

    #[error("directory not empty")]
    NotEmpty,

    #[error("name too long")]
    NameTooLong,

    #[error("file exists")]
    Exists,

    #[error("repair failed: {0}")]
    RepairFailed(String),
}

impl FfsError {
    /// Convert this error into a POSIX errno suitable for FUSE replies.
    #[must_use]
    pub fn to_errno(&self) -> libc::c_int {
        match self {
            Self::Io(err) => err.raw_os_error().unwrap_or(libc::EIO),
            Self::Corruption { .. } | Self::RepairFailed(_) => libc::EIO,
            Self::Format(_) => libc::EINVAL,
            Self::MvccConflict { .. } => libc::EAGAIN,
            Self::Cancelled => libc::ECANCELED,
            Self::NoSpace => libc::ENOSPC,
            Self::NotFound(_) => libc::ENOENT,
            Self::PermissionDenied => libc::EACCES,
            Self::NotDirectory => libc::ENOTDIR,
            Self::IsDirectory => libc::EISDIR,
            Self::NotEmpty => libc::ENOTEMPTY,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::Exists => libc::EEXIST,
        }
    }
}

/// Result alias using `FfsError`.
pub type Result<T> = std::result::Result<T, FfsError>;
