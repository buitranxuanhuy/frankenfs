#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_core::FrankenFsEngine;
use ffs_types::InodeNumber;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeMetadata {
    pub ino: InodeNumber,
    pub size: u64,
    pub mode: u16,
    pub links: u16,
}

#[derive(Debug, Clone)]
pub struct MountOptions {
    pub read_only: bool,
    pub allow_other: bool,
    pub max_write: u32,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            allow_other: false,
            max_write: 128 * 1024,
        }
    }
}

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("operation not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("invalid mountpoint: {0}")]
    InvalidMountpoint(String),
    #[error("engine lock poisoned")]
    EngineLock,
    #[error("runtime error: {0}")]
    Runtime(String),
}

pub trait FuseBackend {
    fn lookup(&self, path: &Path, cx: &Cx) -> Result<Option<InodeMetadata>, FuseError>;
    fn read(&self, ino: InodeNumber, offset: u64, size: u32, cx: &Cx)
    -> Result<Vec<u8>, FuseError>;
}

#[derive(Debug, Clone)]
pub struct FrankenFuseMount {
    mountpoint: PathBuf,
    options: MountOptions,
    engine: Arc<Mutex<FrankenFsEngine>>,
}

impl FrankenFuseMount {
    pub fn new(
        mountpoint: impl Into<PathBuf>,
        options: MountOptions,
        engine: Arc<Mutex<FrankenFsEngine>>,
    ) -> Result<Self, FuseError> {
        let mountpoint = mountpoint.into();
        if mountpoint.as_os_str().is_empty() {
            return Err(FuseError::InvalidMountpoint(
                "mountpoint cannot be empty".to_owned(),
            ));
        }

        Ok(Self {
            mountpoint,
            options,
            engine,
        })
    }

    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    #[must_use]
    pub fn options(&self) -> &MountOptions {
        &self.options
    }

    /// Placeholder mount entrypoint.
    ///
    /// Real kernel-FUSE integration is tracked in parity docs and intentionally
    /// staged after core metadata + MVCC conformance milestones.
    pub fn mount(&self) -> Result<(), FuseError> {
        let _snapshot = self
            .engine
            .lock()
            .map_err(|_| FuseError::EngineLock)?
            .snapshot();
        Err(FuseError::NotImplemented("FUSE mount runtime"))
    }
}
