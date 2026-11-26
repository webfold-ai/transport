//! Durable object storage: the signed objects exactly as they crossed the wire.
//!
//! Because every object is self-authenticating, the persisted form needs no extra integrity
//! layer of its own: on load each object is decoded (signature re-verified) and re-applied
//! through the same validation as a live one, so a corrupted, truncated or tampered file is
//! refused rather than trusted. Files are written 0600 via a temp file, fsync and rename, and
//! the directory is fsynced, so a crash leaves the old object or the new one, never half.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use transport::zone_sync::MAX_BODY_LEN;

/// Largest file we will read back (an encoded object is at most body + id + signer + signature).
const MAX_FILE: usize = MAX_BODY_LEN + 1024;

/// What `load_all` returns: `(key, bytes)` pairs, and the escaped names of entries that were skipped.
pub type Loaded = (Vec<(String, Vec<u8>)>, Vec<String>);

/// Where signed objects live between restarts.
pub trait ObjectStore: Send + Sync {
    /// Durably replace the object stored under `key`.
    fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()>;
    /// Every stored object as `(key, bytes)`. Unreadable or oversized entries are skipped and
    /// reported through the second element of the result.
    fn load_all(&self) -> std::io::Result<Loaded>;
}

/// In-memory store (tests, ephemeral nodes).
#[derive(Default)]
pub struct MemoryObjectStore {
    map: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryObjectStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrite raw bytes under a key (tests use this to simulate disk corruption).
    pub fn corrupt(&self, key: &str, bytes: Vec<u8>) {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_string(), bytes);
    }
}

impl ObjectStore for MemoryObjectStore {
    fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_string(), bytes.to_vec());
        Ok(())
    }

    fn load_all(&self) -> std::io::Result<Loaded> {
        let m = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok((
            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Vec::new(),
        ))
    }
}

/// A directory of `<key>.obj` files.
pub struct FileObjectStore {
    dir: PathBuf,
}

impl FileObjectStore {
    /// Open (creating, mode 0700) `dir`.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        Ok(FileObjectStore {
            dir: dir.to_path_buf(),
        })
    }

    fn valid_key(key: &str) -> bool {
        !key.is_empty()
            && key.len() <= 80
            && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }
}

impl ObjectStore for FileObjectStore {
    fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        if !Self::valid_key(key) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bad object key",
            ));
        }
        let tmp = self.dir.join(format!(".{key}.tmp"));
        let fin = self.dir.join(format!("{key}.obj"));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &fin)?;
        if let Ok(d) = std::fs::File::open(&self.dir) {
            d.sync_all()?;
        }
        Ok(())
    }

    fn load_all(&self) -> std::io::Result<Loaded> {
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(key) = name.strip_suffix(".obj") else {
                continue;
            };
            if !Self::valid_key(key) {
                skipped.push(crate::escape::esc(&name));
                continue;
            }
            let meta = entry.metadata()?;
            if !meta.is_file() || usize::try_from(meta.len()).map_or(true, |l| l > MAX_FILE) {
                skipped.push(crate::escape::esc(&name));
                continue;
            }
            match std::fs::read(entry.path()) {
                Ok(b) => out.push((key.to_string(), b)),
                Err(_) => skipped.push(crate::escape::esc(&name)),
            }
        }
        out.sort();
        Ok((out, skipped))
    }
}
