//! Publish one metadata checkpoint without truncating its previous version.

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod access_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_security;
#[cfg(windows)]
mod windows_security;

use crate::error::Result;
use parking_lot::Mutex;
use same_file::Handle;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Remembers the last checkpoint this writer successfully made durable.
/// The serialized digest avoids a second in-memory copy of large field indexes.
/// File identity prevents a deleted/replaced checkpoint from being skipped.
#[derive(Debug, Default)]
pub(crate) struct Checkpoint {
    saved: Mutex<Option<SavedCheckpoint>>,
}

#[derive(Debug)]
struct SavedCheckpoint {
    path: PathBuf,
    digest: [u8; 32],
    identity: Handle,
    stamp: FileStamp,
}

#[derive(Debug, PartialEq)]
struct FileStamp {
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    changed: (i64, i64),
}

impl FileStamp {
    fn read(metadata: Metadata) -> io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

// A cloned manager owns a new checkpoint writer. It must establish durability
// itself rather than inherit another manager's publication acknowledgement.
impl Clone for Checkpoint {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Checkpoint {
    pub(crate) fn save(&self, path: &Path, chunks: &[&[u8]]) -> Result<()> {
        self.save_with(path, chunks, || {
            atomic_write(path, |file| {
                for chunk in chunks {
                    file.write_all(chunk)?;
                }
                Ok(())
            })
        })
    }

    fn save_with(
        &self,
        path: &Path,
        chunks: &[&[u8]],
        publish: impl FnOnce() -> Result<File>,
    ) -> Result<()> {
        let mut hash = Sha256::new();
        for chunk in chunks {
            hash.update(chunk);
        }
        let digest: [u8; 32] = hash.finalize().into();
        let mut saved = self.saved.lock();
        if let Some(previous) = saved.as_ref() {
            if previous.path == path && previous.digest == digest {
                if let Ok(current) = Handle::from_path(path) {
                    if current == previous.identity
                        && current
                            .as_file()
                            .metadata()
                            .and_then(FileStamp::read)
                            .ok()
                            .as_ref()
                            == Some(&previous.stamp)
                    {
                        return Ok(());
                    }
                }
            }
        }

        // Clear BEFORE attempting publication: rename may succeed and then
        // directory sync fail. Retrying must run all barriers in that case.
        *saved = None;
        let file = publish()?;

        // Failure to obtain a cache identity is not a failed checkpoint: the
        // publication above is already durable. It just prevents skipping the
        // next save. Concurrent out-of-band file edits are not supported.
        if let Ok(identity) = Handle::from_file(file) {
            if let Ok(stamp) = identity.as_file().metadata().and_then(FileStamp::read) {
                *saved = Some(SavedCheckpoint {
                    path: path.to_owned(),
                    digest,
                    identity,
                    stamp,
                });
            }
        }
        Ok(())
    }
}

/// Write a complete checkpoint beside its destination, sync it, then replace
/// the destination atomically. Readers see either the old file or the new one.
/// This is a per-file guarantee, not a transaction across metadata files.
///
/// Unix also syncs the directory so the replacement survives a power loss.
/// Windows supports the file sync and atomic replacement, but has no portable
/// directory-sync equivalent here. Errors before replacement leave the old
/// checkpoint intact; a directory-sync error is returned after replacement.
///
/// Replacements preserve ownership, mode, Linux POSIX ACLs and macOS extended
/// ACLs. Linux requires working ACL/security-xattr APIs and an identical initial
/// security label on the staging file, and
/// restores capabilities after writing. Content-bound IMA/EVM signatures and
/// unfamiliar system ACL xattrs are rejected. Security attributes hidden from
/// the caller and path-based MAC policy are outside this preservation contract;
/// store policy must cover the staging names as well as the final names.
/// macOS authorization labels (com.apple.macl) are rejected rather than lost.
/// Replacing an existing Unix checkpoint requires reading its security metadata
/// through an open file and permission to restore its ownership and ACL.
///
/// Windows preserves source owner/group, native DACL/ACE flags and integrity
/// policy through descriptor-at-creation verification before any payload bytes.
/// Audit-only SACLs are outside the preservation contract; other enforcement
/// SACL components, EFS/reparse files, and readonly destinations are rejected.
/// See windows_security for required access and external-policy boundaries.
///
/// Unique temporary names allow concurrent callers to write independently.
/// A process killed before replacement can leave an unused temporary file;
/// loaders only open the final checkpoint name.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn atomic_write(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<File> {
    // A bare relative filename has an empty parent, which means the current
    // directory rather than a directory that can be opened by its empty name.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    #[cfg(unix)]
    let directory = File::open(parent)?;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let (mut temporary, source) = unix_security::prepare(path, parent)?;

    #[cfg(windows)]
    let (mut temporary, security) = windows_security::prepare(path, parent)?;

    write(temporary.as_file_mut())?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unix_security::finish(source.as_ref(), temporary.as_file())?;
    #[cfg(windows)]
    windows_security::finish(security.as_ref(), temporary.as_file())?;
    temporary.as_file().sync_all()?;
    #[cfg(not(windows))]
    let published = temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(windows)]
    let published = {
        // tempfile::persist clears Windows attributes through a new path-based
        // access check. This native same-volume rename retains the controls and
        // attributes already verified through our handle.
        let (file, temporary_path) = temporary.into_parts();
        std::fs::rename(&temporary_path, path)?;
        file
    };

    #[cfg(unix)]
    directory.sync_all()?;

    Ok(published)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn atomic_write(_path: &Path, _write: impl FnOnce(&mut File) -> Result<()>) -> Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic checkpoint access-control preservation is unsupported on this platform",
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn unchanged_checkpoint_skips_publication_but_changed_bytes_replace_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        let checkpoint = Checkpoint::default();
        checkpoint.save(&path, &[b"old", b" bytes"]).unwrap();
        let before = Handle::from_path(&path).unwrap();
        let stamp = FileStamp::read(before.as_file().metadata().unwrap()).unwrap();

        checkpoint
            .save_with(&path, &[b"old bytes"], || {
                panic!("unchanged durable checkpoint must not publish");
            })
            .unwrap();
        assert_eq!(Handle::from_path(&path).unwrap(), before);
        assert_eq!(
            FileStamp::read(fs::metadata(&path).unwrap()).unwrap(),
            stamp
        );

        checkpoint.save(&path, &[b"new bytes"]).unwrap();
        assert_ne!(Handle::from_path(&path).unwrap(), before);
        assert_eq!(fs::read(&path).unwrap(), b"new bytes");
    }

    #[test]
    fn failed_publication_invalidates_prior_acknowledgement() {
        for replace_first in [false, true] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("state.bin");
            let checkpoint = Checkpoint::default();
            checkpoint.save(&path, &[b"old"]).unwrap();
            let result = checkpoint.save_with(&path, &[b"new"], || {
                if replace_first {
                    // Model an error after rename, such as failed directory sync.
                    // The caller must not infer success from the new file's bytes.
                    atomic_write(&path, |file| Ok(file.write_all(b"new")?))?;
                }
                Err(io::Error::new(io::ErrorKind::Other, "publication failed").into())
            });
            assert!(result.is_err());
            assert!(checkpoint.saved.lock().is_none());
            let current = Handle::from_path(&path).unwrap();
            let bytes: &[u8] = if replace_first { b"new" } else { b"old" };

            // Even equal on-disk content must be republished after the error.
            checkpoint.save(&path, &[bytes]).unwrap();
            assert_ne!(Handle::from_path(&path).unwrap(), current);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn missing_replaced_and_modified_destinations_are_repaired() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        let checkpoint = Checkpoint::default();
        checkpoint.save(&path, &[b"expected"]).unwrap();

        atomic_write(&path, |file| Ok(file.write_all(b"replaced")?)).unwrap();
        checkpoint.save(&path, &[b"expected"]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"expected");

        fs::write(&path, b"short").unwrap();
        checkpoint.save(&path, &[b"expected"]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"expected");

        fs::remove_file(&path).unwrap();
        checkpoint.save(&path, &[b"expected"]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"expected");
    }

    #[test]
    fn another_path_or_writer_must_establish_its_own_durability() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        let alias = dir.path().join("alias.bin");
        let checkpoint = Checkpoint::default();
        checkpoint.save(&path, &[b"same"]).unwrap();
        let original = Handle::from_path(&path).unwrap();

        // A second hard-link name has not had its directory entry synced by us.
        fs::hard_link(&path, &alias).unwrap();
        checkpoint.save(&alias, &[b"same"]).unwrap();
        assert_ne!(Handle::from_path(&alias).unwrap(), original);

        let before = Handle::from_path(&alias).unwrap();
        checkpoint.clone().save(&alias, &[b"same"]).unwrap();
        assert_ne!(Handle::from_path(&alias).unwrap(), before);
        let before = Handle::from_path(&alias).unwrap();
        Checkpoint::default().save(&alias, &[b"same"]).unwrap();
        assert_ne!(Handle::from_path(&alias).unwrap(), before);
    }

    #[test]
    fn partial_write_error_preserves_previous_checkpoint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"complete previous checkpoint").unwrap();

        let result = atomic_write(&path, |file| {
            file.write_all(b"partial")?;
            assert_eq!(fs::read(&path)?, b"complete previous checkpoint");
            Err(io::Error::new(io::ErrorKind::Other, "injected write failure").into())
        });

        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"complete previous checkpoint");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_first_write_leaves_no_checkpoint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        let result = atomic_write(&path, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::new(io::ErrorKind::Other, "injected write failure").into())
        });
        assert!(result.is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn replacement_keeps_old_open_file_intact() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("branches.bin");
        atomic_write(&path, |file| Ok(file.write_all(b"old checkpoint")?)).unwrap();
        let mut old_file = File::open(&path).unwrap();

        atomic_write(&path, |file| Ok(file.write_all(b"new")?)).unwrap();

        let mut old_bytes = Vec::new();
        old_file.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(old_bytes, b"old checkpoint");
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn replacement_failure_is_reported_and_cleans_temporary_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        fs::create_dir(&path).unwrap();
        let result = atomic_write(&path, |file| Ok(file.write_all(b"checkpoint")?));
        assert!(result.is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn first_checkpoint_uses_normal_creation_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let ordinary = dir.path().join("ordinary");
        File::create(&ordinary).unwrap();
        let path = dir.path().join("state.bin");
        atomic_write(&path, |file| Ok(file.write_all(b"checkpoint")?)).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            fs::metadata(&ordinary).unwrap().permissions().mode() & 0o777,
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        atomic_write(&path, |file| Ok(file.write_all(b"new")?)).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    // This child exits inside the actual writer, bypassing all Rust destructors.
    // The parent verifies that even a synced but unfinished temp is never read
    // as the checkpoint, and that an abandoned temp does not block the next save.
    #[test]
    fn interrupted_writer_child() {
        let Some(path) = std::env::var_os("CHRONICLE_ATOMIC_WRITE_CHILD_PATH") else {
            return;
        };
        atomic_write(Path::new(&path), |file| {
            file.write_all(b"unfinished checkpoint")?;
            file.sync_all()?;
            std::process::exit(73);
        })
        .unwrap();
        panic!("child should exit before publication");
    }

    #[test]
    fn process_exit_during_write_preserves_checkpoint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"previous checkpoint").unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "atomic_file::tests::interrupted_writer_child"])
            .env("CHRONICLE_ATOMIC_WRITE_CHILD_PATH", &path)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        assert_eq!(fs::read(&path).unwrap(), b"previous checkpoint");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);

        atomic_write(&path, |file| Ok(file.write_all(b"next checkpoint")?)).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"next checkpoint");
    }
}
