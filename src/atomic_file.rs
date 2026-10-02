//! Publish one metadata checkpoint without truncating its previous version.

use crate::error::Result;
use std::fs::{self, File};
use std::io;
use std::path::Path;

/// Write a complete checkpoint beside its destination, sync it, then replace
/// the destination atomically. Readers see either the old file or the new one.
/// This is a per-file guarantee, not a transaction across metadata files.
///
/// Unix also syncs the directory so the replacement survives a power loss.
/// Windows supports the file sync and atomic replacement, but has no portable
/// directory-sync equivalent here. Errors before replacement leave the old
/// checkpoint intact; a directory-sync error is returned after replacement.
///
/// Unique temporary names allow concurrent callers to write independently.
/// A process killed before replacement can leave an unused temporary file;
/// loaders only open the final checkpoint name.
pub(crate) fn atomic_write(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    // A bare relative filename has an empty parent, which means the current
    // directory rather than a directory that can be opened by its empty name.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    #[cfg(unix)]
    let directory = File::open(parent)?;

    let mut builder = tempfile::Builder::new();
    builder.prefix(".chronicle-checkpoint-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Match OpenOptions' creation mode, including the process umask.
        builder.permissions(fs::Permissions::from_mode(0o666));
    }
    let mut temporary = builder.tempfile_in(parent)?;

    // Retain existing access permissions when replacing a checkpoint.
    match fs::metadata(path) {
        Ok(metadata) => temporary
            .as_file()
            .set_permissions(metadata.permissions())?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    write(temporary.as_file_mut())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;

    #[cfg(unix)]
    directory.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::TempDir;

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
