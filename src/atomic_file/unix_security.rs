//! Preserve the access policy of a replaced Unix checkpoint.
//!
//! Existing files are staged privately, so changing ownership and ACLs never
//! exposes an intermediate policy. New files use ordinary creation semantics.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use tempfile::NamedTempFile;

#[cfg(target_os = "linux")]
#[path = "linux_security.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos_security.rs"]
mod platform;

pub(super) fn prepare(path: &Path, parent: &Path) -> io::Result<(NamedTempFile, Option<File>)> {
    // A symlink's access policy is not the policy of the directory entry that
    // rename replaces. Reject links and special files rather than guessing.
    let source = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => {
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint destination must be a regular file",
                ));
            }
            Some(file)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(".chronicle-checkpoint-");
    let temporary = if let Some(source) = source.as_ref() {
        platform::private_temporary(&builder, parent, source)?
    } else {
        builder.permissions(fs::Permissions::from_mode(0o666));
        builder.tempfile_in(parent)?
    };
    Ok((temporary, source))
}

pub(super) fn finish(source: Option<&File>, destination: &File) -> io::Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    let metadata = source.metadata()?;
    let current = destination.metadata()?;
    // Changing ownership can clear mode bits and security attributes. Do it
    // first, while the file is still private. Failure keeps the old checkpoint.
    if current.uid() != metadata.uid() || current.gid() != metadata.gid() {
        // Keep the staging mode from becoming a grant to the restored owner
        // before its real ACL and mode are installed. Our open descriptor
        // still permits the remaining operations.
        destination.set_permissions(fs::Permissions::from_mode(0))?;
        // SAFETY: the borrowed descriptor remains open for the call.
        if unsafe { libc::fchown(destination.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    platform::copy_access(source, destination)?;
    // On Linux the ACL must be installed BEFORE chmod widens the mode, or a
    // denied named user could open a readable file in between those calls.
    destination.set_permissions(metadata.permissions())?;
    let actual = destination.metadata()?;
    if actual.uid() != metadata.uid()
        || actual.gid() != metadata.gid()
        || actual.mode() & 0o7777 != metadata.mode() & 0o7777
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "checkpoint ownership or mode could not be preserved",
        ));
    }
    Ok(())
}
