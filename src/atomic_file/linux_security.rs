use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use tempfile::NamedTempFile;
use xattr::FileExt;

const ACCESS_ACL: &str = "system.posix_acl_access";

pub(super) fn private_temporary(
    builder: &tempfile::Builder<'_, '_>,
    parent: &Path,
    source: &File,
) -> io::Result<NamedTempFile> {
    // tempfile's mode 0600 masks inherited POSIX ACL grants, including named
    // users. The file remains private until copy_access installs its policy.
    let temporary = builder.tempfile_in(parent)?;
    let mut expected = security_attributes(source)?;
    let mut initial = security_attributes(temporary.as_file())?;
    // Capabilities grant executable privileges rather than constrain reading.
    // Restore them only after writing, which can clear them.
    expected.remove(std::ffi::OsStr::new("security.capability"));
    initial.remove(std::ffi::OsStr::new("security.capability"));
    if initial != expected {
        // Relabeling now is too late: another MAC domain sharing our UID may
        // already have opened the empty file under its initial label.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "checkpoint temporary creation cannot preserve its security labels",
        ));
    }
    Ok(temporary)
}

fn attribute(file: &File, name: &std::ffi::OsStr) -> io::Result<Option<Vec<u8>>> {
    match file.get_xattr(name) {
        Err(error) if error.raw_os_error() == Some(libc::ENOTSUP) => Ok(None),
        result => result,
    }
}

fn security_attributes(file: &File) -> io::Result<BTreeMap<OsString, Vec<u8>>> {
    let mut result = BTreeMap::new();
    let names = match file.list_xattr() {
        Ok(names) => names,
        Err(error) if error.raw_os_error() == Some(libc::ENOTSUP) => return Ok(result),
        Err(error) => return Err(error),
    };
    for name in names {
        let bytes = name.as_bytes();
        if bytes.starts_with(b"security.") || bytes.starts_with(b"system.") {
            if name == ACCESS_ACL {
                continue;
            }
            // IMA/EVM values authenticate the old contents/metadata; copying
            // their bytes onto a changed checkpoint cannot preserve validity.
            // Other filesystem-specific ACL schemes need their own native API.
            if name == "security.ima" || name == "security.evm" || bytes.starts_with(b"system.") {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("cannot preserve checkpoint security attribute {name:?}"),
                ));
            }
            let value = attribute(file, &name)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "checkpoint security attribute disappeared",
                )
            })?;
            result.insert(name, value);
        }
    }
    Ok(result)
}

pub(super) fn copy_access(source: &File, destination: &File) -> io::Result<()> {
    // Copy security labels (e.g. SELinux/Smack) as well as the discretionary
    // ACL. Read failures and labels we cannot set are publication failures.
    // Privileged attributes hidden by the filesystem are outside this contract.
    let expected = security_attributes(source)?;
    let current = security_attributes(destination)?;
    for name in current.keys().filter(|name| !expected.contains_key(*name)) {
        destination.remove_xattr(name)?;
    }
    for (name, value) in &expected {
        if current.get(name) != Some(value) {
            destination.set_xattr(name, value)?;
        }
    }
    let acl = attribute(source, ACCESS_ACL.as_ref())?;
    match &acl {
        Some(value) => destination.set_xattr(ACCESS_ACL, value)?,
        None => {
            // The parent may now have a default ACL that the old file never
            // had. Remove the inherited ACL rather than retaining new grants.
            if attribute(destination, ACCESS_ACL.as_ref())?.is_some() {
                destination.remove_xattr(ACCESS_ACL)?;
            }
        }
    }
    if attribute(destination, ACCESS_ACL.as_ref())? != acl
        || security_attributes(destination)? != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "checkpoint ACL or security labels could not be preserved",
        ));
    }
    Ok(())
}
