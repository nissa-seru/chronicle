//! Darwin's filesec APIs copy the complete discretionary security object.
//! copyfile(COPYFILE_ACL) is unsuitable: it merges inherited ACLs and can ignore
//! ownership/ACL installation failures. fchmodx_np applies the original object.

use libc::{c_char, c_int, c_void};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::ptr;
use tempfile::NamedTempFile;

// Public Darwin <sys/fcntl.h>, <sys/stat.h> and <sys/acl.h> APIs that libc does
// not currently bind. All security/ACL allocations are opaque owned objects.
const FILESEC_MODE: c_int = 4;
const FILESEC_ACL: c_int = 5;
const ACL_FLAG_NO_INHERIT: c_int = 1 << 17;

extern "C" {
    fn filesec_init() -> *mut c_void;
    fn filesec_free(security: *mut c_void);
    fn filesec_set_property(security: *mut c_void, property: c_int, value: *const c_void) -> c_int;
    fn filesec_query_property(security: *mut c_void, property: c_int, present: *mut c_int)
        -> c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: c_int, stat: *mut libc::stat, security: *mut c_void) -> c_int;
    fn fchmodx_np(fd: c_int, security: *mut c_void) -> c_int;
    fn openx_np(path: *const c_char, flags: c_int, security: *mut c_void) -> c_int;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_free(acl: *mut c_void) -> c_int;
    fn acl_get_flagset_np(acl: *mut c_void, flags: *mut *mut c_void) -> c_int;
    fn acl_add_flag_np(flags: *mut c_void, flag: c_int) -> c_int;
}

struct Security(*mut c_void);

impl Security {
    fn new() -> io::Result<Self> {
        // SAFETY: no arguments; the returned allocation is owned by this RAII
        // wrapper and released with its paired Darwin allocator.
        let security = unsafe { filesec_init() };
        if security.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(security))
    }
}

impl Drop for Security {
    fn drop(&mut self) {
        // SAFETY: exactly one matching free of the owned filesec allocation.
        unsafe { filesec_free(self.0) };
    }
}

struct Acl(*mut c_void);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: exactly one matching free of the owned ACL allocation.
        unsafe { acl_free(self.0) };
    }
}

fn check(result: c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn reject_authorization_label(file: &File, name: &std::ffi::CStr) -> io::Result<()> {
    // SAFETY: the descriptor and NUL-terminated name remain live; a zero-sized
    // query with a null buffer asks only whether the attribute exists.
    let size =
        unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), ptr::null_mut(), 0, 0, 0) };
    if size >= 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "checkpoint carries a macOS authorization label that cannot be preserved",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOATTR) {
        Ok(())
    } else {
        // An unsupported/denied metadata query is not proof of absence.
        Err(error)
    }
}

pub(super) fn private_temporary(
    builder: &tempfile::Builder<'_, '_>,
    parent: &Path,
    source: &File,
) -> io::Result<NamedTempFile> {
    // com.apple.macl carries app authorization outside the filesec ACL. There
    // is no supported ordinary-file API here for preserving that policy.
    reject_authorization_label(source, c"com.apple.macl")?;
    let security = Security::new()?;
    // A mode alone does not suppress inherited Darwin ACL grants. Install an
    // empty non-inheriting ACL AT CREATION, before anyone can open the file.
    // SAFETY: allocations remain live through openx_np; property setters copy
    // their input, and acl_get_flagset_np returns storage within the live ACL.
    unsafe {
        let acl = Acl(acl_init(0));
        if acl.0.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut flags = ptr::null_mut();
        check(acl_get_flagset_np(acl.0, &mut flags))?;
        check(acl_add_flag_np(flags, ACL_FLAG_NO_INHERIT))?;
        let mode: libc::mode_t = 0o600;
        check(filesec_set_property(
            security.0,
            FILESEC_MODE,
            ptr::from_ref(&mode).cast(),
        ))?;
        check(filesec_set_property(
            security.0,
            FILESEC_ACL,
            ptr::from_ref(&acl.0).cast(),
        ))?;
    }
    let temporary = builder.make_in(parent, |path| {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: the string and security object remain live for this call.
        let fd = unsafe {
            openx_np(
                path.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
                security.0,
            )
        };
        if fd == -1 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: openx_np returned a fresh owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    })?;
    reject_authorization_label(temporary.as_file(), c"com.apple.macl")?;
    Ok(temporary)
}

pub(super) fn copy_access(source: &File, destination: &File) -> io::Result<()> {
    reject_authorization_label(source, c"com.apple.macl")?;
    reject_authorization_label(destination, c"com.apple.macl")?;
    let security = Security::new()?;
    // SAFETY: stat's layout matches Darwin's inode64 API; both descriptors and
    // the opaque security allocation remain live throughout these calls.
    unsafe {
        let mut stat = std::mem::zeroed::<libc::stat>();
        check(fstatx_np(source.as_raw_fd(), &mut stat, security.0))?;
        let mut has_acl = 0;
        check(filesec_query_property(
            security.0,
            FILESEC_ACL,
            &mut has_acl,
        ))?;
        if has_acl == 0 {
            // Absence means remove the staging ACL, not "leave it unchanged".
            // _FILESEC_REMOVE_ACL is the documented pointer-valued sentinel.
            check(filesec_set_property(
                security.0,
                FILESEC_ACL,
                1usize as *const c_void,
            ))?;
        }
        check(fchmodx_np(destination.as_raw_fd(), security.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_label_gate_distinguishes_absence_from_presence() {
        let file = tempfile::tempfile().unwrap();
        // Exercise the native xattr existence query with an ordinary attribute:
        // creating real MACL policy can require OS-managed user consent.
        let name = c"com.chronicle.test-authorization";
        reject_authorization_label(&file, name).unwrap();
        // Even a zero-length value is presence, not an absent label.
        let result =
            unsafe { libc::fsetxattr(file.as_raw_fd(), name.as_ptr(), ptr::null(), 0, 0, 0) };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        assert_eq!(
            reject_authorization_label(&file, name).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
