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

pub(super) fn private_temporary(
    builder: &tempfile::Builder<'_, '_>,
    parent: &Path,
    _source: &File,
) -> io::Result<NamedTempFile> {
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
    builder.make_in(parent, |path| {
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
    })
}

pub(super) fn copy_access(source: &File, destination: &File) -> io::Result<()> {
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
