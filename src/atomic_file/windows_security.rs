//! Windows checkpoint security: create with native source controls, verify before writing.
//!
//! Access checks use native owner/group, DACL and integrity labels. Audit-only
//! SACLs require privileges not normally held by a store and are not copied.
//! Other enforcement SACL components, EFS, and reparse points fail closed.
//! Readonly destinations fail before staging. Replacing an existing checkpoint
//! requires READ_CONTROL and the ability to create its owner/group and native
//! descriptor; inability to preserve them is an error, not a mode-only fallback.
//! Concurrent external security/path changes and path-based policy equivalence
//! are outside this single-writer per-file contract. Staging names need the same
//! external policy coverage as checkpoint names.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use tempfile::NamedTempFile;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_FILTER_SECURITY_INFORMATION, PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
    SECURITY_DESCRIPTOR_REVISION, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};

// These enforcement components are readable with READ_CONTROL, unlike audit
// SACL entries. Query them all so an unsupported policy is rejected, not lost.
const SECURITY_PARTS: u32 = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | LABEL_SECURITY_INFORMATION
    | ATTRIBUTE_SECURITY_INFORMATION
    | SCOPE_SECURITY_INFORMATION
    | PROCESS_TRUST_LABEL_SECURITY_INFORMATION as u32
    | ACCESS_FILTER_SECURITY_INFORMATION as u32;

// GetSecurityInfo returns one LocalAlloc-owned self-relative descriptor. All
// SID/ACL views below remain valid while this owner is alive; Windows validates
// their layout, and GetAce bounds each native ACE before we inspect its bytes.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

impl Descriptor {
    fn read(file: &File) -> io::Result<Self> {
        let mut descriptor = null_mut();
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                SECURITY_PARTS,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if error != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(Self(descriptor))
    }

    fn control(&self) -> io::Result<u16> {
        let mut control = 0;
        let mut revision = 0;
        check(unsafe { GetSecurityDescriptorControl(self.0, &mut control, &mut revision) })?;
        Ok(control)
    }

    fn owner(&self) -> io::Result<PSID> {
        let mut sid = null_mut();
        let mut defaulted = 0;
        check(unsafe { GetSecurityDescriptorOwner(self.0, &mut sid, &mut defaulted) })?;
        Ok(sid)
    }

    fn group(&self) -> io::Result<PSID> {
        let mut sid = null_mut();
        let mut defaulted = 0;
        check(unsafe { GetSecurityDescriptorGroup(self.0, &mut sid, &mut defaulted) })?;
        Ok(sid)
    }

    fn acl(&self, sacl: bool) -> io::Result<(bool, *mut ACL)> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        check(unsafe {
            if sacl {
                GetSecurityDescriptorSacl(self.0, &mut present, &mut acl, &mut defaulted)
            } else {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted)
            }
        })?;
        Ok((present != 0, acl))
    }

    fn validate_policy(&self) -> io::Result<()> {
        let (_, sacl) = self.acl(true)?;
        if !sacl.is_null() {
            for index in 0..unsafe { (*sacl).AceCount } as u32 {
                let mut ace: *mut c_void = null_mut();
                check(unsafe { GetAce(sacl, index, &mut ace) })?;
                if unsafe { (*(ace as *const ACE_HEADER)).AceType }
                    != SYSTEM_MANDATORY_LABEL_ACE_TYPE as u8
                {
                    return Err(unsupported(
                        "checkpoint has unsupported enforcement SACL entries",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(super) struct Security {
    source: File,
    descriptor: Descriptor,
}

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    // CreateFileW alone does not provide std::fs's long-path conversion. Use
    // std's public Windows normalization (GetFullPathNameW) before adding a
    // verbatim prefix to long DOS/UNC paths. Canonicalization would require the
    // destination to exist and could follow a reparse point before validation.
    let verbatim: &[u16] = &[92, 92, 63, 92]; // \\?\
    let nt: &[u16] = &[92, 63, 63, 92]; // \??\
    let mut original: Vec<u16> = path.as_os_str().encode_wide().collect();
    if original.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in checkpoint path",
        ));
    }
    if original.starts_with(verbatim) || original.starts_with(nt) {
        original.push(0);
        return Ok(original);
    }
    let absolute = std::path::absolute(path)?;
    let mut value: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in checkpoint path",
        ));
    }
    if value.len() + 1 >= 248 && !value.starts_with(verbatim) && !value.starts_with(nt) {
        let device: Vec<u16> = "\\\\.\\".encode_utf16().collect();
        if value.starts_with(&device) {
            value.splice(..4, verbatim.iter().copied());
        } else if value.starts_with(&[b'\\' as u16, b'\\' as u16]) {
            value.splice(..2, "\\\\?\\UNC\\".encode_utf16());
        } else if value.get(1) == Some(&(b':' as u16)) && value.get(2) == Some(&(b'\\' as u16)) {
            value.splice(..0, verbatim.iter().copied());
        }
    }
    value.push(0);
    Ok(value)
}

fn open_native(
    path: &Path,
    access: u32,
    disposition: u32,
    security: *const SECURITY_ATTRIBUTES,
) -> io::Result<File> {
    let name = wide(path)?;
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            security,
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn validate_file(file: &File) -> io::Result<()> {
    let attributes = file.metadata()?.file_attributes();
    if attributes
        & (FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
        != 0
    {
        return Err(unsupported(
            "checkpoint replacement does not support EFS, reparse points, or directories",
        ));
    }
    Ok(())
}

pub(super) fn prepare(path: &Path, parent: &Path) -> io::Result<(NamedTempFile, Option<Security>)> {
    let source = match open_native(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        OPEN_EXISTING,
        null(),
    ) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let security = if let Some(source) = source {
        validate_file(&source)?;
        let descriptor = Descriptor::read(&source)?;
        descriptor.validate_policy()?;
        if source.metadata()?.permissions().readonly() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "readonly checkpoints cannot be replaced",
            ));
        }
        Some(Security { source, descriptor })
    } else {
        None
    };

    // Supply the source controls at CREATE_NEW, rather than broad inherited
    // defaults that would later be tightened. Windows may transform inheritance;
    // a mismatched result is rejected while permanently empty, never repaired
    // and reused for data a prematurely opened handle could then observe.
    let mut native: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    if let Some(security) = security.as_ref() {
        let descriptor = &security.descriptor;
        let pointer = &mut native as *mut _ as PSECURITY_DESCRIPTOR;
        check(unsafe { InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) })?;
        check(unsafe { SetSecurityDescriptorOwner(pointer, descriptor.owner()?, 0) })?;
        check(unsafe { SetSecurityDescriptorGroup(pointer, descriptor.group()?, 0) })?;
        let (present, dacl) = descriptor.acl(false)?;
        check(unsafe { SetSecurityDescriptorDacl(pointer, present as i32, dacl, 0) })?;
        let (present, sacl) = descriptor.acl(true)?;
        // An empty SACL supplied as present is treated as auditing metadata by
        // CreateFile and requires SeSecurityPrivilege. Selective queries may
        // return that empty container even though no enforcement ACE exists.
        let has_label = present && !sacl.is_null() && unsafe { (*sacl).AceCount } > 0;
        check(unsafe { SetSecurityDescriptorSacl(pointer, has_label as i32, sacl, 0) })?;
        let controls = SE_DACL_PROTECTED | SE_SACL_PROTECTED;
        check(unsafe {
            SetSecurityDescriptorControl(pointer, controls, descriptor.control()? & controls)
        })?;
        attributes.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        attributes.lpSecurityDescriptor = pointer;
    }
    let temp = tempfile::Builder::new()
        .prefix(".chronicle-checkpoint-")
        .make_in(parent, |name| {
            open_native(
                name,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
                CREATE_NEW,
                if security.is_some() {
                    &attributes
                } else {
                    null()
                },
            )
        })?;
    validate_file(temp.as_file())?;
    if let Some(security) = security.as_ref() {
        let created = Descriptor::read(temp.as_file())?;
        created.validate_policy()?;
        if !equivalent(&created, &security.descriptor)? {
            return Err(unsupported(
                "Windows changed checkpoint access controls during staging creation",
            ));
        }
    }
    Ok((temp, security))
}

fn acl_equal(left: (bool, *mut ACL), right: (bool, *mut ACL)) -> io::Result<bool> {
    if left.0 != right.0 || left.1.is_null() != right.1.is_null() {
        return Ok(false);
    }
    if left.1.is_null() {
        return Ok(true);
    }
    unsafe {
        if (*left.1).AclRevision != (*right.1).AclRevision
            || (*left.1).AceCount != (*right.1).AceCount
        {
            return Ok(false);
        }
        for index in 0..(*left.1).AceCount as u32 {
            let mut a: *mut c_void = null_mut();
            let mut b: *mut c_void = null_mut();
            check(GetAce(left.1, index, &mut a))?;
            check(GetAce(right.1, index, &mut b))?;
            if std::slice::from_raw_parts(
                a as *const u8,
                (*(a as *const ACE_HEADER)).AceSize as usize,
            ) != std::slice::from_raw_parts(
                b as *const u8,
                (*(b as *const ACE_HEADER)).AceSize as usize,
            ) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn enforcement_equal(left: &Descriptor, right: &Descriptor) -> io::Result<bool> {
    let left = left.acl(true)?;
    let right = right.acl(true)?;
    let empty =
        |acl: (bool, *mut ACL)| !acl.0 || acl.1.is_null() || unsafe { (*acl.1).AceCount } == 0;
    if empty(left) && empty(right) {
        return Ok(true);
    }
    acl_equal(left, right)
}

/// Compare access-bearing native controls for a non-container checkpoint.
/// AUTO_INHERIT_REQ/AUTO_INHERITED track propagation to child objects; regular
/// files have none. Protection bits control inbound inheritance and are kept,
/// along with every ACE's bytes, order, and flags (including INHERITED_ACE).
fn equivalent(left: &Descriptor, right: &Descriptor) -> io::Result<bool> {
    let owner = unsafe { EqualSid(left.owner()?, right.owner()?) } != 0;
    let group = unsafe { EqualSid(left.group()?, right.group()?) } != 0;
    let controls = SE_DACL_PROTECTED | SE_SACL_PROTECTED;
    Ok(owner
        && group
        && acl_equal(left.acl(false)?, right.acl(false)?)?
        && enforcement_equal(left, right)?
        && (left.control()? & controls) == (right.control()? & controls))
}

pub(super) fn finish(security: Option<&Security>, temporary: &File) -> io::Result<()> {
    let Some(security) = security else {
        return Ok(());
    };
    // Concurrent external policy mutation is unsupported. Detect a changed
    // retained source or staging descriptor before publication when observable.
    let current = Descriptor::read(&security.source)?;
    let actual = Descriptor::read(temporary)?;
    if !equivalent(&current, &security.descriptor)? || !equivalent(&actual, &security.descriptor)? {
        return Err(unsupported(
            "checkpoint access controls changed during publication",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;

    fn set_policy(file: &File, sddl: &str, parts: u32) {
        let mut descriptor = null_mut();
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        })
        .unwrap();
        let descriptor = Descriptor(descriptor);
        use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
        let flags = if parts & DACL_SECURITY_INFORMATION != 0 {
            parts
                | if descriptor.control().unwrap() & SE_DACL_PROTECTED != 0 {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_DACL_SECURITY_INFORMATION
                }
        } else {
            parts
        };
        let error = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                flags,
                null_mut(),
                null_mut(),
                if parts & DACL_SECURITY_INFORMATION != 0 {
                    descriptor.acl(false).unwrap().1
                } else {
                    null()
                },
                if parts & (LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION) != 0 {
                    descriptor.acl(true).unwrap().1
                } else {
                    null()
                },
            )
        };
        assert_eq!(
            error,
            ERROR_SUCCESS,
            "set native test policy: {}",
            io::Error::from_raw_os_error(error as i32)
        );
    }

    fn assert_roundtrip(policy: Option<&str>, parts: u32) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old checkpoint").unwrap();
        let source = open_native(
            &path,
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            OPEN_EXISTING,
            null(),
        )
        .unwrap();
        if let Some(policy) = policy {
            set_policy(&source, policy, parts);
        }
        let expected = Descriptor::read(&source).unwrap();
        super::super::atomic_write(&path, |temporary| {
            assert!(
                equivalent(&expected, &Descriptor::read(temporary).unwrap()).unwrap(),
                "controls must match before data"
            );
            temporary.write_all(b"new checkpoint")?;
            Ok(())
        })
        .unwrap();
        let result = open_native(&path, READ_CONTROL, OPEN_EXISTING, null()).unwrap();
        assert!(equivalent(&expected, &Descriptor::read(&result).unwrap()).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"new checkpoint");
    }

    #[test]
    fn inherited_native_descriptor_survives_staging() {
        assert_roundtrip(None, 0);
    }

    #[test]
    fn protected_dacl_and_owner_rights_survive_staging() {
        // Constrain the owner's implicit WRITE_DAC, but permit ordinary file
        // data and descriptor reads. The destination's owner remains the same.
        assert_roundtrip(
            Some("D:P(D;;WD;;;OW)(A;;FA;;;OW)"),
            DACL_SECURITY_INFORMATION,
        );
    }

    #[test]
    fn explicit_integrity_policy_survives_staging() {
        assert_roundtrip(Some("S:(ML;;NWNRNX;;;ME)"), LABEL_SECURITY_INFORMATION);
    }

    #[test]
    fn unsupported_resource_policy_never_reaches_payload_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old checkpoint").unwrap();
        let source = open_native(&path, READ_CONTROL | WRITE_DAC, OPEN_EXISTING, null()).unwrap();
        set_policy(
            &source,
            r#"S:(RA;;;;;WD;("classification",TS,0x0,"sensitive"))"#,
            ATTRIBUTE_SECURITY_INFORMATION,
        );
        let result = super::super::atomic_write(&path, |_| {
            panic!("unsupported policy must reject before bytes")
        });
        assert!(
            matches!(result, Err(crate::StoreError::Io(error)) if error.kind() == io::ErrorKind::Unsupported)
        );
        assert_eq!(fs::read(&path).unwrap(), b"old checkpoint");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn readonly_checkpoint_rejects_before_payload_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old checkpoint").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let result = super::super::atomic_write(&path, |_| {
            panic!("readonly checkpoint must reject before bytes")
        });
        assert!(
            matches!(result, Err(crate::StoreError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(&path).unwrap(), b"old checkpoint");
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
    }

    #[test]
    fn write_failure_preserves_original_controls_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old checkpoint").unwrap();
        let source = open_native(&path, READ_CONTROL | WRITE_DAC, OPEN_EXISTING, null()).unwrap();
        set_policy(
            &source,
            "D:P(D;;WD;;;OW)(A;;FA;;;OW)",
            DACL_SECURITY_INFORMATION,
        );
        let before = Descriptor::read(&source).unwrap();
        let result = super::super::atomic_write(&path, |file| {
            file.write_all(b"partial secret")?;
            Err(io::Error::new(io::ErrorKind::Other, "injected write error").into())
        });
        assert!(result.is_err());
        assert!(equivalent(&before, &Descriptor::read(&source).unwrap()).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"old checkpoint");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn unreadable_source_security_rejects_before_payload_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old checkpoint").unwrap();
        let source = open_native(&path, READ_CONTROL | WRITE_DAC, OPEN_EXISTING, null()).unwrap();
        // OWNER RIGHTS also suppresses the owner's implicit READ_CONTROL.
        set_policy(
            &source,
            "D:P(D;;RC;;;OW)(A;;FA;;;OW)",
            DACL_SECURITY_INFORMATION,
        );
        let result = super::super::atomic_write(&path, |_| {
            panic!("unreadable descriptor must reject before bytes")
        });
        // This preexisting handle keeps WRITE_DAC; restore test permissions
        // before checking the result so failure assertions leave clean fixtures.
        set_policy(&source, "D:P(A;;FA;;;OW)", DACL_SECURITY_INFORMATION);
        assert!(
            matches!(result, Err(crate::StoreError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(&path).unwrap(), b"old checkpoint");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn changed_parent_inheritance_never_writes_under_different_controls() {
        use std::cell::Cell;
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = fs::OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir.path())
            .unwrap();
        set_policy(&parent, "D:P(A;OICI;FA;;;OW)", DACL_SECURITY_INFORMATION);
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old checkpoint").unwrap();
        // Add and remove a parent grant after the source file already exists.
        // Native propagation can update the source's inherited ACL each time.
        for parent_policy in ["D:P(A;OICI;FA;;;OW)(A;OICI;GR;;;BG)", "D:P(A;OICI;FA;;;OW)"] {
            set_policy(&parent, parent_policy, DACL_SECURITY_INFORMATION);
            let source = open_native(&path, READ_CONTROL, OPEN_EXISTING, null()).unwrap();
            let expected = Descriptor::read(&source).unwrap();
            let before = fs::read(&path).unwrap();
            let called = Cell::new(false);
            let result = super::super::atomic_write(&path, |file| {
                called.set(true);
                assert!(
                    equivalent(&expected, &Descriptor::read(file).unwrap()).unwrap(),
                    "changed inheritance must be checked before payload"
                );
                file.write_all(b"new checkpoint")?;
                Ok(())
            });
            match result {
                Ok(published) => {
                    assert!(called.get());
                    assert!(equivalent(&expected, &Descriptor::read(&published).unwrap()).unwrap());
                    assert_eq!(fs::read(&path).unwrap(), b"new checkpoint");
                }
                Err(_) => {
                    assert!(
                        !called.get(),
                        "a rejected inheritance result must remain empty"
                    );
                    assert_eq!(fs::read(&path).unwrap(), before);
                }
            }
        }
    }

    #[test]
    fn ordinary_long_paths_support_creation_and_replacement() {
        let root = tempfile::tempdir().unwrap();
        let mut parent = root.path().to_owned();
        for _ in 0..6 {
            parent.push("checkpoint-long-path-segment-without-verbatim-prefix");
        }
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("state.bin");
        assert!(path.as_os_str().encode_wide().count() > 300);
        assert!(!path.to_string_lossy().starts_with(r"\\?\"));
        for bytes in [b"first".as_slice(), b"replacement".as_slice()] {
            super::super::atomic_write(&path, |file| Ok(file.write_all(bytes)?)).unwrap();
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let verbatim = fs::canonicalize(&path).unwrap();
        super::super::atomic_write(&verbatim, |file| Ok(file.write_all(b"verbatim")?)).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"verbatim");
    }

    #[test]
    fn native_path_conversion_preserves_verbatim_and_long_unc_names() {
        let nt = Path::new(r"\??\C:\checkpoint.bin");
        assert_eq!(
            wide(nt).unwrap(),
            nt.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        );
        let unc = format!(r"\\server\share\{}\checkpoint.bin", "segment".repeat(50));
        let converted = wide(Path::new(&unc)).unwrap();
        let expected = format!(r"\\?\UNC\{}", &unc[2..]);
        assert_eq!(
            converted,
            expected.encode_utf16().chain(Some(0)).collect::<Vec<_>>()
        );
    }
}
