use super::atomic_write;
#[cfg(target_os = "linux")]
use super::Checkpoint;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tempfile::TempDir;

#[test]
fn replacement_is_private_while_writing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.bin");
    fs::write(&path, b"old").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    atomic_write(&path, |file| {
        assert_eq!(file.metadata()?.mode() & 0o777, 0o600);
        file.write_all(b"new")?;
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
}

#[test]
fn symlink_destination_is_rejected_before_writing() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("target");
    let path = dir.path().join("state.bin");
    fs::write(&target, b"old").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(atomic_write(&path, |_| panic!("must not write")).is_err());
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(target).unwrap(), b"old");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn inaccessible_security_source_fails_without_publishing() {
    // Root bypasses DAC; this regression exercises the unprivileged failure.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("inaccessible source requires an unprivileged test process");
        return;
    }
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.bin");
    fs::write(&path, b"old").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let result = atomic_write(&path, |_| panic!("must not write"));
    assert!(result.is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"old");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn failure_to_restore_ownership_leaves_previous_checkpoint() {
    // An unprivileged process can stage a replacement owned by itself, but
    // cannot then restore the real destination's owner if that owner differs.
    // Inject that failure at the finish boundary without requiring a root-owned
    // fixture: a write callback supplies a foreign-owned source (/dev/null).
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("ownership failure requires an unprivileged test process");
        return;
    }
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.bin");
    fs::write(&path, b"old").unwrap();
    let result = atomic_write(&path, |file| {
        file.write_all(b"new")?;
        let foreign_owner = File::open("/dev/null")?;
        super::unix_security::finish(Some(&foreign_owner), file)?;
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&path).unwrap(), b"old");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use xattr::FileExt;

    const ACCESS: &str = "system.posix_acl_access";
    const DEFAULT: &str = "system.posix_acl_default";

    // Linux's version-2 POSIX ACL xattr encoding; no libacl or setfacl binary
    // is needed by either the production code or these regression fixtures.
    fn acl(named_permissions: u16) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (1u16, 6u16, u32::MAX),        // owner rw
            (2, named_permissions, 65534), // nobody: explicit grant or deny
            (4, 4, u32::MAX),              // group r
            (16, 4, u32::MAX),             // mask r
            (32, 4, u32::MAX),             // other r
        ] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(permissions.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn replacement_preserves_named_acl_denials_and_grants() {
        for permissions in [0, 4] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("state.bin");
            fs::write(&path, b"old").unwrap();
            let expected = acl(permissions);
            xattr::set(&path, ACCESS, &expected).unwrap();
            let before = fs::metadata(&path).unwrap();
            atomic_write(&path, |file| Ok(file.write_all(b"new")?)).unwrap();
            assert_eq!(xattr::get(&path, ACCESS).unwrap(), Some(expected));
            let after = fs::metadata(&path).unwrap();
            assert_eq!(
                (after.uid(), after.gid(), after.mode()),
                (before.uid(), before.gid(), before.mode())
            );
            assert_eq!(fs::read(path).unwrap(), b"new");
        }
    }

    #[test]
    fn changed_parent_default_acl_cannot_add_grants_to_replacement() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old").unwrap();
        assert_eq!(xattr::get(&path, ACCESS).unwrap(), None);
        xattr::set(dir.path(), DEFAULT, &acl(4)).unwrap();
        atomic_write(&path, |file| {
            // The inherited ACL is present, but masked by mode 0600 until it
            // is removed. chmod must not expose its grant before that removal.
            assert!(file.get_xattr(ACCESS)?.is_some());
            assert_eq!(file.metadata()?.mode() & 0o077, 0);
            Ok(file.write_all(b"new")?)
        })
        .unwrap();
        assert_eq!(xattr::get(&path, ACCESS).unwrap(), None);
        assert_eq!(fs::read(path).unwrap(), b"new");
    }

    #[test]
    fn new_checkpoint_inherits_the_ordinary_creation_acl() {
        let dir = TempDir::new().unwrap();
        xattr::set(dir.path(), DEFAULT, &acl(4)).unwrap();
        let ordinary = dir.path().join("ordinary");
        File::create(&ordinary).unwrap();
        let path = dir.path().join("state.bin");
        atomic_write(&path, |file| Ok(file.write_all(b"new")?)).unwrap();
        assert_eq!(
            xattr::get(&path, ACCESS).unwrap(),
            xattr::get(&ordinary, ACCESS).unwrap()
        );
        assert_eq!(
            fs::metadata(path).unwrap().mode(),
            fs::metadata(ordinary).unwrap().mode()
        );
    }

    #[test]
    fn acl_change_invalidates_cached_checkpoint_and_is_retained() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        let checkpoint = Checkpoint::default();
        checkpoint.save(&path, &[b"same"]).unwrap();
        let old = same_file::Handle::from_path(&path).unwrap();
        xattr::set(&path, ACCESS, &acl(0)).unwrap();
        checkpoint.save(&path, &[b"same"]).unwrap();
        assert_ne!(same_file::Handle::from_path(&path).unwrap(), old);
        assert_eq!(xattr::get(&path, ACCESS).unwrap(), Some(acl(0)));
    }

    #[test]
    fn replacement_preserves_supplementary_group() {
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(count >= 0);
        let mut groups = vec![0; count as usize];
        assert_eq!(
            unsafe { libc::getgroups(count, groups.as_mut_ptr()) },
            count
        );
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old").unwrap();
        let original = fs::metadata(&path).unwrap();
        let Some(group) = groups.into_iter().find(|group| *group != original.gid()) else {
            eprintln!("no alternate supplementary group available");
            return;
        };
        use std::os::unix::io::AsRawFd;
        let file = File::open(&path).unwrap();
        assert_eq!(
            unsafe { libc::fchown(file.as_raw_fd(), original.uid(), group) },
            0
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o2640)).unwrap();
        atomic_write(&path, |file| Ok(file.write_all(b"new")?)).unwrap();
        let after = fs::metadata(path).unwrap();
        assert_eq!(after.uid(), original.uid());
        assert_eq!(after.gid(), group);
        assert_eq!(after.mode() & 0o7777, 0o2640);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    fn chmod(args: &[&str], path: &std::path::Path) {
        assert!(Command::new("/bin/chmod")
            .args(args)
            .arg(path)
            .status()
            .unwrap()
            .success());
    }

    fn acl(path: &std::path::Path) -> String {
        let output = Command::new("/bin/ls")
            .arg("-le")
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn replacement_preserves_extended_acl_including_inherited_entries() {
        let dir = TempDir::new().unwrap();
        chmod(
            &["+a", "everyone deny execute,file_inherit,only_inherit"],
            dir.path(),
        );
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old").unwrap();
        chmod(&["+a", "user:nobody allow read"], &path);
        let expected = acl(&path);
        assert!(expected.contains("inherited"));
        assert!(expected.contains("allow read"));
        // Different inheritance now must not change the original ACL.
        chmod(&["-N"], dir.path());
        chmod(&["+a", "everyone allow read,file_inherit"], dir.path());
        atomic_write(&path, |file| {
            let temporary = fs::read_dir(dir.path())?
                .map(|entry| entry.unwrap().path())
                .find(|entry| {
                    entry
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".chronicle-checkpoint-")
                })
                .unwrap();
            assert!(!acl(&temporary).contains("allow read"));
            Ok(file.write_all(b"new")?)
        })
        .unwrap();
        assert_eq!(acl(&path), expected);
        assert_eq!(fs::read(path).unwrap(), b"new");
    }
}
