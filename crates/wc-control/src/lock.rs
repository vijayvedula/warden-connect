//! The single-writer lock (`docs/08-lld.md` §8.5.2).
//!
//! Both the state log and the evidence chain are append-only with exactly one
//! writer. That writer is elected by an advisory `flock` held for the lifetime of
//! the handle; a second writer fails immediately with [`Code::STORE_LOCKED`]
//! rather than interleaving records into a file whose integrity depends on
//! ordering.
//!
//! This is the crate's only `unsafe`, wrapped so no caller ever sees it.

use std::fs::{File, OpenOptions};
use std::path::Path;

use wc_core::error::{Code, Result, WcError};

/// An exclusive lock. Dropping it closes the descriptor, which releases the
/// `flock` — so the lock's lifetime is exactly the handle's lifetime, with no
/// unlock call to forget.
#[derive(Debug)]
pub struct LockGuard {
    _file: File,
}

/// Take the exclusive writer lock on `<dir>/<name>.lock`.
pub fn acquire(dir: &Path, name: &str) -> Result<LockGuard> {
    let path = dir.join(format!("{name}.lock"));
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            WcError::with_detail(Code::STORE_LOCKED, format!("{}: {}", path.display(), e))
                .with_source(e)
        })?;

    flock_exclusive(&file, &path)?;
    Ok(LockGuard { _file: file })
}

#[cfg(unix)]
fn flock_exclusive(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `flock` takes a raw fd and two ints and has no memory-safety
    // preconditions. The fd is valid because `file` is a live, owned `File` for
    // the duration of the call, and we only read the return value.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };

    if rc == 0 {
        return Ok(());
    }
    Err(WcError::with_detail(
        Code::STORE_LOCKED,
        format!(
            "another writer holds {} — this log is single-writer by design",
            path.display()
        ),
    )
    .with_source(std::io::Error::last_os_error()))
}

#[cfg(not(unix))]
fn flock_exclusive(_file: &File, path: &Path) -> Result<()> {
    // Refusing beats pretending: with no advisory lock, two writers would
    // interleave records and corrupt the log silently.
    Err(WcError::with_detail(
        Code::STORE_LOCKED,
        format!(
            "single-writer locking for {} requires a unix platform",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_second_holder_is_refused_and_drop_releases() {
        let dir = std::env::temp_dir().join(format!("wc-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        {
            let _held = acquire(&dir, "t").unwrap();
            let err = acquire(&dir, "t").unwrap_err();
            assert_eq!(err.code(), Code::STORE_LOCKED);
        }
        // The guard is gone, so the lock must be available again.
        assert!(acquire(&dir, "t").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
