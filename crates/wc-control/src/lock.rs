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
    let file = open_lock_file(&path)?;
    flock_exclusive(&file, &path)?;
    Ok(LockGuard { _file: file })
}

/// What a standby did while waiting for the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Election {
    /// Milliseconds spent waiting before the lock was taken.
    ///
    /// Milliseconds rather than seconds because a healthy handover is fast — the previous
    /// process has already exited and the kernel has already released the `flock` — so a
    /// whole-second figure reports every good failover as `0` and can only measure the bad
    /// ones.
    pub waited_ms: u64,
    /// Whether the lock was free on the **first attempt**.
    ///
    /// Tracked rather than inferred from `waited_ms == 0`, which is the bug this field had
    /// on its first version: a handover completing inside a second reported as
    /// uncontended, so the successor's own startup log would have claimed it was the
    /// first writer. That is the one line an operator reads after a failover.
    pub uncontended: bool,
}

impl Election {
    /// The sentence for a startup banner.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.uncontended {
            "took the writer lock unopposed; this process is active".to_string()
        } else {
            format!(
                "took over the writer lock after {} ms; the previous active writer is gone",
                self.waited_ms
            )
        }
    }
}

/// Wait for the exclusive writer lock, polling until it is free (P1 #10).
///
/// [`acquire`] is non-blocking and that is right for a one-shot command: `connect
/// register` competing with a running `serve` should fail immediately and say so, not hang.
/// But it made **high availability a claim with no mechanism**. §8.5.2 says HA is
/// "active/standby with that lock as the election primitive", and a standby had no way to
/// stand by: the second process failed at startup and exited, so failover meant an external
/// supervisor restarting a process that would then race the dying one.
///
/// This is the election. The standby holds no lock, writes nothing, and takes over when the
/// active process releases — which happens on a clean exit *and* on a crash, because a
/// `flock` is owned by the file descriptor and the kernel closes it when the process dies.
/// That is the property that makes this usable: there is no lease to expire and no
/// heartbeat to get wrong.
///
/// # What it deliberately does not do
///
/// **No fencing token, and therefore no protection against a partitioned active.** `flock`
/// is advisory and node-local: two hosts mounting the same NFS export can both believe they
/// hold it. That is not a gap this function can close, and pretending otherwise would be
/// worse than saying it — see the deployment note in `docs/physical-architecture.md`. A
/// shared-filesystem HA pair needs the storage layer to guarantee single-attachment
/// (`ReadWriteOnce`, an EBS volume, a SAN LUN), and that guarantee is what is actually
/// doing the fencing.
pub fn acquire_waiting(
    dir: &Path,
    name: &str,
    timeout: std::time::Duration,
    poll: std::time::Duration,
    mut on_wait: impl FnMut(u64),
) -> Result<(LockGuard, Election)> {
    let path = dir.join(format!("{name}.lock"));
    let started = std::time::Instant::now();
    let mut announced = 0u64;
    let mut contended = false;

    loop {
        // Reopened each attempt rather than held across the loop: a failed `flock` leaves
        // the descriptor open, and holding one to a file the active writer may replace
        // would mean waiting on the wrong inode forever.
        let file = open_lock_file(&path)?;
        match flock_exclusive(&file, &path) {
            Ok(()) => {
                return Ok((
                    LockGuard { _file: file },
                    Election {
                        waited_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                        uncontended: !contended,
                    },
                ));
            }
            Err(e) => {
                contended = true;
                if started.elapsed() >= timeout {
                    // Timing out is a real outcome and must not look like the lock being
                    // taken: a standby that gave up has to exit non-zero so its supervisor
                    // notices, rather than starting up holding nothing.
                    return Err(WcError::with_detail(
                        Code::STORE_LOCKED,
                        format!(
                            "waited {}s for {} and the active writer still holds it;                              giving up rather than starting without the lock",
                            started.elapsed().as_secs(),
                            path.display()
                        ),
                    )
                    .with_source(e));
                }
                let elapsed = started.elapsed().as_secs();
                if elapsed > announced {
                    announced = elapsed;
                    on_wait(elapsed);
                }
                std::thread::sleep(poll);
            }
        }
    }
}

fn open_lock_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| {
            WcError::with_detail(Code::STORE_LOCKED, format!("{}: {}", path.display(), e))
                .with_source(e)
        })
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
        // Clear first: `create_dir_all` on an EXISTING directory succeeds and leaves its
        // contents, and these paths repeat across runs because a pid gets reused and the
        // counter restarts at 0. `Drop` does not run when a test aborts or a run is killed,
        // so leftovers accumulate — 2,956 of them were sitting in /tmp when this was found.
        // A stale log underneath a durability test can fail it, and can also make it PASS
        // for the wrong reason, which is the worse half.
        let _ = std::fs::remove_dir_all(&dir);
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

    // --- election (P1 #10) -------------------------------------------------

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wc-elect-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_first_writer_takes_the_lock_without_waiting() {
        // A standby that is started first *is* the active process. If this waited for a
        // timeout before serving, every cold start of an HA pair would take that long.
        let dir = scratch("first");
        let (_guard, election) = acquire_waiting(
            &dir,
            "t",
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(10),
            |_| {},
        )
        .unwrap();
        assert!(election.uncontended, "{election:?}");
        assert!(election.describe().contains("unopposed"), "{election:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_standby_takes_over_when_the_active_writer_releases() {
        // The handover P1 #10 said was never exercised. Before `acquire_waiting`, the
        // second process failed at startup and exited, so "active/standby with that lock as
        // the election primitive" had no standby in it.
        let dir = scratch("handover");
        let held = acquire(&dir, "t").unwrap();

        let waiting_dir = dir.clone();
        let standby = std::thread::spawn(move || {
            acquire_waiting(
                &waiting_dir,
                "t",
                std::time::Duration::from_secs(10),
                std::time::Duration::from_millis(5),
                |_| {},
            )
        });

        // Let it establish that the lock is genuinely contended before releasing, so the
        // test is a handover and not a race the standby happened to win first.
        std::thread::sleep(std::time::Duration::from_millis(60));
        drop(held);

        let (_guard, election) = standby.join().unwrap().unwrap();
        assert!(
            !election.uncontended,
            "the successor must know it was one, even for a sub-second handover — the \
             first version inferred this from `waited == 0` in whole seconds and got \
             every fast failover backwards: {election:?}"
        );
        assert!(election.describe().contains("took over"), "{election:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_standby_that_times_out_fails_rather_than_starting_without_the_lock() {
        // The dangerous alternative. A standby whose wait expired and then started anyway
        // would be a second writer, which is the one thing this whole file exists to
        // prevent — and it would have looked like a successful failover.
        let dir = scratch("timeout");
        let _held = acquire(&dir, "t").unwrap();

        let err = acquire_waiting(
            &dir,
            "t",
            std::time::Duration::from_millis(80),
            std::time::Duration::from_millis(10),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::STORE_LOCKED);
        assert!(
            format!("{err}").contains("giving up rather than starting without the lock"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn waiting_is_announced_so_a_standby_is_not_a_silent_process() {
        // An operator looking at a standby needs to see that it is standing by. A process
        // that logs nothing for an hour is indistinguishable from one that is wedged, and
        // the difference matters at exactly the moment somebody is deciding whether to
        // kill it.
        let dir = scratch("announce");
        let _held = acquire(&dir, "t").unwrap();

        let announced = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&announced);
        let _ = acquire_waiting(
            &dir,
            "t",
            std::time::Duration::from_millis(1_600),
            std::time::Duration::from_millis(20),
            move |secs| sink.lock().unwrap().push(secs),
        );
        let seen = announced.lock().unwrap().clone();
        assert!(!seen.is_empty(), "at least one wait notice in 1.6s");
        // Once per elapsed second, not once per poll — otherwise a 20 ms poll produces
        // fifty lines a second and the log becomes the reason nobody reads the log.
        assert_eq!(
            seen.len(),
            seen.iter().collect::<std::collections::BTreeSet<_>>().len(),
            "each second announced once: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
