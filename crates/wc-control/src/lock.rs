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
    /// Kept for the drop trace only. The lock's lifetime is the descriptor's, not this field's.
    path: std::path::PathBuf,
    _file: File,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // The close is what releases the flock; this only records that it happened, so a trace can
        // show whether a release was missing or merely late.
        trace(&self.path, &self._file, "release");
    }
}

/// Take the exclusive writer lock on `<dir>/<name>.lock`.
pub fn acquire(dir: &Path, name: &str) -> Result<LockGuard> {
    let path = dir.join(format!("{name}.lock"));
    // Retried briefly, and the reason is measured rather than assumed.
    //
    // `registry::tests::transitions_are_durable_across_reopen` failed about one run in six with
    // WC-8003 on a path unique to its own process and test. Instrumenting `acquire` with the pid and
    // the inode showed the release logged immediately before the blocking acquire — same process,
    // same inode, nothing else holding it. A minimal probe (`reacquire_after_drop_never_blocks`)
    // then reproduced it with nothing but this function: 20,000 acquire-drop-acquire cycles never
    // block in isolation, and block within one run under parallel test load.
    //
    // So on this platform a `flock` taken immediately after a release on the same inode can
    // transiently see the old lock. Reporting that as "another writer holds this" is a lie — nobody
    // holds it — and an operator restarting a control plane right after stopping one would read it.
    //
    // Bounded and short on purpose. This does not weaken the single-writer guarantee: `flock` still
    // arbitrates, and a genuinely held lock is still held after 50ms. A longer or unbounded wait is
    // what `open_with_standby` is for, and it is a deliberate election rather than a retry.
    const ATTEMPTS: u32 = 8;
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        let file = open_lock_file(&path)?;
        trace(&path, &file, "acquire");
        match flock_exclusive(&file, &path) {
            Ok(()) => {
                return Ok(LockGuard {
                    path: path.clone(),
                    _file: file,
                })
            }
            Err(e) => {
                trace(&path, &file, "BLOCKED");
                last = Some(e);
                // Reopened next time round: a failed `flock` leaves this descriptor open, and
                // holding it would mean waiting on an inode the writer may have replaced.
                drop(file);
                if attempt + 1 < ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_millis(1 << attempt.min(4)));
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| WcError::with_detail(Code::STORE_LOCKED, "lock could not be taken")))
}

/// Diagnostics for a lock that should not have been contended.
///
/// Opt-in through `WARDEN_CONNECT_TRACE_LOCKS`, and doing nothing otherwise — a lock path is taken
/// on every write and this must not cost anything in the ordinary case.
///
/// It exists because `registry::tests::transitions_are_durable_across_reopen` fails roughly one run
/// in six with `WC-8003` on a path that is unique per process and per test. Everything reachable by
/// reading was ruled out: the prefix is used by no other module, `LockGuard` is owned by value and
/// never shared with a thread, and the test's own inner scope drops before it reopens. `EWOULDBLOCK`
/// requires another LIVE descriptor on the same inode, so the inode and the pid are the two facts
/// that would identify the holder — and neither is visible from the failure message.
fn trace(path: &Path, file: &File, what: &str) {
    if std::env::var_os("WARDEN_CONNECT_TRACE_LOCKS").is_none() {
        return;
    }
    let ino = std::os::unix::fs::MetadataExt::ino(&match file.metadata() {
        Ok(m) => m,
        Err(_) => return,
    });
    let line = format!(
        "{what} pid={} tid={:?} ino={ino} fd={} path={}\n",
        std::process::id(),
        std::thread::current().id(),
        std::os::unix::io::AsRawFd::as_raw_fd(file),
        path.display()
    );
    // Appended to one file rather than printed. `cargo test` captures stdout per test, so a
    // contended lock's other holder — which is in a DIFFERENT test — is invisible on stderr. The
    // whole question is who else had it, so the trace has to outlive the test that noticed.
    match std::env::var("WARDEN_CONNECT_TRACE_LOCKS") {
        Ok(p) if p != "1" => {
            use std::io::Write as _;
            if let Ok(mut fh) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
            {
                let _ = fh.write_all(line.as_bytes());
            }
        }
        _ => eprint!("LOCKTRACE {line}"),
    }
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
                    LockGuard {
                        path: path.clone(),
                        _file: file,
                    },
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// The reproduction, kept and ignored.
    ///
    /// 20,000 acquire-drop-acquire cycles never block in isolation and block within one run under
    /// parallel test load — which is how the transient `EWOULDBLOCK` behind
    /// `registry::tests::transitions_are_durable_across_reopen` was finally identified.
    ///
    /// `#[ignore]` because it is a load generator, not a test. Left in the suite it made a *shim*
    /// test time out at 5s — a diagnostic that breaks its neighbours is measuring the harness.
    ///
    ///     cargo test -p warden-connect-control --lib -- --ignored reacquire
    #[test]
    #[ignore = "load generator: this is the reproduction, not a check"]
    fn reacquire_after_drop_never_blocks() {
        let dir = std::env::temp_dir().join(format!("wc-lockprobe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..20_000u32 {
            let g = acquire(&dir, "events").expect("first");
            drop(g);
            let g2 = acquire(&dir, "events");
            assert!(g2.is_ok(), "blocked on iteration {i}: {:?}", g2.err());
            drop(g2);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The fix, tested deterministically rather than by racing.
    ///
    /// A holder releases after a delay well inside the retry budget. Before the retry existed this
    /// reported `WC-8003 another writer holds …` — true at the instant it looked, and a lie by the
    /// time an operator read it.
    #[test]
    fn a_lock_released_a_moment_later_is_acquired_rather_than_reported_as_contended() {
        let dir = std::env::temp_dir().join(format!("wc-lockwait-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let held = acquire(&dir, "events").expect("the holder takes it first");
        let d = dir.clone();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(held);
            let _ = &d;
        });
        // Inside the retry budget, so this must wait and succeed.
        let taken = acquire(&dir, "events");
        releaser.join().unwrap();
        assert!(
            taken.is_ok(),
            "a lock released 20ms in must be acquired, not reported as contended: {:?}",
            taken.err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And a lock genuinely held is still refused. The retry must not become a wait.
    #[test]
    fn a_lock_that_stays_held_is_still_refused() {
        let dir = std::env::temp_dir().join(format!("wc-lockheld-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _held = acquire(&dir, "events").expect("first");
        let started = std::time::Instant::now();
        let err = acquire(&dir, "events").expect_err("a held lock is held");
        assert_eq!(err.code(), Code::STORE_LOCKED);
        // Bounded. An unbounded wait here would turn a second writer into a hang, and a hang is
        // indistinguishable from a slow start — which is the failure `open_with_standby` exists to
        // make explicit and deliberate.
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "the retry budget must stay small: waited {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
