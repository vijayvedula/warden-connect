//! Spawning a child process with piped stdio, without racing a sibling for the pipe.
//!
//! Creating a pipe and marking it close-on-exec are two steps, not one, on the platforms this
//! runs on. A thread that forks in between inherits the other thread's pipe ends. The child that
//! borrowed them exits none the wiser; the pipe stays open because a stranger is holding the
//! other end, and the thread waiting on it waits for a writer that will never write and a reader
//! that will never close.
//!
//! What that looks like from outside is not a deadlock, which would at least be obvious. It is a
//! shim that answered correctly and was recorded as not answering at all — a verifier reporting
//! `no answer within 20s` about a process that exited 0, having printed the verdict, nineteen
//! seconds earlier. The refusal is real, its stated reason is fiction, and rerunning clears it.
//!
//! Every spawn in this workspace goes through [`spawn_piped`], which holds a process-wide lock
//! across the spawn so no two of them are ever mid-pipe together. The lock is held for the fork,
//! never for the child's lifetime, so callers still run concurrently — it costs a spawn's worth
//! of serialisation and buys a gate that means what it says.

use std::io;
use std::process::{Child, Command};
use std::sync::{Mutex, OnceLock};

/// Held across every spawn in this process, so no thread forks while another is between
/// creating a pipe and marking it close-on-exec.
fn gate() -> &'static Mutex<()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
}

/// Spawn `cmd`, serialised against every other [`spawn_piped`] in this process.
///
/// Use this for **any** child with piped stdio. A spawn that bypasses the gate can still steal a
/// pipe from one that uses it: the protection is only as complete as its adoption.
///
/// # Errors
///
/// Whatever [`Command::spawn`] returns — the gate changes when the fork happens, not whether it
/// succeeds.
pub fn spawn_piped(cmd: &mut Command) -> io::Result<Child> {
    // A panic elsewhere poisons the lock but leaves no shared state behind to be corrupted:
    // there is no state, only the timing. Recover rather than turn one panic into a process that
    // can no longer spawn anything.
    let _held = gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cmd.spawn()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::{Read, Write};
    use std::process::Stdio;

    #[test]
    fn a_gated_spawn_still_carries_a_query_and_its_answer() {
        let mut child = spawn_piped(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("cat; printf 'answered\\n'")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped()),
        )
        .expect("/bin/sh must be spawnable");

        {
            let mut stdin = child.stdin.take().expect("piped stdin");
            stdin.write_all(b"query\n").expect("the query must land");
        }
        let mut buf = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut buf)
            .expect("the answer must arrive");
        child.wait().expect("the child must be reapable");

        assert_eq!(buf, "query\nanswered\n");
    }

    // The race itself is NOT pinned here. Two synthetic reproducers were written and both passed
    // with the gate removed, so neither was evidence of anything; a test that cannot fail for the
    // reason it names is worse than no test, because it retires the question.
    //
    // What pins the gate instead is a pair of things that can actually fail:
    //   * `scripts/spawn-adoption.sh` fails the build if any process is spawned outside this
    //     module, which is the failure mode the gate really has — a bypass, not a bug in the
    //     lock;
    //   * `scm.rs`'s own suite under `--test-threads 8`, which is where the race was found and
    //     measured: 4 hangs in 60 runs without the gate, 0 in 180 with it.
}
