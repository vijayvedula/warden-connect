//! External signers: keys this process does not hold (`docs/key-custody.md`).
//!
//! [`wc_core::contract::Signer`] is the seam. This module supplies the one
//! implementation that reaches real hardware **without adding a dependency**: it
//! delegates to a command the operator supplies.
//!
//! That is a deliberate choice over a vendored KMS SDK. An AWS/GCP/Azure client, or
//! a PKCS#11 binding, is a large dependency tree with its own credential model, and
//! §8.3 requires every new dependency to be justified per-crate. A short shell
//! wrapper around `aws kms sign`, `pkcs11-tool` or `yubico-piv-tool` costs nothing,
//! works with hardware that exists today, and keeps the credential model in the
//! operator's hands rather than ours.
//!
//! # The protocol
//!
//! ```text
//! stdin   the JWS signing input, base64url (no padding), one line
//! stdout  the signature, base64url (no padding). Nothing else
//! stderr  inherited — diagnostics go to the control plane's own stderr
//! exit    0, or the signature is refused
//! ```
//!
//! base64 in both directions rather than raw bytes, so a wrapper can be a shell
//! script without anyone having to think about binary-safe pipes.
//!
//! # The trap, stated once because it costs an estate
//!
//! **JWS ECDSA is the raw `R‖S` concatenation. Every HSM and KMS interface returns
//! DER.** A wrapper that forwards DER produces contracts that are well-formed,
//! signed, distributed — and rejected by every mediator, for no reason visible from
//! either end. [`wc_core::contract::IssuerKey`] length-checks the result and names
//! DER specifically when it sees it, so this is one error message rather than an
//! outage. The conversion belongs in the wrapper.
//!
//! # A wrapper that works
//!
//! A PIV token (YubiKey, Nitrokey) via `pkcs11-tool`, which emits `R‖S` directly and
//! so needs no conversion — the shape to prefer for exactly that reason:
//!
//! ```sh
//! #!/bin/sh
//! set -eu
//! tr '_-' '/+' | base64 -d \
//!   | pkcs11-tool --sign --mechanism ECDSA-SHA256 --id "$WC_PIV_ID" \
//!                 --login --pin-source "$WC_PIV_PIN_FILE" \
//!   | base64 | tr -d '=\n' | tr '/+' '_-'
//! ```
//!
//! For a KMS that returns DER, the wrapper must convert. `a_real_helper_produces_a
//! _signature_that_verifies` in this module's tests is a working example of that
//! conversion, kept executable so the guidance cannot rot into being wrong.
//!
//! Verify any wrapper before trusting it: a contract it signs must pass
//! `connect verify`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use wc_core::contract::{Algorithm, IssuerKey, Signer};
use wc_core::error::{Code, Result, WcError};

/// How long a signing helper gets before the operation is refused.
///
/// A signing call that hangs hangs issuance, and an issuance that never returns is
/// an outage that presents as slowness. Ten seconds is generous for a KMS round trip
/// and short enough that a stuck token is a visible failure.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A signer that delegates to an external command.
#[derive(Debug, Clone)]
pub struct CommandSigner {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl CommandSigner {
    /// Build a signer from a program and its arguments.
    ///
    /// The command runs once per signature. That is the right shape here: nothing on
    /// the request path signs — §8.10.3's hot path is `gate::verify`, a public-key
    /// check in the mediator — so a process spawn per mint is invisible against a
    /// human approval.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, args: &[String]) -> CommandSigner {
        CommandSigner {
            program: program.into(),
            args: args.to_vec(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> CommandSigner {
        self.timeout = timeout;
        self
    }

    /// Parse an operator-supplied command line: the program, then its arguments,
    /// split on whitespace.
    ///
    /// Whitespace splitting means no quoting and no shell. Both are deliberate: a
    /// signing helper invoked through a shell is an injection surface on the one
    /// operation everything else rests on, so anything needing quotes belongs in a
    /// script file that this command names.
    pub fn parse(command: &str) -> Result<CommandSigner> {
        let mut parts = command.split_whitespace();
        let program = parts.next().ok_or_else(|| {
            WcError::with_detail(Code::CONFIG_INVALID, "signing command is empty")
        })?;
        let args: Vec<String> = parts.map(str::to_string).collect();
        Ok(CommandSigner::new(program, &args))
    }

    /// Build an [`IssuerKey`] that signs through this command.
    pub fn into_issuer_key(self, kid: &str, alg: Algorithm) -> Result<IssuerKey> {
        IssuerKey::external(kid, alg, Box::new(self))
    }

    fn fail(&self, detail: impl std::fmt::Display) -> WcError {
        WcError::with_detail(
            Code::SIGNATURE_INVALID,
            format!("signing helper {}: {detail}", self.program.display()),
        )
    }
}

/// Kill a child and reap it, so a timed-out helper is not left behind.
fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl Signer for CommandSigner {
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>> {
        // stderr is inherited rather than piped. Piping both and reading them in
        // sequence deadlocks if the helper fills one pipe before closing the other,
        // and a signing helper's diagnostics are more use in the control plane's own
        // stderr than buried in an error string.
        let mut child = wc_core::proc::spawn_piped(
            Command::new(&self.program)
                .args(&self.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()),
        )
        .map_err(|e| self.fail("cannot spawn").with_source(e))?;

        let encoded = URL_SAFE_NO_PAD.encode(signing_input);
        {
            let Some(mut stdin) = child.stdin.take() else {
                kill(&mut child);
                return Err(self.fail("no stdin on the helper"));
            };
            // Dropped at the end of this block, which closes the pipe. A helper that
            // reads to EOF would otherwise wait for input that never ends.
            if let Err(e) = stdin
                .write_all(encoded.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
            {
                drop(stdin);
                kill(&mut child);
                return Err(self.fail("cannot write the signing input").with_source(e));
            }
        }

        let Some(mut stdout) = child.stdout.take() else {
            kill(&mut child);
            return Err(self.fail("no stdout on the helper"));
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = String::new();
            let read = stdout.read_to_string(&mut buf);
            let _ = tx.send(read.map(|_| buf));
        });

        let out = match rx.recv_timeout(self.timeout) {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => {
                kill(&mut child);
                return Err(self.fail("cannot read the signature").with_source(e));
            }
            Err(_) => {
                kill(&mut child);
                return Err(self.fail(format!("no signature within {:?}", self.timeout)));
            }
        };

        let status = child
            .wait()
            .map_err(|e| self.fail("cannot reap").with_source(e))?;
        if !status.success() {
            // Status before output: a helper that failed and still printed something
            // must not have that something treated as a signature.
            return Err(self.fail(format!("exited {status}")));
        }

        let trimmed = out.trim();
        if trimmed.is_empty() {
            return Err(self.fail("exited 0 and produced no signature"));
        }
        URL_SAFE_NO_PAD.decode(trimmed.as_bytes()).map_err(|e| {
            self.fail("signature is not base64url (no padding)")
                .with_source(e)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");
    const KID: &str = "wc-custody-es256";

    /// A scratch directory that cleans up after itself.
    struct Dir(PathBuf);

    impl Dir {
        fn new(label: &str) -> Dir {
            let p = std::env::temp_dir().join(format!(
                "wc-signer-{label}-{}-{:x}",
                std::process::id(),
                label.bytes().map(u64::from).sum::<u64>()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        /// Write an executable helper and return its path.
        fn script(&self, name: &str, body: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn signed(key: &IssuerKey) -> Result<String> {
        wc_core::contract::sign_detached(&serde_json::json!({"sub": "t", "seq": 42}), key)
    }

    #[test]
    fn a_real_helper_produces_a_signature_that_verifies() {
        // End to end through the documented protocol, with a wrapper that does the
        // DER→R‖S conversion the module doc tells operators to do. Kept executable so
        // the guidance cannot rot into being wrong.
        let dir = Dir::new("openssl");
        let keyfile = dir.path().join("key.pem");
        std::fs::write(&keyfile, PRIV).unwrap();
        // One script, in python, because the two things that bite a real wrapper are
        // both easy to get silently wrong in shell: base64url needs **re-padding**
        // before it can be decoded, and ECDSA DER has to become raw R‖S. Getting
        // either wrong produces a 64-byte signature over the wrong bytes, which
        // fails as "signature verification failed" and tells you nothing.
        let script = dir.script(
            "sign",
            &format!(
                r#"#!/usr/bin/env python3
import base64, subprocess, sys, tempfile, os

raw = sys.stdin.read().strip()
raw += "=" * (-len(raw) % 4)                 # base64url arrives unpadded
message = base64.urlsafe_b64decode(raw)

with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(message)
    path = f.name
try:
    der = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", "{key}", path],
        check=True, capture_output=True,
    ).stdout
finally:
    os.unlink(path)

assert der[0] == 0x30, "not a DER SEQUENCE"
i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)

def integer(i):
    assert der[i] == 0x02, "not a DER INTEGER"
    n = der[i + 1]
    # A leading 0x00 is DER's sign padding; a short value needs left-padding to 32
    return der[i + 2 : i + 2 + n].rjust(32, b"\0")[-32:], i + 2 + n

r, i = integer(i)
s, _ = integer(i)
sys.stdout.write(base64.urlsafe_b64encode(r + s).decode().rstrip("="))
"#,
                key = keyfile.display()
            ),
        );

        let key = CommandSigner::new(&script, &[])
            .into_issuer_key(KID, Algorithm::ES256)
            .unwrap();
        let jws = signed(&key).expect("the documented wrapper must work");

        let mut keys = wc_core::contract::IssuerKeys::new();
        keys.add_ec_pem(KID, PUB, Algorithm::ES256).unwrap();
        let back: serde_json::Value = wc_core::contract::verify_detached(&jws, KID, &keys).unwrap();
        assert_eq!(back["seq"], 42);
    }

    #[test]
    fn a_helper_that_exits_non_zero_signs_nothing() {
        // And specifically: one that fails *and prints something* must not have that
        // something used as a signature.
        let dir = Dir::new("angry");
        let script = dir.script("sign", "#!/bin/sh\ncat > /dev/null\necho AAAA\nexit 3\n");
        let key = CommandSigner::new(&script, &[])
            .into_issuer_key(KID, Algorithm::ES256)
            .unwrap();
        let err = signed(&key).unwrap_err();
        assert!(err.detail().contains("exited"), "{}", err.detail());
    }

    #[test]
    fn a_helper_that_succeeds_and_prints_nothing_signs_nothing() {
        // The silent-success case: exit 0, no output. Treating that as a signature
        // would mint an artifact signed with zero bytes.
        let dir = Dir::new("quiet");
        let script = dir.script("sign", "#!/bin/sh\ncat > /dev/null\nexit 0\n");
        let key = CommandSigner::new(&script, &[])
            .into_issuer_key(KID, Algorithm::ES256)
            .unwrap();
        let err = signed(&key).unwrap_err();
        assert!(err.detail().contains("no signature"), "{}", err.detail());
    }

    #[test]
    fn a_hanging_helper_is_refused_and_not_left_running() {
        let dir = Dir::new("hang");
        let script = dir.script("sign", "#!/bin/sh\ncat > /dev/null\nsleep 60\n");
        let key = CommandSigner::new(&script, &[])
            .with_timeout(Duration::from_millis(300))
            .into_issuer_key(KID, Algorithm::ES256)
            .unwrap();
        let started = std::time::Instant::now();
        let err = signed(&key).unwrap_err();
        assert!(
            err.detail().contains("no signature within"),
            "{}",
            err.detail()
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout did not fire: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_helper_that_forwards_der_is_told_exactly_what_is_wrong() {
        // The most likely misconfiguration by a wide margin, and the reason the
        // length check exists: without it this mints a contract every mediator
        // rejects for no visible reason. `MEQ` base64-decodes to 0x30 0x44 — a DER
        // SEQUENCE header, which is what the check looks for.
        let dir = Dir::new("der");
        let script = dir.script("sign", "#!/bin/sh\ncat > /dev/null\nprintf 'MEQ'\n");
        let key = CommandSigner::new(&script, &[])
            .into_issuer_key(KID, Algorithm::ES256)
            .unwrap();
        let err = signed(&key).unwrap_err();
        assert!(err.detail().contains("64-byte"), "{}", err.detail());
        assert!(err.detail().contains("DER-encoded"), "{}", err.detail());
    }

    #[test]
    fn a_missing_helper_fails_at_the_first_signature_not_at_construction() {
        // Honest about a limitation: the command is not probed when the key is built,
        // so a typo in the path surfaces on the first mint rather than at startup.
        // Named here so nobody assumes otherwise.
        let key = CommandSigner::new("/nonexistent/wc-signer", &[])
            .into_issuer_key(KID, Algorithm::ES256)
            .unwrap();
        let err = signed(&key).unwrap_err();
        assert!(err.detail().contains("cannot spawn"), "{}", err.detail());
    }

    #[test]
    fn the_command_line_is_split_without_a_shell() {
        let s = CommandSigner::parse("/usr/local/bin/wc-sign --key-id alias/wc-issuer").unwrap();
        assert_eq!(s.program, PathBuf::from("/usr/local/bin/wc-sign"));
        assert_eq!(s.args, vec!["--key-id", "alias/wc-issuer"]);
        assert_eq!(
            CommandSigner::parse("   ").unwrap_err().code(),
            Code::CONFIG_INVALID
        );
    }
}
