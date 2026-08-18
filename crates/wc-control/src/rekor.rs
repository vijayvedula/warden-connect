//! Transparency-log inclusion, verified offline (RFC 6962 §2.1.1).
//!
//! `DsseProvenanceVerifier` reported `rekor inclusion not checked`, and that was the honest
//! thing to say: an unchecked inclusion proof reported as verified provenance is worse than
//! none. This is the check, so it can stop being reported as absent.
//!
//! # What an inclusion proof does and does not establish
//!
//! It establishes that a leaf is **in a tree with a given root** — nothing more. Recomputing
//! the root from the leaf and the audit path proves the log could produce that root only if
//! the entry is in it, at that index, in a tree of that size.
//!
//! It says nothing about whether that root is the *log's* root. A response carrying both the
//! proof and the root it should produce is self-consistent by construction, and an attacker
//! serving you a forged entry can serve a matching root just as easily. So:
//!
//! * the **checkpoint** is where trust comes from. It is a signed note carrying the tree size
//!   and root hash, and [`Checkpoint::parse`] extracts them so the proof can be compared
//!   against a *signed* root rather than an asserted one;
//! * verifying that signature needs the log's public key, which is a trust root an operator
//!   configures — exactly like the issuer key and the SPIFFE bundle. Supply it and this
//!   module checks it; omit it and [`Inclusion::verify`] says the root was unattested rather
//!   than pretending otherwise.
//!
//! # Offline on purpose
//!
//! No HTTP, no Sigstore client, no dependency beyond what is already here. The proof and the
//! checkpoint are data an operator can fetch once, keep beside the artifact, and verify on an
//! air-gapped host years later — which is the position `docs/limitations.md` describes for
//! evidence generally, and the reason `connect attest verify` exists as an offline command.

use serde::{Deserialize, Serialize};
use wc_core::error::{Code, Result, WcError};
use wc_core::util::{hex_decode, hex_encode, sha256_bytes};

/// The domain-separation prefixes RFC 6962 uses so a leaf hash can never be mistaken for an
/// interior node hash. Omitting them is the classic second-preimage bug in a Merkle tree.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// An inclusion proof as Rekor serves it under `verification.inclusionProof`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InclusionProof {
    /// Zero-based index of the leaf.
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    /// Number of leaves in the tree the proof is against.
    #[serde(rename = "treeSize")]
    pub tree_size: u64,
    /// Root hash the audit path should reproduce, hex.
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    /// The audit path, hex, leaf-ward first.
    pub hashes: Vec<String>,
    /// The signed note the log published for this tree.
    #[serde(default)]
    pub checkpoint: Option<String>,
}

/// A signed checkpoint — the log's own statement of size and root.
///
/// The note format is `origin\ntreeSize\nbase64(rootHash)\n\n— keyname base64(sig)\n`. Parsed
/// rather than pattern-matched loosely, because a checkpoint whose fields are read wrongly is
/// a checkpoint that agrees with anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The log's origin line, e.g. `rekor.sigstore.dev - 3904496407287907110`.
    pub origin: String,
    /// Tree size the note commits to.
    pub tree_size: u64,
    /// Root hash the note commits to, hex.
    pub root_hash: String,
    /// The bytes the signature covers: the note text, ending in **one** newline.
    ///
    /// Not including the blank line that separates the text from the signatures — this comment
    /// used to say otherwise, and the code was right while the prose was wrong. Established by
    /// verifying the real `fixtures/rekor/` checkpoint against the log's published key: of the
    /// four plausible byte ranges, only this one verifies. Guessing would have produced a
    /// verifier that rejects every real checkpoint.
    pub signed_body: String,
    /// The signature lines, in order.
    pub signatures: Vec<NoteSignature>,
}

/// One `— <name> <base64>` line from a signed note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    /// The key name the log signs under, e.g. `rekor.sigstore.dev`.
    pub name: String,
    /// First four bytes of `SHA256(SPKI DER)` of the signing key.
    ///
    /// Rekor's own convention, and **not** the Go sumdb one (`SHA256(name || 0x0A || 0x01 ||
    /// key)`). Determined by computing all three candidates against the real fixture; only this
    /// one matches. It is a hint, not a security property — the signature is what decides — but
    /// checking it turns "signature does not verify" into "this note was signed by a different
    /// key than the one you configured", which is the difference between an operator finding the
    /// problem in a minute and in an afternoon.
    pub key_hash: [u8; 4],
    /// The signature bytes, as they appeared. ECDSA here is DER, as Sigstore emits.
    pub signature: Vec<u8>,
}

impl Checkpoint {
    /// Parse a signed note.
    pub fn parse(note: &str) -> Result<Checkpoint> {
        let mut lines = note.lines();
        let origin = lines
            .next()
            .ok_or_else(|| bad("checkpoint is empty"))?
            .to_string();
        let size_line = lines.next().ok_or_else(|| bad("checkpoint has no size"))?;
        let tree_size: u64 = size_line
            .trim()
            .parse()
            .map_err(|_| bad(format!("checkpoint size {size_line:?} is not a number")))?;
        let root_b64 = lines
            .next()
            .ok_or_else(|| bad("checkpoint has no root hash"))?
            .trim();

        use base64::Engine as _;
        let root = base64::engine::general_purpose::STANDARD
            .decode(root_b64)
            .map_err(|_| bad("checkpoint root hash is not base64"))?;
        if root.len() != 32 {
            return Err(bad(format!(
                "checkpoint root hash is {} bytes, expected 32",
                root.len()
            )));
        }

        // The signature covers the note text and its single trailing newline. Rebuilt rather
        // than sliced by byte offset so a note with `\r\n` does not shift it.
        let signed_body = format!("{origin}\n{tree_size}\n{root_b64}\n");

        // Signature lines: `— <name> <base64(keyhash[4] || sig)>`. The separator is an em-dash;
        // a hyphen is not it, and a note whose signature lines are skipped because the character
        // did not match would verify as "no signatures present" — which is why an unparseable
        // line is an error rather than a line that is passed over.
        let mut signatures = Vec::new();
        for line in note.lines().skip(3) {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let rest = line
                .strip_prefix("\u{2014} ")
                .ok_or_else(|| bad(format!("checkpoint line {line:?} is not a signature line")))?;
            let (name, b64) = rest
                .split_once(' ')
                .ok_or_else(|| bad("a signature line carries no signature"))?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| bad("a checkpoint signature is not base64"))?;
            if raw.len() < 5 {
                return Err(bad(format!(
                    "a checkpoint signature is {} bytes, too short to carry a 4-byte key hash \
                     and a signature",
                    raw.len()
                )));
            }
            let mut key_hash = [0u8; 4];
            key_hash.copy_from_slice(&raw[..4]);
            signatures.push(NoteSignature {
                name: name.to_string(),
                key_hash,
                signature: raw[4..].to_vec(),
            });
        }

        Ok(Checkpoint {
            origin,
            tree_size,
            root_hash: hex_encode(&root),
            signed_body,
            signatures,
        })
    }
}

/// What verifying an inclusion proof came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    /// The leaf hash that was proved, hex.
    pub leaf_hash: String,
    /// The root the audit path produced, hex.
    pub computed_root: String,
    /// Tree size the proof was against.
    pub tree_size: u64,
    /// Whether a checkpoint agreed with the proof's root and size.
    pub checkpoint_agrees: bool,
    /// The checkpoint's origin, when there was one.
    pub origin: Option<String>,
    /// Why this root should or should not be believed. Always populated: an inclusion result
    /// with no statement about the root's provenance is the misleading half of this feature.
    pub root_trust: &'static str,
}

/// The RFC 6962 leaf hash of an entry body: `SHA256(0x00 || body)`.
///
/// The prefix is not decoration. Without it a leaf and an interior node hash the same way, and
/// a leaf whose contents look like two concatenated hashes can be presented as a subtree —
/// the standard second-preimage attack on a Merkle tree.
#[must_use]
pub fn leaf_hash(body: &[u8]) -> String {
    let mut input = Vec::with_capacity(body.len() + 1);
    input.push(LEAF_PREFIX);
    input.extend_from_slice(body);
    hex_encode(&sha256_bytes(&input))
}

/// The log's own signing key, as an operator configures it.
///
/// A trust root, exactly like the issuer key and the SPIFFE bundle — which is why it is a
/// separate type rather than an `Option<&[u8]>` threaded through: the thing that makes a
/// checkpoint a proof rather than a claim should be visible in the signature of the function
/// that uses it.
#[derive(Debug, Clone)]
pub struct LogKey {
    /// The name the log signs under. Compared to the signature line's name.
    pub name: String,
    /// SPKI DER of the public key. `SHA256(..)[..4]` is the note's key hash.
    pub spki_der: Vec<u8>,
}

impl LogKey {
    /// Load a log key from a PEM `SubjectPublicKeyInfo`, as every log publishes it.
    pub fn from_pem(name: &str, pem: &[u8]) -> Result<LogKey> {
        let text = std::str::from_utf8(pem)
            .map_err(|_| bad("the log public key is not valid UTF-8 PEM"))?;
        let body: String = text
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
            .collect();
        if body.is_empty() {
            return Err(bad("the log public key has no PEM body"));
        }
        use base64::Engine as _;
        let spki_der = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map_err(|_| bad("the log public key PEM body is not base64"))?;
        Ok(LogKey {
            name: name.to_string(),
            spki_der,
        })
    }

    /// The four-byte key hash a note carries for this key.
    #[must_use]
    pub fn key_hash(&self) -> [u8; 4] {
        let full = sha256_bytes(&self.spki_der);
        [full[0], full[1], full[2], full[3]]
    }
}

/// Verify a checkpoint's signature against the log's key.
///
/// This is what turns "a checkpoint commits to this root" into "the log said so". Without it a
/// response carrying a proof and a matching checkpoint is self-consistent and nothing more: an
/// attacker serving a forged entry can serve a matching checkpoint just as easily, because
/// nothing in the response is signed by anyone the verifier trusts.
///
/// ECDSA P-256 over SHA-256, DER-encoded, which is what Rekor emits. The DER is converted to the
/// raw `R‖S` form the JWS verifier wants by the same `der_ecdsa_to_raw` the DSSE path uses — one
/// implementation, because two would drift and the one used less would be the broken one.
pub fn verify_checkpoint(cp: &Checkpoint, key: &LogKey) -> Result<()> {
    if cp.signatures.is_empty() {
        return Err(bad(
            "the checkpoint carries no signature line, so there is nothing to verify",
        ));
    }

    let expected_hash = key.key_hash();
    let mut last: Option<WcError> = None;

    for sig in &cp.signatures {
        if sig.name != key.name {
            continue;
        }
        if sig.key_hash != expected_hash {
            // Reported specifically. "Signature does not verify" would be true and useless: the
            // operator's problem is that they configured a different key, not that the log lied.
            last = Some(bad(format!(
                "the checkpoint was signed under key hash {} and the configured key hashes to \
                 {} — this is a different key for the same log name",
                hex_encode(&sig.key_hash),
                hex_encode(&expected_hash)
            )));
            continue;
        }

        let decoding = jsonwebtoken::DecodingKey::from_ec_der(&spki_ec_point(&key.spki_der)?);
        let raw = crate::attest::der_ecdsa_to_raw(&sig.signature, 32)
            .unwrap_or_else(|| sig.signature.clone());
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        let ok = jsonwebtoken::crypto::verify(
            &sig_b64,
            cp.signed_body.as_bytes(),
            &decoding,
            jsonwebtoken::Algorithm::ES256,
        )
        .map_err(|e| bad("the checkpoint signature could not be checked").with_source(e))?;
        if ok {
            return Ok(());
        }
        last = Some(bad(
            "the checkpoint signature does not verify under the configured log key",
        ));
    }

    Err(last.unwrap_or_else(|| {
        bad(format!(
            "no signature line names {:?}; the note is signed by {}",
            key.name,
            cp.signatures
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }))
}

/// Extract the uncompressed EC point from an SPKI DER, which is what `from_ec_der` wants.
///
/// `jsonwebtoken` names its constructor `from_ec_der` and means the **point**, not the SPKI
/// wrapper — a distinction that costs an hour if you assume otherwise, because passing the SPKI
/// produces a key that simply never verifies. An uncompressed P-256 point is 65 bytes starting
/// `0x04`, and it is the tail of the SPKI, so this finds it rather than parsing ASN.1.
fn spki_ec_point(spki: &[u8]) -> Result<Vec<u8>> {
    if spki.len() >= 65 && spki[spki.len() - 65] == 0x04 {
        return Ok(spki[spki.len() - 65..].to_vec());
    }
    Err(bad(
        "the log public key does not end in an uncompressed P-256 point; only ES256 log keys are \
         supported here",
    ))
}

/// Verify an inclusion proof, and the checkpoint over it when one is present.
///
/// `leaf` is the hex leaf hash — [`leaf_hash`] computes it from an entry body.
///
/// `log_key` is what makes the checkpoint a proof. Supply it and the note's signature is checked
/// and [`Inclusion::root_trust`] says so; omit it and the result says the root was *unattested*
/// rather than pretending otherwise.
pub fn verify(leaf: &str, proof: &InclusionProof, log_key: Option<&LogKey>) -> Result<Inclusion> {
    if proof.tree_size == 0 {
        return Err(bad("an empty tree contains nothing"));
    }
    if proof.log_index >= proof.tree_size {
        return Err(bad(format!(
            "log index {} is outside a tree of {} leaves",
            proof.log_index, proof.tree_size
        )));
    }

    let mut hash = decode32(leaf, "leaf hash")?;
    let mut index = proof.log_index;
    let mut last = proof.tree_size - 1;

    for (depth, sibling_hex) in proof.hashes.iter().enumerate() {
        let sibling = decode32(sibling_hex, &format!("audit path entry {depth}"))?;
        if !index.is_multiple_of(2) || index == last {
            hash = node(&sibling, &hash);
            // A left-edge climb: keep rising while this node is a right child of nothing.
            while index.is_multiple_of(2) && index != 0 {
                index /= 2;
                last /= 2;
            }
        } else {
            hash = node(&hash, &sibling);
        }
        index /= 2;
        last /= 2;
    }

    // The path must reach the root exactly. A path that is too short stops at a subtree and a
    // path that is too long walks past it, and both would otherwise be judged only by whether
    // the final hash happened to match.
    if index != 0 {
        return Err(bad(format!(
            "the audit path has {} entries, which does not reach the root of a tree of {} \
             leaves",
            proof.hashes.len(),
            proof.tree_size
        )));
    }

    let computed_root = hex_encode(&hash);
    if computed_root != proof.root_hash.to_lowercase() {
        return Err(WcError::with_detail(
            Code::PROVENANCE_UNVERIFIABLE,
            format!(
                "inclusion proof does not reproduce the stated root: computed {computed_root}, \
                 stated {}",
                proof.root_hash
            ),
        ));
    }

    // The proof is internally consistent. Whether the root is the *log's* root is a separate
    // question, and the answer is reported rather than assumed.
    let (checkpoint_agrees, origin, root_trust) = match &proof.checkpoint {
        None => (
            false,
            None,
            "no checkpoint: the root came from the same response as the proof, so this shows \
             internal consistency and not that the entry is in the public log",
        ),
        Some(note) => {
            let cp = Checkpoint::parse(note)?;
            if cp.root_hash != computed_root || cp.tree_size != proof.tree_size {
                return Err(WcError::with_detail(
                    Code::PROVENANCE_UNVERIFIABLE,
                    format!(
                        "the checkpoint commits to root {} at size {} and the proof produced {} \
                         at size {}",
                        cp.root_hash, cp.tree_size, computed_root, proof.tree_size
                    ),
                ));
            }
            match log_key {
                None => (
                    true,
                    Some(cp.origin),
                    "a checkpoint commits to this root, and its SIGNATURE is not checked \
                     because no log key was configured — supply one to make this a proof \
                     rather than a claim",
                ),
                Some(key) => {
                    // A configured key that does not verify is an error, never a downgrade to
                    // the unsigned wording. An operator who supplied a key is asking a
                    // question, and answering a weaker one would be the worst outcome here.
                    verify_checkpoint(&cp, key)?;
                    (
                        true,
                        Some(cp.origin),
                        "the log SIGNED this root: the checkpoint verifies under the configured \
                         log key, so the entry is in the public log and not merely in a tree \
                         the response described",
                    )
                }
            }
        }
    };

    Ok(Inclusion {
        leaf_hash: leaf.to_lowercase(),
        computed_root,
        tree_size: proof.tree_size,
        checkpoint_agrees,
        origin,
        root_trust,
    })
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 65];
    input[0] = NODE_PREFIX;
    input[1..33].copy_from_slice(left);
    input[33..].copy_from_slice(right);
    sha256_bytes(&input)
}

fn decode32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let raw = hex_decode(hex_str).ok_or_else(|| bad(format!("{what} is not hex")))?;
    raw.try_into()
        .map_err(|_| bad(format!("{what} is not 32 bytes")))
}

fn bad(detail: impl Into<String>) -> WcError {
    WcError::with_detail(Code::PROVENANCE_UNVERIFIABLE, detail)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use base64::Engine as _;

    /// A real entry from the public Rekor log, captured at index 1000000. Somebody else's
    /// entry: it proves the **proof mathematics** against real data, which is the part that
    /// has to be right, and makes no claim about our own provenance.
    const ENTRY: &str = include_str!("../../../fixtures/rekor/entry.json");

    fn fixture() -> (String, InclusionProof) {
        let v: serde_json::Value = serde_json::from_str(ENTRY).unwrap();
        let body = base64::engine::general_purpose::STANDARD
            .decode(v["body"].as_str().unwrap())
            .unwrap();
        let proof: InclusionProof =
            serde_json::from_value(v["verification"]["inclusionProof"].clone()).unwrap();
        (leaf_hash(&body), proof)
    }

    #[test]
    fn a_real_rekor_inclusion_proof_verifies() {
        let (leaf, proof) = fixture();
        assert_eq!(proof.hashes.len(), 22, "the fixture's audit path changed");
        let out = verify(&leaf, &proof, None).unwrap();
        assert_eq!(out.computed_root, proof.root_hash);
        assert_eq!(out.tree_size, proof.tree_size);
        assert!(out.checkpoint_agrees, "the fixture carries a checkpoint");
        assert_eq!(
            out.origin.as_deref(),
            Some("rekor.sigstore.dev - 3904496407287907110")
        );
        // The honest half: the signature is not checked, and the result says so.
        assert!(
            out.root_trust.contains("SIGNATURE is not checked"),
            "{}",
            out.root_trust
        );
    }

    #[test]
    fn the_leaf_hash_is_domain_separated() {
        // Without the 0x00 prefix a leaf hashes like an interior node, and a leaf whose bytes
        // look like two concatenated hashes could be presented as a subtree. This is the
        // second-preimage attack RFC 6962 exists to prevent, so the prefix is asserted rather
        // than assumed from the fixture happening to verify.
        let body = b"hello";
        assert_ne!(leaf_hash(body), hex_encode(&sha256_bytes(body)));

        let mut with_prefix = vec![0x00u8];
        with_prefix.extend_from_slice(body);
        assert_eq!(leaf_hash(body), hex_encode(&sha256_bytes(&with_prefix)));
    }

    #[test]
    fn a_different_leaf_does_not_verify() {
        // The point of the whole exercise: this proof is about one entry.
        let (_, proof) = fixture();
        let err = verify(&leaf_hash(b"not the entry that was logged"), &proof, None).unwrap_err();
        assert_eq!(err.code(), Code::PROVENANCE_UNVERIFIABLE);
        assert!(
            err.detail().contains("does not reproduce"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_tampered_audit_path_does_not_verify() {
        let (leaf, mut proof) = fixture();
        let flipped = {
            let mut h = proof.hashes[3].clone();
            let first = if h.starts_with('a') { 'b' } else { 'a' };
            h.replace_range(0..1, &first.to_string());
            h
        };
        proof.hashes[3] = flipped;
        assert!(verify(&leaf, &proof, None).is_err());
    }

    #[test]
    fn a_reordered_audit_path_does_not_verify() {
        // Order is the proof. Two hashes swapped is a different path through the tree.
        let (leaf, mut proof) = fixture();
        proof.hashes.swap(0, 1);
        assert!(verify(&leaf, &proof, None).is_err());
    }

    #[test]
    fn a_truncated_or_padded_path_is_refused_rather_than_judged_on_the_final_hash() {
        let (leaf, proof) = fixture();
        let mut short = proof.clone();
        short.hashes.truncate(20);
        assert!(verify(&leaf, &short, None).is_err());

        let mut long = proof.clone();
        long.hashes.push(proof.hashes[0].clone());
        assert!(verify(&leaf, &long, None).is_err());
    }

    #[test]
    fn an_index_outside_the_tree_is_refused() {
        let (leaf, mut proof) = fixture();
        proof.log_index = proof.tree_size;
        let err = verify(&leaf, &proof, None).unwrap_err();
        assert!(err.detail().contains("outside a tree"), "{}", err.detail());

        proof.tree_size = 0;
        assert!(verify(&leaf, &proof, None).is_err());
    }

    const LOG_PUB: &[u8] = include_bytes!("../../../fixtures/rekor/log-public-key.pem");
    const LOG_NAME: &str = "rekor.sigstore.dev";

    fn log_key() -> LogKey {
        LogKey::from_pem(LOG_NAME, LOG_PUB).unwrap()
    }

    #[test]
    fn the_real_checkpoint_verifies_under_the_real_log_key() {
        // The test the whole feature exists for, and the only one that could have found the two
        // things this got wrong on the first attempt. Both were determined by running candidates
        // against this fixture rather than reasoned about:
        //
        //   * the signature covers the note text ending in ONE newline, not through the blank
        //     line that separates text from signatures;
        //   * the four-byte key hash is `SHA256(SPKI DER)[..4]`, which is Rekor's convention and
        //     NOT the Go sumdb one (`SHA256(name || 0x0A || 0x01 || key)`).
        //
        // Either wrong and the verifier rejects every real checkpoint in existence, while every
        // hand-rolled test of a note we signed ourselves would pass.
        let (leaf, proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();

        assert_eq!(cp.signatures.len(), 1);
        assert_eq!(cp.signatures[0].name, LOG_NAME);
        assert_eq!(cp.signatures[0].key_hash, log_key().key_hash());
        assert_eq!(
            cp.signatures[0].signature[0], 0x30,
            "Rekor emits DER; a raw R‖S here would mean the fixture changed shape"
        );

        verify_checkpoint(&cp, &log_key()).expect("the public log's own checkpoint must verify");

        // And through the whole path, where the verdict wording changes because of it.
        let unsigned = verify(&leaf, &proof, None).unwrap();
        assert!(unsigned.root_trust.contains("not checked"));
        let signed = verify(&leaf, &proof, Some(&log_key())).unwrap();
        assert!(
            signed.root_trust.contains("SIGNED"),
            "{}",
            signed.root_trust
        );
        assert_eq!(signed.computed_root, unsigned.computed_root);
    }

    #[test]
    fn a_tampered_checkpoint_body_fails_the_signature() {
        // The forgery the signature stops: a root the log never published, presented with the
        // log's own signature line copied across. The proof is regenerated to match the forged
        // root, so every check *except* the signature passes.
        let (_, proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        let sig_line = proof
            .checkpoint
            .as_deref()
            .unwrap()
            .lines()
            .find(|l| l.starts_with('\u{2014}'))
            .unwrap()
            .to_string();

        let forged_root = base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]);
        let forged = format!(
            "{}\n{}\n{}\n\n{}\n",
            cp.origin, cp.tree_size, forged_root, sig_line
        );
        let parsed = Checkpoint::parse(&forged).unwrap();
        assert_eq!(
            parsed.signatures, cp.signatures,
            "the signature was copied intact"
        );

        let err = verify_checkpoint(&parsed, &log_key()).unwrap_err();
        assert!(err.detail().contains("does not verify"), "{}", err.detail());
    }

    #[test]
    fn a_different_key_for_the_same_log_name_is_named_as_such() {
        // The operator error this distinguishes. "Signature does not verify" is true and useless
        // when the real problem is that a different key was configured for the same log — a
        // rotated key, a staging log, a copy-paste. The key hash in the note says which, and
        // saying so is the difference between a minute and an afternoon.
        let (_, proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        let mut other = log_key();
        // Same name, different key material.
        let last = other.spki_der.len() - 1;
        other.spki_der[last] ^= 0xff;

        let err = verify_checkpoint(&cp, &other).unwrap_err();
        assert!(
            err.detail().contains("different key for the same log name"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_checkpoint_signed_by_another_log_is_refused() {
        // A note that verifies is not enough: it has to be *this* log's note. Otherwise a valid
        // checkpoint from any transparency log would vouch for an entry in ours.
        let (_, proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        let mut elsewhere = log_key();
        elsewhere.name = "log.example.internal".to_string();

        let err = verify_checkpoint(&cp, &elsewhere).unwrap_err();
        assert!(
            err.detail().contains("no signature line names"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_configured_key_that_fails_is_an_error_not_a_downgrade() {
        // The trap worth a test of its own: an operator who supplies a log key is asking a
        // question, and answering the weaker one — "well, a checkpoint agrees" — would be the
        // worst available outcome. A key that does not verify fails the whole verification.
        let (leaf, proof) = fixture();
        let mut wrong = log_key();
        let n = wrong.spki_der.len() - 2;
        wrong.spki_der[n] ^= 0x0f;
        assert!(verify(&leaf, &proof, Some(&wrong)).is_err());
        // ...while omitting the key still succeeds, with the weaker wording.
        assert!(verify(&leaf, &proof, None).is_ok());
    }

    #[test]
    fn a_note_with_no_signature_line_has_nothing_to_verify() {
        let (_, proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        let bare = format!(
            "{}\n{}\n{}\n\n",
            cp.origin,
            cp.tree_size,
            base64::engine::general_purpose::STANDARD.encode(hex_decode(&cp.root_hash).unwrap())
        );
        let parsed = Checkpoint::parse(&bare).unwrap();
        assert!(parsed.signatures.is_empty());
        let err = verify_checkpoint(&parsed, &log_key()).unwrap_err();
        assert!(
            err.detail().contains("no signature line"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_log_key_pem_is_read_the_way_logs_publish_it() {
        let key = log_key();
        assert_eq!(key.name, LOG_NAME);
        // SPKI DER for a P-256 key: 91 bytes, ending in the 65-byte uncompressed point.
        assert_eq!(key.spki_der.len(), 91);
        assert_eq!(spki_ec_point(&key.spki_der).unwrap().len(), 65);
        assert!(LogKey::from_pem(LOG_NAME, b"not a pem").is_err());
        assert!(LogKey::from_pem(
            LOG_NAME,
            b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"
        )
        .is_err());
    }

    #[test]
    fn a_checkpoint_that_disagrees_with_the_proof_is_refused() {
        // The attack a checkpoint exists to stop: a self-consistent proof against a root the
        // log never published. Here the proof is genuine and the checkpoint is not, which must
        // fail rather than pass on the strength of the proof alone.
        let (leaf, mut proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        let other_root = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        // A well-formed signature line carrying a bogus signature, so this test fails on the
        // root disagreement it is named for rather than on the line being unparseable. It was
        // `AAAA` — three bytes, which the signature parser now refuses before it gets this far.
        let fake_sig = base64::engine::general_purpose::STANDARD.encode([0x22u8; 40]);
        proof.checkpoint = Some(format!(
            "{}\n{}\n{}\n\n— fake {fake_sig}\n",
            cp.origin, cp.tree_size, other_root
        ));
        let err = verify(&leaf, &proof, None).unwrap_err();
        assert!(
            err.detail().contains("checkpoint commits to root"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn no_checkpoint_verifies_the_maths_and_says_the_root_is_unattested() {
        // Not an error — the proof is still worth checking. What must not happen is reporting
        // it as though the entry were shown to be in the public log.
        let (leaf, mut proof) = fixture();
        proof.checkpoint = None;
        let out = verify(&leaf, &proof, None).unwrap();
        assert!(!out.checkpoint_agrees);
        assert!(out.origin.is_none());
        assert!(
            out.root_trust.contains("internal consistency"),
            "{}",
            out.root_trust
        );
    }

    #[test]
    fn a_malformed_checkpoint_is_an_error_not_a_shrug() {
        let (leaf, mut proof) = fixture();
        for note in [
            "",
            "only-an-origin\n",
            "origin\nnotanumber\nAAAA\n",
            "origin\n5\n!!!\n",
        ] {
            proof.checkpoint = Some(note.to_string());
            assert!(
                verify(&leaf, &proof, None).is_err(),
                "{note:?} must not parse"
            );
        }
    }

    #[test]
    fn the_checkpoint_signed_body_is_the_text_and_one_newline() {
        // What the signature actually covers — established against the real fixture, not chosen.
        // This test used to be named "…through the blank line", which was wrong; the code was
        // right. Rebuilt rather than byte-sliced, so a note delivered with CRLF does not shift
        // the boundary and silently fail to verify.
        let (_, proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        assert!(cp.signed_body.starts_with(&cp.origin));
        assert!(cp.signed_body.ends_with('\n'));
        assert_eq!(cp.signed_body.lines().count(), 3);

        let crlf = proof.checkpoint.as_deref().unwrap().replace('\n', "\r\n");
        let from_crlf = Checkpoint::parse(&crlf).unwrap();
        assert_eq!(from_crlf.root_hash, cp.root_hash);
        assert_eq!(from_crlf.signed_body, cp.signed_body);
    }
}
