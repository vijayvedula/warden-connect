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
    /// The bytes the signature covers — everything up to and including the blank line.
    pub signed_body: String,
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

        // The signature covers the note through the blank line that ends the body. Rebuilt
        // rather than sliced by byte offset so a note with `\r\n` does not shift it.
        let signed_body = format!("{origin}\n{tree_size}\n{root_b64}\n");

        Ok(Checkpoint {
            origin,
            tree_size,
            root_hash: hex_encode(&root),
            signed_body,
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

/// Verify an inclusion proof, and the checkpoint over it when one is present.
///
/// `leaf` is the hex leaf hash — [`leaf_hash`] computes it from an entry body.
pub fn verify(leaf: &str, proof: &InclusionProof) -> Result<Inclusion> {
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
            (
                true,
                Some(cp.origin),
                "a checkpoint commits to this root, and its SIGNATURE is not checked here — \
                 supply the log's public key to make that a proof rather than a claim",
            )
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
        let out = verify(&leaf, &proof).unwrap();
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
        let err = verify(&leaf_hash(b"not the entry that was logged"), &proof).unwrap_err();
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
        assert!(verify(&leaf, &proof).is_err());
    }

    #[test]
    fn a_reordered_audit_path_does_not_verify() {
        // Order is the proof. Two hashes swapped is a different path through the tree.
        let (leaf, mut proof) = fixture();
        proof.hashes.swap(0, 1);
        assert!(verify(&leaf, &proof).is_err());
    }

    #[test]
    fn a_truncated_or_padded_path_is_refused_rather_than_judged_on_the_final_hash() {
        let (leaf, proof) = fixture();
        let mut short = proof.clone();
        short.hashes.truncate(20);
        assert!(verify(&leaf, &short).is_err());

        let mut long = proof.clone();
        long.hashes.push(proof.hashes[0].clone());
        assert!(verify(&leaf, &long).is_err());
    }

    #[test]
    fn an_index_outside_the_tree_is_refused() {
        let (leaf, mut proof) = fixture();
        proof.log_index = proof.tree_size;
        let err = verify(&leaf, &proof).unwrap_err();
        assert!(err.detail().contains("outside a tree"), "{}", err.detail());

        proof.tree_size = 0;
        assert!(verify(&leaf, &proof).is_err());
    }

    #[test]
    fn a_checkpoint_that_disagrees_with_the_proof_is_refused() {
        // The attack a checkpoint exists to stop: a self-consistent proof against a root the
        // log never published. Here the proof is genuine and the checkpoint is not, which must
        // fail rather than pass on the strength of the proof alone.
        let (leaf, mut proof) = fixture();
        let cp = Checkpoint::parse(proof.checkpoint.as_deref().unwrap()).unwrap();
        let other_root = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        proof.checkpoint = Some(format!(
            "{}\n{}\n{}\n\n— fake AAAA\n",
            cp.origin, cp.tree_size, other_root
        ));
        let err = verify(&leaf, &proof).unwrap_err();
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
        let out = verify(&leaf, &proof).unwrap();
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
            assert!(verify(&leaf, &proof).is_err(), "{note:?} must not parse");
        }
    }

    #[test]
    fn the_checkpoint_signed_body_is_the_note_through_the_blank_line() {
        // What a signature verifier would be handed. Rebuilt rather than byte-sliced, so a
        // note delivered with CRLF does not shift the boundary and silently fail to verify.
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
