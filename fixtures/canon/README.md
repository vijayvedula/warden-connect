# `wcs1` canonicalisation vectors

**Input surface → canonical bytes → digest.** Thirty-one vectors, the interoperability
contract for `wcs1` (LLD §8.7.1).

`surface_digest` is what pins a declared surface, and drift detection is a comparison of
digests. So two implementations that disagree about the bytes do not merely differ — one of
them will report drift that did not happen, or miss drift that did. Until this directory
existed there were unit tests and a fuzz target and **no published expected-digest set**,
which meant `wcs1` was only ever verifiable against our own implementation.
`docs/limitations.md` — the register retired in the 2026-08-21 docs rewrite (git history at `3f30697`) — called that the most valuable thing
missing.

## Running them

```sh
scripts/canon-conformance.sh                    # our canonicaliser — a self-check
scripts/canon-conformance.sh ./my-canon         # yours
scripts/canon-conformance.sh ./my-canon --json  # machine-readable
```

Your canonicaliser is invoked as `<your-canon> <input.json> <mcp|a2a> <entity-id>` and must
either write the canonical document to stdout and exit 0, or exit non-zero printing the
`WC-NNNN` code. The **document** is compared, not only the digest, and a mismatch prints the
first differing byte offset with context — "your sha256 differs from ours" is not something
anybody can act on.

`<entity-id>` is passed in because it is *inside* the canonical document. A harness using its
own would compute a different digest for an identical surface and report a disagreement that
is not one.

## What is here

| File | Contents |
|---|---|
| `*.input.json` | One surface per vector |
| `expected.json` | Per vector: the `kind`, the **`rule`** it pins, and either `expect: "accept"` with the exact `document`, its `manifest` digest and the per-item digests, or the `WC-*` code a conforming implementation must refuse with |

`rule` is in the fixture rather than only in this document so a failing harness can print
*why* a vector exists, not just that two hex strings differ.

Regenerate with `python3 scripts/gen-canon-vectors.py`. Every vector also runs as a Rust
test (`canon::golden::every_published_vector_still_holds`), because a published vector set
that nothing checks rots into fiction.

## The three rules a third party is most likely to get wrong

Written out because each is a deliberate choice that a reasonable implementer would make
differently, and each was checked against a plausible wrong implementation before publishing.

**1 · Zero-width and bidi characters are preserved.** `zero-width-preserved` and
`bidi-preserved` differ from clean text. Stripping them is the obvious hygiene move and it is
wrong here: a stripped surface hashes *identically* to the clean one, so an
invisible-instruction attack becomes invisible to drift detection too. **Normalisation must
never launder an attack.** Screening is what objects to the characters; the pin's job is only
to notice they changed.

**2 · Numbers keep the form they were written in.** `1` and `1.0` are different documents and
therefore different digests (`number-integer` vs `number-float`), and `1e2` canonicalises as
`100.0` — a float, so not equal to the integer `100` (`number-exponent`). Many JSON stacks
normalise these, and any that does will disagree here. The choice is conservative in the safe
direction: a callee that reformats its schema raises a drift event that a human dismisses,
which is a cost. The alternative is a change that canonicalises to something identical, which
is a missed detection.

**3 · Only allowlisted fields survive, and the allowlist includes two fields you may not
expect.** MCP's **tool-level `title`** (revision 2025-06-18) and A2A's
**`skills[].examples`** are pinned — see `tool-title` and `skill-examples`. Both were once
outside the allowlist, and because the injection screener walks this same projection, an
injection placed in either **moved no digest and scored zero**. Everything not allowlisted —
`_meta`, vendor extensions, `provider`, `documentationUrl`, `capabilities`, unknown
annotations — is dropped, so changing one is *not* drift (`dropped-fields`,
`card-dropped-fields`, `annotation-allowlist`).

## Identity claims the set makes about itself

Asserted by `canon::golden::the_vectors_own_identity_claims_hold`, so this table cannot drift
away from the digests:

| Claim | Vectors |
|---|---|
| NFC: decomposed and precomposed are **the same** surface | `nfc` == `nfc-precomposed` |
| Member order is not significant | `baseline` == `key-order` |
| Item order is not significant | `baseline` == `tool-order` |
| `1` and `1.0` are **different** | `number-integer` != `number-float` |
| Example order is authored, not sorted away | `skill-examples` != `skill-examples-reordered` |
| A card version bump moves the manifest… | `card-baseline` != `card-version-bump` |
| …and never a contracted skill's digest | their `items.settle` are equal |

That last pair is the property the whole per-item design exists for: a callee bumping its
version must not invalidate every contract in the estate.

## Version policy

`wcs1` is **frozen**. If a vector's expected digest ever changes, the honest reading is not
"update the fixture" — it is that every pin in every registry has been invalidated, and the
path is `wcs2` with the shadow re-pin in §8.7.1. `expected.json` records `wcs1_version` so a
harness can say which version it checked rather than assuming.

## What these vectors do not cover

* **Surfaces at the limits.** `Limits` refusals — oversize, too many items, too deep, an
  over-long name — are exercised by unit tests and the fuzz target, not here, because the
  expected behaviour is a refusal with a code rather than a digest and the inputs are large.
* **Whether your *screener* agrees.** These vectors pin the projection; two implementations
  can canonicalise identically and still disagree about what is an injection.
* **A signed distribution.** These are files in a git repository. Nothing yet attests that
  the set you downloaded is the set we published — the same gap
  `docs/releasing.md` recorded for the contract vectors, before the register retired in the 2026-08-21 docs rewrite (git history at `3f30697`).

A canonicalisation disagreement is a finding whoever turns out to be wrong. In a format meant
to be interoperable, disagreeing about the bytes **is** the bug —
[`SECURITY.md`](../../.github/SECURITY.md) has the disclosure process.
