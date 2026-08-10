#!/usr/bin/env python3
"""Generate `fixtures/canon/` — the `wcs1` canonicalisation vector set.

    python3 scripts/gen-canon-vectors.py

`surface_digest` is what pins a surface, so two implementations must agree on it **byte for
byte** or drift detection means nothing between them. Until this existed there were unit
tests and a fuzz target and no published *input surface -> expected digest* set, which is
the one thing a third party actually needs. `docs/limitations.md` called it the most
valuable thing missing.

## What this script is and is not

Each vector is authored here as an input plus the **normative rule it pins**, and that rule
is the reviewable part. The expected digests are then read out of `connect canon`, because
`wcs1` is defined by that implementation (`WCS1_VERSION = 1`, frozen) — a vector set for a
reference implementation records what the reference does.

That makes this a *change detector plus a specification*, not an independent second reading.
The independent reading is somebody else's implementation running
`scripts/canon-conformance.sh`, which is the whole point of publishing the set.

So: adding a vector is cheap and safe. Changing an existing vector's expected digest is
almost always wrong — it means `wcs1` moved, every pin in every registry is invalidated, and
the answer is `wcs2` with a shadow re-pin (§8.7.1), not a new fixture.
"""

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "fixtures" / "canon"

# The entity a vector canonicalises against. It is inside the canonical document, so it has
# to be fixed and stated rather than defaulted — a harness that used its own would compute
# different digests for identical surfaces and report a disagreement that is not one.
ENTITY = "spiffe://org/ns/tools/sa/vectors"


def binary() -> pathlib.Path:
    for candidate in ("target/release/connect", "target/debug/connect"):
        path = REPO / candidate
        if path.is_file():
            return path
    sys.exit("no connect binary; run `cargo build --release -p wc-cli` first")


# --- the vectors -------------------------------------------------------------
#
# `rule` is the normative statement each case exists to pin. It is in the fixture, not only
# in the README, so a third party's harness can print *why* a vector failed rather than only
# that two hex strings differ.

MCP: list[tuple[str, str, dict]] = [
    (
        "baseline",
        "The shape everything else varies from: two tools, schemas, an annotation.",
        {"tools": [
            {"name": "get_balance", "description": "Read an account balance.",
             "inputSchema": {"type": "object",
                             "properties": {"account_id": {"type": "string"}},
                             "required": ["account_id"]},
             "annotations": {"readOnlyHint": True, "title": "Get balance"}},
            {"name": "wire_funds", "description": "Move money between accounts.",
             "inputSchema": {"type": "object",
                             "properties": {"amount": {"type": "number"}},
                             "required": ["amount"]}},
        ]},
    ),
    (
        "key-order",
        "Member order in the input is not significant: objects are emitted sorted by key.",
        {"tools": [
            {"annotations": {"title": "Get balance", "readOnlyHint": True},
             "inputSchema": {"required": ["account_id"],
                             "properties": {"account_id": {"type": "string"}},
                             "type": "object"},
             "description": "Read an account balance.", "name": "get_balance"},
            {"inputSchema": {"required": ["amount"],
                             "properties": {"amount": {"type": "number"}},
                             "type": "object"},
             "description": "Move money between accounts.", "name": "wire_funds"},
        ]},
    ),
    (
        "tool-order",
        "Tool order in the input is not significant: items are emitted sorted by name.",
        {"tools": [
            {"name": "wire_funds", "description": "Move money between accounts.",
             "inputSchema": {"type": "object",
                             "properties": {"amount": {"type": "number"}},
                             "required": ["amount"]}},
            {"name": "get_balance", "description": "Read an account balance.",
             "inputSchema": {"type": "object",
                             "properties": {"account_id": {"type": "string"}},
                             "required": ["account_id"]},
             "annotations": {"readOnlyHint": True, "title": "Get balance"}},
        ]},
    ),
    (
        "bare-array",
        "A bare array of tools is accepted as equivalent to {\"tools\": [...]}.",
        [{"name": "t", "description": "d"}],
    ),
    (
        "dropped-fields",
        "Only allowlisted fields survive. `_meta`, vendor extensions and unknown members are "
        "dropped, so adding one is NOT drift.",
        {"tools": [{"name": "t", "description": "d", "_meta": {"trace": "abc"},
                    "x-vendor": {"anything": [1, 2, 3]}, "unknownField": "ignored"}],
         "serverInfo": {"name": "banner", "version": "9.9.9"}},
    ),
    (
        "tool-title",
        "The tool-level `title` MCP added in revision 2025-06-18 IS pinned. Leaving it out "
        "made a poisoned display name invisible to both drift detection and screening.",
        {"tools": [{"name": "t", "title": "Wire funds", "description": "d"}]},
    ),
    (
        "annotation-allowlist",
        "Exactly five annotations are pinned — title, readOnlyHint, destructiveHint, "
        "idempotentHint, openWorldHint. Others are dropped.",
        {"tools": [{"name": "t", "annotations": {
            "title": "T", "readOnlyHint": False, "destructiveHint": True,
            "idempotentHint": False, "openWorldHint": True, "vendorHint": "dropped"}}]},
    ),
    (
        "order-free-arrays",
        "`required` and `enum` carry no order, so they are sorted. Reordering them is not "
        "drift.",
        {"tools": [{"name": "t", "inputSchema": {
            "type": "object",
            "properties": {"currency": {"type": "string", "enum": ["SGD", "AUD", "USD"]}},
            "required": ["z", "a", "m"]}}]},
    ),
    (
        "ordered-arrays",
        "Every other array keeps its order, because order can carry meaning. `anyOf` here.",
        {"tools": [{"name": "t", "inputSchema": {
            "anyOf": [{"type": "string"}, {"type": "integer"}]}}]},
    ),
    (
        "null-members",
        "Null members are dropped, so an explicit null and an absent member canonicalise "
        "identically.",
        {"tools": [{"name": "t", "description": "d", "outputSchema": None,
                    "annotations": None}]},
    ),
    (
        "nfc",
        "Text is NFC-normalised: a decomposed sequence and its precomposed form are the "
        "same surface. This vector is authored decomposed (e + U+0301).",
        {"tools": [{"name": "t", "description": "café balance"}]},
    ),
    (
        "nfc-precomposed",
        "The precomposed twin of `nfc`. Its digest MUST equal that vector's — the only pair "
        "here required to collide.",
        {"tools": [{"name": "t", "description": "café balance"}]},
    ),
    (
        "zero-width-preserved",
        "A zero-width space is PRESERVED, not stripped. Normalisation must never launder an "
        "attack, so this differs from `baseline`-style clean text.",
        {"tools": [{"name": "t", "description": "transfer​ funds"}]},
    ),
    (
        "bidi-preserved",
        "A right-to-left override is preserved for the same reason.",
        {"tools": [{"name": "t", "description": "transfer\u202E funds"}]},
    ),
    (
        "case-significant",
        "Case is significant. No case folding anywhere.",
        {"tools": [{"name": "t", "description": "READ"}]},
    ),
    (
        "number-integer",
        "Numbers are emitted as written. `1` is an integer and stays one — compare "
        "`number-float`, whose digest MUST differ. The most likely place for a third-party "
        "implementation to disagree.",
        {"tools": [{"name": "t", "inputSchema": {"maximum": 1}}]},
    ),
    (
        "number-float",
        "`1.0` keeps its fractional form, so it does NOT canonicalise to `1`. Conservative "
        "in the safe direction: a reformatted schema reads as drift, and no change is ever "
        "laundered into looking identical.",
        {"tools": [{"name": "t", "inputSchema": {"maximum": 1.0}}]},
    ),
    (
        "number-exponent",
        "An exponent is expanded by the JSON reader, so `1e2` canonicalises as `100.0` — a "
        "float, and therefore NOT equal to the integer `100`. If your implementation "
        "disagrees anywhere, expect it here.",
        {"tools": [{"name": "t", "inputSchema": {"maximum": 1e2}}]},
    ),
    (
        "unicode-text",
        "Non-Latin text and astral-plane characters survive intact.",
        {"tools": [{"name": "t", "description": "賁款を送る \U0001f4b8"}]},
    ),
    (
        "empty-tools",
        "An empty tool list canonicalises rather than erroring. A surface with nothing on it "
        "is a fact about the callee, not a malformed document.",
        {"tools": []},
    ),
    (
        "nested-schema",
        "Nesting is walked to depth, not truncated.",
        {"tools": [{"name": "t", "inputSchema": {"type": "object", "properties": {
            "a": {"type": "object", "properties": {
                "b": {"type": "object", "properties": {
                    "c": {"type": "array", "items": {"type": "string"}}}}}}}}}]},
    ),
]

A2A: list[tuple[str, str, dict]] = [
    (
        "card-baseline",
        "Skills are the items; card-level fields land in `meta`, so a version bump moves the "
        "manifest and no contracted skill digest.",
        {"name": "Settlement Agent", "version": "2.1.0", "description": "Settles payments.",
         "url": "https://acme.example/a2a",
         "securitySchemes": {"oauth2": {"type": "oauth2"}},
         "skills": [
             {"id": "settle", "name": "Settle", "description": "Settle a payment.",
              "inputModes": ["text"], "outputModes": ["text"], "tags": ["payments"]},
             {"id": "quote", "name": "Quote", "description": "Quote a settlement."}]},
    ),
    (
        "card-version-bump",
        "The same card at 2.2.0. Its manifest MUST differ from `card-baseline` and the "
        "`settle` item digest MUST match it.",
        {"name": "Settlement Agent", "version": "2.2.0", "description": "Settles payments.",
         "url": "https://acme.example/a2a",
         "securitySchemes": {"oauth2": {"type": "oauth2"}},
         "skills": [
             {"id": "settle", "name": "Settle", "description": "Settle a payment.",
              "inputModes": ["text"], "outputModes": ["text"], "tags": ["payments"]},
             {"id": "quote", "name": "Quote", "description": "Quote a settlement."}]},
    ),
    (
        "skill-examples",
        "`skills[].examples` IS pinned. A2A defines it as example prompts, which makes it "
        "the most directly model-directed text on a card; it was unpinned and unscreened "
        "while `tags` was both.",
        {"name": "A", "version": "1.0.0", "skills": [
            {"id": "s", "name": "S", "description": "d",
             "examples": ["Reconcile yesterday's ledger", "Show unmatched rows"]}]},
    ),
    (
        "skill-examples-reordered",
        "The same examples in the other order. Example order is authored, so it is NOT "
        "sorted away: this digest MUST differ from `skill-examples`.",
        {"name": "A", "version": "1.0.0", "skills": [
            {"id": "s", "name": "S", "description": "d",
             "examples": ["Show unmatched rows", "Reconcile yesterday's ledger"]}]},
    ),
    (
        "skill-name-fallback",
        "A skill with no `id` is keyed by its `name`, so it can still be contracted.",
        {"name": "A", "version": "1.0.0",
         "skills": [{"name": "Reconcile", "description": "d"}]},
    ),
    (
        "card-dropped-fields",
        "Card fields outside the allowlist — `provider`, `documentationUrl`, `iconUrl`, "
        "`capabilities` — are dropped. Changing one is not drift.",
        {"name": "A", "version": "1.0.0", "description": "d",
         "provider": {"organization": "Acme"},
         "documentationUrl": "https://acme.example/docs",
         "iconUrl": "https://acme.example/icon.png",
         "capabilities": {"streaming": True},
         "skills": [{"id": "s", "name": "S", "description": "d"}]},
    ),
    (
        "card-no-skills",
        "A card with no skills is valid and pins to a manifest with no items.",
        {"name": "A", "version": "1.0.0", "description": "d", "skills": []},
    ),
]

# Inputs that must be REFUSED, with the code a conforming implementation returns.
REJECTS: list[tuple[str, str, str, str, object]] = [
    (
        "duplicate-tool-names", "mcp", "WC-1002",
        "Two tools with one name make the per-item digest ambiguous, so the document is "
        "refused rather than resolved by last-wins.",
        {"tools": [{"name": "t", "description": "first"},
                   {"name": "t", "description": "second"}]},
    ),
    (
        "duplicate-skill-ids", "a2a", "WC-1002",
        "The same rule for A2A skills.",
        {"name": "A", "version": "1.0.0", "skills": [
            {"id": "s", "name": "One", "description": "d"},
            {"id": "s", "name": "Two", "description": "d"}]},
    ),
    (
        "not-a-surface", "mcp", "WC-1002",
        "A document with no tool list is not an MCP surface.",
        {"greeting": "hello"},
    ),
]


def canon(binary_path: pathlib.Path, path: pathlib.Path, kind: str) -> dict:
    proc = subprocess.run(
        [str(binary_path), "canon", str(path), "--kind", kind, "--entity", ENTITY, "--json"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return {"error": (proc.stdout + proc.stderr).strip()}
    return json.loads(proc.stdout)


def main() -> None:
    connect = binary()
    OUT.mkdir(parents=True, exist_ok=True)
    vectors: dict[str, dict] = {}

    for kind, cases in (("mcp", MCP), ("a2a", A2A)):
        for name, rule, body in cases:
            path = OUT / f"{name}.input.json"
            path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n")
            result = canon(connect, path, kind)
            if "error" in result:
                sys.exit(f"{name}: expected success, got {result['error']}")
            vectors[f"{name}.input.json"] = {
                "kind": kind,
                "rule": rule,
                "expect": "accept",
                "document": result["document"],
                "manifest": result["manifest"],
                "items": result["items"],
            }

    for name, kind, code, rule, body in REJECTS:
        path = OUT / f"{name}.input.json"
        path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n")
        result = canon(connect, path, kind)
        if "error" not in result:
            sys.exit(f"{name}: expected a refusal, it was accepted")
        if code not in result["error"]:
            sys.exit(f"{name}: expected {code}, got {result['error']}")
        vectors[f"{name}.input.json"] = {
            "kind": kind,
            "rule": rule,
            "expect": code,
        }

    expected = {
        "schema": 1,
        "wcs1_version": 1,
        "entity": ENTITY,
        "note": (
            "`expect` is either \"accept\" — in which case `document` is the exact canonical "
            "bytes, `manifest` the sha256 over them, and `items` the per-item digests a "
            "contract pins — or the WC-* code a conforming implementation must refuse with. "
            "`rule` is the normative statement the vector exists to pin. Digests are over "
            "the canonical document, not the input file."
        ),
        "vectors": dict(sorted(vectors.items())),
    }
    (OUT / "expected.json").write_text(json.dumps(expected, indent=2, ensure_ascii=False) + "\n")

    accepts = sum(1 for v in vectors.values() if v["expect"] == "accept")
    print(f"{len(vectors)} vectors written to {OUT.relative_to(REPO)}")
    print(f"  {accepts} accept · {len(vectors) - accepts} refuse")


if __name__ == "__main__":
    main()
