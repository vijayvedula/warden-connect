#!/usr/bin/env bash
# The `wcs1` canonicalisation harness.
#
# `surface_digest` is what pins a declared surface, so drift detection between two
# implementations means nothing unless they agree on it **byte for byte**. There were unit
# tests and a fuzz target and no published *input surface -> expected digest* set — which
# `docs/limitations.md` called the most valuable thing missing, because it is the one thing
# a third party needs and the one thing our own tests cannot supply.
#
# Usage:
#     scripts/canon-conformance.sh                        # our canonicaliser
#     scripts/canon-conformance.sh ./my-canon             # yours
#     scripts/canon-conformance.sh ./my-canon --json      # machine-readable
#
# ── The contract your canonicaliser must satisfy ──────────────────────────────
#
# It is invoked once per vector as:
#
#     <your-canon> <input.json> <mcp|a2a> <entity-id>
#
# and must either:
#
#   · exit 0 and write the canonical `wcs1` document to stdout — the exact bytes, nothing
#     else, no trailing newline required; or
#   · exit non-zero and print the `WC-NNNN` code somewhere on stdout or stderr.
#
# The document is compared, not only its digest. Two implementations that disagree have to
# know *where*, and "your sha256 differs from ours" is not something anybody can act on —
# so this prints the first differing byte offset and both sides' bytes around it.
#
# `<entity-id>` is passed in rather than defaulted because it is **inside** the canonical
# document. A harness that used its own would compute a different digest for an identical
# surface and report a disagreement that is not one.
#
# Exit codes: 0 conformant · 1 one or more vectors disagreed · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VECTORS="$REPO/fixtures/canon"
EXPECTED="$VECTORS/expected.json"

CANON="${1:-}"
JSON=0
for arg in "$@"; do
    [ "$arg" = "--json" ] && JSON=1
done
[ "$CANON" = "--json" ] && CANON=""

command -v python3 >/dev/null 2>&1 || { echo "need python3 to read expected.json" >&2; exit 2; }
[ -f "$EXPECTED" ] || {
    echo "no $EXPECTED — run python3 scripts/gen-canon-vectors.py" >&2
    exit 2
}

# Ours by default, so a bare invocation is a self-check and CI has something to run.
if [ -z "$CANON" ]; then
    OURS="$REPO/target/release/connect"
    [ -x "$OURS" ] || OURS="$REPO/target/debug/connect"
    [ -x "$OURS" ] || { echo "no connect binary; run cargo build" >&2; exit 2; }
    SHIM="$(mktemp)"
    cat > "$SHIM" <<SHIMEOF
#!/usr/bin/env bash
exec "$OURS" canon "\$1" --kind "\$2" --entity "\$3" --document
SHIMEOF
    chmod +x "$SHIM"
    CANON="$SHIM"
    trap 'rm -f "$SHIM"' EXIT
fi

command -v "$CANON" >/dev/null 2>&1 || [ -x "$CANON" ] || {
    echo "not executable: $CANON" >&2
    exit 2
}

CANON="$CANON" VECTORS="$VECTORS" EXPECTED="$EXPECTED" JSON="$JSON" python3 - <<'PY'
import hashlib
import json
import os
import subprocess
import sys

canon = os.environ["CANON"]
vectors_dir = os.environ["VECTORS"]
as_json = os.environ["JSON"] == "1"
spec = json.load(open(os.environ["EXPECTED"]))
entity = spec["entity"]

results = []

def first_difference(a: str, b: str) -> str:
    """Where two documents diverge, in terms somebody can act on."""
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            lo = max(0, i - 30)
            return (f"first differs at byte {i}\n"
                    f"      expected: …{a[lo:i + 30]!r}\n"
                    f"      got:      …{b[lo:i + 30]!r}")
    if len(a) != len(b):
        longer = "got" if len(b) > len(a) else "expected"
        return (f"identical for {limit} bytes, then {longer} continues: "
                f"{(b if longer == 'got' else a)[limit:limit + 60]!r}")
    return "identical"

for name, want in spec["vectors"].items():
    path = os.path.join(vectors_dir, name)
    proc = subprocess.run([canon, path, want["kind"], entity],
                          capture_output=True, text=True)
    output = proc.stdout
    combined = proc.stdout + proc.stderr

    if want["expect"] != "accept":
        code = want["expect"]
        ok = proc.returncode != 0 and code in combined
        detail = "" if ok else (
            f"expected refusal {code}; exit={proc.returncode} out={combined.strip()[:120]!r}"
        )
        results.append((name, ok, detail, want["rule"]))
        continue

    if proc.returncode != 0:
        results.append((name, False,
                        f"expected acceptance, exit={proc.returncode}: "
                        f"{combined.strip()[:120]!r}", want["rule"]))
        continue

    # A trailing newline is a printing habit, not part of the document.
    got_doc = output.rstrip("\n")
    want_doc = want["document"]
    if got_doc == want_doc:
        results.append((name, True, "", want["rule"]))
        continue

    got_digest = "sha256:" + hashlib.sha256(got_doc.encode()).hexdigest()
    detail = (f"document mismatch\n      "
              f"expected manifest {want['manifest']}\n      "
              f"got      manifest {got_digest}\n      "
              f"{first_difference(want_doc, got_doc)}")
    results.append((name, False, detail, want["rule"]))

passed = [r for r in results if r[1]]
failed = [r for r in results if not r[1]]

if as_json:
    print(json.dumps({
        "total": len(results),
        "passed": len(passed),
        "failed": [{"vector": n, "detail": d, "rule": r} for n, _, d, r in failed],
    }, indent=2))
else:
    print(f"wcs1 vectors  {len(results)} total · wcs1 v{spec['wcs1_version']}")
    print(f"entity        {entity}\n")
    for name, ok, detail, rule in results:
        mark = "ok  " if ok else "FAIL"
        print(f"  {mark}  {name}")
        if not ok:
            print(f"      rule: {rule}")
            for line in detail.splitlines():
                print(f"      {line}" if not line.startswith("      ") else line)
    print()
    if failed:
        print(f"{len(failed)} of {len(results)} vectors disagreed.")
        print("A canonicalisation disagreement is a finding whoever turns out to be wrong:")
        print("in a format meant to be interoperable, disagreeing about the bytes IS the bug.")
    else:
        print(f"conformant · {len(passed)} vectors")

sys.exit(1 if failed else 0)
PY
