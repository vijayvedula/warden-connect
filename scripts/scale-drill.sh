#!/usr/bin/env bash
# The scale drill: operate a 10⁵-contract estate, and time what an operator actually runs.
#
#     scripts/scale-drill.sh            # 100,000 contracts
#     SCALE=250000 scripts/scale-drill.sh
#
# ## Why this exists
#
# `docs/proving-ground.md` item 2.5 said it in one line: **"Benchmarked, never operated."**
# `connect bench --scale` measures issuance, verification and rebuild at 10⁵ and the gates pass —
# and nobody had ever run the *operator* commands against a log that size. Those are the ones an
# incident depends on: `audit verify` when somebody asks whether the chain is intact,
# `retention --retire` when the log has to be trimmed, `posture` when the question is what the
# estate looks like right now.
#
# A control plane that mints in 250 µs and needs forty minutes to verify its own chain is not a
# fast control plane. It is a fast mint path attached to an unusable operator experience, and the
# gates as they stood could not tell the difference.
#
# ## What it measures
#
#   1  building the estate — how long 10⁵ contracts take to exist at all;
#   2  `audit verify` over the whole evidence chain, with and without the anchor key;
#   3  `retention --retire`, which moves old rows out and is the only thing that bounds growth;
#   4  the read paths an operator uses under pressure: `posture`, `contracts`, `blast-radius`;
#   5  `policy lint` and `policy dry-run`, which is what a change is checked against;
#   6  disk footprint and peak RSS, because "needs 8 GB to verify its own chain" is a constraint
#      that belongs in the docs rather than in an incident.
#
# ## What it does not do
#
# **It does not gate.** These are measurements on whatever hardware you ran them on, and a
# threshold set from one laptop would fail on a smaller CI runner and pass on a bigger one — the
# mistake this project already made twice with latency assertions. The numbers land in
# `docs/proving-ground.md` with the hardware named; a *gate* needs the cluster in item 2.
#
# Requires: cargo (built binaries), python3, openssl.
# Exit 0 measured · 2 setup. Never 1: there is nothing here to fail.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCALE="${SCALE:-100000}"
command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 2; }
if ! cargo build --release --workspace --quiet 2>&1; then
    echo "the workspace does not build; the drill would be measuring nothing" >&2
    exit 2
fi
CONNECT="$REPO/target/release/connect"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export WARDEN_CONNECT_ROOT="$WORK/root"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }

# Wall clock and peak RSS for one command. `/usr/bin/time -l` on macOS, `-v` on GNU; both are
# parsed rather than assumed, because a drill that silently reports 0 MB is worse than one that
# says it could not measure.
measure() {  # measure <label> <command...>
    local label="$1"; shift
    local t0 t1 secs rss
    t0=$(python3 -c 'import time; print(time.time())')
    if /usr/bin/time -l "$@" > cmd.out 2> cmd.time; then
        :
    else
        printf '  %-26s FAILED (see below)\n' "$label"
        tail -3 cmd.out cmd.time | sed 's/^/       /'
        return 1
    fi
    t1=$(python3 -c 'import time; print(time.time())')
    secs=$(python3 -c "print(f'{$t1 - $t0:.2f}')")
    rss=$(python3 - <<'PY'
import re, sys
text = open('cmd.time', errors='replace').read()
m = re.search(r'(\d+)\s+maximum resident set size', text)          # macOS, bytes
if m:
    print(f"{int(m.group(1)) / 1_048_576:.0f} MB"); sys.exit()
m = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', text)  # GNU, KiB
if m:
    print(f"{int(m.group(1)) / 1024:.0f} MB"); sys.exit()
print("rss unmeasured")
PY
)
    printf '  %-26s %8ss   %s\n' "$label" "$secs" "$rss"
}

bold "scale drill"
step "scale     $SCALE contracts"
step "work dir  $WORK"
step "hardware  $(uname -sm) · $(python3 -c 'import os; print(os.cpu_count())') cpus"
echo

# --- the estate ---------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out issuer.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in issuer.tmp -out issuer.pem 2>/dev/null
openssl ec -in issuer.pem -pubout -out issuer.pub.pem 2>/dev/null
rm -f issuer.tmp
openssl ecparam -name prime256v1 -genkey -noout -out anchor.tmp 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in anchor.tmp -out anchor.pem 2>/dev/null
openssl ec -in anchor.pem -pubout -out anchor.pub.pem 2>/dev/null
rm -f anchor.tmp

cat > connect-policy.toml <<'POLICY'
default = "require_approval"
version = "scale-drill@v1"

[[zone]]
id = "internal.bench"
trust = "internal"

[standing]
reviewed_at = 0

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
approver_role = "scale.operator"
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the scale is under test here, not the policy"
POLICY

bold "1 · build the estate"
# Two steps, and the difference between them is the reason this drill exists. `bench` measures
# against an estate built **in memory** — right for a latency gate, which must not pay for a disk
# write per iteration. `--materialise` writes the same estate to a real state log, which is what
# an operator command has to read. The first version of this drill ran only the gates and then
# timed `audit verify` at 0.02s against an empty log, reporting a 10⁵ estate as instant to verify.
measure "gates (in memory)" "$CONNECT" bench --signing-key issuer.pem --kid k1 \
    --verify-pub issuer.pub.pem --iterations 200 --scale "$SCALE" --anchor-key anchor.pem
grep -E "registry::register|store::rebuild|blast_radius|export::dora" cmd.out | sed 's/^/     /'
# `--anchor-key` matters more than it looks. Without it the chain gets no checkpoints, and then
# `audit verify` reports COMPLETENESS UNVERIFIED — links intact, truncation unprovable — while
# `retention --retire` correctly refuses to move rows the anchor never attested. The first version
# of this drill omitted it and measured both commands doing nothing.
measure "materialise to disk" "$CONNECT" bench --materialise --scale "$SCALE" \
    --by human:scale@org --anchor-key anchor.pem --anchor-interval 1000
tail -1 cmd.out | sed 's/^/     /'
measure "reopen (log replay)" "$CONNECT" contracts --json

echo
bold "2 · what the log costs"
python3 - <<'PY'
import os
root = os.environ["WARDEN_CONNECT_ROOT"]
def size(path):
    total = 0
    for dirpath, _, names in os.walk(path):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(dirpath, n))
            except OSError:
                pass
    return total
for label, sub in [("state log", "tenants/default/state"),
                   ("evidence chain", "tenants/default/evidence"),
                   ("artifacts", "tenants/default/artifacts"),
                   ("whole root", "")]:
    p = os.path.join(root, sub) if sub else root
    if os.path.exists(p):
        mb = size(p) / 1_048_576
        print(f"  {label:<26} {mb:8.1f} MB")
PY

echo
bold "3 · the operator commands"
# The point of the drill. Each of these is something somebody runs while an incident is open, and
# none had ever been timed against a log this size.
measure "audit verify" "$CONNECT" audit verify
measure "audit verify --anchor-pub" "$CONNECT" audit verify --anchor-pub anchor.pub.pem
measure "posture" "$CONNECT" posture
measure "posture --expiring" "$CONNECT" posture --expiring
measure "contracts" "$CONNECT" contracts
measure "contracts --dormant" "$CONNECT" contracts --dormant
measure "policy lint" "$CONNECT" policy lint
measure "policy dry-run" "$CONNECT" policy dry-run
FIRST_ENTITY="$("$CONNECT" entities --json 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if isinstance(d,list) and d else "")' 2>/dev/null)"
if [ -n "$FIRST_ENTITY" ]; then
    measure "blast-radius" "$CONNECT" blast-radius "$FIRST_ENTITY"
else
    step "blast-radius              skipped: could not read an entity id from the estate"
fi
# `--now` well past every row's retention window, or nothing is old enough to retire and the
# measurement is of a no-op. The first version of this measured exactly that: 0.0 MB retired, 0.03s.
FUTURE=$(python3 -c 'import time; print(int(time.time()) + 400 * 86400)')
measure "retention (report)" "$CONNECT" retention --now "$FUTURE"
measure "retention --retire" "$CONNECT" retention --retire --now "$FUTURE" \
    --anchor-pub anchor.pub.pem
# Printed rather than summarised, because this one has a caveat and hiding it behind a timing would
# be the wrong kind of tidy. The output says the real reason: the contract retention window is
# ~7 years and this estate has 400 days of history, so `rows expired 0`. The timing is the cost of
# *deciding* that, not of retiring 10⁵ rows.
#
# An earlier version of this comment blamed the synthetic contracts' `exp: u64::MAX`. That was a
# guess, and the drill's own output contradicts it — which is the argument for printing the command's
# words instead of paraphrasing them. The retire path is covered by
# `cargo test -p warden-connect-control --lib retention`.
sed 's/^/     /' cmd.out | head -6

echo
bold "4 · after retiring"
python3 - <<'PY'
import os
root = os.environ["WARDEN_CONNECT_ROOT"]
ev = os.path.join(root, "tenants/default/evidence")
if os.path.isdir(ev):
    live = retired = 0
    for dirpath, _, names in os.walk(ev):
        for n in names:
            p = os.path.join(dirpath, n)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if "retired" in dirpath:
                retired += sz
            else:
                live += sz
    print(f"  {'evidence live':<26} {live / 1_048_576:8.1f} MB")
    print(f"  {'evidence retired':<26} {retired / 1_048_576:8.1f} MB")
PY
measure "audit verify (after retire)" "$CONNECT" audit verify --anchor-pub anchor.pub.pem
tail -4 cmd.out | sed 's/^/     /'

echo
bold "MEASURED — no thresholds here, deliberately"
cat <<'NOTE'
These are numbers from one machine, named above. A threshold set from a laptop fails on a smaller
CI runner and passes on a bigger one, which this project has already got wrong twice with latency
assertions. Copy the numbers into docs/proving-ground.md item 2.5 with the hardware; a *gate*
needs the cluster in item 2, where the hardware is fixed and the estate is real.
NOTE
exit 0
