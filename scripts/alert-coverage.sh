#!/usr/bin/env bash
# Every alert rule must be asserted by at least one unit test.
#
#     scripts/alert-coverage.sh
#
# `promtool check rules` proves the file parses. `promtool test rules` proves the assertions
# that exist pass. **Neither notices a rule nobody asserted** — promtool is given the tests and
# checks them; it never asks what was left out. So a rule with no test is green twice over,
# which is the most convincing kind of silence.
#
# This existed because 3 of 10 rules were asserted nowhere, while `alerts_test.yml`'s own
# header claimed "each rule is proven against the shape of data the exposition actually
# produces". One of those three — `WardenConnectExpirySweepStalled` — turned out to be unable
# to fire at all: written as a bare `and` between `{window="1h"}` and a metric labelled by
# approval mode, so the intersection was always empty and a stalled expiry sweep was silent.
# It had been in the repository, unfireable, since the day it was written.
#
# That is this codebase's signature defect (`docs/threat-model.md` Part 1): a control that
# reads as configured and does nothing. An alert is a control, and an untested alert is the
# purest form of it — the failure mode is that nothing happens on the day it was written for.
#
# Exit 0 every rule is asserted · 1 one is not · 2 setup.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RULES="$REPO/deploy/prometheus/alerts.yml"
TESTS="$REPO/deploy/prometheus/alerts_test.yml"

for f in "$RULES" "$TESTS"; do
    [ -r "$f" ] || { echo "cannot read $f" >&2; exit 2; }
done

# `alertname:` in the test file is the assertion; `alert:` in the rules file is the definition.
# Deliberately not a YAML parse: this must run wherever CI runs, and the two keys are
# unambiguous enough that a dependency would buy nothing. `sort -u` because a rule asserted
# five times is still one rule covered.
defined=$(grep -oE '^[[:space:]]*-[[:space:]]*alert:[[:space:]]*[A-Za-z0-9_]+' "$RULES" \
          | grep -oE '[A-Za-z0-9_]+$' | sort -u)
asserted=$(grep -oE '^[[:space:]]*alertname:[[:space:]]*[A-Za-z0-9_]+' "$TESTS" \
           | grep -oE '[A-Za-z0-9_]+$' | sort -u)

[ -n "$defined" ] || { echo "no alert rules found in $RULES; the grep has probably rotted" >&2; exit 2; }

missing=$(comm -23 <(printf '%s\n' "$defined") <(printf '%s\n' "$asserted"))
# The reverse direction too: an assertion naming a rule that no longer exists passes
# `promtool test rules` silently, because a test for an absent alert trivially expects nothing.
# That is how a renamed rule loses its coverage without anything going red.
stale=$(comm -13 <(printf '%s\n' "$defined") <(printf '%s\n' "$asserted"))

total=$(printf '%s\n' "$defined" | grep -c .)
covered=$(comm -12 <(printf '%s\n' "$defined") <(printf '%s\n' "$asserted") | grep -c .)
printf 'alert coverage: %s/%s rules asserted\n' "$covered" "$total"

status=0
if [ -n "$missing" ]; then
    echo
    echo "these rules are defined and asserted NOWHERE:"
    printf '  · %s\n' $missing
    echo
    echo "An untested alert rule fails silently on the day it was written for. Add a test to"
    echo "$(basename "$TESTS") that synthesises the series and asserts the alert fires — and one"
    echo "that asserts it stays quiet, because a rule that always fires gets muted in week two."
    status=1
fi
if [ -n "$stale" ]; then
    echo
    echo "these tests name a rule that does not exist (renamed or deleted?):"
    printf '  · %s\n' $stale
    echo
    echo "promtool passes these — a test for an absent alert expects nothing and gets nothing."
    status=1
fi

exit "$status"
