#!/usr/bin/env python3
"""Drive a long-lived mediator through a key rotation, one phase at a time.

Called by `scripts/rotation-drill.sh`, which does the setup. Separate because the whole
point of this drill is that **one process stays alive across the rotation** — a shell loop
that starts a mediator per phase would prove the opposite of what is being claimed.

The mediator speaks JSON-RPC over stdio, so this holds its pipes open, swaps the JWKS the
control plane publishes, waits out the TTL, and asks again.
"""

# Python 3.9 is the floor the SDK claims and what ships on macOS, and PEP 604 annotations
# (`Path | None`) are evaluated at def time without this. Ironically the exact check I ran
# against the SDK, failed here on the first run.
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import time

TOOL = "alpha"


class Mediator:
    """A running `connect-mediate`, kept alive across every phase."""

    def __init__(self, argv: list[str]):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.next_id = 100
        self._send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "rotation-drill", "version": "1"}},
        })
        self._read()

    def _send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _read(self) -> dict:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            # Its stderr is the only thing that can say why, and a driver that swallowed it
            # would turn every startup problem into "it has died".
            assert self.proc.stderr is not None
            self.proc.wait(timeout=5)
            why = self.proc.stderr.read().strip()
            raise SystemExit(
                "the mediator exited before answering (status "
                f"{self.proc.returncode}). Its stderr:\n"
                + "\n".join(f"  {l}" for l in why.splitlines()[-25:])
            )
        return json.loads(line)

    def call(self) -> tuple[bool, str]:
        """Attempt the contracted tool. Returns (executed, detail)."""
        self.next_id += 1
        self._send({
            "jsonrpc": "2.0", "id": self.next_id, "method": "tools/call",
            "params": {"name": TOOL, "arguments": {}},
        })
        reply = self._read()
        blob = json.dumps(reply)
        if "executed" in blob:
            return True, "executed"
        for token in blob.replace('\\"', " ").split():
            if token.startswith("WC-"):
                return False, token.strip('",:')
        return False, blob[:90]

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> str:
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        assert self.proc.stderr is not None
        return self.proc.stderr.read()


def quarantine_the_callee() -> bool:
    """Quarantine the callee through the control plane's API.

    Over HTTP rather than the CLI because `serve` holds the writer lock — the state log is
    single-writer, so while a control plane is running the CLI cannot write to its root.
    """
    import os
    import urllib.error
    import urllib.request

    api, token, callee = os.environ.get("API"), os.environ.get("TOKEN"), os.environ.get("CALLEE")
    if not (api and token and callee):
        return False
    body = json.dumps({
        "party": callee,
        "reason": "rotation drill: does containment reach a live session?",
        "approvers": ["human:drill@org", "human:second@org"],
    }).encode()
    req = urllib.request.Request(
        f"{api}/v1/quarantine",
        data=body,
        method="POST",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "idempotency-key": "rotation-drill-quarantine",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status in (200, 201, 202)
    except urllib.error.HTTPError as e:
        print(f"        (quarantine returned {e.code}: {e.read()[:160]!r})")
        return False
    except Exception as e:
        print(f"        (quarantine failed: {e})")
        return False


def main() -> int:
    work = pathlib.Path(sys.argv[1])
    ttl = int(sys.argv[2])
    argv = sys.argv[3:]

    live = work / "jwks-live.json"
    both = work / "jwks-kid1-kid2.json"
    only_new = work / "jwks-kid2.json"

    failures: list[str] = []

    def publish(which: pathlib.Path) -> None:
        shutil.copyfile(which, live)
        # The TTL is what makes this a rotation rather than a restart: the running process
        # has to notice on its own. TTL + 2 leaves room for the read without making the
        # drill slow enough that somebody stops running it.
        time.sleep(ttl + 2)

    def check(
        n: str,
        name: str,
        med: Mediator,
        expect: bool,
        why: str,
        code: str | None = None,
    ) -> None:
        """Assert the outcome AND, for a refusal, the reason.

        `code` is not optional in spirit. Checking only EXECUTE/REFUSE let this drill report
        a clean containment pass while every call was in fact being denied on posture
        (`WC-3109`) because it had been pointed at enforce mode — three phases green for a
        reason that had nothing to do with what they claim to test.
        """
        executed, detail = med.call()
        ok = executed == expect
        if ok and code is not None and code not in detail:
            ok = False
            detail = f"{detail} — REFUSED FOR THE WRONG REASON, wanted {code}"
        want = "EXECUTE" if expect else f"REFUSE/{code or '?'}"
        print(f"  {'ok  ' if ok else 'FAIL'} phase {n} · {name}")
        print(f"        want {want:14} got {'EXECUTE' if executed else 'REFUSE'} ({detail})")
        print(f"        {why}")
        if not ok:
            failures.append(f"phase {n} ({name}): wanted {want}, got {detail}")
        if not med.alive():
            failures.append(f"phase {n}: the mediator died")

    print("\nPhases 1-3 use ONE mediator process, never restarted, while the key set it")
    print(f"trusts is republished under it with a {ttl}s TTL.\n")

    first = Mediator(argv)

    check("1", "baseline: kid-1 trusted", first, True,
          "the contract is signed by kid-1 and kid-1 is published. If this fails nothing "
          "below means anything.")

    publish(both)
    check("2", "kid-2 added alongside kid-1", first, True,
          "adding a key must not disturb the one already in use — this is the overlap every "
          "rotation runs through, and a mediator that dropped kid-1 here would cut live "
          "traffic mid-rotation.")

    # The phase that found the bug. It used to EXECUTE: `State::Live` cached the admitted
    # connection at `initialize` and no later call re-consulted the contract, so retiring an
    # issuer key reached new connections and never running ones.
    publish(only_new)
    check("3", "kid-1 WITHDRAWN — does it reach the LIVE session?", first, False,
          "the refresh rebuilds the snapshot against the published keys, the contract no "
          "longer verifies, and `Cache::install` replaces the set — so the contract is gone "
          "and `still_in_force` refuses the next call. This phase EXECUTED before the "
          "containment seam existed.", code="WC-4001")

    # Containment must not lift when the cause does. A cut session stays cut.
    publish(both)
    check("4a", "kid-1 republished — the CUT session must stay cut", first, False,
          "containment is terminal: reinstating a key permits a NEW connection and does not "
          "resurrect one already told it was over. If this EXECUTES, an attacker who can "
          "cause a brief key flap gets their session back.", code="WC-4001")

    # Recovery needs a fresh process, precisely because 4a must fail closed. A second
    # mediator is the honest way to show the estate is not left dark.
    second = Mediator(argv)
    check("4b", "a NEW mediator on the republished set", second, True,
          "recovery, and proof the published set is serviceable again — the refresh loop "
          "having survived is visible in the first mediator's own log below.")

    # Phase 5 asks the question phase 3 raised: if a withdrawn key reaches a live session,
    # does an explicit CONTAINMENT ORDER? That is the more serious question by far, and it
    # goes through the operator's real action rather than a simulated one.
    if quarantine_the_callee():
        time.sleep(ttl + 2)
        check("5", "the callee is QUARANTINED on the control plane", second, False,
              "this is what `connect quarantine` is for, and the phase that mattered most: it "
              "returned 202, and before the containment seam existed the session kept "
              "executing while the mediator's own log said `1 rejected` — it knew, and served "
              "anyway. WC-4001 and not WC-3105 because quarantine WITHDRAWS the contract from "
              "the served set, and `resolve` looks the contract up before it consults the "
              "revocation feed — so absence is what an operator actually sees here. The "
              "WC-3105 path, where the contract is still in the set and the feed carries the "
              "revocation, is covered by the mediation tests.", code="WC-4001")
    else:
        print("  ---- phase 5 · SKIPPED: could not quarantine via the API ----")
        failures.append("phase 5: the quarantine could not be issued, so containment is untested")

    stderr = first.stop()
    second.stop()
    # Printed on success too, because the containment claim rests on the mediator KNOWING the
    # contract was gone. Without this the result is "the session stopped working", which is
    # also what a crashed refresh loop looks like.
    evidence = [
        l for l in stderr.splitlines()
        if any(w in l for w in ("refresh", "removed", "installed", "contract(s)",
                                "rejected", "issuer keys changed"))
    ]
    if evidence:
        print("\n  what the first mediator itself reported:")
        for line in evidence[-8:]:
            print(f"    {line.strip()}")

    if failures:
        print("\nDRILL FAILED")
        for f in failures:
            print(f"  · {f}")
        print("\nThe last 20 lines of the first mediator's stderr:")
        for line in stderr.strip().splitlines()[-20:]:
            print(f"  {line}")
        return 1

    print("\nDRILL PASSED — rotation overlap is safe, and containment reaches a live session")
    print("by both routes: a withdrawn issuer key and an explicit quarantine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
