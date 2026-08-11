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
    only_old = work / "jwks-kid1.json"
    both = work / "jwks-kid1-kid2.json"
    only_new = work / "jwks-kid2.json"

    med = Mediator(argv)
    failures: list[str] = []

    def phase(n: int, name: str, publish: pathlib.Path | None, expect: bool, why: str) -> None:
        if publish is not None:
            shutil.copyfile(publish, live)
            # The TTL is what makes this a rotation rather than a restart: the running
            # process has to notice on its own. Waiting TTL + 2 leaves room for the read
            # without making the drill slow enough that somebody stops running it.
            time.sleep(ttl + 2)
        executed, detail = med.call()
        ok = executed == expect
        mark = "ok  " if ok else "FAIL"
        want = "EXECUTE" if expect else "REFUSE"
        print(f"  {mark} phase {n} · {name}")
        print(f"        want {want:8} got {'EXECUTE' if executed else 'REFUSE'} ({detail})")
        print(f"        {why}")
        if not ok:
            failures.append(f"phase {n} ({name}): wanted {want}, got {detail}")
        if not med.alive():
            failures.append(f"phase {n}: the mediator died")

    print("\nEvery phase below uses the SAME mediator process. It is never restarted, and")
    print(f"the key set it trusts is republished under it with a {ttl}s TTL.\n")

    phase(1, "baseline: kid-1 trusted", None, True,
          "the contract is signed by kid-1 and kid-1 is published. If this fails nothing "
          "below means anything.")

    phase(2, "kid-2 added alongside kid-1", both, True,
          "adding a key must not disturb the one already in use — this is the overlap every "
          "rotation runs through, and a mediator that dropped kid-1 here would cut live "
          "traffic mid-rotation.")

    # Phase 3 is the one that found something. A withdrawn key does NOT stop a live session,
    # because `State::Live` caches the admitted connection at `initialize` and no later call
    # re-verifies the contract. `expect=True` records the behaviour as it is; the note below
    # says what it means, so nobody reads a green drill as "withdrawal works".
    phase(3, "kid-1 WITHDRAWN — does it reach a live session?", only_new, True,
          "FINDING: it does not. The call still executes on a contract signed by a key that is "
          "no longer published. Re-verifying per call would cost a signature check inside the "
          "sub-millisecond per-call budget, so the caching is deliberate — but it means "
          "WITHDRAWING A KEY IS NOT A WAY TO STOP A RUNNING SESSION. A NEW mediator refuses "
          "it; this one does not. See limitations.md.")

    phase(4, "kid-1 republished", both, True,
          "recovery, and proof the refresh loop is still running after it served a refusal "
          "— a loop that stopped on failure would leave the estate dark until a restart.")

    # Phase 5 asks the question phase 3 raised. If withdrawing a key does not reach a live
    # session, does CONTAINMENT? That is the more serious question by far, and inferring the
    # answer from the code would be exactly the habit this whole exercise exists to break.
    quarantined = quarantine_the_callee()
    if quarantined:
        time.sleep(ttl + 2)
        executed, detail = med.call()
        print("  ---- phase 5 · the callee is QUARANTINED on the control plane ----")
        print(f"        got {'EXECUTE' if executed else 'REFUSE'} ({detail})")
        if executed:
            print("        The live session kept working. Containment reached the feed and not")
            print("        this already-initialised connection: `State::Live` is established")
            print("        once at `initialize` and every later call uses the cached")
            print("        `Admitted`. This is what `wc_mediator::drain` was for, and drain")
            print("        has no caller. Recorded in limitations.md, NOT asserted as correct.")
        else:
            print("        Containment reached the live session.")
    else:
        print("  ---- phase 5 · skipped: could not quarantine via the API ----")

    stderr = med.stop()
    # Printed on success too, because phase 5's finding rests on the mediator KNOWING the
    # contract was withdrawn and serving the call anyway. Without this the claim would be
    # "the live session kept working", which is compatible with the feed never arriving —
    # a different and less damning story.
    evidence = [
        l for l in stderr.splitlines()
        if any(w in l for w in ("refresh", "removed", "installed", "contract(s)", "rejected"))
    ]
    if evidence:
        print("\n  what the mediator itself reported:")
        for line in evidence[-8:]:
            print(f"    {line.strip()}")

    if failures:
        print("\nDRILL FAILED")
        for f in failures:
            print(f"  · {f}")
        print("\nThe last 20 lines of the mediator's stderr:")
        for line in stderr.strip().splitlines()[-20:]:
            print(f"  {line}")
        return 1

    print("\nDRILL PASSED — the four key-set phases behaved as recorded. Phase 3 is a FINDING,")
    print("not a success: a withdrawn key does not reach an already-admitted connection.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
