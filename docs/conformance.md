# The conformance kit

**Any implementation may mint a connection contract, and a contract is valid iff a
conforming verifier accepts it.** That sentence is what makes
`application/warden-connection+jws` a candidate standard rather than a product format, and
it is the whole basis of the claim that you are not locked in to this data plane: implement
the checks in your own egress layer, pass these vectors, and you interoperate.

Written for production-readiness P2 #16, which put it plainly — the kit was *"fixtures, not
a kit"*: nineteen files and an `expected.json`, no harness a third party could point at
their own verifier, and no version policy. Until there was one, "no lock-in" was an
assertion.

---

## Run it against your verifier

```sh
scripts/conformance.sh ./my-verifier
scripts/conformance.sh ./my-verifier --json     # for CI
scripts/conformance.sh                          # ours, as a self-check
```

Your verifier is invoked once per vector:

```
<your-verifier> <artifact.jws> <issuer-pub.pem> <kid> <mediator-id> <unix-time> <alg>
```

and must

* **exit 0** if the contract is valid;
* **exit non-zero and print the `WC-NNNN` code** on stdout or stderr if not.

The code is compared, not just the exit status. *"It rejected it"* is half the claim; *"it
rejected it for the right reason"* is the half that makes two implementations
interoperable. A verifier returning `WC-3102` where the vector says `WC-3101` has confused
a signature failure with algorithm confusion, and those have different incident responses:
one is a corrupted or tampered artifact, the other is somebody probing your algorithm
handling.

### `<kid>` and `<alg>` are your configuration, not the artifact's claim

This is the subtlety the harness exists to get right, and getting it wrong makes a test
pass while testing nothing.

`unknown-kid.jws` is a vector *because* the artifact names a `kid` nobody published. A
harness that configured the verifier from the artifact's own header would register the
trusted key **under the attacker's name**, resolve it, verify the signature, and admit the
vector. So `trust_kid` in the manifest is the key your verifier must trust, and the
artifact's claim is left to be something your verifier fails to resolve.

Found by running this harness against our own verifier, which is why
`scripts/conformance.sh` with no arguments is a self-check rather than a convenience.

## The two stages, and the scenarios that close the second

Verification splits in two (§8.6.3), and the manifest now says which is which in a
`stage` field rather than leaving it to prose in a README:

| Stage | Vectors | Needs |
|---|---|---|
| `artifact` | 15 | the artifact and a trusted key. Any verifier can run these |
| `context` | 4 | an authenticated peer, the callee's presented surface, a revocation feed, or local zone policy |

A command-line verifier has none of the context inputs, so **the four context vectors are
valid artifacts to it and it must admit them.** Counting that as a pass would tell an
implementer they had covered nineteen checks when they had covered fifteen, so the harness
reports them as `DEFR` — deferred — and never as passes.

**The scenarios close them.** `fixtures/contracts/scenarios/` supplies what the context stage
needs, and the harness runs a second pass:

```
<your-mediator> <artifact.jws> <issuer-pub.pem> <kid> <mediator-id> <unix-time> <alg> <scenario.json>
```

The convention is the verifier's plus one argument, so an artifact-only implementation that
ignores the eighth fails the context vectors rather than silently appearing to pass them.
Point the harness at yours with `MEDIATOR_CMD=./my-mediator scripts/conformance.sh`.

Six scenarios, and **one of them must be admitted** — `valid-es256.json`, every context check
satisfied. Without it an implementation that refuses everything would pass all five refusals.
The harness is mutation-checked against exactly those two wrong implementations: an
artifact-only verifier (5 failures) and a refuse-everything stub (6 failures).

| Scenario | Code | What it pins |
|---|---|---|
| `valid-es256.json` | *admit* | the positive control |
| `peer-mismatch.json` | `WC-3106` | identity is authenticated and compared, never taken from the contract's claim |
| `revoked-jti.json` | `WC-3105` | revocation applies at admission, with no cache rebuild |
| `surface-superset.json` | `WC-3108` | a contracted item the callee no longer presents is drift |
| `posture-unattested.json` | `WC-3109` | posture travels in the artifact and is enforced by the mediator |
| `zone-crossing.json` | `WC-3110` | zone policy is the mediator's; a signed contract cannot open a crossing |

`crates/wc-mediator` is the reference implementation, and §8.6.3 lists the eleven checks in
order.

## The vectors

Fifteen artifact-stage:

| Vector | Code | What it attacks |
|---|---|---|
| `valid-es256.jws` | *admit* | the reference contract |
| `valid-ed25519.jws` | *admit* | the same contract under EdDSA |
| `hmac-hs256.jws` | `WC-3101` | a shared secret would let anyone who can verify also mint |
| `alg-none.jws` | `WC-3101` | unsigned, claiming `alg: none` |
| `alg-confusion-ed-for-es.jws` | `WC-3101` | a real EdDSA signature under a `kid` registered for ES256 |
| `unknown-kid.jws` | `WC-3102` | a key the verifier does not trust |
| `no-kid.jws` | `WC-3102` | no `kid`, so no key resolves |
| `tampered-payload.jws` | `WC-3102` | the surface widened after signing |
| `expired.jws` | `WC-3103` | `exp` past — there is no grace period |
| `nbf-future.jws` | `WC-3103` | not valid yet |
| `aud-other-mediator.jws` | `WC-3104` | replay against a different mediator |
| `schema-99.jws` | `WC-3120` | a newer payload schema: reject rather than guess |
| `unknown-claim.jws` | `WC-3120` | an unrecognised claim a verifier must not ignore |
| `wrong-typ.jws` | `WC-3120` | a JWT that is not a connection contract |
| `oversize.jws` | `WC-3121` | past the 64 KiB ceiling |

Four context-stage: `revoked-jti` (`WC-3105`), `surface-superset` (`WC-3108`),
`posture-unattested` (`WC-3109`), `zone-crossing` (`WC-3110`).

The two vectors that must be **admitted** matter more than the seventeen that must be
refused, because a verifier that rejects everything satisfies every rejection vector
perfectly.

### The keys are worthless by construction

`fixtures/keys/` holds published test keys. They exist so the vectors are runnable by
anyone; they secure nothing, and `expected.json` maps each `kid` to its public PEM.

### The clock is part of the vector

`expected.json` fixes `now` at `1785312500`. Several vectors are about the validity window,
so a verifier that used the wall clock would pass `expired.jws` today and fail it never, or
pass `nbf-future.jws` eventually. The harness passes the fixed time; your verifier must
accept it.

## Version policy

`expected.json` carries `vectors_version`, separate from the payload `schema`. The two
answer different questions: `schema` is *what shape a contract is*, `vectors_version` is
*what a conforming verifier is asked to prove*.

| Change | Bump | Why |
|---|---|---|
| a new vector added | **minor** (`1.0` → `1.1`) | your verifier still passes what it passed; there is more to pass |
| a vector's description clarified | minor | nothing about behaviour changed |
| an existing vector's `expect` changed | **major** (`1.x` → `2.0`) | a verifier that passes today fails tomorrow, through no change of its own |
| a vector's `stage` changed | major | it moves between "you must handle this" and "a mediator must" |
| a vector removed | major | something that was required no longer is, and a verifier may have depended on knowing that |
| a `WC-*` code renumbered | major | the codes are public interface — see [releasing.md](releasing.md) |

**A major bump is a promise being broken**, so it comes with a changelog entry saying which
vector and why. The point of a version on a vector set is that an implementer can say "we
conform to 1.x" and have that mean something six months later.

## If you disagree with us

Report it — **even when you are not sure whose bug it is.** In a format meant to be
interoperable, two implementations disagreeing about what is valid *is* the bug, regardless
of which one turns out to be wrong. See [SECURITY.md](../SECURITY.md) under *Conformance
findings*; the most useful report is a new vector plus the code you believe a conforming
verifier must return.

Two of these vectors' harness bugs were found exactly this way, by running the kit against
the implementation that defines it.

## What this kit does not yet cover

* **The mediator's eleven checks as vectors.** The context stage is four artifacts and a
  prose description of what a mediator must do with them. **That is now done**:
  `fixtures/contracts/scenarios/` carries the peers, presented surfaces, revocation feeds and
  zone policy, driven by `connect verify --scenario` and by this harness's mediator pass. Six
  scenarios, one of them a positive control. What remains is a second implementation to run
  them against.
* **A second implementation of `wcs1`.** The vector set itself is now published —
  [`fixtures/canon/`](../fixtures/canon/README.md), 31 vectors, driven by
  `scripts/canon-conformance.sh` on the same calling-convention pattern as this kit. What is
  unproven is agreement: it has been run against our canonicaliser and against a deliberately
  wrong one, never against a real second implementation. The three rules most likely to be
  implemented differently — preserved zero-width and bidi characters, numbers kept in the form
  they were written, and the field allowlist — are written out in that README so a disagreement
  arrives as a citation rather than as two hex strings.
* **A signed distribution.** The vectors are files in a git repository. Nothing attests
  that the set you downloaded is the set we published — see the provenance gap in
  [releasing.md](releasing.md).
