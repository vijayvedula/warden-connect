# Security Policy

warden-connect is a connection control plane — a security product whose whole value is
that a bound on a connection is real. We take vulnerabilities seriously and welcome
coordinated disclosure.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

- Use **GitHub Private Vulnerability Reporting** — the "Report a vulnerability" button on
  the repository's **Security** tab (preferred).

Include: affected version or commit, a description, reproduction steps or a PoC, impact,
and any suggested remediation. If the finding is about the artifact format, a **failing
test vector** in the shape of `fixtures/contracts/` is the most useful thing you can
send — see [Conformance](#conformance-findings) below.

### Our commitment

- **Acknowledge** within **3 business days**.
- **Triage + severity** (CVSS) within **7 business days**.
- **Fix timeline** shared after triage; Critical and High prioritised.
- **Credit** in the advisory unless you prefer to remain anonymous.
- A **CVE** is requested for confirmed vulnerabilities.

### Safe harbour

Good-faith research under this policy is authorised: we will not pursue legal action for
testing that respects the scope below, avoids privacy violations and service degradation,
and gives us reasonable time to remediate before public disclosure (default coordinated
disclosure window: **90 days**).

---

## In scope

The threat model is [docs/07-hld.md §7.8](docs/07-hld.md) — eleven named threats with
their controls and stated residuals. The highest-value targets:

- **Contract forgery (A1)** — anything that makes a verifier accept an artifact its
  issuer did not sign. Algorithm confusion, `alg: none`, HMAC substitution, `kid`
  selection attacks, JWKS ingest flaws, DER-versus-`R‖S` signature confusion.
- **Ceiling escape** — anything where `effective` ends up **wider** than
  `contract.surface ∩ token.scope ∩ policy_decision`. A contract is a ceiling and must
  only ever narrow; a path that lets it widen anything is the most serious class of bug
  this repository can have.
- **Canonicalisation divergence (`wcs1`)** — two documents that should produce different
  `surface_digest` values and do not, or the same document digesting differently across
  implementations. Note that zero-width and bidirectional characters are **preserved**
  deliberately: normalisation must never launder an attack.
- **Replay across mediators (A2)** — `aud` binding, `nbf`/`exp`, `jti` tracking.
- **Peer impersonation (A3)** — anything that lets a claimed identity be treated as an
  authenticated one, including forwarding headers or mesh metadata believed from the
  wrong hop.
- **Surface pinning and rug-pull (A4)** — a callee changing its declared surface without
  the pin catching it; screening bypass; an injection payload that passes screening.
- **Revocation and quarantine bypass** — acting after a revocation, a corrupted feed
  being treated as an empty feed, or a `quarantined` posture being overridable.
- **Evidence forgeability** — rewriting or rolling back the hash chain, or defeating the
  signed anchor.
- **Fail-open conditions** — any dependency failure that yields "allow" where the
  fail-closed matrix in §7.8 says deny. **This includes a control that is configured and
  does nothing.** Historically the most common real defect here: an enforcement mode that
  reads as set and is not consulted, a staleness bound that never trips, a trust set that
  is never refreshed. If you find one of these, it is in scope even if no single request
  can be shown to bypass anything.
- **HTTP surface** — token authentication, role checks, the transport policy
  (`--behind-tls-proxy` and `--trusted-proxy`), idempotency handling.
- **Key custody** — anything that causes a signing key to be read from local disk while
  `--require-external-signing` is set, or a delegated signer's output to be
  misinterpreted.

## Out of scope

- **Prompt injection inside the agent's reasoning.** warden-connect bounds *connections*;
  it does not police a model's thinking. An injection that causes the agent to make a
  call the contract permits is working as designed — that is what the ceiling being
  narrow is for.
- **Semantic behaviour change within an unchanged declared surface.** A tool whose
  description and schema are unchanged but which behaves differently is
  `warden-trace`'s problem, and is named as A4's residual.
- **A host compromise that already holds the signing keys.** Documented non-goal until
  key custody is fully delegated; see [docs/08-lld.md §8.12.1](docs/08-lld.md).
- **`--insecure-plaintext`.** It accepts bearer tokens over plaintext from anywhere. That
  is what it says, it is named so it is visible in the process list and the startup
  banner, and reporting that it does it is not a finding.
- **A mediator that is not actually inline (A5).** Enforcement requires the mediator to
  be on the path; that is a deployment property, stated as A5's residual.
- **Third-party MCP servers, agent frameworks or identity providers themselves.**
- **Self-inflicted misconfiguration** — running `--observe` and expecting denials, an
  empty zone matrix, or a control plane with no durable volume.
- **Known and documented gaps.** Everything in [docs/07-hld.md §7.13](docs/07-hld.md)
  and [docs/08-lld.md §8.16b](docs/08-lld.md) is already public. A report that a stated
  gap is a gap is welcome as an issue, not as a vulnerability.

## Conformance findings

The contract format is intended as a candidate standard: **any implementation may mint a
contract, and a contract is valid iff a conforming verifier accepts it.**
`fixtures/contracts/` holds nineteen test vectors with an `expected.json` naming the
`WC-*` code each must produce.

If your independent verifier disagrees with ours on any vector, that is worth reporting
even when you are not sure whose bug it is — a disagreement about what is valid is a
security finding in a format meant to be interoperable. The most useful report is a new
vector plus the code you believe a conforming verifier must return.

## Supported versions

Pre-1.0 (beta): the latest `main` and the most recent tagged release receive security
fixes. Pin a release for production.

## Beta / production-use notice

warden-connect is in **beta** and has **not** undergone an independent security audit.
[docs/07-hld.md §7.13](docs/07-hld.md) is the honest list of what is missing, written
before anyone asked for it. Recommended adoption:

1. **Control plane only, first.** Register the estate, pin surfaces, collect evidence.
   Nothing is enforced, so nothing can break — and the register and the audit trail are
   most of the value.
2. **Observe mode** on the mediators. Findings are recorded, connections are not denied.
3. **Enforce** per zone pair, starting with the relationships you understand best.
4. For **regulated or high-stakes enforcement**, conduct your own review until a public
   audit lands.

## Hardening checklist (operators)

- **Move the anchor key off the host first** (`--anchor-signer`). A checkpoint signed by
  a key the host holds proves only that the host agrees with itself.
- Set `--require-external-signing` once every signer is delegated, so a regression to a
  local key is a startup failure rather than a silent downgrade.
- Never run a non-loopback `serve` without `--behind-tls-proxy` **and**
  `--trusted-proxy`. Without the second, any address that can reach the port can assert
  its own security.
- Point mediators at `--jwks-url` rather than a pinned PEM, so a compromised key can be
  withdrawn by publishing rather than by redeploying. Keep `--jwks-max-stale` tight
  enough that a key set nobody can refresh stops being served.
- Keep `keys.toml` and the evidence chain on **different** storage from the signing keys.
- Ship the evidence chain to **WORM/SIEM**; schedule `connect audit verify` including the
  anchor.
- Approver keys must not share the control plane's KMS — dual control that one
  compromise defeats is not dual control.
- Run `cargo deny check` in your build; pin a release rather than tracking `main`.
