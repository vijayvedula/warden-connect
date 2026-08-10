# Workload identity without SPIFFE or SPIRE

Most enterprises do not run SPIRE. They have Kubernetes projected service-account tokens,
IRSA, Azure workload identity, GCP service accounts, or HashiCorp Vault identity tokens —
and every one of those is a JWT with a published JWKS and a subject that is **not** a
`spiffe://` URI.

That mattered more than it looks. `--svid` requires a SPIFFE subject, so a party without
one could not pass admission stage 1, stayed `Unattested` for ever, and the mediator's
check 9 refused every call with `WC-3109`. The only workable configuration was
`--observe`. **Enforce mode was effectively SPIRE-only**, which was never a design
decision — it was an unnoticed consequence of one verifier.

`--oidc-token` is stage 1 for those estates, on the same terms: a signature under a key
from the issuer's own JWKS, an audience bound to this control plane, an expiry judged
against an injected clock, and a subject that maps to exactly one party.

## The shape of it

```sh
connect register agent \
  --card agent-card.signed.json \
  --owner human:priya@org --zone internal.apac-ops \
  --id "urn:wc:oidc:prod-apac:system:serviceaccount:payments:recon" \
  --oidc-token /var/run/secrets/tokens/warden \
  --oidc-issuer https://kubernetes.default.svc \
  --oidc-label prod-apac \
  --trust-key k8s-sa-1=cluster-jwks.pem \
  --aud warden-connect \
  --card-key card-1=card-signer.pub.pem --require-card-signature \
  --attest provenance.dsse.json --prov-key builder-1=builder.pub.pem \
  --builder https://ci.example.org/builder@v1 --artifact-digest sha256:… \
  --by human:priya@org
```

That reaches `Posture::Attested` with no SPIFFE identity anywhere in the estate — verified
end to end, including a mediated call through `connect-mediate` that executes the
contracted tool and blocks the uncontracted one.

## The entity id is derived, not asserted

```
urn:wc:oidc:<label>:<subject>
```

There is no mapping table. The id is computed from the token, which is the property worth
having: **a token for subject *A* can only ever authenticate as the one id derived from
*A*.** An administered mapping file would be a second trust surface, and whoever could
edit it could silently re-point an identity.

The consequence for you: **register the party under the derived id.** Register it under
anything else and stage 1 refuses with `WC-1001`, naming both ids. That is deliberate —
the alternative is a client choosing its own name.

## Why `--oidc-label`, and why it may not contain a colon

Every Kubernetes cluster mints `system:serviceaccount:default:default`. Without the issuer
folded into the id, a token from *any* configured issuer would authenticate as the same
party — the same species of confusion as trusting a key across algorithms. The label is
that fold, and it is your short local name for the issuer: `prod-apac`, `dev-emea`.

A label containing `:` is **refused**, because the derivation would be ambiguous:
`label="a:b"` with subject `c` and `label="a"` with subject `b:c` name the same party.
Kubernetes subjects are colon-separated, so that collision is one careless label away
rather than exotic. `a_label_containing_a_colon_is_refused` asserts the collision exists
before asserting the refusal.

## `--oidc-issuer` is required

Not optional, and not defaulted. Without it, any key in `--trust-key` would authenticate a
token from whichever issuer holds that key — so a second trusted issuer becomes a way to
impersonate a party in the first. `an_empty_issuer_or_label_is_refused_rather_than_defaulted`
covers it, along with the empty-audience and empty-label cases.

## Per-issuer notes

| Issuer | `--oidc-issuer` | `--oidc-subject-claim` | Subject looks like |
|---|---|---|---|
| Kubernetes (projected SA token) | `https://kubernetes.default.svc` — or the cluster's external OIDC URL | `sub` | `system:serviceaccount:payments:recon` |
| EKS / IRSA | the cluster's OIDC provider URL | `sub` | `system:serviceaccount:ns:sa` |
| GKE workload identity | `https://container.googleapis.com/v1/projects/…` | `sub` | the SA's numeric unique id |
| Azure workload identity | `https://login.microsoftonline.com/<tenant>/v2.0` | `sub` | the federated-credential subject |
| Vault identity tokens | `https://vault.corp.example/v1/identity/oidc` | `sub` | the Vault entity id |

**`--oidc-subject-claim` exists because issuers disagree.** Some put an opaque number in
`sub` and the readable name in `email` or a custom claim. Naming the claim is the
difference between an id an operator can recognise and one nobody can match to a workload;
it defaults to `sub` and is worth setting deliberately.

**Get the JWKS from the issuer, not from the token.** For Kubernetes:

```sh
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
```

`IssuerKeys::add_jwks` reads that directly. It reports what it skipped and why, so a key
you expected to be trusted and is not shows up as a reason rather than a silence — and a
rotation is [`--jwks-url`](observability.md) rather than a redeploy.

## Two things this does not change

**The audience is still load-bearing.** Mint tokens *for* warden-connect —
`--audience=warden-connect` on the projected volume, or the equivalent — and set `--aud` to
match. A token minted for the Kubernetes API server and replayed here is refused, which is
the point of `aud` existing.

**Trust in the issuer is still yours to establish.** Stage 1 proves a token was signed by a
key in the JWKS you configured. Who is entitled to a token from that issuer is the
issuer's problem: a cluster where any pod can mint a token for any service account gives
you an identity worth what that cluster's RBAC is worth. Exactly the same limit as SPIRE's
trust domain, written down in [limitations.md](limitations.md).

## What still requires SPIFFE

The **mediator's authenticated peer modes**. `--peer-mode mtls`, `mesh` and `jwt-svid` all
resolve the peer through a SPIFFE URI and refuse anything else. Only `--peer-mode
configured` — the default, and the honest one for a sidecar owning one agent — accepts a
derived `urn:wc:oidc:…` id.

For the stdio sidecar that is the whole topology, so nothing is lost: the verified loop
above runs in `configured` mode. The authenticated modes matter for the **shared-gateway**
topology, and that topology is not deployable for other reasons already recorded in
limitations.md. When it is, those three modes need the same treatment this document
describes — and until then, `configured` records that identity came from configuration
rather than a handshake, which is what its startup banner says.
