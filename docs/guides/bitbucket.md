# Bitbucket Cloud — implementation guide

Bring one provider and one consumer under connection contracts, end to end.
Every command names the directory it runs from and the identity that runs it.

Bitbucket names a repository as `workspace/slug`. A bare repository name 404s at
the host, and the shim then reports "not merged" rather than "no such repo".

> **Unverified against a live tenant**
>
> The `bitbucket.sh` shim's field paths agree with the fixtures and with the
> code, which means both could be wrong together. Only the GitHub path has been exercised
> end to end against a live host. Treat this guide and its shim as a template,
> and run the probe in §05 before anything else.

## 00 · What you end up with

| Artifact | Where | Written by |
|---|---|---|
| Surface | `warden/surface.json`, provider repo | provider |
| Offer | `warden/offer.toml`, provider repo | provider |
| Need | `warden/needs.toml`, consumer repo | consumer |
| Contract | the control-plane state log | warden-connect — signed, never committed |
| Receipt | `warden/contracts/<cid>.toml` | warden-connect — no signature, grants nothing |

> **the model**
>
> A contract is a **ceiling**, never a grant: `effective = contract.surface ∩ token.scope ∩ policy_decision`. Both parties consent by merging a reviewed change in their own repository, and neither can produce a contract alone.

## 01 · Prerequisites

| Need | This host |
|---|---|
| CLI | `curl` and `jq` |
| Environment | `BITBUCKET_USER`, `BITBUCKET_APP_PASSWORD` |
| Repo identifier form | `workspace/slug` |
| Shim | `scripts/scm/bitbucket.sh` |
| Toolchain | Rust 1.89+, `jq`, `python3` |

> **token scope**
>
> The app password needs **Repositories: Read** and **Pull requests: Read**. Branch restrictions are read through the same credential.

> **not implemented on this host**
>
> `repos` and `open_pr` are not implemented, so `connect inventory`, `inventory promote --raise-pr`, `receipt --repo` and `--state-repo` do not work here. Everything in this guide does.

## 02 · Set up the workspace

One directory holding three checkouts and the control-plane state. Everything below runs from here or from one of the two repositories, and each step says which.

*lay it out — run from `~/wc`*

```sh
mkdir -p ~/wc && cd ~/wc

git clone <warden-connect>  warden-connect
git clone <provider repo>   payments-mcp
git clone <consumer repo>   recon-bot

cargo build --release --workspace --manifest-path warden-connect/Cargo.toml
```

*two variables every later step depends on — run from `~/wc`*

```sh
export C="$HOME/wc/warden-connect/target/release/connect"

# The state log. WITHOUT this it defaults to `.connect` RELATIVE TO THE
# CURRENT DIRECTORY, so a command run from a different folder silently
# reads and writes a different registry.
export WARDEN_CONNECT_ROOT="$HOME/wc/state"
mkdir -p "$WARDEN_CONNECT_ROOT"
```

*an issuer key. warden-connect does not generate keys: `keys new` prints this recipe and then asks you to register the public half. Two steps because `ecparam -genkey` emits SEC1 and the loader wants PKCS#8. — run from `~/wc`*

```sh
openssl ecparam -name prime256v1 -genkey -noout -out sec1.pem
openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out issuer.pem
openssl ec -in issuer.pem -pubout -out issuer.pub
rm sec1.pem
```

> **a walkthrough key**
>
> This one is on disk. In production the issuer key never reaches the process: `--signer COMMAND` takes a base64url signing input on stdin and returns a signature, so the key stays in an HSM or KMS. `--require-external-signing` refuses to start if any key would be read from local disk.

*a connect policy naming the zones you are about to register. Without it, issuance reads ./connect-policy.toml relative to wherever you stand. — run from `~/wc`*

```sh
cat > drill-policy.toml <<EOF
default = "require_approval"
version = "connect-policy@walkthrough-v1"

[[zone]]
id = "internal.payments"
trust = "internal"

[[zone]]
id = "internal.apac"
trust = "internal"

[standing]
enabled = false
reviewed_at = $(date +%s)

[[rules]]
decision = "require_approval"
owner_merge_approves = true
reason = "the registered owner approving a reviewed merge is the consent"
EOF

$C policy lint --policy drill-policy.toml
```

> **why a policy of your own**
>
> The shipped `connect-policy.toml` declares `internal.apac-ops`, not `internal.apac`. A zone the policy has never heard of refuses with `WC-2011`, and `owner_merge_approves = true` is what lets a reviewed merge settle a request instead of demanding a signed approval. Expect two warnings from the lint: no `approver_role`, and standing policy off. Both are right for a walkthrough.

> **the most common way to get stuck**
>
> The default state root is `.connect`, **relative to the working directory**. Register a party from `~/wc` and publish an offer from `~/wc/payments-mcp` and the second command sees an empty registry, because it opened a different state log. Export `WARDEN_CONNECT_ROOT` as an absolute path once, in every shell you use.

| Directory | What runs there |
|---|---|
| `~/wc` | registration, issuance, verification — anything against the control plane |
| `~/wc/payments-mcp` | `offer lint`, `offer publish`, the provider's git |
| `~/wc/recon-bot` | `need check`, `need apply`, the consumer's git |

*repo identifiers, in this host's form — run from `~/wc`*

```sh
# THE FULL FORM: workspace/slug
# A bare repository name 404s at the host, and the shim then reports
# "not merged" rather than "no such repo".
export PROVIDER_REPO="myworkspace/payments-mcp"
export CONSUMER_REPO="myworkspace/recon-bot"
```

## 03 · Guard both branches

On **both** repositories. An unguarded branch means a merge proves nothing, and every contract is refused with `WC-1001`.

### 3.1 · Add a branch restriction on `main`

*or from the CLI — run from `~/wc`*

```sh
curl -sf -u "$BITBUCKET_USER:$BITBUCKET_APP_PASSWORD" -X POST \
  "https://api.bitbucket.org/2.0/repositories/$WORKSPACE/$SLUG/branch-restrictions" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"require_approvals_to_merge","value":1,"pattern":"main"}'
```

## 04 · Decide who approves

Two accounts. Whoever opens a pull request cannot approve it.

| Role | Does |
|---|---|
| Author | commits the manifest, opens the pull request |
| Approver | approves and merges — must be the registered owner |

> **owner is a host login**
>
> There is no identity mapping layer. `--owner` at registration must be the **exact login this host reports** for whoever approves. `human:` is stripped from both sides and the compare is case-insensitive; anything else refuses with `WC-3024`.

*— run from `~/wc`*

```sh
export OWNER_LOGIN="<the approving account's login on this host>"
```

## 05 · Probe the shim before anything else

**Unverified against a live tenant.** The field paths agree with the fixtures and with the code, which means both could be wrong together. Run step 4 before anything else.

Merge one throwaway pull request on the provider repo, approved by the other account, then read it back. This is the cheapest way to find a wrong field path or a token scope.

*read the merge back — run from `~/wc`*

```sh
$C scm probe --shim warden-connect/scripts/scm/bitbucket.sh --label scm \
  --repo "$PROVIDER_REPO" --sha <merge-sha> \
  --expect-ref refs/heads/main --expect-protected \
  --expect-approver "$OWNER_LOGIN"
```

| Field | Must be | If it is not |
|---|---|---|
| `merged` | `true` | you pushed instead of merging |
| `protected` | `true` | step 3 was skipped, or the token cannot read policy |
| `author` | named | the shim is broken; an empty author makes separation of duties vacuous |
| `approvers` | the owner, not the author | the wrong account approved |
| `base_sha` | a commit | read from `destination.commit.hash`; without it every contract refuses with `WC-3025` |

## 06 · Register both parties

Registration is not connectivity. A registered party holds zero contracts.

### 6.1 · Write the surface into the provider repo

It belongs at a reserved path, because the same file is what step 7 publishes. Registering from a loose copy elsewhere would pin a digest that no repository can be shown to hold.

*the declared surface — run from `~/wc/payments-mcp`*

```sh
mkdir -p warden
cat > warden/surface.json <<'JSON'
{
  "tools": [
    { "name": "get_balance",    "description": "Read a balance." },
    { "name": "transfer_funds", "description": "Move money." }
  ]
}
JSON
```

### 6.2 · Register the provider and the consumer

*both point at files by path; neither writes to a repo — run from `~/wc`*

```sh
export PROVIDER="urn:acme:mcp:payments-mcp"
export CONSUMER="urn:acme:agent:recon-bot"

cat > recon-bot/card.json <<'JSON'
{
  "name": "recon",
  "description": "consumer",
  "version": "1.0.0",
  "skills": [ { "id": "d", "name": "d", "description": "d" } ]
}
JSON

$C register server --id "$PROVIDER" \
  --surface payments-mcp/warden/surface.json \
  --endpoint "npx -y @acme/pay" --owner "$OWNER_LOGIN" \
  --zone internal.payments --by "$OWNER_LOGIN"

$C register agent --id "$CONSUMER" --card recon-bot/card.json \
  --owner "$OWNER_LOGIN" --zone internal.apac --by "$OWNER_LOGIN"

$C activate "$PROVIDER" --by "$OWNER_LOGIN"
$C activate "$CONSUMER" --by "$OWNER_LOGIN"
```

### 6.3 · Check it landed

*— run from `~/wc`*

```sh
$C entities
$C show "$PROVIDER"
```

The `owner` field is what every approval check reads. If `entities` is empty here, `WARDEN_CONNECT_ROOT` is not set in this shell.

## 07 · Provider — publish the offer

### 7.1 · Write the terms

*payments-mcp/warden/offer.toml — run from `~/wc/payments-mcp`*

```sh
asset = "urn:acme:mcp:payments-mcp"

[[term]]
items    = ["get_balance"]
approval = "pre_granted"
ttl_max  = 604800
to       = { zone = "internal.*" }

[[term]]
items    = ["transfer_funds"]
approval = "named_consumer"
ttl_max  = 3600
to       = { zone = "internal.*" }
```

| `approval` | Means |
|---|---|
| `pre_granted` | anyone matching `to` may consume it; consent given in advance |
| `named_consumer` | each consumer is approved individually |

No consumer is named. A provider writes this before any consumer exists.

### 7.2 · Lint

*needs no control plane — run from `~/wc/payments-mcp`*

```sh
$C offer lint
```

### 7.3 · Pull request, approve, merge

*as the author — run from `~/wc/payments-mcp`*

```sh
git checkout -b publish-offer
git add warden/
git commit -m "publish offer"
git push -u origin publish-offer
# then open the pull request in the UI, or:
curl -sf -u "$BITBUCKET_USER:$BITBUCKET_APP_PASSWORD" -X POST \
  "https://api.bitbucket.org/2.0/repositories/$WORKSPACE/$SLUG/pullrequests" \
  -H 'Content-Type: application/json' \
  -d '{"title":"publish offer","source":{"branch":{"name":"publish-offer"}}}'
```

*as the approver — the registered owner — run from `~/wc/payments-mcp`*

```sh
# as the OTHER account
curl -sf -u "$OTHER_USER:$OTHER_APP_PASSWORD" -X POST \
  "https://api.bitbucket.org/2.0/repositories/$WORKSPACE/$SLUG/pullrequests/<id>/approve"
```

*merge — run from `~/wc/payments-mcp`*

```sh
curl -sf -u "$BITBUCKET_USER:$BITBUCKET_APP_PASSWORD" -X POST \
  "https://api.bitbucket.org/2.0/repositories/$WORKSPACE/$SLUG/pullrequests/<id>/merge"
```

> **this first merge**
>
> carries no `[approval]` block yet, so the **registered owner** stands in as the approver. That is the bootstrap, and it applies only while the key is absent.

### 7.4 · Publish to the control plane

*the MERGE commit, not the branch head — run from `~/wc/payments-mcp`*

```sh
git checkout main && git pull
git rev-parse HEAD
```

*publish it — run from `~/wc/payments-mcp`*

```sh
$C offer publish --surface warden/surface.json --terms warden/offer.toml \
  --repo "$PROVIDER_REPO" --sha <merge-sha> \
  --shim ../warden-connect/scripts/scm/bitbucket.sh --shim-label scm
```

*what the catalogue now holds — run from `~/wc`*

```sh
$C offer list
```

## 08 · Consumer — declare the need

### 8.1 · Write the need

*recon-bot/warden/needs.toml — run from `~/wc/recon-bot`*

```sh
asset = "urn:acme:agent:recon-bot"

[[need]]
to      = "urn:acme:mcp:payments-mcp"
tools   = ["get_balance"]
justify = "APAC daily reconciliation"
ttl     = 604800
```

### 8.2 · Check it against what is offered

*reads the registry, takes no lock — run from `~/wc/recon-bot`*

```sh
$C need check --manifest warden/needs.toml --repo "$CONSUMER_REPO"
```

| Disposition | Means | Next |
|---|---|---|
| `GRANT` | pre-granted to this audience | merge, then `need apply` mints |
| `PENDING` | the term is `named_consumer` | step 9 — the provider approves |
| `REFUSED` | not offered to you, with a per-item reason | ask the provider to widen the offer |

### 8.3 · Pull request, approve, merge

The same three commands as 7.3, on `~/wc/recon-bot`. Author and approver must differ here too.

### 8.4 · Apply it

*mints for GRANT, opens a request for PENDING — run from `~/wc/recon-bot`*

```sh
$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha <merge-sha> \
  --shim ../warden-connect/scripts/scm/bitbucket.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

## 09 · Provider — approve a gated item

Only for `named_consumer` terms. No key ceremony: the provider approves by merging.

### 9.1 · See what is waiting

*— run from `~/wc`*

```sh
$C requests --all
```

### 9.2 · Emit the approval file

*what the provider will review — run from `~/wc`*

```sh
$C approve <req-id> --emit emitted/
```

It names the request, the parties, the items and the TTL *in words*, and binds them by digest — a reviewer sees what they are agreeing to without computing a hash.

### 9.3 · Commit it to the provider repo and merge it

*— run from `~/wc/payments-mcp`*

```sh
cp ../emitted/<req-id>.toml warden/approvals/
# then pull request, approve as the owner, merge
```

### 9.4 · Settle the request

*— run from `~/wc`*

```sh
$C approve <req-id> --merge-repo "$PROVIDER_REPO" --sha <merge-sha> \
  --approval-file emitted/<req-id>.toml \
  --shim warden-connect/scripts/scm/bitbucket.sh --shim-label scm \
  --kid k1 --issuer-key issuer.pem --policy drill-policy.toml
```

## 10 · Verify

*what exists now — run from `~/wc`*

```sh
$C contracts
$C show "$PROVIDER"
$C blast-radius --id "$CONSUMER" --depth 2 --services
```

### 10.1 · Write the receipt back

*a record, not a grant — run from `~/wc`*

```sh
$C receipt --cid <cid> --out payments-mcp/warden/contracts/
```

> **never committed**
>
> The signed contract is **not** written to any repository. A signed artifact in git verifies until its expiry no matter what the registry says, and git cannot express revocation — a deletion is another commit and the blob stays reachable. The receipt carries no signature and no key.

### 10.2 · Verify it independently

*the verifier is the ground truth — run from `~/wc`*

```sh
$C verify --file contract.jws --issuer-pub issuer.pub \
  --mediator-id warden:mediator:local
```

## 11 · Declare who may approve

Once the flow works, replace the bootstrap with an explicit list — in a **second** pull request, because the first had nothing to govern it.

*add to both manifests — run from `~/wc/payments-mcp and ~/wc/recon-bot`*

```sh
[approval]
approvers = ["alice-login", "bob-login"]
min       = 1
```

| At the base commit | Behaviour |
|---|---|
| no `[approval]` key | registry owner stands in |
| `approvers = []` | `refuse` — an instruction, not a gap |
| `approvers = […]` | that list decides |

> **read at the base**
>
> The list is read from the commit the pull request *targets*, not from the pull request. Adding yourself and approving in one change does not work: joining the list and using it are two merges, and the first is governed by whoever was already on it.

A later change is reported by `offer publish` and `need apply` as `APPROVER SET CHANGED`, with the digest before and after.

## 12 · Put the mediator in the path

Everything above is the control plane. This is where the ceiling is enforced.

*data plane — run from `~/wc`*

```sh
./warden-connect/target/release/connect-mediate --help
```

| At connect | At each call |
|---|---|
| 14 gates: signature, alg, expiry, audience, revocation, both peer identities, the pin, posture, zone pair, token binding, issuer, schema, size | `tools/list` filtered to `surface.tools`; rate, spend and concurrency ceilings |

The catalogue filter is the most valuable thing here: the model never sees the tool it is not contracted for, so it cannot be talked into attempting it.

## 13 · When it refuses

Every refusal names a cause.

| Code | Means | Look at |
|---|---|---|
| `WC-8004` | The shim could not be started | Your `--shim` path — it is relative to the directory you are in. |
| `WC-2001` | Entity not found | `WARDEN_CONNECT_ROOT` is unset in this shell, so you opened a different state log. |
| `WC-1001` | Not a reviewed merge | Merged, not pushed? Branch guarded? Approved by someone other than the author? |
| `WC-3025` | Approver not in `[approval]` at the base, or no `base_sha` | The block on `main` *before* your change. |
| `WC-3026` | Fewer approvers than `min` | `min`, and who actually approved. |
| `WC-3024` | The registered owner did not approve | `$C show <id>`. The owner must be the host login. |
| `WC-3027` | The same person approved both sides | The zone bar requires two different people. |
| `WC-3023` | The reviewed file is not the submitted one | You edited after approval. |
| `WC-3010` | Requested surface exceeds the offer | The diff is in the message. |
| `WC-3011` | Connection policy denied it | `connect-policy.toml`. |
| `WC-8003` | Another writer holds the state log | Use `--read-only` for the portal. |

## 14 · Checklist

warden-connect · connection control plane for agents. Reference: `docs/07-hld.md`, `docs/08-lld.md`, `docs/use-cases/`.
