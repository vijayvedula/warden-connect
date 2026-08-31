# warden-connect, end to end

One provider and one consumer, from two empty repositories to a contracted
call refused at a real gateway. Every command names the directory it runs from
and the account that runs it.

Three accounts appear throughout. `$PROVIDER_LOGIN` and `$CONSUMER_LOGIN` own a
repository each and approve on their own side; `$AUTHOR_LOGIN` commits and opens
the pull requests. The author must never be an approver — that is exactly what
the merge-consent check tests.

| Part | Sections |
|---|---|
| Stand the estate up | 00–08 · accounts, keys, policy, registration, branch guards, shim probe |
| Fill the repositories | 09–10 · the provider's offer and server, the consumer's need and client |
| Contract a connection | 11–13 · the pre-granted path, then the gated one |
| Enforce | 14–15b · pick one: stdio mediator, Envoy, or Kong |
| Prove it | 16–19 · what passes, what refuses, and where each refusal comes from |

> **Written 2026-08-28, corrected since**
>
> Rate, concurrency and spend ceilings were removed from warden-connect on
> 2026-08-29, the day after this was walked. Section 17.5 and the Kong
> `ceiling_scope` key went with them; both now say so rather than describing a
> refusal that no longer happens. Everything else is as it was walked.

## 00 · What is where

> **this replaces two guides, and adds the thing neither had**
>
> The GitHub runbook and the gateway runbook shared their whole middle — two repositories, two merges, one minted contract — and differed only at the end. They are one document now. What neither said is that **the id shape you register decides which enforcement points stay available**, and that decision comes before registration. It is §04.

> **someone has walked this, and it cost twelve corrections**
>
> Every section here except §14 has been executed by a reader following the page — live GitHub, three accounts, two reviewed merges, a gated term approved by the provider’s owner, and a real Envoy 1.31.10 that admitted two calls and refused six distinct ways. **Every output shown is that run’s real text.** Twelve things were wrong on the first pass, and the ones you are likeliest to hit are left in place as stop-notes rather than quietly corrected — a guide that shows only the happy path teaches you nothing about the failure you are about to cause. Two of the twelve were not guide bugs at all but product bugs, and are fixed in the code: a second contract between the same two parties was verified, counted, and silently unreachable, and three unrelated refusal paths all reported the same bare `WC-4001`. Both are the same defect class this project is about — a control that reads as configured and does nothing.

Five parts. Part 3 repeats per connection; part 4 is a choice.

|  | Part | Sections | When |
|---|---|---|---|
| **0** | Decide and prepare | 01 what you build · 02 accounts · 03 prerequisites · 04 **the id decision** | read first |
| **1** | Stand the estate up | 05 workspace · 06 register and attest · 07 guard the branches · 08 probe the shim | once per estate |
| **2** | Fill the repositories | 09 provider · 10 consumer | once per pair |
| **3** | Contract a connection | 11 publish · 12 the pre-granted path · 13 the gated path | **per connection** |
| **4** | Enforce — pick one | 14 Path A: stdio mediator · 15 Path B: Envoy · 15b Path C: Kong | once per deployment |
| **5** | Test success and failure | 16 success · 17 failure · 18 refusals · 19 gaps | every time |

## 01 · What you build

One MCP server, one client, one contract, and an enforcement point you choose.

| Piece | What it is | Lives in |
|---|---|---|
| `payments-mcp` | the provider: a real MCP server — three tools over Streamable HTTP | its own GitHub repository, with `warden/offer.toml` and `warden/surface.json` |
| `recon-bot` | the consumer: a real MCP client | its own repository, with `warden/needs.toml` |
| the contract | a signed JWS covering **two** of the three tools | on disk beside the enforcement point. **Never in a repository** |
| the enforcement point | either a stdio mediator or an Envoy sidecar | §14 or §15 |

#### The three tools, and why three

| Tool | In the offer as | What it demonstrates |
|---|---|---|
| `get_balance` | `pre_granted` | the contracted path: it works |
| `list_transactions` | `pre_granted` | that the catalogue filter keeps what is contracted, not just one item |
| `transfer_funds` | `named_consumer` | the gated path in §13 — and, until it is gated-approved, the surface ceiling refusing a real write |

> **the server is real**
>
> It holds balances, answers with them, and appends every executed call to a log. §17 asserts the **absence** of a refused call in that log, which is the only thing that distinguishes a refusal from a refusal that forwarded anyway.

## 02 · The three accounts

Two repositories, and in each one the author and the approver must be different people.

| Repository | Author — commits, opens the PR | Approver — approves and merges | Registered owner |
|---|---|---|---|
| `payments-mcp` | `$AUTHOR_LOGIN` | `$PROVIDER_LOGIN` | `$PROVIDER_LOGIN` |
| `recon-bot` | `$AUTHOR_LOGIN` | `$CONSUMER_LOGIN` | `$CONSUMER_LOGIN` |

| Rule | Satisfied by |
|---|---|
| author ≠ approver, per repository | `$AUTHOR_LOGIN` vs `$PROVIDER_LOGIN`; `$AUTHOR_LOGIN` vs `$CONSUMER_LOGIN` |
| the approver is the registered owner | `$PROVIDER_LOGIN` owns the server, `$CONSUMER_LOGIN` owns the agent |
| approvers differ across the two sides | so `require_distinct_approvers` would also pass |

> **one author in both repositories is fine**
>
> Nothing requires authors to differ across sides. What must hold is that *within* a repository the author is not the approver, and that the approver is the account registered as owner.

> **there is no account switcher inside a command**
>
> Every block below that reaches GitHub starts with `gh auth switch`. It is not cosmetic: a `--shim` command shells out to `gh` and inherits whichever account is active. Without admin on the repository it is reading, the branch-protection lookup 404s and the shim reports `protected:false` — a token problem arriving as a policy problem.

## 03 · Prerequisites

| Need | For | Install |
|---|---|---|
| Rust 1.89+ | both binaries | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| `gh`, three logins | §07 onward | `brew install gh`, then `gh auth login` once per account |
| Python 3.9+ | the server and the client | already on macOS |
| `cryptography` | signs the attestation material in §06 | `python3 -m pip install 'cryptography>=42'` |
| OpenSSL | keys, and the certificates in Path B | already on macOS |
| Docker | **Path B only** — runs Envoy | Docker Desktop, or `brew install colima docker` then `colima start` |

*check it, including all three logins · run from `anywhere` · local only*

```sh
rustc --version
python3 -c 'import cryptography; print("cryptography", cryptography.__version__)'
openssl version
gh auth status        # expect all three accounts
docker info >/dev/null && echo "docker ok — Path B available"
```

## 04 · The decision that comes first: which id shape

Both `spiffe://` and `urn:` are valid entity ids. They are not interchangeable, and the choice constrains what you can do later.

| Shape | Means | Reach |
|---|---|---|
| `urn:acme:mcp:payments-mcp` | an id nothing authenticated. Derived, and honest about it — `connect inventory promote` mints these deliberately | the contract flow, and Path A. A `urn:` party can **never** reach `Attested`, because stage 1 needs a JWT-SVID and a SPIFFE `sub` must be a `spiffe://` URI |
| `spiffe://bank.example/ns/mesh/sa/payments-mcp` | a workload identity a system can prove | everything. **Required for Path B**: the caller is read from a certificate’s URI SAN, and `peer.rs` refuses anything not starting `spiffe://` |

> **pick spiffe:// unless you have a reason not to**
>
> This guide uses `spiffe://` throughout, so both paths stay open. If you ran the earlier GitHub-only runbook you will have `urn:acme:…` parties registered; those keep working for Path A and **cannot** be used for Path B. Re-registering under a `spiffe://` id is the fix, and it is a new party — ids are identities, not labels.

#### What goes wrong if you mix them

| Symptom | Cause |
|---|---|
| Path B refuses everything with WC-4001 | the contract names a `urn:` caller; the certificate SAN carries a `spiffe://` one. They never match, and the message says nothing about ids |
| the callee is stuck `Unattested`, WC-3109 in enforce mode | stage 1 cannot pass for a `urn:` party. The CLI warns about this under `register server --id`, and it is easy to read past |

#### The ids this guide uses

*export these in every shell — they appear in the offer, the need, the contract and the certificate · run from `anywhere` · local only*

```sh
export CALLEE=spiffe://bank.example/ns/mesh/sa/payments-mcp
export CALLER=spiffe://bank.example/ns/mesh/sa/recon-bot
export MED=warden:mediator:gateway-1
export ISS=https://connect.internal
```

> **the mediator id is not an entity id**
>
> `$MED` is the audience a contract is minted for. It is matched exactly against each contract’s `aud`, so one id per enforcement point is the right granularity — it is what lets you revoke one deployment without touching another.

## Stand the estate up

Three checkouts, one state directory, both parties registered and attested, and the source host proved to answer honestly before anything depends on it.

## 05 · Workspace

Three checkouts and one state directory. Nothing here touches GitHub.

*the three accounts, first — everything below refers to them · run from `~/wc` · local only*

```sh
# Three distinct GitHub accounts. The author must not be either approver.
export PROVIDER_LOGIN="<provider-owner-login>"   # owns payments-mcp, approves there
export CONSUMER_LOGIN="<consumer-owner-login>"   # owns recon-bot, approves there
export AUTHOR_LOGIN="<author-login>"             # commits and opens the pull requests
```

*lay it out · run from `~/wc` · local only*

```sh
cd ~/wc

mkdir -p ~/wc && cd ~/wc

git clone https://github.com/<your-org>/warden-connect  warden-connect
git clone https://github.com/$PROVIDER_LOGIN/payments-mcp    payments-mcp
git clone https://github.com/$CONSUMER_LOGIN/recon-bot       recon-bot

cd warden-connect
cargo build --release --workspace
cargo build --release --manifest-path daemon/wc-extproc/Cargo.toml
```

*three variables, in every shell · run from `~/wc` · local only*

```sh
cd ~/wc

export WC="$HOME/wc/warden-connect"
export C="$WC/target/release/connect"
export WARDEN_CONNECT_ROOT="$HOME/wc/state"
mkdir -p "$WARDEN_CONNECT_ROOT"
```

> **the single most common way to get stuck**
>
> The state root defaults to `.connect`, **relative to the working directory**. Register from `~/wc`, publish from `~/wc/payments-mcp`, and the second command opens a different, empty estate — then reports that the party you just registered does not exist. Export `WARDEN_CONNECT_ROOT` and keep it exported.

### 5.1 · Two keypairs

The issuer key signs contracts; the approver key signs a per-consumer approval in §13. Both are needed before anything mints.

*PKCS#8, which is what connect accepts · run from `~/wc` · local only*

```sh
cd ~/wc

for k in issuer approver; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$k.sec1.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$k.sec1.pem" -out "$k.priv.pem"
  openssl ec  -in "$k.priv.pem" -pubout -out "$k.pub.pem"
  rm -f "$k.sec1.pem"
done

head -1 issuer.priv.pem
```

*expected*

```sh
-----BEGIN PRIVATE KEY-----
```

> **the two-step conversion is not ceremony**
>
> `openssl ecparam -genkey` emits **SEC1**, whose header reads `BEGIN EC PRIVATE KEY`. `connect` refuses that with `WC-3102 issuer key is not an EC PKCS#8 PEM`. The `pkcs8 -topk8` step converts it, and the header becomes `BEGIN PRIVATE KEY`. Check the header rather than discovering it mid-mint.

> **the approver key must never be the issuer key**
>
> If the control plane can sign its own approvals, dual control is theatre and the evidence chain cannot tell the difference afterwards. `connect` refuses the two being the same material at startup, by fingerprint — which is why this generates a separate keypair rather than reusing one.

> **these are test keys**
>
> A real estate keeps the issuer key in an HSM or a signing service and uses `--signer COMMAND` instead of `--issuer-key`. Nothing else about the flow changes.

*the approver registry — who may sign an approval, and with which key · run from `~/wc` · local only*

```sh
cd ~/wc

cat > approvers.toml <<EOF
[[approver]]
id = "human:$PROVIDER_LOGIN"
key = "$HOME/wc/approver.pub.pem"
roles = ["platform.operator"]
EOF

cat approvers.toml
```

> **the key path inside is ABSOLUTE on purpose**
>
> It is resolved against the **current working directory**, not against the location of `approvers.toml`. A relative `approver.pub.pem` works only while you happen to be in `~/wc`, and fails with `WC-8004 cannot read approver key` from anywhere else — checked. The unquoted heredoc expands `$HOME` when the file is written, so the path is fixed from then on.

### 5.2 · The estate's policy

Every mint routes through policy evaluation. Without this file `need apply` refuses with `WC-8001` and mints nothing.

*one file, and it is read RELATIVE to the working directory unless you pass --policy · run from `~/wc` · local only*

```sh
cd ~/wc

cat > connect-policy.toml <<EOF
default = "require_approval"
version = "connect-policy@e2e-v1"

[[zone]]
id = "internal.mesh"
trust = "internal"

[standing]
enabled = false
reviewed_at = $(date +%s)

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
decision = "require_approval"
owner_merge_approves = true
ttl_max = "7d"
terms = { evidence_sink = "ocsf://siem", evidence_delivery = "fail-safe" }
reason = "the registered owner approving a reviewed merge is the consent"
EOF

$C policy lint --policy connect-policy.toml
mkdir -p ~/wc/contracts
```

*expected — two warnings, both of them the point*

```text
  warning rule[0] requires approval but names no approver_role
  warning standing.enabled is false, so every request goes to a human — the v1 posture. 0 rule(s) say `allow` and will escalate instead. Set it true only once these limits have been reviewed

usable · 2 warning(s)
```

| Line | Why it is there |
|---|---|
| `owner_merge_approves = true` | the consent is a reviewed merge by the callee’s registered owner. Without it, a rule that demands a role or two approvers refuses the merge path — **silence stays closed** |
| `terms = { ... }` | terms set here bound every contract the rule matches |
| `id = "internal.mesh"` | must match the zone both parties were registered in (§06.3), or no rule matches |
| the two warnings | expected: the rule names no `approver_role` because the owner-merge path replaces it, and standing is off so every request reaches a human |

> **it is read relative to the working directory**
>
> The default is `connect-policy.toml` in the current directory. §12 and §13 run from inside a repository, so they pass `--policy ~/wc/connect-policy.toml` explicitly. Omit that and you get `WC-8001 cannot read connect-policy.toml` and nothing is minted.

> **the second cargo build is not optional for Path B**
>
> The verifier lives in `daemon/wc-extproc`, outside the workspace, because it carries an async runtime the embeddable crates may not. `cargo build --workspace` does not build it. If `--manifest-path daemon/wc-extproc/Cargo.toml` reports `manifest path … does not exist`, you are either not in the checkout or the checkout predates that work — `git pull`.

## 06 · Register and attest both parties

Registration is not connectivity: a registered party holds zero contracts. Nothing in this section touches GitHub.

### 6.1 · The surface goes in the provider repo, generated from the server

At the reserved path, because §11 publishes that same file. Registering from a loose copy elsewhere pins a digest no repository can be shown to hold.

*save ledger_server.py first — §09.3 lists it in full · run from `~/wc/payments-mcp` · local only*

```sh
cd ~/wc/payments-mcp

cd ~/wc/payments-mcp && mkdir -p warden
# save ledger_server.py here (§09.3)

python3 ledger_server.py --emit-surface > warden/surface.json
head -14 warden/surface.json
```

> **generate it; never write it by hand**
>
> The pinned digest covers the **whole tool object**, `inputSchema` included. A surface that differs from what `tools/list` returns is a `WC-3108` on the first catalogue — drift reported when nothing has drifted. This was written by hand in an earlier draft and that is exactly what happened.

### 6.2 · Attestation material, and the signed surface

Enforce mode requires the callee to be `Attested`: three legs, three distinct keys. `scripts/.attest-material.py` mints test material; in production these come from SPIRE, your signing service and your CI.

*run from `~/wc` · local only*

```sh
cd ~/wc

DIGEST=$($C canon payments-mcp/warden/surface.json --kind mcp --entity "$CALLEE" \
  | awk '/^manifest/{print $2}')
BUILDER="https://github.com/$PROVIDER_LOGIN/payments-mcp/.github/workflows/deploy.yml@refs/heads/main"

python3 "$WC/scripts/.attest-material.py" ~/wc/material \
  "$CALLEE" "$MED" "$BUILDER" "$DIGEST"

$C attest surface --surface payments-mcp/warden/surface.json \
  --card-key "card-signer-1=$HOME/wc/material/card-signer.priv.pem" \
  --out payments-mcp/warden/surface.signed.json
```

### 6.3 · Register the server, then the agent

*the --id is the SPIFFE id from §04, not a derived one · run from `~/wc` · local only*

```sh
cd ~/wc

M=~/wc/material

$C register server --id "$CALLEE" \
  --surface payments-mcp/warden/surface.signed.json \
  --endpoint http://127.0.0.1:8931/mcp \
  --owner human:$PROVIDER_LOGIN --zone internal.mesh --by human:$PROVIDER_LOGIN \
  --svid "$M/jwt-svid.token" --trust-key "spiffe-bundle-1=$M/spiffe-bundle.pub.pem" \
  --aud "$MED" \
  --card-key "card-signer-1=$M/card-signer.pub.pem" --require-card-signature \
  --attest "$M/provenance.dsse.json" --prov-key "builder-1=$M/builder.pub.pem" \
  --builder "$BUILDER" --bind-surface

$C show "$CALLEE" | grep posture
```

*expected*

```sh
  posture  Attested
```

> **if it is not Attested, read register's own output**
>
> `show` reports the resulting posture but not which leg failed — the per-stage verdicts are computed at admission and not persisted. The stage that failed is named in `register`’s output, so keep it.

*the agent, and activate both · run from `~/wc` · local only*

```sh
cd ~/wc

printf '{"name":"recon-bot","description":"Reconciles ledgers.","version":"1.0.0","skills":[{"id":"r","name":"reconcile","description":"Reconcile."}]}' > card.json

$C register agent --card card.json --owner human:$CONSUMER_LOGIN \
  --zone internal.mesh --id "$CALLER" --by human:$CONSUMER_LOGIN

$C activate "$CALLER" --by human:$CONSUMER_LOGIN
$C activate "$CALLEE" --by human:$PROVIDER_LOGIN
```

## 07 · Give the author access, then guard the branches

Two things the owners do once per repository. Both are easy to skip and both stop the flow dead.

### 7.1 · Invite the author to both repositories

`$AUTHOR_LOGIN` authors in both repos and owns neither. Without an accepted invitation the very first push fails, and the error names permissions rather than membership.

*what it looks like when this step is missing*

```text
remote: Permission to $PROVIDER_LOGIN/payments-mcp.git denied to $AUTHOR_LOGIN.
fatal: unable to access 'https://github.com/$PROVIDER_LOGIN/payments-mcp/': The requested URL returned error: 403

pull request create failed: GraphQL: Head sha can't be blank, Base sha can't be blank,
No commits between main and probe, Head ref must be a branch (createPullRequest)
```

> **the second error is a consequence, not a separate problem**
>
> The push failed, so the branch never reached GitHub, so there is nothing to open a pull request from. Fix the push and both go away.

*provider owner invites · run from `anywhere` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
gh api -X PUT repos/$PROVIDER_LOGIN/payments-mcp/collaborators/$AUTHOR_LOGIN \
  -f permission=push
```

*consumer owner invites · run from `anywhere` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
gh api -X PUT repos/$CONSUMER_LOGIN/recon-bot/collaborators/$AUTHOR_LOGIN \
  -f permission=push
```

> **`push`, not `maintain` or `admin`**
>
> The author needs to commit and open pull requests. It must not be able to merge its own — that is what branch protection in §7.3 enforces, and a higher permission plus `enforce_admins: false` would quietly hand it back.

### 7.2 · The author accepts both invitations

An invitation is not access. This is the step that is invisible until it is missing, because nothing in the earlier output mentions it.

*list what is pending, then accept each · run from `anywhere` · as $AUTHOR_LOGIN*

```text
gh auth switch --user $AUTHOR_LOGIN

gh api /user/repository_invitations \
  --jq '.[] | "\(.id)\t\(.repository.full_name)"'

# one PATCH per id from the list above
gh api -X PATCH /user/repository_invitations/<ID>
```

*accept everything pending, in one line · run from `anywhere` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN

for id in $(gh api /user/repository_invitations --jq '.[].id'); do
  gh api -X PATCH "/user/repository_invitations/$id" && echo "accepted $id"
done
```

*the invitee checks nothing is left pending · run from `anywhere` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
gh api /user/repository_invitations --jq 'length'
```

*expected*

```sh
0
```

*each OWNER confirms the grant landed — 204 yes, 404 no · run from `anywhere` · as each repository owner*

```sh
gh auth switch --user $PROVIDER_LOGIN
gh api repos/$PROVIDER_LOGIN/payments-mcp/collaborators/$AUTHOR_LOGIN --silent \
  && echo "payments-mcp: collaborator" || echo "payments-mcp: NOT a collaborator"

gh auth switch --user $CONSUMER_LOGIN
gh api repos/$CONSUMER_LOGIN/recon-bot/collaborators/$AUTHOR_LOGIN --silent \
  && echo "recon-bot: collaborator" || echo "recon-bot: NOT a collaborator"
```

> **this check has to run as the OWNER, not as the author**
>
> Listing collaborators **requires push access**, so an account that is not yet a collaborator gets `HTTP 403 Must have push access to view repository collaborators` rather than a clean 404 — the question answers itself only for someone who already has the answer. Checked: as the owner it is 204 or 404, as the invitee it is 403 either way.

> **the git identity warning you will also see is unrelated**
>
> `git` may warn that it guessed your `user.name` and `user.email`. It does not affect any of this: the shim reads the pull request’s `user.login` — the GitHub account that opened it — not the commit author. Set them if you like the tidiness; nothing here depends on it.

### 7.3 · Guard both branches

An unguarded branch means a merge proves nothing. Every contract would refuse with `WC-1001`.

*payments-mcp — a JSON body, not -f flags · run from `~/wc` · as $PROVIDER_LOGIN*

```sh
cd ~/wc

gh auth switch --user $PROVIDER_LOGIN
export PROVIDER_REPO=$PROVIDER_LOGIN/payments-mcp
export CONSUMER_REPO=$CONSUMER_LOGIN/recon-bot

gh api -X PUT repos/$PROVIDER_REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
JSON
```

*recon-bot — same body, consumer repo · run from `~/wc` · as $CONSUMER_LOGIN*

```sh
cd ~/wc

gh auth switch --user $CONSUMER_LOGIN

gh api -X PUT repos/$CONSUMER_REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
JSON
```

> **why a JSON body and not `-f` flags**
>
> `-f` sends everything as a string and the review count must be an integer; `required_status_checks` has to be present even when null. The `--input -` form is the one that works.

## 08 · Probe the shim before anything depends on it

Merge one throwaway pull request and read it back. The cheapest way to find a token scope or a wrong variable.

### 8.1 · A throwaway PR, authored and approved by different accounts

*author · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/payments-mcp

gh auth switch --user $AUTHOR_LOGIN

git fetch origin &&
git switch -C probe origin/main &&
echo probe > PROBE.md && git add PROBE.md &&
git commit -m "probe" &&
git push -u origin probe &&
gh pr create --base main --head probe --title probe --body ""
```

*approver, and capture the merge commit · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
cd ~/wc/payments-mcp

gh auth switch --user $PROVIDER_LOGIN

export PR=$(gh pr list --head probe --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on probe}"
gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head probe --state merged --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE}"
```

> **why every branch block here starts with `fetch` and `switch -C`**
>
> The obvious form — `git checkout main && git pull && git checkout -b probe` — breaks in a way that is quiet and expensive. If `pull` refuses (divergent branches with no reconcile strategy set, which is the default on a fresh machine), the `&&` chain stops and the branch is never created — but a following `git add` and `git commit` on their own lines still run, and land the commit on **main**. The push then fails with `src refspec … does not match any`, which points at the branch and not at the commit you have just misplaced. `git switch -C <branch> origin/main` creates or resets the branch at the remote’s main whatever your local main is doing, so there is nothing to reconcile. The whole sequence is chained with `&&` so a failure anywhere stops it rather than continuing on the wrong branch.

### 8.2 · Read it back through the shim

*assert, do not just print · run from `~/wc` · as $PROVIDER_LOGIN*

```sh
cd ~/wc

$C scm probe --shim "$WC/scripts/scm/github.sh" --label github \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --expect-ref refs/heads/main --expect-protected --expect-approver $PROVIDER_LOGIN
```

> **why this section exists at all**
>
> A signing shim cannot lie — cryptography catches it. An SCM shim’s answer is just JSON, so one that reports a merge happened mints a contract on fabricated evidence and nothing downstream can tell. That is why the shim is a trusted component and why this command exists. Run it whenever a token, an account or a repository changes.

## Fill the repositories

The server and its terms in one; the client and its needs in the other. Each side declares in its own tree, which is what lets each side's approver merge without reviewing the other's.

## 09 · The provider repository

*$PROVIDER_LOGIN/payments-mcp*

```text
ledger_server.py               the MCP server (§09.3)
warden/surface.json            GENERATED — §06.1
warden/surface.signed.json     GENERATED — §06.2
warden/offer.toml              the terms (§09.1)
```

### 9.1 · The terms — two of them, on purpose

*write it at the reserved path · run from `~/wc/payments-mcp` · local only*

```sh
cd ~/wc/payments-mcp

cat > warden/offer.toml <<EOF
asset = "$CALLEE"

[approval]
approvers = ["$PROVIDER_LOGIN"]
min = 1

[[term]]
items = ["get_balance", "list_transactions"]
approval = "pre_granted"
ttl_max = 604800
to = { zone = "internal.*" }

[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
to = { zone = "internal.*" }
EOF

cat warden/offer.toml
```

| Field | Is | Is NOT |
|---|---|---|
| `approval` | a MODE: `pre_granted` or `named_consumer` | a place to name a consumer — there is no syntax for that |
| `to` | the AUDIENCE: `zone` and `tier`, both optional | a consumer. It is a class, and both absent means *any* consumer |

| `approval` | When a need arrives |
|---|---|
| `pre_granted` | the offer **is** the consent for anyone matching the audience — §12 mints immediately |
| `named_consumer` | per-consumer sign-off. **Nothing is minted**; the whole need becomes a request the callee’s owner decides — §13 |

> **no consumer is named, and that is the design**
>
> A provider writes this **before any consumer exists**. The offer is held until a need arrives, which is what lets neither party review the other’s pull request. Pre-granting approves *a class, once, in a reviewed commit* — a stronger artifact than a per-consumer ticket rubber-stamped fifty times. `[approval]` is a different thing entirely: who may approve a change to *this file*, read at the pull request’s **base commit**.

> **both values lint clean**
>
> Checked. `offer lint` will not tell you that `named_consumer` means nothing gets minted — the first sign is §12 producing no artifact. Which term you put an item in is a decision, not a formality.

*lint — needs no control plane, no key, no account · run from `~/wc/payments-mcp` · local only*

```sh
cd ~/wc/payments-mcp

$C offer lint
```

### 9.2 · Commit both files as one pull request

*author · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/payments-mcp

gh auth switch --user $AUTHOR_LOGIN

git fetch origin &&
git switch -C publish-offer origin/main &&
git add ledger_server.py warden/ &&
git commit -m "the ledger server, its surface and its terms" &&
git push -u origin publish-offer &&
gh pr create --fill
```

*approver — the account named in [approval] · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
cd ~/wc/payments-mcp

gh auth switch --user $PROVIDER_LOGIN
export PR=$(gh pr list --head publish-offer --state open --json number -q ".[0].number")
gh pr review "$PR" --approve && gh pr merge "$PR" --merge
export PROVIDER_SHA=$(gh pr list --head publish-offer --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "PROVIDER_SHA=$PROVIDER_SHA"
```

### 9.3 · Publish the offer

The merge just happened, so the consent now exists to be read back. This must come **before** the consumer's `need check` in §10.1: a need is checked against offers that are actually held, and there is no central fallback by design.

*held until a need arrives — no consumer is named · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
cd ~/wc/payments-mcp

gh auth switch --user $PROVIDER_LOGIN

$C offer publish --kind mcp \
  --repo "$PROVIDER_REPO" --sha "$PROVIDER_SHA" \
  --shim "$WC/scripts/scm/github.sh" --shim-label github

$C offer status --asset "$CALLEE"
```

> **run it from INSIDE the repository, and do not pass the paths**
>
> `--surface` and `--terms` default to `warden/surface.json` and `warden/offer.toml`, and those paths are **reserved**: the value is checked as given, so `payments-mcp/warden/offer.toml` from `~/wc` is refused with `WC-8004` even though it points at the right file. A discovery sweep reads the reserved path and nothing else, so a declaration it cannot find means the estate’s inventory under-reports by exactly this repository. `WARDEN_CONNECT_ROOT` is exported, so changing directory does not move the state root. Four commands enforce this: `offer publish`, `offer lint`, `need check` and `need apply`.

> **why this can run from a laptop**
>
> It does not assert the consent — it reads the merge back from GitHub through the shim and checks it was approved by a declared approver who was not the author. Where the command runs makes no difference to what is verified; what matters is the state root it writes to. In production it belongs in the provider’s pipeline.

> **if you skip this, §10.1 refuses and the message points elsewhere**
>
> `need check` would report *no offer is held for … There is no central fallback by design, so provider consent is never implied* and exit `WC-3011`. That is correct and it reads like a problem with the need, which it is not.

### 9.4 · The server, in full

*$PROVIDER_LOGIN/payments-mcp — ledger_server.py*

```text
#!/usr/bin/env python3
"""A real MCP server over Streamable HTTP: a small account ledger.

Three tools, and only two are ever contracted in the guide. `transfer_funds` is a write and is
deliberately left out of the offer, so the surface ceiling has something worth refusing.

Every executed call is appended to $LEDGER_LOG. The guide asserts the ABSENCE of a refused call
there — a refusal that still forwarded the request would look identical from the client's side.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("LEDGER_LOG", "/tmp/ledger.log")
# Serve a surface that does not match the pin, for the drift step.
DRIFT = os.environ.get("LEDGER_DRIFT") == "1"

ACCOUNTS = {"ACC-1": 1240.50, "ACC-2": 87.10}
JOURNAL = []

TOOLS = [
    {
        "name": "get_balance",
        "description": "Read the balance of one account.",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "required": ["account"],
        },
    },
    {
        "name": "list_transactions",
        "description": "List recent transactions for one account.",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "required": ["account"],
        },
    },
    {
        "name": "transfer_funds",
        "description": "Move money between two accounts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["from_account", "to_account", "amount"],
        },
    },
]

def tools():
    if not DRIFT:
        return TOOLS
    # One description changed. That is enough to move the pin, which is the point.
    return [
        dict(t, description=t["description"] + " (v2)") if t["name"] == "get_balance" else t
        for t in TOOLS
    ]

def call_tool(name, args):
    with open(LOG, "a") as fh:
        fh.write(f"EXECUTED {name} {json.dumps(args, sort_keys=True)}\n")
    if name == "get_balance":
        acct = args.get("account", "")
        if acct not in ACCOUNTS:
            return f"no such account: {acct}"
        return f"{acct} balance {ACCOUNTS[acct]:.2f}"
    if name == "list_transactions":
        acct = args.get("account", "")
        return f"{acct}: 3 transactions in the last 7 days"
    if name == "transfer_funds":
        JOURNAL.append(args)
        return "TRANSFERRED {} -> {} for {}".format(
            args.get("from_account"), args.get("to_account"), args.get("amount")
        )
    raise KeyError(name)

def dispatch(msg):
    m = msg.get("method")
    if m == "initialize":
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ledger-mcp", "version": "1"},
        }
    if m == "tools/list":
        return {"tools": tools()}
    if m == "tools/call":
        p = msg.get("params") or {}
        text = call_tool(p.get("name"), p.get("arguments") or {})
        return {"content": [{"type": "text", "text": text}], "isError": False}
    if m and m.startswith("notifications/"):
        return {}
    raise KeyError(m)

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        try:
            msg = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            self._send(400, b'{"error":"not json"}')
            return
        mid = msg.get("id")
        try:
            result = dispatch(msg)
        except KeyError as exc:
            if mid is None:
                self._send(202, b"")
                return
            self._send(200, json.dumps({
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"unknown method: {exc}"}}).encode())
            return
        if mid is None:
            self._send(202, b"")
            return
        self._send(200, json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}).encode())

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

if "--emit-surface" in sys.argv:
    # What the provider repo commits as warden/surface.json.
    #
    # EXACTLY what `tools/list` returns, `inputSchema` included. The canonicaliser covers the
    # whole tool object, so emitting only name and description produces a digest that will never
    # match what the server presents — a WC-3108 on the first catalogue, reading as drift when
    # nothing has drifted. Generated rather than hand-written for the same reason.
    json.dump({"tools": tools()}, sys.stdout, indent=2)
    print()
    raise SystemExit(0)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
srv = ThreadingHTTPServer(("0.0.0.0", port), H)
sys.stderr.write(f"ledger-mcp on :{port}  tools={[t['name'] for t in tools()]}\n")
sys.stderr.flush()
srv.serve_forever()
```

## 10 · The consumer repository

*$CONSUMER_LOGIN/recon-bot*

```text
mcp_client.py                  the MCP client (§10.3)
warden/needs.toml              what it needs, and who may approve that
```

### 10.1 · The need

*write it at the reserved path · run from `~/wc/recon-bot` · local only*

```sh
cd ~/wc/recon-bot

cat > warden/needs.toml <<EOF
asset = "$CALLER"

[approval]
approvers = ["$CONSUMER_LOGIN"]
min = 1

[[need]]
to = "$CALLEE"
tools = ["get_balance", "list_transactions"]
justify = "reconciliation reads balances it then checks against the warehouse"
ttl = 86400
EOF

cat warden/needs.toml
```

> **the path is `needs.toml`, plural**
>
> The reserved path is `warden/needs.toml`. `need.toml` works only with `--allow-nonstandard-path`, and discovery will not find it.

> **ask for what you want minted now**
>
> `transfer_funds` is deliberately absent. Asking for it here would make the whole need gated — all-or-nothing — and nothing would mint. §13 asks for it separately, which is the shape that lets the read-only tools work today while the write waits for a human.

> **this needs §09.3 to have run first**
>
> A need is checked against offers that are **actually held**. If the provider has not published, this refuses with *no offer is held for … There is no central fallback by design, so provider consent is never implied* and exits `WC-3011`. Correct, and it reads like a problem with the need rather than a missing publish.

*check it against the provider's published offer — mints nothing · run from `~/wc/recon-bot` · local only*

```sh
cd ~/wc/recon-bot

$C need check --manifest warden/needs.toml
```

### 10.2 · Commit and merge, consumer side

*author · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/recon-bot

gh auth switch --user $AUTHOR_LOGIN

git fetch origin &&
git switch -C declare-need origin/main &&
git add mcp_client.py warden/ &&
git commit -m "declare a need on payments-mcp" &&
git push -u origin declare-need &&
gh pr create --fill
```

*approver — a different account again · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
cd ~/wc/recon-bot

gh auth switch --user $CONSUMER_LOGIN
export PR=$(gh pr list --head declare-need --state open --json number -q ".[0].number")
gh pr review "$PR" --approve && gh pr merge "$PR" --merge
export CONSUMER_SHA=$(gh pr list --head declare-need --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "CONSUMER_SHA=$CONSUMER_SHA"
```

> **the two refusals this shape exists to produce**
>
> The author of a pull request cannot be its approver — `WC-3027`. And the approver must have been in `[approval]` as it stood at the **base commit**, or `WC-3025`. A GitHub review is not an approval unless the person giving it was already named.

### 10.3 · The client, in full

*$CONSUMER_LOGIN/recon-bot — mcp_client.py*

```text
#!/usr/bin/env python3
"""A real MCP client over Streamable HTTP, presenting a client certificate.

    mcp_client.py list
    mcp_client.py call get_balance '{"account":"ACC-1"}'

Why a client certificate and not a bearer token: at the gateway the caller's identity IS its
mTLS peer certificate. Envoy verifies it, puts the SPIFFE id from the URI SAN into
`x-forwarded-client-cert`, and the verifier reads it from there. A client that cannot present
one has no identity, matches no contract, and is refused — which is correct, and is why this
script exists rather than curl in the guide.

Deliberately small and dependency-free: the point is to show what any MCP client has to do to
sit behind this gateway, not to be a client library.
"""
import json
import os
import ssl
import sys
import urllib.request

URL = os.environ.get("MCP_URL", "https://localhost:10000/mcp")
CERT = os.environ.get("MCP_CLIENT_CERT", "certs/client.crt")
KEY = os.environ.get("MCP_CLIENT_KEY", "certs/client.key")
CA = os.environ.get("MCP_CA", "certs/ca.crt")

_next_id = [0]
_session = [None]

def rpc(method, params=None):
    _next_id[0] += 1
    frame = {"jsonrpc": "2.0", "id": _next_id[0], "method": method}
    if params is not None:
        frame["params"] = params

    ctx = ssl.create_default_context(cafile=CA)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)

    req = urllib.request.Request(
        URL,
        data=json.dumps(frame).encode(),
        headers={
            "content-type": "application/json",
            # Both, because a server may answer either.
            "accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    if _session[0]:
        req.add_header("mcp-session-id", _session[0])

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            sid = resp.headers.get("mcp-session-id")
            if sid:
                _session[0] = sid
            body = resp.read().decode()
    except urllib.error.HTTPError as e:
        # A refusal from the verifier arrives as HTTP 200 with a JSON-RPC error, so anything
        # here is a transport-level failure — Envoy itself, or no verifier at all.
        return {"transport_error": f"HTTP {e.code}", "body": e.read().decode()[:300]}
    except Exception as e:
        return {"transport_error": f"{type(e).__name__}: {e}"}

    if not body:
        return {"transport_error": "empty response"}
    try:
        return json.loads(body)
    except ValueError:
        return {"transport_error": "not JSON", "body": body[:300]}

def show(frame):
    if "transport_error" in frame:
        print(f"TRANSPORT  {frame['transport_error']}")
        if frame.get("body"):
            print(f"           {frame['body']}")
        return 2
    if "error" in frame:
        err = frame["error"]
        code = (err.get("data") or {}).get("code", "")
        print(f"REFUSED    {code or err.get('code')}  {err.get('message', '')}")
        return 1
    result = frame.get("result", {})
    if "tools" in result:
        print("TOOLS      " + ", ".join(sorted(t["name"] for t in result["tools"])))
    else:
        for block in result.get("content", []):
            if block.get("type") == "text":
                print(f"OK         {block['text']}")
        if result.get("isError"):
            return 1
    return 0

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    # Every MCP session opens with initialize. The verifier's pin ledger is filled by the
    # tools/list that any well-behaved client sends next, which is why `list` is the first
    # thing the guide runs.
    rpc("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ledger-cli", "version": "1"},
    })
    verb = sys.argv[1]
    if verb == "list":
        sys.exit(show(rpc("tools/list")))
    if verb == "call":
        name = sys.argv[2]
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        sys.exit(show(rpc("tools/call", {"name": name, "arguments": args})))
    sys.exit(f"unknown verb {verb!r}; use list or call")

main()
```

> **the same file serves both paths**
>
> Under Path A the agent talks stdio to a mediator and this file is a convenience for testing. Under Path B it is the real client, and its client certificate is the caller’s identity — which is why `curl` with a header cannot stand in for it.

## Contract a connection

Both merges have happened. Now they become a signed artifact — and the gated term becomes a question somebody has to answer.

## 11 · What the offer now holds

The offer was published in §09.3 and the need merged in §10.2. Both halves of the consent now exist, and neither party reviewed the other's pull request.

*what this consumer can contract · run from `~/wc/recon-bot` · local only*

```sh
cd ~/wc/recon-bot

$C need check --manifest warden/needs.toml
```

*real output*

```sh
OK       spiffe://bank.example/ns/mesh/sa/recon-bot -> spiffe://bank.example/ns/mesh/sa/payments-mcp
  cid    conn_56ba5ab4772276d5
  jti    cx_696a697669e649e3b6c70f12
  items  get_balance, list_transactions
  ttl    86400s
  offer  version 1

2 contractable · 0 awaiting the provider · 0 refused
```

> **it reports what WOULD be contracted, and mints nothing**
>
> The `cid` and `jti` are derived from the inputs, so they are the ids §12 will actually produce — and the `ttl` is what survives after the offer’s ceiling is applied. Safe to run on every pull request, which is where a manifest asking for something nobody offers is cheapest to fix.

> **transfer_funds is absent on purpose**
>
> This manifest asks only for the two pre-granted items, so nothing is awaiting. Ask for the gated one here and the whole need waits — §13.

> **why this can run from a laptop**
>
> It does not assert the consent — it reads the merge back from GitHub through the shim and checks it was approved by a declared approver who was not the author. Where the command runs makes no difference to what is verified; what matters is the state root it writes to. In production it belongs in the provider’s pipeline.

## 12 · The pre-granted path

Two items, both pre-granted. This mints.

*the consumer's half — this writes the artifact · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
cd ~/wc/recon-bot

gh auth switch --user $CONSUMER_LOGIN

$C need apply \
  --repo "$CONSUMER_REPO" --sha "$CONSUMER_SHA" \
  --mediator "$MED" \
  --policy ~/wc/connect-policy.toml \
  --shim "$WC/scripts/scm/github.sh" --shim-label github \
  --issuer-key ~/wc/issuer.priv.pem --kid issuer-1 --out ~/wc/contracts

ls ~/wc/contracts/*.jws
```

> **from inside the consumer repo, same reason as §09.3**
>
> `--manifest` defaults to `warden/needs.toml` and that path is reserved. Passing `recon-bot/warden/needs.toml` from `~/wc` is refused with `WC-8004`. The key and output paths are absolute precisely because the working directory has moved.

> **no .jws is ever committed**
>
> The artifact goes beside the enforcement point, never into a repository. The repositories carry declarations and receipts; the signed grant is a credential. Check it stayed out: `git log --all --name-only | grep -c "\.jws"` should be 0 in both.

> **idempotent, which cuts both ways**
>
> The artifact id is derived from the inputs, so re-running an unchanged build finds the contract already current and does nothing — no duplicate, and no request row. That also means **it will not retry a write that failed**. If `~/wc/contracts` did not exist the first time, the mint was still recorded in the state log and the file was never written, and re-running will not write it either.

*recover an artifact the state store has and the out directory does not · run from `~/wc` · local only*

```sh
cd ~/wc

ls -1 ~/wc/contracts/*.jws
$C contracts                        # what the state log holds

# the store keeps the authoritative copy
cp ~/wc/state/tenants/default/state/contracts/*.jws ~/wc/contracts/
ls -1 ~/wc/contracts/*.jws
```

> **the store is the source of truth, not the out directory**
>
> `--out` is a convenience copy for whatever consumes the artifact. The contract itself is recorded in the state log, which is why `connect contracts` can list one whose file you cannot find.

## 13 · The gated path

`transfer_funds` is `named_consumer`. Asking for it produces a question, not a contract.

> **at a gateway, one contract per party pair — pick your ask accordingly**
>
> The resolver finds a contract by **(caller, callee)**, and that map holds one entry per pair. A second contract between the same two parties verifies, is counted, and is then **unreachable** — the verifier warns `contract … is UNREACHABLE` at startup, and which one wins is artifact order. The inline mediator can disambiguate, because an agent may carry a `cid` in `initialize`. A gateway filter resolves before any body is read, so it never has one. **For Path B, put every tool you need in ONE need.** The two-manifest form below keeps the read-only contract working, and the gated contract it produces is dead at a gateway until you drop the other one.

### 13.1 · Ask for it, and see what that does

Two ways to ask, and they are not equivalent.

| Where you ask | Consequence |
|---|---|
| add `transfer_funds` to `warden/needs.toml` | the need is **all-or-nothing**: nothing mints, including the two pre-granted items, until the provider signs off. The designed behaviour, and it takes your working contract away while you wait |
| a second manifest at another path | the read-only contract keeps working, but the file is **not at the reserved path**, so discovery will never see it and `--allow-nonstandard-path` is required on every command that reads it |

*the second-manifest form — note the flag · run from `~/wc/recon-bot` · local only*

```sh
cd ~/wc/recon-bot

cat > warden/needs-write.toml <<EOF
asset = "$CALLER"

[approval]
approvers = ["$CONSUMER_LOGIN"]
min = 1

[[need]]
to = "$CALLEE"
tools = ["transfer_funds"]
justify = "month-end settlement posts one transfer, reviewed by treasury"
ttl = 3600
EOF

$C need check --manifest warden/needs-write.toml --allow-nonstandard-path
```

*real output*

```text
PENDING  spiffe://bank.example/ns/mesh/sa/recon-bot -> spiffe://bank.example/ns/mesh/sa/payments-mcp
  items  transfer_funds
  ttl    3600s (the guarded term's ceiling, if approved)
  next   `connect need apply` opens the request; the provider's registered owner approves it

0 contractable · 1 awaiting the provider · 0 refused
connect: WC-3024 callee's registered owner did not approve: 1 need(s) are offered to you but need the provider's own sign-off; run `connect need apply` to open the request
```

> **without the flag this refuses at startup, not at policy**
>
> A manifest anywhere but `warden/needs.toml` is refused with `WC-8004` and a long message about discovery under-reporting — because a declaration a sweep cannot find means the estate's inventory is wrong by exactly this repository. The flag says you meant it.

> **and note the exit code**
>
> `need check` exits non-zero with `WC-3024` for a gated need. That is a build-failing result on purpose: in a pipeline it stops, and the message names the command that opens the request.

### 13.2 · Commit it, and have the consumer's approver merge it

Same shape as §10.2, and for the same reason: the consumer's half of this consent is a reviewed merge in the consumer's own repository. Without it there is no `$WRITE_SHA` for §13.3 to read back, and nothing to verify.

*author · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/recon-bot

gh auth switch --user $AUTHOR_LOGIN

git fetch origin &&
git switch -C declare-write origin/main &&
git add warden/needs-write.toml &&
git commit -m "declare a need for transfer_funds, behind the provider's gate" &&
git push -u origin declare-write &&
gh pr create --fill
```

> **the untracked file survives the branch switch**
>
> `needs-write.toml` was written in §13.1 and is not committed yet. `git switch -C … origin/main` carries untracked files across, so the file is still there to `git add`.

*approver — the account in [approval], and not the author · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
cd ~/wc/recon-bot

gh auth switch --user $CONSUMER_LOGIN

export PR=$(gh pr list --head declare-write --state open --json number -q ".[0].number")
gh pr review "$PR" --approve && gh pr merge "$PR" --merge

export WRITE_SHA=$(gh pr list --head declare-write --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "WRITE_SHA=$WRITE_SHA"
```

> **this merge is the CONSUMER's consent, not the provider's**
>
> It says the consumer’s owner agrees to ask. The provider’s per-consumer sign-off is a separate act, in §13.3 — which is the whole point of a `named_consumer` term. Two merges got you the pre-granted contract; this gated one needs a merge *and* an approval.

### 13.3 · The provider answers it

The gated item becomes a request the callee’s **registered owner** decides. Write access to the repository is not consent from a service you do not own.

*after merging the second manifest, apply it — this creates the request · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
cd ~/wc/recon-bot

$C need apply --manifest warden/needs-write.toml --allow-nonstandard-path \
  --repo "$CONSUMER_REPO" --sha "$WRITE_SHA" --mediator "$MED" \
  --policy ~/wc/connect-policy.toml \
  --shim "$WC/scripts/scm/github.sh" --shim-label github \
  --issuer-key ~/wc/issuer.priv.pem --kid issuer-1 --out ~/wc/contracts

$C requests
```

*the provider's owner approves it · run from `~/wc` · as $PROVIDER_LOGIN*

```sh
cd ~/wc

gh auth switch --user $PROVIDER_LOGIN

$C approve <req-id> --by human:$PROVIDER_LOGIN \
  --approvers ~/wc/approvers.toml \
  --approver-key ~/wc/approver.priv.pem \
  --issuer-key ~/wc/issuer.priv.pem --kid issuer-1 --out ~/wc/contracts

ls ~/wc/contracts/*.jws
```

> **two artifacts now, not one**
>
> The pre-granted contract from §12 and this gated one are separate: separate `cid`, separate `jti`, separate lifetimes. The enforcement point loads both, and `transfer_funds` stops being refused by the surface ceiling.

> **the approver must be the callee's REGISTERED owner**
>
> Write access to the provider’s repository is not consent from a service you do not own. `human:$PROVIDER_LOGIN` is who §06.3 registered as `--owner`, and that is the only account this approval accepts.

> **all-or-nothing, deliberately**
>
> If one manifest mixes pre-granted and gated items, **nothing** mints until the gate is answered. A partial mint would hand the consumer a narrower contract than they asked for and let their first build quietly succeed without the tool — which is the failure mode this codebase keeps finding. Two manifests is how you get the read-only contract now and the write later.

> **skip this section on a first run**
>
> Everything from §14 onward works with the §12 contract alone, and `transfer_funds` staying uncontracted is what makes §17.1’s refusal worth watching. Come back here when you want to see the gate.

## Enforce — pick one

The same contract, consumed at one of two places. Path A is beside the agent and works with any id shape; Path B is in the network path and needs spiffe://.

## 14 · Path A — the stdio mediator

A binary the MCP client spawns. Identity comes from the command line, so the enforcement point sits with whoever runs the agent.

> **the one section not walked end to end**
>
> Every other section on this page has been executed by a reader against live GitHub and a real Envoy. This one has not — its commands come from the mediator’s own test suite and drills, which do pass, but nobody has followed *these words in this order* on a clean machine. Expect the class of defect the other twelve were: a path assumed, a step out of order, a file never created. If you take this path, read §18 first.

*what it checks · run from `~/wc` · local only*

```sh
cd ~/wc

$WC/target/release/connect-mediate --help | head -30
```

| At connect | At each call |
|---|---|
| 14 gates: signature, alg, expiry, audience, revocation, both peer identities, the pin, posture, zone pair, token binding, issuer, schema, size | `tools/list` filtered to the contracted items |

*in the path, against the real server · run from `~/wc`*

```sh
cd ~/wc

python3 payments-mcp/ledger_server.py 8931 &

# ONE --contract per artifact here too: the mediator drops the extras from a glob, silently.
ARGS=(); for f in ~/wc/contracts/*.jws; do ARGS+=(--contract "$f"); done

printf '%s\n%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | $WC/target/release/connect-mediate \
     --upstream-url http://127.0.0.1:8931/mcp \
     --mediator-id "$MED" --issuer-id "$ISS" \
     --caller "$CALLER" --callee "$CALLEE" \
     --issuer-pub issuer.pub.pem --kid issuer-1 \
     "${ARGS[@]}"
```

> **the catalogue filter is the point**
>
> The model never sees the tool it is not contracted for, so it cannot be talked into attempting it. That is a stronger control than refusing the call, and it is the same code on both paths.

> **what Path A cannot be**
>
> Peer identity here is `--caller` and `--callee` on a command line. The code records that as `verified: false` — "configured by the operator; not authenticated". It is correct for a sidecar owning one agent, and it means the enforcement point is inside the trust domain of the person being governed. A developer can edit their own client config. Path B is where that stops being true.

## 15 · Path B — the Envoy gateway

A sidecar beside the proxy, run by the platform team — neither the calling team nor the called one. Requires `spiffe://` ids.

### 15.1 · Install Envoy

*run from `anywhere`*

```sh
docker pull envoyproxy/envoy:v1.31-latest
docker run --rm envoyproxy/envoy:v1.31-latest --version
```

> **any 1.29+ has what this needs**
>
> `allow_mode_override` and `request_attributes`, both checked against 1.31.10. §15.3 validates the config against whichever version you pulled, which is the check that matters.

### 15.2 · Mesh identity

In a real mesh SPIRE issues these. Here a local CA stands in and the shape is identical: the client certificate’s URI SAN **is** the caller.

*the SAN must be exactly $CALLER · run from `~/wc/e2e/certs` · local only*

```sh
cd ~/wc/e2e/certs

mkdir -p ~/wc/e2e/certs && cd ~/wc/e2e/certs

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 \
  -subj "/CN=bank-mesh-ca"

printf '[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > srv.cnf
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt \
  -days 2 -extfile srv.cnf -extensions ext

printf '[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=URI:%s\n' "$CALLER" > cli.cnf
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=recon-bot"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt \
  -days 2 -extfile cli.cnf -extensions ext

openssl x509 -in client.crt -noout -text | grep -A1 "Subject Alternative Name"
```

*expected*

```sh
            X509v3 Subject Alternative Name: 
                URI:spiffe://bank.example/ns/mesh/sa/recon-bot
```

> **why the client cannot just send the header**
>
> Envoy throws it away. `forward_client_cert_details: SANITIZE_SET` drops any inbound `x-forwarded-client-cert` and re-sets it from the verified peer certificate — which is the whole reason the header can be believed. A walkthrough where the client sent its own would test nothing: the verifier would see no identity, refuse everything, and every refusal step would pass for the wrong reason.

### 15.3 · The Envoy configuration

Copy `scripts/envoy/gateway-e2e.yaml` from the checkout. Five settings are load-bearing.

| Setting | If it is wrong |
|---|---|
| `failure_mode_allow: false` | the verifier being unreachable **allows** traffic. The single most important line |
| `allow_mode_override: true` | the catalogue is never buffered, so `tools/list` is never filtered and the model sees every tool. The failure that looks like everything working |
| `request_body_mode: BUFFERED` | the tool name is in the body; without it every call looks the same |
| `request_attributes: [xds.cluster_name, xds.route_name]` | no route matches, so every request is refused |
| `forward_client_cert_details: SANITIZE_SET` | no identity reaches the verifier — also every request refused |

*validate against YOUR Envoy · run from `~/wc/warden-connect`*

```sh
cd ~/wc/warden-connect

cd "$WC"
docker run --rm \
  -v "$PWD/scripts/envoy/gateway-e2e.yaml:/e.yaml" \
  -v "$HOME/wc/e2e/certs:/certs:ro" \
  envoyproxy/envoy:v1.31-latest --mode validate -c /e.yaml
```

*expected*

```sh
configuration '/e.yaml' OK
```

### 15.4 · The route table

*which registered party each Envoy cluster fronts · run from `~/wc/e2e` · local only*

```sh
cd ~/wc/e2e

mkdir -p ~/wc/e2e && cd ~/wc/e2e

cat > routes.toml <<EOF
[[route]]
cluster = "payments-mcp"
callee = "$CALLEE"
EOF

cat routes.toml
```

The callee comes from the route **Envoy chose**, reported in `xds.cluster_name` after routing — never from the request. Keying on the `:authority` header would be caller-controlled: a caller could send an authority mapping to one callee while the route table sends the request to another, and the verifier would check the wrong service’s contract while appearing to work.

> **the cluster name must match the Envoy config exactly**
>
> This is the mistake that was made **three times** while writing this page. The symptom is every request refusing `WC-4001 no contract for this caller and callee`, which points at the contract and not at the route. If you see that, compare `cluster` here against `route: { cluster: … }` in the Envoy config before you look anywhere else.

### 15.5 · Start the server, the verifier and Envoy

#### first, stop anything from a previous run

This section binds four ports. A verifier left over from an earlier attempt starts, prints every line of its configuration as though all is well, and then dies on the last one — so the useful error is the **last** line, not the first.

*free the ports before you bind them · run from `anywhere` · local only*

```sh
docker rm -f wc-gateway-e2e 2>/dev/null
pkill -f wc-extproc 2>/dev/null
pkill -f ledger_server 2>/dev/null
pkill -f "connect serve" 2>/dev/null

for p in 8841 8931 9002 10000; do
  printf '%-6s ' "$p"
  lsof -iTCP:$p -sTCP:LISTEN -P >/dev/null 2>&1 && echo "STILL IN USE" || echo "free"
done
```

*expected*

```sh
8841   free
8931   free
9002   free
10000  free
```

> **what a bound port looks like**
>
> The verifier logs its whole configuration before it binds, so a failure here reads like a success followed by an unrelated error: `wc-extproc: serving ext_proc on 0.0.0.0:9002` `Error: tonic::transport::Error(Transport, Os { code: 48, kind: AddrInUse, message: "Address already in use" })` Every line above it is correct and irrelevant. Read the bottom of `verify.log` first.

*the server, and the log §17 depends on · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

export LEDGER_LOG=~/wc/e2e/ledger.log && : > "$LEDGER_LOG"
python3 ~/wc/payments-mcp/ledger_server.py 8931 &

curl -s -X POST http://127.0.0.1:8931/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | python3 -c 'import json,sys; print([t["name"] for t in json.load(sys.stdin)["result"]["tools"]])'
```

*expected — all three, because the server knows nothing about contracts*

```sh
['get_balance', 'list_transactions', 'transfer_funds']
```

*the issuer key as a published set, then the verifier · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

$C keys add --kid issuer-1 --public ~/wc/issuer.pub.pem --keyring ring.toml
$C keys jwks --keyring ring.toml --out jwks.json

# ONE --contract per artifact. `--contract *.jws` silently loads only the FIRST.
ARGS=(); for f in ~/wc/contracts/*.jws; do ARGS+=(--contract "$f"); done
echo "loading ${#ARGS[@]} / 2 flags"

"$WC/daemon/wc-extproc/target/release/wc-extproc" \
  --listen 0.0.0.0:9002 \
  --routes routes.toml \
  --mediator-id "$MED" --issuer-id "$ISS" \
  --jwks-file jwks.json "${ARGS[@]}" \
  --mesh-origin 127.0.0.1 > verify.log 2>&1 &

sleep 1 && cat verify.log
```

*what it prints, and what each line is telling you*

```text
wc-extproc: 2 contract(s) verified, 2 read
wc-extproc: mediator warden:mediator:gateway-1, issuer https://connect.internal (Enforce)
wc-extproc: route table routes.toml (1 key(s))
wc-extproc: XFCC believed only from 127.0.0.1
wc-extproc: pin required before any tools/call; verification does not expire
wc-extproc: Envoy must set failure_mode_allow=false and allow_mode_override=true; without the second, catalogues are never filtered
wc-extproc: serving ext_proc on 0.0.0.0:9002
```

> **read any UNREACHABLE warning before anything else**
>
> If two artifacts cover the same (caller, callee) pair, one can never be resolved here and the verifier says so at startup: `WARNING contract … is UNREACHABLE — … covers the same pair … Put the tools you need in ONE contract`. Without that line the symptom is the tool list of the *wrong* contract, with every other diagnostic saying the configuration is correct — because it is.

> **count the contracts in that first line**
>
> `--contract` takes **one artifact per occurrence**. `--contract ~/wc/contracts/*.jws` expands to several paths, the flag consumes the first and the rest are ignored — **silently**. With two contracts that reads `1 contract(s) verified, 1 read` and everything the missing one covers is refused `WC-4001`, which points at the contract and not at the flag. Checked: the glob form loaded 1 of 2, the loop loaded 2 of 2. If you skipped §13 you will have one contract and should see 1.

> **`--mesh-origin` is required and is not decoration**
>
> It names the origin an XFCC header may be believed from. An unset mesh trust believes **nothing**, so a verifier started without it would refuse every request — which is why the flag refuses to be omitted rather than defaulting to something permissive.

*Envoy · run from `anywhere`*

```sh
docker run -d --name wc-gateway-e2e -p 10000:10000 \
  -v "$WC/scripts/envoy/gateway-e2e.yaml:/etc/envoy/envoy.yaml:ro" \
  -v "$HOME/wc/e2e/certs:/certs:ro" \
  envoyproxy/envoy:v1.31-latest -c /etc/envoy/envoy.yaml --log-level warning

docker logs wc-gateway-e2e 2>&1 | tail -3
```

## Test success and failure

Every output below is the real text from a real run against this exact stack. The refusals are the point — an enforcement layer nobody has watched refuse is a logging layer.

## 15b · Path C — the Kong gateway

The same decision, inside Kong’s own worker. No extra process and no extra hop: Kong already embeds LuaJIT, so a thin Lua plugin drives a Rust library over FFI. Requires `spiffe://` ids.

> **pick this over Path B when Kong is already your gateway**
>
> Nothing here is better than Path B on the merits — it is the same `wc-gateway` deciding. What differs is what you already run. If Envoy or a mesh is in the path, use §15. If Kong is, use this and add no processes. Kong is also the **better shape** in one respect: it decides response buffering before it proxies, so the catalogue filter needs none of the `mode_override` care §15.4 spends on it.

|  | Path B · Envoy | Path C · Kong |
|---|---|---|
| What runs | a separate `wc-extproc` process | a `.so` in the nginx worker |
| Hops added | one, loopback gRPC | **none** |
| Caller identity | `x-forwarded-client-cert`, origin-checked | the peer certificate’s URI SAN |
| Route key | `xds.cluster_name` | `kong.router.get_service().name` |
| Ceilings scope | per verifier process | per nginx **worker** — §15b.5 |

### 15b.1 · Certificates

Identical to §15.2 — a local CA standing in for SPIRE, and a client certificate whose URI SAN **is** the caller. **If you already ran §15.2, skip this** and reuse `~/wc/e2e/certs`.

> **Kong verifies the chain; the plugin only reads it**
>
> The plugin refuses unless nginx reports `ssl_client_verify = SUCCESS`. That ordering is the safety argument: a mis-parsed certificate yields a *wrong* identity, which resolves to no contract, and cannot yield a forged one — because an attacker cannot get an arbitrary certificate past the CA first.

### 15b.2 · Build the library for Kong’s container

> **update your checkout first — this crate is newer than your estate**
>
> `crates/wc-kong` did not exist when §05 cloned the repository. If you set up before it landed, the build below fails with `package ID specification `warden-connect-kong` did not match any packages` and helpfully suggests `warden-connect-core`, which is not the problem. Pull first: `cd "$WC" && git fetch origin && git merge --ff-only origin/main && ls crates/wc-kong`

Kong runs Linux. If you are on macOS, a library built on your host will not load — so it is built *in* a container, for the container. The first run downloads a toolchain and a crate index; later ones are seconds.

*run from `$WC` · local only*

```sh
cd "$WC"
git fetch origin && git merge --ff-only origin/main
ls crates/wc-kong    # must exist before the build below

docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD:/src" -w /src -e CARGO_HOME=/src/target/docker-cargo \
  rust:1.89-bookworm \
  cargo build --release -p warden-connect-kong --target-dir /src/target/docker

file target/docker/release/libwc_kong.so
```

*what you want to see*

```sh
target/docker/release/libwc_kong.so: ELF 64-bit LSB shared object, ARM aarch64 ...
```

> **already on Linux?**
>
> Then `cargo build --release -p warden-connect-kong` is enough and the `.so` is under `target/release/`. Use that path below.

### 15b.3 · Lay out what Kong will mount

One directory holds everything Kong reads. The library is **copied in**, not bind-mounted separately — a second mount cannot create its own mountpoint inside a read-only one.

*run from `~/wc/kong` · local only*

```sh
cd ~/wc/kong

mkdir -p ~/wc/kong && cd ~/wc/kong

cp "$WC/target/docker/release/libwc_kong.so" .
cp ~/wc/issuer.pub.pem issuer_pub.pem
cp ~/wc/e2e/routes.toml .
mkdir -p contracts && cp ~/wc/contracts/*.jws contracts/
cp ~/wc/e2e/certs/ca.crt ~/wc/e2e/certs/server.crt ~/wc/e2e/certs/server.key .
chmod 644 ./*.crt ./*.key

ls
```

> **one contract per file, and Kong needs each one named**
>
> The plugin takes an array of paths, so a glob is fine here — unlike `--contract` on the command line, which §15.5 has to expand by hand. List every file: a contract you leave out is a caller who gets `WC-4001`.

### 15b.4 · Kong’s declarative config

DB-less. One service, one route, and the plugin. The service name is what `routes.toml`’s `cluster` column has to match — it is the same slot Envoy calls a cluster, so one table serves both paths.

*run from `~/wc/kong` · local only*

```sh
cd ~/wc/kong

# UNQUOTED heredoc, so $MED and $ISS expand as it is written. Nothing else in this
# YAML holds a dollar sign, which is what makes that safe here.
cat > kong.yml <<YAML
_format_version: "3.0"
services:
  - name: payments-mcp          # MUST equal the cluster column of routes.toml
    url: http://host.docker.internal:8931
    routes:
      - name: mcp
        paths: ["/mcp"]
        strip_path: true
plugins:
  - name: warden-connect
    config:
      library_path: /wc/libwc_kong.so
      contracts: ["/wc/contracts/CHANGE_ME.jws"]
      routes: /wc/routes.toml
      identity: tls
      issuer_pub: /wc/issuer_pub.pem
      kid: issuer-1
      mediator_id: "$MED"
      issuer_id: "$ISS"
      mode: enforce
YAML

ls contracts/
grep -nE 'mediator_id|issuer_id|contracts:' kong.yml
```

> **three values here are yours, not mine**
>
> This block was run against a real §15 estate and four things in it had to change from what a fresh checkout would suggest. Check all of them before you start Kong: **1 · the service name.** Kong’s service name is what the plugin matches against the `cluster` column of `routes.toml`. §15 wrote `cluster = "payments-mcp"`, so the service must be `payments-mcp`. Name it anything else and every call is `WC-4001` with nothing wrong anywhere else. **2 · the kid.** `issuer-1` is what §12 generated. Read yours from the artifact: `cut -d. -f1 ~/wc/contracts/*.jws | head -1 | base64 -d`. **3 · the issuer key.** §12 put it at `~/wc/issuer.pub.pem`. **4 · the contract filename** — below.

> **you probably have more than one artifact, and you want ONE of them**
>
> `ls ~/wc/contracts/` shows the pre-granted contract from §12. `~/wc/contracts/gated/` holds the one §13 minted after the owner approved. **Both are for the same party pair** — `recon-bot` to `payments-mcp` — and this filter resolves by pair, never by `cid`. Load both and one is verified, counted and *unreachable*; which one wins is the order you listed them in. List the §12 artifact only. If you want `transfer_funds` contracted as well, that is one contract covering three tools, not two contracts — §19. The plugin now says so at startup either way. Two artifacts where one fails to verify prints `N of M artifact(s) verified` and the code for each rejection, because "1 contract(s) verified" from two files told you nothing about which one.

> **the contracts list must name your actual files**
>
> The block above assumes one artifact called `conn.jws`. Fix the `contracts:` line to list what `ls contracts/` actually printed, each as `/wc/contracts/<name>`. Starting with a file that is not there is a startup error that names the path, which is the easy case; starting *without* a contract you meant to include is a `WC-4001` later, which is not.

> **why identity is not optional**
>
> `identity` has no default. Both `tls` and `xfcc` are legitimate and they have different threat models, so the plugin refuses to start rather than pick. Setting **both** — `identity: tls` with a `mesh_origin` — is also a startup error: a PEP that tried one and fell back to the other would let whoever can suppress one source select the other.

### 15b.5 · Start Kong

*run from `~/wc/kong` · local only*

```sh
cd ~/wc/kong

# A port preflight, because the failure otherwise reads as "Kong did not start".
for p in 8443; do
  lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1 \
    && echo "PORT $p IS BUSY — stop whatever holds it first" || echo "port $p free"
done

docker rm -f wc-kong >/dev/null 2>&1
docker run -d --name wc-kong \
  -v ~/wc/kong:/wc:ro \
  -v "$WC/crates/wc-kong/lua:/wc-lua:ro" \
  -e KONG_DATABASE=off \
  -e KONG_DECLARATIVE_CONFIG=/wc/kong.yml \
  -e "KONG_PLUGINS=bundled,warden-connect" \
  -e "KONG_LUA_PACKAGE_PATH=/wc-lua/?.lua;;" \
  -e "KONG_PROXY_LISTEN=0.0.0.0:8000, 0.0.0.0:8443 ssl" \
  -e KONG_NGINX_PROXY_SSL_CLIENT_CERTIFICATE=/wc/ca.crt \
  -e KONG_NGINX_PROXY_SSL_VERIFY_CLIENT=optional \
  -e KONG_SSL_CERT=/wc/server.crt \
  -e KONG_SSL_CERT_KEY=/wc/server.key \
  -e KONG_NGINX_WORKER_PROCESSES=2 \
  -e KONG_LOG_LEVEL=notice \
  -p 8443:8443 \
  kong:3.9

sleep 7
docker ps --filter name=wc-kong --format 'status: {{.Status}}'

# The plugin builds its handle on the FIRST REQUEST, so warm it up before reading the log —
# grep straight after `docker run` finds nothing and looks like a failure.
curl -sk --cert ~/wc/e2e/certs/client.crt --key ~/wc/e2e/certs/client.key \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://127.0.0.1:8443/mcp > /dev/null

docker logs wc-kong 2>&1 | grep -E 'contract\(s\) verified|in force'
```

*real output — yours will name your own contract file*

```sh
conn_6afbd4b5126d1774.warden_mediator_gateway-1.jws
3:  - name: payments-mcp          # MUST equal the cluster column of routes.toml
13:      contracts: ["/wc/contracts/CHANGE_ME.jws"]
17:      kid: issuer-1
18:      mediator_id: "warden:mediator:gateway-1"
19:      issuer_id: "https://connect.internal"
```

*real output*

```text
wc-kong: contract conn_7f3a91c4 (cx_84be0011) across 2 instance(s): 10/hour configured -> up to 20/hour in force, 3 concurrent configured -> up to 6 in force
[warden-connect] warden-connect 0.1.1: 1 contract(s) verified
```

> **exited, not running? read the YAML error**
>
> A declarative-config mistake makes Kong exit rather than start degraded, which is the right behaviour and an easy one to miss — `docker run -d` prints a container id either way. Check with `docker ps -a --filter name=wc-kong`; if it says `Exited`, `docker logs wc-kong` names the line and column: `failed parsing declarative configuration: 13:19: did not find expected ',' or ']'` Line 13 is the `contracts:` array. An editor that put a stray `wq` inside the brackets produces exactly this.

> **read the second line before the first**
>
> There is no `ceiling_scope` key any more. Rate, concurrency and spend were removed as a capability on 2026-08-29, because a counter that lives in one nginx worker multiplies by `worker_processes` and the number an owner signed was never the number in force. Set volume limits on the proxy instead.

### 15b.6 · Point the tests at Kong

§16 and §17 both apply unchanged except for the URL. Kong is on `8443` and the path is `/mcp`.

*the one substitution · run from `~/wc/kong` · local only*

```sh
cd ~/wc/kong

export PROXY="https://127.0.0.1:8443/mcp"

names() { python3 -c 'import json,sys; print([t["name"] for t in json.load(sys.stdin)["result"]["tools"]])'; }

# What the callee actually serves, straight from it — no enforcement in the way.
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:8931/ | names

# What Kong lets through. Run tools/list FIRST — the pin gate refuses a tools/call until
# a catalogue has passed (WC-1002), which is correct and catches everyone once.
curl -sk --cert ~/wc/e2e/certs/client.crt --key ~/wc/e2e/certs/client.key \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$PROXY" | names
```

*real output*

```sh
['get_balance', 'list_transactions', 'transfer_funds']
['get_balance', 'list_transactions']
```

> **that difference is the whole product**
>
> Three tools exist on the callee. Two are contracted. The third is not hidden by the server, not omitted by the client, and not blocked by a firewall — it is removed from the catalogue in the path, by a filter reading an artifact two owners approved in a pull request. Dump the body without `names` and you can confirm `transfer_funds` is simply absent.

> **why tools/list first, every time**
>
> Gate 8 compares the surface the callee presents against the digest in the contract, and a filter cannot fetch a catalogue itself. Until one passes through, nothing has checked the surface — so a `tools/call` on a fresh contract is refused `WC-1002`. That is the correct answer, not a bug, and it is the same on Path B.

### 15b.7 · A refusal Kong takes before the plugin sees it

§17.4 refuses an unmapped route with `WC-4001`. On Kong a request to a path with **no route at all** never reaches the plugin — Kong answers first.

*real output*

```sh
{"message":"no Route matched with those values", ...}
```

> **not a warden refusal, and it should not look like one**
>
> That is Kong’s own 404 and it is correct: there is nothing to enforce a contract on. The warden `WC-4001` for an unmapped callee is the different case — a route that *does* match, whose service name is absent from `routes.toml`. To see it, add a second service to `kong.yml` named something the route table does not know, give it its own path, and call that.

### 15b.8 · Stop it

*run from `anywhere` · local only*

```sh
docker rm -f wc-kong
```

## 16 · Success

### 16.1 · The catalogue the agent is allowed to see

*the client presents its certificate and sends no identity header · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

export MCP_URL=https://localhost:10000/mcp
export MCP_CLIENT_CERT=certs/client.crt MCP_CLIENT_KEY=certs/client.key MCP_CA=certs/ca.crt

python3 ~/wc/recon-bot/mcp_client.py list
```

*real output*

```sh
TOOLS      get_balance, list_transactions
```

> **compare with §15.5**
>
> The same server answered both. Curl saw three tools; the client behind the gateway sees two. Nothing changed on the server — `transfer_funds` is simply not in this contract, so the model is never shown it.

### 16.2 · Both contracted calls

*run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

python3 ~/wc/recon-bot/mcp_client.py call get_balance '{"account":"ACC-1"}'
python3 ~/wc/recon-bot/mcp_client.py call list_transactions '{"account":"ACC-1"}'
```

*real output*

```sh
OK         ACC-1 balance 1240.50
OK         ACC-1: 3 transactions in the last 7 days
```

> **what just happened**
>
> Envoy verified a certificate, wrote a SPIFFE id into a header the caller cannot set, and asked a sidecar. The sidecar checked a signed contract and a pinned surface digest — and only then did the request reach a server that has never heard of any of it.

## 17 · Failure

Eight refusals. Run them in order — two depend on the state the one before leaves.

### 17.1 · A tool that exists but is not in this contract

*transfer_funds is real, and moves money · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

python3 ~/wc/recon-bot/mcp_client.py \
  call transfer_funds '{"from_account":"ACC-1","to_account":"ACC-2","amount":9999}'
```

*real output*

```sh
REFUSED    WC-4002  BLOCKED by warden-connect: WC-4002 transfer_funds is not in the contracted surface
```

> **this is the gated term, seen from the other side**
>
> The provider offered it — behind `named_consumer`. Until §13 is answered it is not in any contract, so the surface ceiling refuses it. Offered and contracted are different things.

### 17.2 · And prove it never reached the server

The assertion that matters, and the one people skip. A refusal that forwarded anyway looks identical from the client’s side.

*run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

cat ~/wc/e2e/ledger.log
```

*real output — only the allowed calls are there*

```sh
EXECUTED get_balance {"account": "ACC-1"}
EXECUTED list_transactions {"account": "ACC-1"}
```

### 17.3 · A caller with no certificate

*curl, with the CA but no client certificate · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

curl -s --cacert certs/ca.crt -X POST "$MCP_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

*real output — nothing, because the handshake never completed*

```sh

```

> **refused below warden-connect, which is the right layer**
>
> Envoy’s `require_client_certificate: true` ends it at the TLS handshake, so there is no HTTP response and nothing reaches the verifier. The verifier’s own no-identity refusal (`WC-4001`) is what you get when a certificate IS presented but XFCC arrives from an origin `--mesh-origin` does not name.

### 17.4 · A route the table does not map

*the Envoy config carries a second route to an unmapped cluster · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

MCP_URL=https://localhost:10000/other \
  python3 ~/wc/recon-bot/mcp_client.py call get_balance '{"account":"ACC-1"}'
```

*real output*

```sh
REFUSED    WC-4001  BLOCKED by warden-connect: WC-4001 no contract for this caller and callee
```

> **the same message you get from a cluster-name typo**
>
> `WC-4001` means no contract matched (caller, callee). At the gateway the most common cause is not a missing contract but an unmapped or misnamed **route** — see §15.4. Check the route before you check the contract.

### 17.5 · The rate ceiling — removed, and why it is worth reading

This step used to run 25 calls against a 20-per-hour contract and watch the
twenty-first refuse with `WC-4003`. It no longer refuses, because rate,
concurrency and spend were removed as a capability on 2026-08-29.

The reason is worth more than the step was. Counters live in one process. A
contract saying `max_calls_per_hour = 20` admitted twenty **per nginx worker per
node**, so the number an owner signed was never the number in force — measured
at three per process and nine across three, in the same hour. Dividing the
budget across workers turns 3 across 4 into 0 or 1; a shared counter on the hot
path is a network call, which the design forbids outright.

So warden-connect claims one axis and enforces it exactly: **which capabilities
a caller may reach on a callee**. Volume belongs to the proxy, and Envoy and Kong
both rate-limit properly. `WC-4003`, `WC-4004` and `WC-4005` stay in the taxonomy
so old evidence still reads, and nothing emits them.

### 17.6 · The callee changes its surface

Gate 8. Restart the server with one changed description — that alone moves the digest, which is the intended sensitivity.

*run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

pkill -f ledger_server.py
LEDGER_DRIFT=1 LEDGER_LOG=~/wc/e2e/ledger.log \
  python3 ~/wc/payments-mcp/ledger_server.py 8931 &
sleep 1

python3 ~/wc/recon-bot/mcp_client.py list
```

> **by pattern, never by job number**
>
> An earlier version of this said `kill %1`. Job numbers depend on what YOUR shell started and in what order — if you launched the verifier after the ledger server, `%1` is the verifier, and you kill the enforcement point instead of the thing you meant to restart. The symptoms are `Address already in use` from the server that never stopped, and `TRANSPORT HTTP 500` from the verifier that did. A process started in another terminal is not a job in this one at all.

*real output*

```sh
REFUSED    WC-3108  BLOCKED by warden-connect: WC-3108 presented surface digest sha256:1ab91c81… != contracted sha256:1e6c436c…
```

### 17.7 · And the drift revokes what was already verified

Detecting drift and then continuing to allow tool calls would be worse than not looking. A detected mismatch drops the recorded verification.

*immediately after the mismatch above · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

python3 ~/wc/recon-bot/mcp_client.py call get_balance '{"account":"ACC-1"}'
```

*real output*

```sh
REFUSED    WC-1002  BLOCKED by warden-connect: WC-1002 this contract's pin has not been verified: no tools/list has passed through, so the callee's surface is unchecked
```

*restore the server; one list re-pins it · run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

pkill -f ledger_server.py
LEDGER_LOG=~/wc/e2e/ledger.log python3 ~/wc/payments-mcp/ledger_server.py 8931 &
sleep 1 && python3 ~/wc/recon-bot/mcp_client.py list
```

### 17.8 · The verifier goes down

The most important refusal in the guide.

*run from `~/wc/e2e`*

```sh
cd ~/wc/e2e

pkill -f wc-extproc
python3 ~/wc/recon-bot/mcp_client.py call get_balance '{"account":"ACC-1"}'
```

*real output*

```sh
TRANSPORT  HTTP 500
```

> **denied, not allowed**
>
> That 500 is `failure_mode_allow: false` doing its job. Check `ledger.log`: no new line. If the call **succeeds** instead, that setting is wrong and the gateway is decorative — go back to §15.3.

## 18 · Refusals, and where each comes from

Every message here was produced by running it.

#### the contract flow

| What you see | What happened | Fix |
|---|---|---|
| `WC-1001` `… is not a guarded ref` | the branch has no protection, so a merge proves nothing | §07 |
| `WC-3025` | the approver was not in `[approval]` at the BASE commit | §09.1 — and remember it is read at the base, not the head |
| `WC-3027` | the author approved their own pull request | §02: author ≠ approver, per repository |
| `need apply` mints nothing, no error | every item is behind `named_consumer` | §13 — a gated need is a question, not a contract. Both values lint clean, so lint will not tell you |
| a party is stuck `Unattested` | stage 1 cannot pass for a `urn:` id | §04 — re-register under a `spiffe://` id |
| `WC-8004` `an offer must live at `warden/offer.toml` (or the same for `needs.toml`) | the path was given as `<repo>/warden/…` from a parent directory. It is checked AS GIVEN, not resolved — so it is refused even though it points at the right file | run the command from inside that repository and omit the path flag; it defaults to the reserved path. `WARDEN_CONNECT_ROOT` is exported, so the state root does not move with you |
| `WC-8004` `cannot read the issuer key …` | the keypair was never generated, or is somewhere else | §05.1. The paths in §12 and §13 are absolute because those commands run from inside a repository |
| `WC-3102` `issuer key is not an EC PKCS#8 PEM` | the key is SEC1 — `openssl ecparam -genkey` straight to a file | the `pkcs8 -topk8` step in §05.1. `head -1` must say `BEGIN PRIVATE KEY` |
| `WC-8004` `cannot read approvers.toml` | `connect approve` needs the approver registry: who may sign, and with which key | §05.1. Pass `--approvers ~/wc/approvers.toml`; the default is the current directory |
| `WC-8004` `cannot read approver key …` | the `key` inside `approvers.toml` is relative and you are not in the directory it is relative to | make it absolute — §05.1 writes it with `$HOME` expanded |
| `WC-8004` `the approver key … and the issuer key … are the same key material` | one keypair used for both. If the control plane can sign its own approvals, dual control is theatre | generate two, as §05.1 does |
| `WC-8001` `cannot read connect-policy.toml` | every mint routes through policy evaluation, and the file is read RELATIVE to the working directory | §05.1 creates it; §12 and §13 pass `--policy ~/wc/connect-policy.toml` because they run from inside a repository |
| `no matches found: …/contracts/*.jws` | nothing was minted, so the glob matched nothing. The real error is the line above it | read the line above. `--out` does not create its directory either — `mkdir -p` first |
| `WC-3011` `no offer is held for …` | the provider has not published, or published from the wrong directory so it silently never landed | §09.3, then `connect offer status --asset "$CALLEE"` to confirm it is actually held |

#### the enforcement point refused

| What you see | What happened | Fix |
|---|---|---|
| `WC-4002` `… is not in the contracted surface` | the tool is real and not in this contract. Working as designed | if it should be allowed: move it to a pre-granted term, or answer the gate in §13 |
| `WC-4001` `no contract for this caller and callee` | no contract matched. At the gateway, most often an unmapped or misnamed ROUTE | check `routes.toml` against the Envoy cluster name FIRST; then the certificate SAN against the contract’s caller |
| `WC-1002` `this contract’s pin has not been verified` | a `tools/call` on a contract no catalogue has passed for | run `list` once. Expected after a verifier restart — the ledger is in memory |
| `WC-3108` | the callee serves a different surface than the contract pinned | regenerate `warden/surface.json` from the server and re-mint. If you hand-wrote it, this is why |
| `WC-4003` / `WC-4005` | retired. Ceilings were removed on 2026-08-29; these codes stay in the taxonomy so old evidence still reads, but nothing emits them | set volume limits on the proxy |
| `WC-3109` | the callee is not `Attested` | §06.3; or run `--observe` and accept softened posture |

#### below warden-connect

| What you see | What happened |
|---|---|
| `TRANSPORT HTTP 500` | Envoy could not reach the verifier and `failure_mode_allow: false` denied. Working as designed |
| `TRANSPORT`, empty, no response | the mTLS handshake failed — certificate missing, expired, or not signed by the CA in the Envoy config |
| the catalogue arrives UNFILTERED | `allow_mode_override: true` is missing, so Envoy never buffered the response body |
| `manifest path … does not exist` | you are not in the checkout, or it predates the verifier — §05 |
| `list` returns the tools of a contract you did not expect | two artifacts cover the same (caller, callee) pair and resolution is by pair, so one is unreachable. The startup log names it with an `UNREACHABLE` warning. Load one contract per pair |
| `1 contract(s) verified` when you expect 2 | `--contract` takes one artifact per occurrence and a glob gives it several — the extras are dropped silently. Build one flag per file, as §15.5 does |
| `connect contracts` lists a contract whose `.jws` you cannot find | `--out` does not create its directory, and `need apply` is idempotent so it will not retry the write. Copy it from `~/wc/state/tenants/default/state/contracts/` — §12 |
| `AddrInUse … Address already in use` | something from a previous run still holds the port. The verifier prints its whole configuration BEFORE it binds, so this is the last line under a page of correct ones — the preflight in §15.5 clears it |
| `src refspec <branch> does not match any` | the branch was never created — usually a `git pull` that refused and broke an `&&` chain, leaving the commit on `main`. Recovery below |
| `Permission to … denied to …` on the first push | the author is not a collaborator, or the invitation was never accepted — §07.1 and §07.2 |

#### if a commit landed on `main` instead of the branch

*move it onto the branch it was meant for, and put main back · run from `the affected repository` · local only*

```text
cd ~/wc/payments-mcp        # or ~/wc/recon-bot
git fetch origin
git log --oneline origin/main..main          # what is stranded on main

git switch -C <branch> origin/main
git checkout <stranded-sha> -- <the files>
git commit -m "<the message>"
git push -u origin <branch> && gh pr create --fill

git branch -f main origin/main               # only after the push succeeds
```

> **the last line discards local main**
>
> Run it only once the branch is pushed, so the content is safely somewhere else. It is the right move when everything stranded on local `main` is either now on the branch or already merged remotely — check with the `git log` line above before you run it, not after.

> **the log line worth knowing about**
>
> An identity that failed to resolve and a caller with no contract both end as `WC-4001`. The verifier writes a separate line naming the origin it would not believe — `grep "peer identity not established" verify.log` — which is the difference between a spoofing attempt and a missing contract.

## 19 · What this does not do

| Gap | Consequence | Where it goes |
|---|---|---|
| **An agent behind `connect-mediate` cannot reach Path B** | `HttpUpstream` presents headers, not a client certificate, so it arrives with no mTLS identity and the handshake fails | the caller needs its own mesh sidecar to originate mTLS. Client-certificate support in `connect-mediate` would be the alternative and does not exist |
| stdio MCP servers | never cross the network, so Path B cannot see them | Path A, which is what it is for |
| warden-connect bounds *which capabilities* a caller may reach, and nothing about volume. Rate, concurrency and spend were removed on 2026-08-29 — a per-process counter never matched the number an owner signed. Envoy and Kong both rate-limit properly |
| the Kong plugin has **no hot reload**. There is no timer and no `wc_reload`, so a contract set or route table changes only when the worker restarts — and a revocation reaches it no faster. Contract `exp` is the real containment |
| `max_spend_usd_per_day` | carried and narrowed correctly; bounds nothing, and cannot be set on a new contract | removed with the other ceilings on 2026-08-29 |
| the pin ledger is in memory | a verifier restart refuses tool calls until some client lists again | fail-closed and self-healing inside one MCP handshake. Worth knowing before it reads as an outage |
| **one contract per party pair at a gateway** | a second contract between the same two parties is verified, counted, and unreachable — resolution is by pair and a filter never has a `cid` | warned about at startup rather than fixed. Making both usable needs either a by-pair multimap with a selection rule, or deferring resolution to the body phase to read a `cid` — design decisions, not fixes |
| Path A’s identity is configuration | a developer can edit their own client config | structural. Path A stops an agent and an accident; it does not stop an operator. That is what Path B is for |

#### Before you call it working

**Verified end to end:** §01–§13 and §15–§17, executed against live GitHub and Envoy 1.31.10 by a reader following this page — three accounts, two repositories, two reviewed merges, a provider-approved gated term, and enforcement refusing six distinct ways while admitting two calls. Every output shown is that run’s real text. **Not exercised:** §14, the stdio mediator. **Not built:** everything in §19.

warden-connect · the connection control plane for AI agents
