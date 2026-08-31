# GitHub — implementation guide

Bring one provider and one consumer under connection contracts, end to end.
Every command names the directory it runs from and the account that runs it.

Three logins appear throughout: `$PROVIDER_LOGIN` and `$CONSUMER_LOGIN` own a
repository each and approve on their own side, and `$AUTHOR_LOGIN` commits and
opens the pull requests. Set all three in §3.2. They must be three distinct
accounts — the author must never be the approver.

## 0 · What is where

Three parts. Only the middle one repeats.

|  | Part | Sections | When |
|---|---|---|---|
| **1** | Set the estate up | 02 prerequisites · 03 workspace · 03b push access · 04 branch protection · 05 probe the shim · 06 register both parties | once per estate |
| **2** | Contract one connection | 07 publish the offer · 08 declare a need · 09 the gated path · 10 verify | **per connection** |
| **3** | Harden and reference | 11 declared approvers · 12 the mediator · 13 refusals · 14 checklist | when the flow works |

> **if you are coming back to this**
>
> Part 1 is already done. Start at **§07** for a new provider, or **§08** to point another consumer at an offer that already exists. §13 is the refusal index.

## 00 · The three accounts

| Repo | Author — commits, opens the PR | Approver — approves and merges | Registered owner |
|---|---|---|---|
| `payments-mcp` | `$AUTHOR_LOGIN` | `$PROVIDER_LOGIN` | `$PROVIDER_LOGIN` |
| `recon-bot` | `$AUTHOR_LOGIN` | `$CONSUMER_LOGIN` | `$CONSUMER_LOGIN` |

> **why this shape works**
>
> `$AUTHOR_LOGIN` authors in both repositories, which is fine — nothing requires authors to differ across sides. What must hold is that in *each* repository the author and the approver are different people, and that the approver is the account you registered as owner. Both hold here.

| Rule | Satisfied by |
|---|---|
| Author ≠ approver, per repo | `$AUTHOR_LOGIN` vs `$PROVIDER_LOGIN`; `$AUTHOR_LOGIN` vs `$CONSUMER_LOGIN` |
| Approver is the registered owner | `$PROVIDER_LOGIN` owns the server, `$CONSUMER_LOGIN` owns the agent |
| Approvers differ across the two sides | `$PROVIDER_LOGIN` and `$CONSUMER_LOGIN` — so `require_distinct_approvers` would also pass |

#### Which account runs which command

> **the account follows the repo, not the step**
>
> A `$C` command with `--shim` shells out to `gh` and **inherits whichever account is active**. It needs *admin* on the repository named in `--repo`, because the shim reads branch protection. Without admin that lookup 404s, the shim reports `protected:false`, and you get `WC-1001 not a guarded ref` — a token problem wearing a policy problem's clothes.

| Command | Reads | Must run as |
|---|---|---|
| `scm probe --repo $PROVIDER_REPO` | payments-mcp | `$PROVIDER_LOGIN` |
| `offer publish` | payments-mcp | `$PROVIDER_LOGIN` |
| `approve --merge-repo $PROVIDER_REPO` | payments-mcp | `$PROVIDER_LOGIN` |
| `need apply` | recon-bot | `$CONSUMER_LOGIN` |
| `register`, `activate`, `entities`, `show`, `contracts`, `offer lint`, `need check`, `policy lint`, `receipt --out`, `verify` | nothing — local state only | any account |

> **paste whole blocks; do not edit inside them**
>
> Ids and shas come from a variable or from the previous command's output, so no block needs changing in place. Editing a line inside a multi-line block is how a stray `\` gets introduced — and a trailing backslash makes `git commit` swallow the next line as arguments, so the commit never happens and the pull request has nothing in it. If in doubt, run the lines one at a time.

#### Switching accounts

*every git/gh block below starts with this, so you never guess which identity is active · run from `anywhere`*

```sh
gh auth switch --user $PROVIDER_LOGIN      # or $CONSUMER_LOGIN, or $AUTHOR_LOGIN
gh auth status
```

> **if an account is not logged in yet**
>
> `gh auth login` once per account. Alternatively approve in the browser as that account and use `gh` only for the author role — the approval lands in `pulls/<n>/reviews` either way, which is all warden-connect reads.

## 01 · What you build

| Artifact | Where | Written by |
|---|---|---|
| Surface | `warden/surface.json`, payments-mcp | `$AUTHOR_LOGIN` |
| Offer | `warden/offer.toml`, payments-mcp | `$AUTHOR_LOGIN` |
| Need | `warden/needs.toml`, recon-bot | `$AUTHOR_LOGIN` |
| Approval file | `warden/approvals/<req>.toml`, payments-mcp | `$AUTHOR_LOGIN`, gated items only |
| Contract | the control-plane state log | warden-connect — signed, never committed |
| Receipt | `warden/contracts/<cid>.toml` | warden-connect — grants nothing |

> **the model**
>
> A contract is a **ceiling**: `effective = contract.surface ∩ token.scope ∩ policy_decision`. Both parties consent by merging a reviewed change in their own repository. Neither can produce a contract alone, and neither needs a signing key.

| Offer term | Consumer gets | Provider does |
|---|---|---|
| `pre_granted` | `GRANT` — mints on apply | nothing further |
| `named_consumer` | `PENDING` | approves that consumer by merging — section 09 |

## Set the estate up

Accounts, repositories, keys and policy. Everything here is done once, and none of it issues a contract — at the end you have two registered parties holding zero connections.

## 02 · Prerequisites

| Need | Held by | Why |
|---|---|---|
| `gh` authenticated for all three accounts | you | the shim shells out to it |
| **Admin** on both repos | `$PROVIDER_LOGIN`, `$CONSUMER_LOGIN` | `merge_evidence` reads branch protection; without admin it 404s and the ref reads as unprotected |
| Public repos, or GitHub Pro | — | branch protection is free only on public personal repos |
| Rust 1.89+, `jq`, `openssl` | platform operator | build and keys |

## 03 · Workspace — platform operator

Three checkouts and one state directory. Nothing here touches GitHub.

*lay it out · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

mkdir -p ~/wc && cd ~/wc

git clone https://github.com/<your-org>/warden-connect  warden-connect
git clone https://github.com/$PROVIDER_LOGIN/payments-mcp        payments-mcp
git clone https://github.com/$CONSUMER_LOGIN/recon-bot           recon-bot

cargo build --release --workspace --manifest-path warden-connect/Cargo.toml
```

### 3.1 · Two variables, in every shell

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

export C="$HOME/wc/warden-connect/target/release/connect"
export WARDEN_CONNECT_ROOT="$HOME/wc/state"
mkdir -p "$WARDEN_CONNECT_ROOT"
```

> **the single most common way to get stuck**
>
> The state root defaults to `.connect`, **relative to the working directory**. Register from `~/wc`, publish from `~/wc/payments-mcp`, and the second command opens a different, empty registry — then reports `WC-2001 entity not found`, which reads as a registration problem. Export it absolute, everywhere.

### 3.2 · Identifiers and accounts

*OWNER/REPO in full — a bare name 404s. The `human:` pair is registry notation for --owner and --by; the bare logins are for gh and --expect-approver · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

export PROVIDER_LOGIN="<provider-owner-login>"
export CONSUMER_LOGIN="<consumer-owner-login>"
export AUTHOR_LOGIN="<author-login>"

export PROVIDER_REPO="$PROVIDER_LOGIN/payments-mcp"
export CONSUMER_REPO="$CONSUMER_LOGIN/recon-bot"

export PROVIDER_OWNER="human:$PROVIDER_LOGIN"
export CONSUMER_OWNER="human:$CONSUMER_LOGIN"
```

### 3.3 · An issuer key

*two steps because `ecparam -genkey` emits SEC1 and the loader wants PKCS#8 · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

openssl ecparam -name prime256v1 -genkey -noout -out sec1.pem
openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out issuer.pem
openssl ec -in issuer.pem -pubout -out issuer.pub
rm sec1.pem
```

> **walkthrough only**
>
> The contract is a signed JWS, and the mediator verifies it against the issuer's public key rather than by asking the control plane — that is why a key is needed at all. In production `--signer COMMAND` keeps it in an HSM or KMS and `--require-external-signing` refuses to start if any key would be read from local disk.

### 3.4 · A connect policy naming the zones you will register

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

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

> **two warnings are expected**
>
> *no `approver_role`* — correct, because consent comes from the merge, and naming a role would refuse merge consent with `WC-3020`. *standing disabled* — correct, every request goes to a human until ceilings are reviewed. The verdict that matters is `usable`. The shipped `connect-policy.toml` declares `internal.apac-ops`, not `internal.apac`, which is why this walkthrough writes its own.

## 03b · Give the author push access

The author commits and opens pull requests in both repositories, so both owners must add them. Two API calls each — an invitation, and its acceptance.

### 3b.1 · Invite, as each repo's owner

*provider repo · run from `~/wc` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc

gh api -X PUT repos/$PROVIDER_REPO/collaborators/$AUTHOR_LOGIN -f permission=push
```

*consumer repo · run from `~/wc` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc

gh api -X PUT repos/$CONSUMER_REPO/collaborators/$AUTHOR_LOGIN -f permission=push
```

### 3b.2 · Accept, as $AUTHOR_LOGIN

*accepts every pending invitation. A literal id here is a zsh redirect, not a placeholder · run from `~/wc` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc

gh api user/repository_invitations \
  -q '.[] | "\(.id)  \(.repository.full_name)"'

for id in $(gh api user/repository_invitations -q '.[].id'); do
  gh api -X PATCH "user/repository_invitations/$id" && echo "accepted $id"
done
```

### 3b.3 · Confirm

*push must be true on both · run from `~/wc` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc

for r in "$PROVIDER_REPO" "$CONSUMER_REPO"; do
  printf "%-34s " "$r"; gh api "repos/$r" -q ".permissions.push"
done
```

> **push, not admin**
>
> `$AUTHOR_LOGIN` needs write to push a branch and open a pull request — nothing more. They must never be the approver: author and approver differ per repository, and that is what `is_reviewed_merge` checks. Write access is not consent.

> **the symptom without it**
>
> `remote: Permission to … denied` on `git push`, then `No commits between main and <branch>` from `gh pr create` — the second is a consequence of the first, not a separate problem.

## 04 · Guard both branches

An unguarded branch means a merge proves nothing. Every contract would refuse with `WC-1001`.

### 4.1 · payments-mcp — as $PROVIDER_LOGIN

*a JSON body, not -f flags: -f sends strings and the review count must be an integer, and required_status_checks has to be present even when null · run from `~/wc` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc

gh api -X PUT repos/$PROVIDER_REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
JSON
```

### 4.2 · recon-bot — as $CONSUMER_LOGIN

*same body, consumer repo · run from `~/wc` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc

gh api -X PUT repos/$CONSUMER_REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
JSON
```

> **leave enforce_admins false**
>
> With it on, GitHub blocks the merge unless the approval comes from an account with write access. Off, the owner can merge regardless — and the review row is already written, which is all warden-connect reads.

> **if a later step says the ref is not guarded**
>
> Protection may be set and simply invisible to the account that is active. Check both at once: `gh api repos/$CONSUMER_REPO/branches/main/protection` as that account — a 404 means either no protection, or no admin, and the shim cannot tell those apart.

> **reviewers are not approvals**
>
> The reviewer dropdown only lists accounts with push access, so you may not be able to *request* a review. Nothing reads review requests — only that `pulls/<n>/reviews` contains an `APPROVED` entry whose login differs from the author.

## 05 · Probe the shim first

Merge one throwaway pull request and read it back. Cheapest way to find a token scope or a wrong variable.

### 5.1 · a throwaway PR — $AUTHOR_LOGIN authors, $PROVIDER_LOGIN approves

*run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/payments-mcp

gh auth switch --user $AUTHOR_LOGIN

git checkout main && git pull
git checkout -b probe
echo probe > PROBE.md && git add PROBE.md
git commit -m "probe"
git push -u origin probe
gh pr create --base main --head probe --title probe --body ""
```

*run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

export PR=$(gh pr list --head probe --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on probe}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head probe --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — probe has no merged pull request}"
```

### 5.2 · Read it back

*run from `~/wc` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc

$C scm probe --shim warden-connect/scripts/scm/github.sh --label scm \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --expect-ref refs/heads/main --expect-protected \
  --expect-approver "$PROVIDER_LOGIN"
```

| Field | Must be | If it is not |
|---|---|---|
| `merged` | `true` | you pushed, or used the branch head instead of the merge commit |
| `protected` | `true` | section 04 skipped, or the token lacks admin |
| `author` | `$AUTHOR_LOGIN` | the shim is broken; an empty author makes separation of duties vacuous |
| `approvers` | `$PROVIDER_LOGIN` | the wrong account approved |
| `base_sha` | a commit | without it every contract refuses with `WC-3025` |

## 06 · Register both parties — platform operator

Registration is not connectivity. A registered party holds zero contracts. Nothing in this section touches GitHub.

### 6.1 · The surface goes in the provider repo — $AUTHOR_LOGIN commits it in 07

It belongs at the reserved path, because the same file is what section 07 publishes. Registering from a loose copy elsewhere pins a digest no repository can be shown to hold.

*run from `~/wc/payments-mcp` · local only — no GitHub access*

```sh
cd ~/wc/payments-mcp

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

### 6.2 · Set the ids

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

export PROVIDER="urn:acme:mcp:payments-mcp"
export CONSUMER="urn:acme:agent:recon-bot"
```

### 6.3 · Write the consumer's card

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

cat > recon-bot/card.json <<'JSON'
{
  "name": "recon",
  "description": "consumer",
  "version": "1.0.0",
  "skills": [ { "id": "d", "name": "d", "description": "d" } ]
}
JSON
```

### 6.4 · Register the provider

*zone must be one drill-policy.toml declares · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

$C register server --id "$PROVIDER" \
  --surface payments-mcp/warden/surface.json \
  --endpoint "npx -y @acme/pay" --owner "$PROVIDER_OWNER" \
  --zone internal.payments --by "$PROVIDER_OWNER"
```

### 6.5 · Register the consumer

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

$C register agent --id "$CONSUMER" --card recon-bot/card.json \
  --owner "$CONSUMER_OWNER" --zone internal.apac --by "$CONSUMER_OWNER"
```

### 6.6 · Activate both

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

$C activate "$PROVIDER" --by "$PROVIDER_OWNER"
$C activate "$CONSUMER" --by "$CONSUMER_OWNER"
```

> **get the owner right the first time**
>
> An entity's owner **cannot be changed** — re-registering over an `Active` record is refused, because a changed party is drift, not an update. The owner must be the account that approves in *that* repository: `$PROVIDER_LOGIN` for payments-mcp, `$CONSUMER_LOGIN` for recon-bot. Get it wrong and `need apply` refuses with `WC-3025`.

### 6.7 · Confirm

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

$C entities
$C show "$PROVIDER"
$C show "$CONSUMER"
```

Empty output means `WARDEN_CONNECT_ROOT` is not set in this shell.

## Contract one connection

Offer, need, and — for a gated item — the provider's approval. This is the part that repeats: every new consumer, every new tool, every renewal walks this same path.

## 07 · Provider — publish the offer

### 7.1 · Write the terms — $AUTHOR_LOGIN

*written by the command, not by hand · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/payments-mcp

cat > warden/offer.toml <<'TOML'
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
TOML
```

No consumer is named. A provider writes this before any consumer exists.

### 7.2 · Lint — needs no control plane, no account

*run from `~/wc/payments-mcp` · local only — no GitHub access*

```sh
cd ~/wc/payments-mcp

$C offer lint
```

### 7.3 · Pull request — $AUTHOR_LOGIN

*branch, stage, commit, push, open the pull request · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/payments-mcp

git checkout main && git pull
git checkout -b publish-offer
git add warden/
git commit -m "publish offer"
git push -u origin publish-offer
gh pr create --base main --head publish-offer --title "publish offer" --body ""

export PR=$(gh pr list --head publish-offer --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on publish-offer}"
```

### 7.4 · Approve and merge — $PROVIDER_LOGIN

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

export PR=$(gh pr list --head publish-offer --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on publish-offer}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head publish-offer --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — publish-offer has no merged pull request}"
```

> **this first merge**
>
> carries no `[approval]` block, so the registered owner stands in as the approver. That is the bootstrap, and it applies only while the key is absent.

### 7.5 · Publish — platform operator

*run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

$C offer publish --surface warden/surface.json --terms warden/offer.toml \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/github.sh --shim-label scm
```

*expected*

```text
consent    1 approved by $PROVIDER_LOGIN via scm
published  urn:acme:mcp:payments-mcp
  version  1
  surface  sha256:68ad9d18...
  offers   get_balance, transfer_funds
  approval none
  affects  nothing — all 0 live contract(s) sit inside these terms
```

## 08 · Consumer — the pre-granted path

> **check this first**
>
> Everything below runs in `recon-bot`, which `$AUTHOR_LOGIN` has not touched yet. If the consumer half of §03b was skipped, the first `git push` fails with `Permission to … denied` and the pull request then fails with `No commits between main and declare-need` — the second being a consequence of the first.

### 8.0 · Confirm $AUTHOR_LOGIN can push to the consumer repo

*true means go; false means run §03b for the consumer repo · run from `~/wc` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc

gh api "repos/$CONSUMER_REPO" -q ".permissions.push"
```

*if it printed false: invite, as the consumer repo's owner · run from `~/wc` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc

gh api -X PUT repos/$CONSUMER_REPO/collaborators/$AUTHOR_LOGIN -f permission=push
```

*then accept, as the author · run from `~/wc` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc

for id in $(gh api user/repository_invitations -q '.[].id'); do
  gh api -X PATCH "user/repository_invitations/$id" && echo "accepted $id"
done

gh api "repos/$CONSUMER_REPO" -q ".permissions.push"
```

### 8.1 · Write the need — $AUTHOR_LOGIN

*written by the command, not by hand · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/recon-bot

mkdir -p warden
cat > warden/needs.toml <<'TOML'
asset = "urn:acme:agent:recon-bot"

[[need]]
to      = "urn:acme:mcp:payments-mcp"
tools   = ["get_balance"]
justify = "APAC daily reconciliation"
ttl     = 604800
TOML
```

### 8.2 · Check before committing — platform operator

*reads the registry, takes no writer lock · run from `~/wc/recon-bot` · as $PROVIDER_LOGIN*

```sh
cd ~/wc/recon-bot

$C need check --manifest warden/needs.toml --repo "$CONSUMER_REPO" \
  --policy ~/wc/drill-policy.toml
```

| Disposition | Means |
|---|---|
| `GRANT` | pre-granted to this audience; mints on apply |
| `PENDING` | the term is `named_consumer` — section 09 |
| `REFUSED` | not offered to you, with a per-item reason |

> **ttl is bounded by the term**
>
> Asking for more than the term's `ttl_max` is refused. `get_balance` allows 604800s; `transfer_funds` allows 3600s.

### 8.3 · Pull request — $AUTHOR_LOGIN

*branch, stage, commit, push, open the pull request · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/recon-bot

git checkout main && git pull
git checkout -b declare-need
git add warden/
git commit -m "declare need"
git push -u origin declare-need
gh pr create --base main --head declare-need --title "declare need" --body ""

export PR=$(gh pr list --head declare-need --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on declare-need}"
```

### 8.4 · Approve and merge — $CONSUMER_LOGIN

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc/recon-bot

export PR=$(gh pr list --head declare-need --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on declare-need}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head declare-need --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — declare-need has no merged pull request}"
```

### 8.5 · Apply — platform operator

*run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc/recon-bot

$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/github.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

*expected*

```text
consumer   3 approved by $CONSUMER_LOGIN via scm

urn:acme:agent:recon-bot -> urn:acme:mcp:payments-mcp
  minted     conn_5aaa5cd8956fca4d (cx_ee279df0a6f4967c179d8839)
  items      get_balance
  ttl        604800s
  offer      version 1

1 minted · 0 awaiting the provider · 0 already current
```

## 09 · The gated path — provider approves a named consumer

Everything above used `pre_granted`. This is the other half, and it crosses both repositories.

### 9.1 · Ask for the gated tool — $AUTHOR_LOGIN

*appended by the command · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/recon-bot

cat >> warden/needs.toml <<'TOML'

[[need]]
to      = "urn:acme:mcp:payments-mcp"
tools   = ["transfer_funds"]
justify = "settlement runs, quarterly"
ttl     = 3600
TOML
```

*branch, stage, commit, push, open the pull request · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/recon-bot

git checkout main && git pull
git checkout -b need-transfer-funds
git add warden/
git commit -m "need transfer_funds"
git push -u origin need-transfer-funds
gh pr create --base main --head need-transfer-funds --title "need transfer_funds" --body ""

export PR=$(gh pr list --head need-transfer-funds --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on need-transfer-funds}"
```

### 9.2 · Approve and merge — $CONSUMER_LOGIN

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc/recon-bot

export PR=$(gh pr list --head need-transfer-funds --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on need-transfer-funds}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head need-transfer-funds --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — need-transfer-funds has no merged pull request}"
```

### 9.3 · Apply — opens a request, mints nothing

*run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc/recon-bot

$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/github.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

*run from `~/wc` · as $PROVIDER_LOGIN*

```sh
cd ~/wc

$C requests --all
```

Act on the `Pending` row. A `Minted` row is already settled and cannot be approved again.

### 9.4 · Emit the approval file — platform operator

*selected by status, so there is nothing to copy · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

export REQ=$($C requests --all --json \
  | jq -r '[.[] | select(.status=="Pending")] | last | .id')
echo "REQ=$REQ"
```

*emitted straight into the provider repo. `--approval-file` is used twice — the local file to read, AND the path looked up in the repository — so it has to be one path that resolves both ways. · run from `~/wc` · as $PROVIDER_LOGIN*

```sh
cd ~/wc

mkdir -p payments-mcp/warden/approvals
$C approve $REQ --emit payments-mcp/warden/approvals/
```

It names the request, the parties, the items and the TTL *in words*, and binds them by digest — a reviewer sees what they are agreeing to without computing a hash.

### 9.5 · Commit it in the PROVIDER repo — $AUTHOR_LOGIN authors

*confirm it landed where the repo will carry it · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
cd ~/wc/payments-mcp

git status --short warden/approvals/
```

*branch, stage, commit, push, open the pull request · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/payments-mcp

git checkout main && git pull
git checkout -b approve-$REQ
git add warden/
git commit -m "approve $REQ"
git push -u origin approve-$REQ
gh pr create --base main --head approve-$REQ --title "approve $REQ" --body ""

export PR=$(gh pr list --head approve-$REQ --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on approve-$REQ}"
```

### 9.6 · Approve and merge — $PROVIDER_LOGIN

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

export PR=$(gh pr list --head approve-$REQ --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on approve-$REQ}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head approve-$REQ --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — approve-$REQ has no merged pull request}"
```

### 9.7 · Settle it — platform operator

*run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

$C approve $REQ --merge-repo "$PROVIDER_REPO" --sha "$SHA" \
  --approval-file warden/approvals/$REQ.toml \
  --shim ../warden-connect/scripts/scm/github.sh --shim-label scm \
  --kid k1 --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

## 10 · Verify — platform operator

*the newest contract's id, so the blocks below need nothing pasted · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

$C contracts

export CID=$($C contracts --json | jq -r 'max_by(.iat) | .cid')
echo "CID=$CID"
```

*run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

$C show "$PROVIDER"
$C blast-radius --id "$CONSUMER" --depth 2 --services
```

### 10.1 · Write the receipt back

*neither --out nor --emit creates the directory · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

mkdir -p payments-mcp/warden/contracts
$C receipt --cid "$CID" --out payments-mcp/warden/contracts/
```

> **the contract is never committed**
>
> A signed artifact in git verifies until its expiry no matter what the registry says, and git cannot express revocation — a deletion is another commit and the blob stays reachable. The receipt carries no signature and no key.

Committing the receipt is a normal pull request, authored by `$AUTHOR_LOGIN` and approved by `$PROVIDER_LOGIN` like any other.

### 10.2 · Verify independently

> **the verifier checks the artifact, not the connection**
>
> It confirms size, alg, signature, schema, typ, nbf/exp, aud, revocation and — with `--issuer-id` — the issuer. It cannot check peer identity, the presented surface hash, zone policy or token binding: those need two live peers and a handshake, which is the mediator's job at connect time. A standalone verifier has no peers to compare against, and says so in its own output.

*every mint persists the signed artifact; this is where it lands. --kid and --issuer-id are both required: without them it refuses, or reports iss unchecked · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

ls state/tenants/default/state/contracts/

$C verify --mediator-id warden:mediator:local \
  --issuer-pub issuer.pub --kid k1 --issuer-id https://connect.internal \
  --file "state/tenants/default/state/contracts/$CID.warden_mediator_local.jws"
```

## Harden, enforce, and look things up

Replace the bootstrap with a declared approver list, put the mediator in the call path, and the reference tables you will come back to.

## 11 · Declare who may approve

Replace the bootstrap with an explicit list — one pull request per repository, and each is still governed by the bootstrap owner, because at its base there is no list yet.

| At the base commit | Behaviour |
|---|---|
| no `[approval]` key | registry owner stands in — this is where you are now |
| `approvers = []` | `refuse` — an instruction, not a gap |
| `approvers = […]` | that list decides, from the next merge onward |

> **read at the base**
>
> The list comes from the commit the pull request *targets*, not from the pull request. Adding yourself and approving in one change does not work: joining the list and using it are two merges, and the first is governed by whoever was already on it.

#### Provider

### 11.1 · Append the block — $AUTHOR_LOGIN

*a table after the [[term]] arrays is valid TOML; `offer lint` confirms it · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/payments-mcp

cat >> warden/offer.toml <<'TOML'

[approval]
approvers = ["$PROVIDER_LOGIN"]
min       = 1
TOML

$C offer lint
```

### 11.2 · Pull request — $AUTHOR_LOGIN

*branch, stage, commit, push, open the pull request · run from `~/wc/payments-mcp` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/payments-mcp

git checkout main && git pull
git checkout -b declare-approvers
git add warden/
git commit -m "declare approvers"
git push -u origin declare-approvers
gh pr create --base main --head declare-approvers --title "declare approvers" --body ""

export PR=$(gh pr list --head declare-approvers --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on declare-approvers}"
```

### 11.3 · Approve and merge — $PROVIDER_LOGIN

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

export PR=$(gh pr list --head declare-approvers --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on declare-approvers}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head declare-approvers --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — declare-approvers has no merged pull request}"
```

### 11.4 · Republish, so the registry sees the new set

*prints APPROVER SET CHANGED, with the digest before and after · run from `~/wc/payments-mcp` · as $PROVIDER_LOGIN*

```sh
gh auth switch --user $PROVIDER_LOGIN
cd ~/wc/payments-mcp

$C offer publish --surface warden/surface.json --terms warden/offer.toml \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/github.sh --shim-label scm
```

#### Consumer

### 11.5 · Append the block — $AUTHOR_LOGIN

*run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/recon-bot

cat >> warden/needs.toml <<'TOML'

[approval]
approvers = ["$CONSUMER_LOGIN"]
min       = 1
TOML

$C need check --manifest warden/needs.toml --repo "$CONSUMER_REPO" \
  --policy ~/wc/drill-policy.toml
```

### 11.6 · Pull request — $AUTHOR_LOGIN

*branch, stage, commit, push, open the pull request · run from `~/wc/recon-bot` · as $AUTHOR_LOGIN*

```sh
gh auth switch --user $AUTHOR_LOGIN
cd ~/wc/recon-bot

git checkout main && git pull
git checkout -b declare-approvers
git add warden/
git commit -m "declare approvers"
git push -u origin declare-approvers
gh pr create --base main --head declare-approvers --title "declare approvers" --body ""

export PR=$(gh pr list --head declare-approvers --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on declare-approvers}"
```

### 11.7 · Approve and merge — $CONSUMER_LOGIN

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc/recon-bot

export PR=$(gh pr list --head declare-approvers --state open --json number -q ".[0].number")
echo "PR=${PR:-NONE — no open pull request on declare-approvers}"

gh pr review "$PR" --approve
gh pr merge "$PR" --merge

export SHA=$(gh pr list --head declare-approvers --state merged \
  --json mergeCommit -q ".[0].mergeCommit.oid")
echo "SHA=${SHA:-NONE — declare-approvers has no merged pull request}"
```

### 11.8 · Apply, so the registry sees the new set

*prints APPROVER SET CHANGED for the consumer side · run from `~/wc/recon-bot` · as $CONSUMER_LOGIN*

```sh
gh auth switch --user $CONSUMER_LOGIN
cd ~/wc/recon-bot

$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/github.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

> **from here on**
>
> Every later merge to `warden/offer.toml` needs `$PROVIDER_LOGIN`, and every later merge to `warden/needs.toml` needs `$CONSUMER_LOGIN` — because those names are now on the branch, at the base of whatever pull request comes next. The registry owner no longer stands in.

## 12 · Put the mediator in the path

*run from `~/wc` · as $PROVIDER_LOGIN*

```sh
cd ~/wc

./warden-connect/target/release/connect-mediate --help
```

| At connect | At each call |
|---|---|
| 14 gates: signature, alg, expiry, audience, revocation, both peer identities, the pin, posture, zone pair, token binding, issuer, schema, size | `tools/list` filtered to `surface.tools`; rate, spend and concurrency ceilings |

The catalogue filter is the most valuable thing here: the model never sees the tool it is not contracted for, so it cannot be talked into attempting it.

## 13 · Refusals

The first table is every refusal a real run of this walkthrough produced, in order.

| Refusal | Cause | Fix |
|---|---|---|
| `src refspec … does not match any` | git | no branch. `git checkout -b` and commit before pushing |
| `WC-1001` *merged onto <empty>* | `$PROVIDER_REPO` was a bare name | the `owner/repo` form. The shim now exits 3 naming it |
| `WC-1001` *merged onto <empty>* | the branch-head sha, not the merge commit | `gh pr view <n> --json mergeCommit` |
| `WC-3025` *registry owner standing in* | registered owner ≠ approving account | owner cannot be changed — owner approves once, or register a new id |
| `WC-1001` *not a guarded ref* | the active `gh` account had no admin on the repo being read, so the protection lookup 404d | `gh auth switch` to the account that owns that repo, then re-run |
| `WC-8001` | no `--policy`; the default is relative to cwd | `--policy ~/wc/drill-policy.toml` |
| `WC-8004` *issuer key* | no key generated | section 3.3 |
| `WC-8004` *cannot write …* | no output flag creates its directory — `--emit`, `--out` | `mkdir -p` the target first |

#### Others you may meet

| Code | Means | Look at |
|---|---|---|
| `WC-2001` | entity not found | `WARDEN_CONNECT_ROOT` unset in this shell |
| `WC-2011` | zone pair unknown | a zone the policy never declared |
| `WC-3010` | requested surface exceeds the offer | the diff is in the message |
| `WC-3020` | no approver held the required role | remove `approver_role`, or route through a signed approval |
| `WC-3023` | the reviewed file is not the submitted one | you edited after approval |
| `WC-3024` | the registered owner did not approve | `$C show <id>` |
| `WC-3027` | the same person approved both sides | here `$PROVIDER_LOGIN` and `$CONSUMER_LOGIN` differ, so this cannot fire |

## 14 · Checklist

warden-connect · connection control plane for agents. Reference: `docs/07-hld.md`, `docs/08-lld.md`, `docs/use-cases/`. Azure Repos and Bitbucket follow the same shape and are **not** yet verified against a live tenant.
