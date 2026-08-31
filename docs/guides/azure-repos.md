# Azure Repos — implementation guide

Bring one provider and one consumer under connection contracts, end to end.
Every command names the directory it runs from and the identity that runs it.

Azure Repos names a repository in three parts — `ORG/PROJECT/REPO` — which is
why the core never parses the string and the shim resolves it.

> **Unverified against a live tenant**
>
> The `azure-repos.sh` shim's field paths agree with the fixtures and with the
> code, which means both could be wrong together. Only the GitHub path has been exercised
> end to end against a live host. Treat this guide and its shim as a template,
> and run the probe in §05 before anything else.

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
| `payments-mcp` | `author@bank.com` | `provider-owner@bank.com` | `provider-owner@bank.com` |
| `recon-bot` | `author@bank.com` | `consumer-owner@bank.com` | `consumer-owner@bank.com` |

> **why this shape works**
>
> `author@bank.com` authors in both repositories, which is fine — nothing requires authors to differ across sides. What must hold is that in *each* repository the author and the approver are different people, and that the approver is the account you registered as owner. Both hold here.

| Rule | Satisfied by |
|---|---|
| Author ≠ approver, per repo | `author@bank.com` vs `provider-owner@bank.com`; `author@bank.com` vs `consumer-owner@bank.com` |
| Approver is the registered owner | `provider-owner@bank.com` owns the server, `consumer-owner@bank.com` owns the agent |
| Approvers differ across the two sides | `provider-owner@bank.com` and `consumer-owner@bank.com` — so `require_distinct_approvers` would also pass |

#### Which account runs which command

> **the account follows the repo, not the step**
>
> A `$C` command with `--shim` shells out to `gh` and **inherits whichever account is active**. It needs *admin* on the repository named in `--repo`, because the shim reads branch protection. Without admin that lookup 404s, the shim reports `protected:false`, and you get `WC-1001 not a guarded ref` — a token problem wearing a policy problem's clothes.

| Command | Reads | Must run as |
|---|---|---|
| `scm probe --repo $PROVIDER_REPO` | payments-mcp | `provider-owner@bank.com` |
| `offer publish` | payments-mcp | `provider-owner@bank.com` |
| `approve --merge-repo $PROVIDER_REPO` | payments-mcp | `provider-owner@bank.com` |
| `need apply` | recon-bot | `consumer-owner@bank.com` |
| `register`, `activate`, `entities`, `show`, `contracts`, `offer lint`, `need check`, `policy lint`, `receipt --out`, `verify` | nothing — local state only | any account |

> **paste whole blocks, do not edit inside them**
>
> Every block is written so nothing needs changing in place — ids and shas come from variables or from the previous command's output. Editing a line inside a multi-line block is how a stray `\` gets introduced, and a trailing backslash makes `git commit` swallow the next line as arguments. If a command looks wrong, run the lines one at a time.

> **paste whole blocks; do not edit inside them**
>
> Ids and shas come from a variable or from the previous command's output, so no block needs changing in place. Editing a line inside a multi-line block is how a stray `\` gets introduced — and a trailing backslash makes `git commit` swallow the next line as arguments, so the commit never happens and the pull request has nothing in it. If in doubt, run the lines one at a time.

#### Switching identity

> **there is no account switcher**
>
> Azure CLI has one signed-in identity. What decides *who* a command acts as is the PAT in `AZURE_DEVOPS_EXT_PAT`, so every block below exports the right one first — the same job `gh auth switch` does on GitHub.

*three PATs, one per person. Each needs Code (read, write) and Pull Request Threads; the two owners also need Policy (read) so the shim can see the branch policy · run from `anywhere`*

```text
export PAT_AUTHOR=<pat>
export PAT_PROVIDER=<pat>
export PAT_CONSUMER=<pat>

export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
az devops configure --defaults organization="$ORG_URL" project="$PROJECT"
```

> **the shim reads whatever is exported**
>
> A `$C … --shim` command shells out to `az` and inherits `AZURE_DEVOPS_EXT_PAT`. Without **Policy (read)** on the repo it is reading, the branch-policy lookup fails, the shim reports `protected:false`, and you get `WC-1001 not a guarded ref` — a token problem arriving as a policy problem.

## 01 · What you build

| Artifact | Where | Written by |
|---|---|---|
| Surface | `warden/surface.json`, payments-mcp | `author@bank.com` |
| Offer | `warden/offer.toml`, payments-mcp | `author@bank.com` |
| Need | `warden/needs.toml`, recon-bot | `author@bank.com` |
| Approval file | `warden/approvals/<req>.toml`, payments-mcp | `author@bank.com`, gated items only |
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
| **Admin** on both repos | `provider-owner@bank.com`, `consumer-owner@bank.com` | `merge_evidence` reads branch protection; without admin it 404s and the ref reads as unprotected |
| Public repos, or GitHub Pro | — | branch protection is free only on public personal repos |
| Rust 1.89+, `jq`, `openssl` | platform operator | build and keys |

## 03 · Workspace — platform operator

Three checkouts and one state directory. Nothing here touches GitHub.

*lay it out · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

mkdir -p ~/wc && cd ~/wc

git clone https://github.com/<your-org>/warden-connect  warden-connect
git clone $ORG_URL/$PROJECT/_git/payments-mcp   payments-mcp
git clone $ORG_URL/$PROJECT/_git/recon-bot      recon-bot

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

*ORG/PROJECT/REPO — three parts, which is why the core never parses it. The `human:` pair is registry notation for --owner and --by; the bare addresses are what Azure reports as uniqueName · run from `~/wc` · local only — no GitHub access*

```sh
cd ~/wc

export ORG_URL="https://dev.azure.com/myorg"
export PROJECT="warden"
export REPO="payments-mcp"

export PROVIDER_REPO="myorg/$PROJECT/payments-mcp"
export CONSUMER_REPO="myorg/$PROJECT/recon-bot"

export PROVIDER_OWNER="human:provider-owner@bank.com"
export CONSUMER_OWNER="human:consumer-owner@bank.com"
export PROVIDER_LOGIN="provider-owner@bank.com"
export CONSUMER_LOGIN="consumer-owner@bank.com"
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

Azure has no per-repository collaborator invite. Push comes from **project group membership** — put the author in Contributors and they can push to every repo in the project.

### 3b.1 · Add the author to the organisation

*express is the free tier; use stakeholder or basic to match your licensing · run from `~/wc` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc

az devops user add --email-id "author@bank.com" \
  --license-type express --org "$ORG_URL"
```

### 3b.2 · Put them in Contributors

*the descriptor is looked up, not pasted · run from `~/wc` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc

export GRP=$(az devops security group list --project "$PROJECT" --org "$ORG_URL" \
  --query "graphGroups[?displayName=='Contributors'].descriptor | [0]" -o tsv)
echo "GRP=${GRP:-NONE — no Contributors group in $PROJECT}"

az devops security group membership add --group-id "$GRP" \
  --member-id "author@bank.com" --org "$ORG_URL"
```

### 3b.3 · Confirm

*a clone that succeeds is the check that matters · run from `~/wc` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc

git ls-remote "$ORG_URL/$PROJECT/_git/payments-mcp" >/dev/null && echo "provider readable"
git ls-remote "$ORG_URL/$PROJECT/_git/recon-bot"    >/dev/null && echo "consumer readable"
```

> **one project, both repos**
>
> If provider and consumer live in **different projects**, repeat 3b.1 and 3b.2 for each. Membership is per project, and that is the unit that grants push.

> **contribute, not administer**
>
> Contributors can push and open pull requests. They cannot change branch policies — which is what you want: the author must not be able to remove the guard that makes their pull request meaningful.

## 04 · Guard both branches

Azure's guard is a **branch policy**. The shim only counts one carrying `minimumApproverCount ≥ 1` — a build-validation policy is not evidence of review, and an unguarded ref refuses every contract with `WC-1001`.

### 4.1 · Provider repo

*the repository id is looked up, not pasted · run from `~/wc` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc

export REPO_ID=$(az repos show --repository payments-mcp \
  --project "$PROJECT" --org "$ORG_URL" --query id -o tsv)
echo "REPO_ID=${REPO_ID:-NONE — no payments-mcp in $PROJECT}"

az repos policy approver-count create --org "$ORG_URL" --project "$PROJECT" \
  --repository-id "$REPO_ID" --branch main \
  --blocking true --enabled true \
  --minimum-approver-count 1 \
  --creator-vote-counts false \
  --reset-on-source-push true
```

### 4.2 · Consumer repo

*same policy, consumer repo · run from `~/wc` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc

export REPO_ID=$(az repos show --repository recon-bot \
  --project "$PROJECT" --org "$ORG_URL" --query id -o tsv)
echo "REPO_ID=${REPO_ID:-NONE — no recon-bot in $PROJECT}"

az repos policy approver-count create --org "$ORG_URL" --project "$PROJECT" \
  --repository-id "$REPO_ID" --branch main \
  --blocking true --enabled true \
  --minimum-approver-count 1 \
  --creator-vote-counts false \
  --reset-on-source-push true
```

### 4.3 · Confirm the shim will see it

*a blocking approver-count policy on refs/heads/main, in both repos · run from `~/wc` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc

az repos policy list --project "$PROJECT" --org "$ORG_URL" -o json \
  | jq -r '.[] | select(.isEnabled and .isBlocking)
      | select((.settings.minimumApproverCount // 0) >= 1)
      | "\(.settings.scope[0].refName)  approvers=\(.settings.minimumApproverCount)"'
```

| Setting | Why |
|---|---|
| `--blocking true` | a non-blocking policy suggests a reviewer and lets the merge through anyway |
| `--minimum-approver-count 1` | what the shim looks for. Without it the ref reads as unguarded |
| `--creator-vote-counts false` | Azure's own author≠approver rule. Leave it false and the two controls agree |
| `--reset-on-source-push true` | a new push discards prior votes, so an approval covers the code that was reviewed |

> **vote 10, not 5**
>
> Azure records approval as a numeric vote. **10** is approved; **5** is *approved with suggestions* and the shim does **not** count it. `az repos pr set-vote --vote approve` sends 10.

## 05 · Probe the shim first

Merge one throwaway pull request and read it back. Cheapest way to find a token scope or a wrong variable.

### 5.1 · a throwaway PR — author@bank.com authors, provider-owner@bank.com approves

*run from `~/wc/payments-mcp` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/payments-mcp

export REPO=payments-mcp

git checkout main && git pull
git checkout -b probe
echo probe > PROBE.md && git add PROBE.md
git commit -m "probe"
git push -u origin probe

az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch probe --target-branch main --title probe >/dev/null
```

*run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

export REPO=payments-mcp

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/probe'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on probe}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — the probe pull request did not complete}"
```

### 5.2 · Read it back

*run from `~/wc` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc

$C scm probe --shim warden-connect/scripts/scm/azure-repos.sh --label scm \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --expect-ref refs/heads/main --expect-protected \
  --expect-approver "$PROVIDER_LOGIN"
```

| Field | Must be | If it is not |
|---|---|---|
| `merged` | `true` | you pushed, or used the branch head instead of the merge commit |
| `protected` | `true` | section 04 skipped, or the token lacks admin |
| `author` | `author@bank.com` | the shim is broken; an empty author makes separation of duties vacuous |
| `approvers` | `provider-owner@bank.com` | the wrong account approved |
| `base_sha` | a commit | without it every contract refuses with `WC-3025` |

## 06 · Register both parties — platform operator

Registration is not connectivity. A registered party holds zero contracts. Nothing in this section touches GitHub.

### 6.1 · The surface goes in the provider repo — author@bank.com commits it in 07

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
> An entity's owner **cannot be changed** — re-registering over an `Active` record is refused, because a changed party is drift, not an update. The owner must be the account that approves in *that* repository: `provider-owner@bank.com` for payments-mcp, `consumer-owner@bank.com` for recon-bot. Get it wrong and `need apply` refuses with `WC-3025`.

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

### 7.1 · Write the terms — author@bank.com

*written by the command, not by hand · run from `~/wc/payments-mcp` · as author@bank.com*

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

### 7.3 · Pull request — author@bank.com

*branch, stage, commit, push, open the pull request · run from `~/wc/payments-mcp` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/payments-mcp

git checkout main && git pull
git checkout -b publish-offer
git add warden/
git commit -m "publish offer"
git push -u origin publish-offer
az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch publish-offer --target-branch main --title "publish offer" >/dev/null

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/publish-offer'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on publish-offer}"
```

### 7.4 · Approve and merge — provider-owner@bank.com

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/publish-offer'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on publish-offer}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — pull request publish-offer did not complete}"
```

> **this first merge**
>
> carries no `[approval]` block, so the registered owner stands in as the approver. That is the bootstrap, and it applies only while the key is absent.

### 7.5 · Publish — platform operator

*run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

$C offer publish --surface warden/surface.json --terms warden/offer.toml \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/azure-repos.sh --shim-label scm
```

*expected*

```text
consent    1 approved by provider-owner@bank.com via scm
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
> Everything below runs in `recon-bot`, which `author@bank.com` has not touched yet. If the consumer half of §03b was skipped, the first `git push` fails with `Permission to … denied` and the pull request then fails with `No commits between main and declare-need` — the second being a consequence of the first.

### 8.0 · Confirm author@bank.com can reach the consumer repo

*a clone that succeeds is the check; a 403 means §03b was not run for this project · run from `~/wc` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc

git ls-remote "$ORG_URL/$PROJECT/_git/recon-bot" >/dev/null \
  && echo "consumer readable" || echo "NO ACCESS — run 3b for this project"
```

*if it failed: add the author to Contributors, as the consumer repo's owner · run from `~/wc` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc

export GRP=$(az devops security group list --project "$PROJECT" --org "$ORG_URL" \
  --query "graphGroups[?displayName=='Contributors'].descriptor | [0]" -o tsv)

az devops security group membership add --group-id "$GRP" \
  --member-id "author@bank.com" --org "$ORG_URL"
```

### 8.1 · Write the need — author@bank.com

*written by the command, not by hand · run from `~/wc/recon-bot` · as author@bank.com*

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

*reads the registry, takes no writer lock · run from `~/wc/recon-bot` · as provider-owner@bank.com*

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

### 8.3 · Pull request — author@bank.com

*branch, stage, commit, push, open the pull request · run from `~/wc/recon-bot` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/recon-bot

git checkout main && git pull
git checkout -b declare-need
git add warden/
git commit -m "declare need"
git push -u origin declare-need
az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch declare-need --target-branch main --title "declare need" >/dev/null

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/declare-need'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on declare-need}"
```

### 8.4 · Approve and merge — consumer-owner@bank.com

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/recon-bot` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc/recon-bot

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/declare-need'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on declare-need}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — pull request declare-need did not complete}"
```

### 8.5 · Apply — platform operator

*run from `~/wc/recon-bot` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc/recon-bot

$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/azure-repos.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

*expected*

```text
consumer   3 approved by consumer-owner@bank.com via scm

urn:acme:agent:recon-bot -> urn:acme:mcp:payments-mcp
  minted     conn_5aaa5cd8956fca4d (cx_ee279df0a6f4967c179d8839)
  items      get_balance
  ttl        604800s
  offer      version 1

1 minted · 0 awaiting the provider · 0 already current
```

## 09 · The gated path — provider approves a named consumer

Everything above used `pre_granted`. This is the other half, and it crosses both repositories.

### 9.1 · Ask for the gated tool — author@bank.com

*appended by the command · run from `~/wc/recon-bot` · as author@bank.com*

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

*branch, stage, commit, push, open the pull request · run from `~/wc/recon-bot` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/recon-bot

git checkout main && git pull
git checkout -b need-transfer-funds
git add warden/
git commit -m "need transfer_funds"
git push -u origin need-transfer-funds
az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch need-transfer-funds --target-branch main --title "need transfer_funds" >/dev/null

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/need-transfer-funds'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on need-transfer-funds}"
```

### 9.2 · Approve and merge — consumer-owner@bank.com

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/recon-bot` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc/recon-bot

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/need-transfer-funds'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on need-transfer-funds}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — pull request need-transfer-funds did not complete}"
```

### 9.3 · Apply — opens a request, mints nothing

*run from `~/wc/recon-bot` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc/recon-bot

$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/azure-repos.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

*run from `~/wc` · as provider-owner@bank.com*

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

*emitted straight into the provider repo. `--approval-file` is used twice — the local file to read, AND the path looked up in the repository — so it has to be one path that resolves both ways. · run from `~/wc` · as provider-owner@bank.com*

```sh
cd ~/wc

mkdir -p payments-mcp/warden/approvals
$C approve $REQ --emit payments-mcp/warden/approvals/
```

It names the request, the parties, the items and the TTL *in words*, and binds them by digest — a reviewer sees what they are agreeing to without computing a hash.

### 9.5 · Commit it in the PROVIDER repo — author@bank.com authors

*confirm it landed where the repo will carry it · run from `~/wc/payments-mcp` · as author@bank.com*

```sh
cd ~/wc/payments-mcp

git status --short warden/approvals/
```

*branch, stage, commit, push, open the pull request · run from `~/wc/payments-mcp` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/payments-mcp

git checkout main && git pull
git checkout -b approve-$REQ
git add warden/
git commit -m "approve $REQ"
git push -u origin approve-$REQ
az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch approve-$REQ --target-branch main --title "approve $REQ" >/dev/null

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/approve-$REQ'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on approve-$REQ}"
```

### 9.6 · Approve and merge — provider-owner@bank.com

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/approve-$REQ'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on approve-$REQ}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — pull request approve-$REQ did not complete}"
```

### 9.7 · Settle it — platform operator

*run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

$C approve $REQ --merge-repo "$PROVIDER_REPO" --sha "$SHA" \
  --approval-file warden/approvals/$REQ.toml \
  --shim ../warden-connect/scripts/scm/azure-repos.sh --shim-label scm \
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

Committing the receipt is a normal pull request, authored by `author@bank.com` and approved by `provider-owner@bank.com` like any other.

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

### 11.1 · Append the block — author@bank.com

*a table after the [[term]] arrays is valid TOML; `offer lint` confirms it · run from `~/wc/payments-mcp` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/payments-mcp

cat >> warden/offer.toml <<'TOML'

[approval]
approvers = ["provider-owner@bank.com"]
min       = 1
TOML

$C offer lint
```

### 11.2 · Pull request — author@bank.com

*branch, stage, commit, push, open the pull request · run from `~/wc/payments-mcp` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/payments-mcp

git checkout main && git pull
git checkout -b declare-approvers
git add warden/
git commit -m "declare approvers"
git push -u origin declare-approvers
az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch declare-approvers --target-branch main --title "declare approvers" >/dev/null

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/declare-approvers'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on declare-approvers}"
```

### 11.3 · Approve and merge — provider-owner@bank.com

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/declare-approvers'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on declare-approvers}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — pull request declare-approvers did not complete}"
```

### 11.4 · Republish, so the registry sees the new set

*prints APPROVER SET CHANGED, with the digest before and after · run from `~/wc/payments-mcp` · as provider-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_PROVIDER
cd ~/wc/payments-mcp

$C offer publish --surface warden/surface.json --terms warden/offer.toml \
  --repo "$PROVIDER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/azure-repos.sh --shim-label scm
```

#### Consumer

### 11.5 · Append the block — author@bank.com

*run from `~/wc/recon-bot` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/recon-bot

cat >> warden/needs.toml <<'TOML'

[approval]
approvers = ["consumer-owner@bank.com"]
min       = 1
TOML

$C need check --manifest warden/needs.toml --repo "$CONSUMER_REPO" \
  --policy ~/wc/drill-policy.toml
```

### 11.6 · Pull request — author@bank.com

*branch, stage, commit, push, open the pull request · run from `~/wc/recon-bot` · as author@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_AUTHOR
cd ~/wc/recon-bot

git checkout main && git pull
git checkout -b declare-approvers
git add warden/
git commit -m "declare approvers"
git push -u origin declare-approvers
az repos pr create --repository "$REPO" --project "$PROJECT" --org "$ORG_URL" \
  --source-branch declare-approvers --target-branch main --title "declare approvers" >/dev/null

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/declare-approvers'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on declare-approvers}"
```

### 11.7 · Approve and merge — consumer-owner@bank.com

*approve, merge, then read the sha from the MERGED pull request — so re-running this block after the merge still works, which $PR alone would not · run from `~/wc/recon-bot` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc/recon-bot

export PR=$(az repos pr list --repository "$REPO" --project "$PROJECT" \
  --org "$ORG_URL" --status active \
  --query "[?sourceRefName=='refs/heads/declare-approvers'].pullRequestId | [0]" -o tsv)
echo "PR=${PR:-NONE — no active pull request on declare-approvers}"

az repos pr set-vote --id "$PR" --vote approve --org "$ORG_URL"
az repos pr update --id "$PR" --status completed --org "$ORG_URL" >/dev/null

export SHA=$(az repos pr show --id "$PR" --org "$ORG_URL" \
  --query lastMergeCommit.commitId -o tsv)
echo "SHA=${SHA:-NONE — pull request declare-approvers did not complete}"
```

### 11.8 · Apply, so the registry sees the new set

*prints APPROVER SET CHANGED for the consumer side · run from `~/wc/recon-bot` · as consumer-owner@bank.com*

```sh
export AZURE_DEVOPS_EXT_PAT=$PAT_CONSUMER
cd ~/wc/recon-bot

$C need apply --manifest warden/needs.toml \
  --repo "$CONSUMER_REPO" --sha "$SHA" \
  --shim ../warden-connect/scripts/scm/azure-repos.sh --shim-label scm \
  --mediator "warden:mediator:local" --kid k1 \
  --issuer-key ~/wc/issuer.pem --policy ~/wc/drill-policy.toml
```

> **from here on**
>
> Every later merge to `warden/offer.toml` needs `provider-owner@bank.com`, and every later merge to `warden/needs.toml` needs `consumer-owner@bank.com` — because those names are now on the branch, at the base of whatever pull request comes next. The registry owner no longer stands in.

## 12 · Put the mediator in the path

*run from `~/wc` · as provider-owner@bank.com*

```sh
cd ~/wc

./warden-connect/target/release/connect-mediate --help
```

| At connect | At each call |
|---|---|
| 14 gates: signature, alg, expiry, audience, revocation, both peer identities, the pin, posture, zone pair, token binding, issuer, schema, size | `tools/list` filtered to `surface.tools`; rate, spend and concurrency ceilings |

The catalogue filter is the most valuable thing here: the model never sees the tool it is not contracted for, so it cannot be talked into attempting it.

## 13 · Refusals

The first table is every refusal the *GitHub* run of this walkthrough produced, translated to Azure. This guide has not been run against a live tenant, so treat it as the list to expect rather than the list observed.

| Refusal | Cause | Fix |
|---|---|---|
| `src refspec … does not match any` | git | no branch. `git checkout -b` and commit before pushing |
| `WC-1001` *merged onto <empty>* | `$PROVIDER_REPO` was a bare name | the `owner/repo` form. The shim now exits 3 naming it |
| `WC-1001` *merged onto <empty>* | the branch-head sha, not the merge commit | `az repos pr show --id --query lastMergeCommit.commitId` |
| `WC-3025` *registry owner standing in* | registered owner ≠ approving account | owner cannot be changed — owner approves once, or register a new id |
| `WC-1001` *not a guarded ref* | the PAT lacked **Policy (read)**, or the only policy on the ref is build validation | export the owner's PAT, and check the policy carries `minimumApproverCount ≥ 1` |
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
| `WC-3027` | the same person approved both sides | here `provider-owner@bank.com` and `consumer-owner@bank.com` differ, so this cannot fire |

## 14 · Checklist

warden-connect · connection control plane for agents. Reference: `docs/07-hld.md`, `docs/08-lld.md`, `docs/use-cases/`. Azure Repos and Bitbucket follow the same shape and are **not** yet verified against a live tenant.
