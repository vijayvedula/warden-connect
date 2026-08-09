# Observability: what is emitted, and what to alert on

§8.14 of [08-lld.md](08-lld.md) lists the metric families. This page is the operator's
side of that: where each number comes from, the four alerts the design implies, and the
questions this telemetry deliberately cannot answer.

Written because production-readiness P1 #11 was right that *"observability is a counter set,
not an operable signal"* — seven unlabelled counters on the control plane, and **no
structured decision log on the mediator path at all**, which is the stream an operator
would actually alert on.

---

## Two planes, two collection shapes

|  | Control plane (`connect serve`) | Mediator (`connect-mediate`) |
|---|---|---|
| Metrics | `GET /metrics`, Prometheus text | `--metrics-file PATH`, rewritten every 10 s |
| Decisions | the evidence chain (`connect audit verify`) | one JSON object per line on **stderr** |
| Why | it already has an HTTP listener | it has none, and adding one would add a port, a bind address and an auth decision to a sidecar whose whole argument is that it adds no surface |

The mediator's metrics file is the node-exporter **textfile collector** convention: the
scrape becomes somebody else's problem and this process keeps no socket open.

### The division that matters most

**A healthy control plane tells you nothing about whether calls are succeeding.**
Issuance can be perfectly clean while every call in the estate is refused — a distrusted
revocation feed does exactly that, by design. The only process that knows a call was
denied is the mediator. If you collect one of these two, collect the mediator's.

---

## Control-plane families

Counters are incremented where the thing happens. **Gauges are derived from the projection
at scrape time**, so a number on a dashboard and a number from `connect posture` cannot
disagree — an incrementally-maintained gauge is a second copy of an answer that drifts the
first time a code path forgets, and a drifted gauge is worse than a missing one because it
is believed.

| Family | Type | Labels | Notes |
|---|---|---|---|
| `wc_denials_total` | counter | `code` | every `WC-*` code, so a spike is attributable |
| `wc_admissions_total` | counter | `result`, `kind`, `mode` | |
| `wc_contracts_minted_total` | counter | `approval_mode` | |
| `wc_discovery_queries_total` | counter | `result` | |
| `wc_discovery_throttled_total` | counter | — | answers withheld by the per-asker throttle |
| `wc_reattest_total` | counter | `result` | |
| `wc_drift_total` | counter | `class` | benign vs material |
| `wc_sink_failures_total` | counter | `sink` | |
| `wc_entities` | gauge | `posture`, `lifecycle`, `tier` | the labels are the point: "how many are unattested" |
| `wc_contracts_active` | gauge | `zone_pair`, `tier` | |
| `wc_contracts_expiring` | gauge | `window` = `1h`/`24h`/`7d` | an already-lapsed contract counts in every window |
| `wc_requests_pending` | gauge | — | awaiting a human |
| `wc_chain_length` | gauge | — | evidence rows |
| `wc_anchor_age_seconds` | gauge | — | **liveness, not integrity** — see below |
| `wc_mediator_unconfirmed` | gauge | — | mediators past an order's deadline |
| `wc_revocation_feed_serving` | gauge | — | `0` means nothing this control plane revokes can reach a mediator |
| `wc_revocation_feed_seq` | gauge | — | pair with each mediator's acknowledged sequence for containment lag |
| `wc_contract_ttl_seconds` | histogram | — | buckets at 15 m, 1 h, 1 d, 7 d, 30 d, 90 d |
| `wc_posture_score` | histogram | — | bucket at 85, the `Attested` threshold |
| `wc_mediator_ack_lag_seconds` | histogram | `mediator` | **bucket at 60**, because §7.10 promises estate-wide propagation under 60 s |

`wc_anchor_age_seconds` is read from the anchor file **without verifying the signature**,
because a scrape has no public key and should not do crypto per request. It says
"checkpoints are still being written", which is a liveness signal. It is emphatically not
an integrity signal: it is exactly the number an attacker who could rewrite the chain would
want to look healthy. Integrity is `connect audit verify --anchor-pub`, on a schedule.

The seven original unlabelled series are still served, under `_total` names
(`wc_entities_total`, `wc_contracts_active_total`, …). A renamed metric does not make a
dashboard panel error — it makes it go blank, which is the failure this whole item is
about.

## Mediator families

| Family | Type | Labels |
|---|---|---|
| `wc_decisions_total` | counter | `decision`, `mode`, `code` |
| `wc_filter_failclosed_total` | counter | — |
| `wc_ceiling_breaches_total` | counter | `kind` = `rate`/`spend`/`concurrency` |
| `wc_filter_tools` | gauge | `state` = `exposed`/`hidden` |
| `wc_revocation_trusted` | gauge | — |
| `wc_contracts_held` | gauge | — |
| `wc_verify_duration_seconds` | histogram | `path` = `warm`/`cold` |

`wc_revocation_trusted` exists here and **not** on the control plane, because distrust is
local to a mediator: one that cannot verify the feed refuses everything, and from the
control plane's side that is indistinguishable from a healthy estate with no traffic.

## The decision log

One JSON object per line on stderr:

```json
{"ts":1785312500,"ev":"connect.decision","service.name":"warden-connect",
 "cid":"conn_7f3a91c4","decision":"deny","code":"WC-4002","mode":"enforce",
 "tool":"transfer_funds","caller":"spiffe://org/ns/agents/sa/recon",
 "callee":"spiffe://org/ns/tools/sa/payments","jti":"cx_84be0011","latency_us":412}
```

Three fields carry the weight:

* **`cid`** — the correlation root. `warden-trace` joins on it; so does the evidence chain.
* **`code`** — a `WC-*` code, never prose, so a dashboard can group by it. An allow carries
  `WC-0000`: there is no `Code::OK` in the taxonomy and inventing one would put success and
  failure in the same namespace, making the estate's most common "error" everything
  working.
* **`mode`** — `enforce` or `observe`. Without it, an observe rollout reads as an estate
  under attack on its first day, because producing a finding on every uncontracted call is
  precisely what observe mode is for.

`--decision-log off|notable|all`, default **`notable`**: denials and observe-mode findings
always, allows only on request. A line per allow in front of a busy agent makes the log a
cost centre, and the observable outcome of a cost centre is that somebody switches it off —
at which point the denials are lost too. **Counters are kept at every level**, including
`off`, so turning logging down costs detail rather than visibility.

Tool names are attacker-influenced (§7.8 A4) and are escaped: a newline in one would
otherwise let a single decision forge a second log line claiming an allow.

---

## The four alerts

These are the ones the design implies and nobody had written down.

**They are now a loadable rules file with unit tests**, not snippets on this page:

```sh
promtool check rules deploy/prometheus/alerts.yml        # 9 rules
promtool test rules  deploy/prometheus/alerts_test.yml   # each one proven to fire
```

`check` proves the file parses; **`test` proves an alert fires**, which is the part that
matters — "the rule loaded" is the same half-claim as a control that reads as configured. The
test file also asserts the cases each alert must stay **quiet** for, because an alert that
fires on an idle estate gets muted, and a muted alert is the one you needed. Mutation-checked:
inverting a threshold and removing the "chain is growing" guard both fail the suite.

Writing them found a defect — see *The self-diagnostics* below.

### 1 · Containment is not landing

```promql
# A containment order nobody has confirmed, past its deadline.
wc_mediator_unconfirmed > 0
```
**Severity: page.** *Unconfirmed is not contained.* A quarantine that the register records
as done while a mediator keeps honouring the contract is the single most dangerous state
this system can be in, because every dashboard says the party was cut off.

Runbook: `connect mediators` names which ones. A mediator that has not confirmed is either
down, unreachable, or holding a stale contract set that is still inside its `exp`.

### 2 · Acknowledgement lag is breaching the design's own number

```promql
# §7.10 promises estate-wide propagation under 60 s.
1 - (
  sum(rate(wc_mediator_ack_lag_seconds_bucket{le="60"}[30m]))
  /
  sum(rate(wc_mediator_ack_lag_seconds_count[30m]))
) > 0.01
```
**Severity: ticket.** Not an incident on its own — it is the claim in §7.10 being measured,
and a drift here is what turns the 60-second promise into a number nobody checks. Alert
before the estate needs it to be true.

### 3 · A distrusted revocation set

```promql
wc_revocation_trusted == 0                 # on any mediator
wc_revocation_feed_serving == 0            # on the control plane
```
**Severity: page.** The first means a mediator cannot verify the feed and is therefore
**refusing every connection** — fail-closed working as designed, and indistinguishable from
outside from a broken estate. Expect it to arrive as "the agents are all down".

The second is quieter and worse: the control plane serves no feed at all, so nothing it
revokes can ever reach a mediator. Nothing else on the endpoint would say so.

Runbook: the mediator's decision log carries the code on every refusal; a distrusted feed
denies with `WC-4001` on connections that previously worked. Fix the feed's signature or
its transport — never by disabling the check.

### 4 · A blocking sink is failing

```promql
increase(wc_sink_failures_total[10m]) > 0
```
**Severity: page if the sink is `blocking`, ticket if `fail-safe`.** A blocking sink that
cannot deliver means **the control plane is refusing to issue** — there is no connection
without a recorded trail (§7.8's fail-closed matrix). A fail-safe sink failing means
evidence is being written to the chain and not shipped, which is a retention problem rather
than an availability one.

### Also worth watching

```promql
# The alert that catches a *stopped sweep* rather than a busy estate.
wc_contracts_expiring{window="1h"} > 0 and rate(wc_contracts_minted_total[1h]) == 0

# Checkpoints have stopped being written.
wc_anchor_age_seconds > 3600 and increase(wc_chain_length[1h]) > 0

# A label set is being folded. Not urgent; means a dashboard is losing detail.
increase(wc_obs_series_dropped_total[1h]) > 0

# A metric name is misspelled somewhere in this codebase.
wc_obs_unknown_family_total > 0
```

### The self-diagnostics, and what writing the rules found

Both of those series are **present at zero** on a healthy process. They were not: the
exposition emitted them only once they had a value, which violated this system's own rule —
*a family that appears only once it has a non-zero value cannot be alerted on.*

For a bare `> 0` alert the conditional version happens to work. What it breaks is everything
around it: `rate()` and `increase()` over a series with no prior sample are empty, a dashboard
panel reads "no data" forever, and `absent()` cannot tell a healthy endpoint from one nobody
is scraping. And `wc_obs_unknown_family_total` exists to catch a **misspelled metric name** —
so having it invisible until the mistake happens is that same mistake, one level up. It
survived because nothing had ever evaluated the alert against a live series.

**The cost, stated:** `wc_obs_series_dropped_total` is per-family, so a control plane emits
about 25 zero-valued series for it. Deliberate — the alert annotates with
`{{ $labels.metric }}`, so an aggregate would say detail was being lost without saying where —
and 25 series per process is worth an alert that can be graphed.

---

## Cardinality

Every family is capped at 256 label sets. Past that, a series folds into
`overflow="true"` and `wc_obs_series_dropped_total{metric}` counts what folded.

It **folds** rather than dropping because a silently missing series reads as *zero* on a
dashboard, and an alert that stops firing because its metric stopped existing is the worst
possible outcome of a monitoring change. `wc_contracts_active{zone_pair,tier}` is the family
most likely to reach the cap — it is quadratic in zones — and an estate with thirty zones
should raise it deliberately rather than discover the fold.

## What this cannot tell you

Named because a dashboard panel that is always zero teaches an operator to ignore the panel:

* **`wc_quarantine_duration_seconds`** — needs the interval between a quarantine and its
  clearing. Both events are in the chain; nothing computes the pairing.
* **`wc_standing_share`** (§8.17-Q4 cap utilisation) — the cap is enforced in `cpolicy`, but
  expressing utilisation as one ratio across zone pairs needs a definition nobody has
  written down. Inventing one would put a number on a dashboard that means whatever the
  implementation decided.
* **Whether a mediator is on the path at all.** §7.8 A5's stated residual: enforcement
  requires the mediator to be inline, and that is a deployment property. A mediator that
  was never started emits nothing, and nothing emits nothing either — so absence of the
  mediator's metrics file is itself the signal, and it needs an alert on staleness rather
  than on a value.
