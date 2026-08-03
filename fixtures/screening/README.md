# Screening calibration corpus

Labelled cases for the A4 declared-surface screener (`docs/08-lld.md` §8.7.4),
exercised by `wc-control`'s `screen::calibration` tests.

## Why this exists

`S1`–`S4` are permitted to **block** admission. `S5`–`S8` may only flag. That
split is a precision argument, not a severity one:

> A screener that blocks legitimate tools gets switched off by the team it
> inconveniences, and a switched-off control has zero recall.

So blocking has to be earned against real text. `ScreenRules.calibrated` is the
switch that lets the blocking classes actually block, and it ships **`false`** in
the built-in ruleset. Setting it to `true` is a claim that the ruleset has been
measured on a corpus — this corpus.

## The gate

| Metric | Definition | Role |
|---|---|---|
| **Precision** | `blocks that should block / all blocks` | **Gated.** Target ≥ 0.98. The tests assert **1.0** on the cases here, so any change that introduces a false positive fails CI. |
| **Recall** | `blocks that should block / all cases that should block` | **Measured and printed, never gated.** Optimising recall at the cost of precision is how a screener gets disabled. |

Corpus size target from the LLD is **≥ 400 labelled items**. This corpus is far
smaller, so the built-in ruleset stays uncalibrated and a deployment that flips
`calibrated = true` is asserting it has done the measurement on its own corpus.
`calibration_target_gates_the_default` enforces exactly that relationship.

## Case format

```json
{
  "id": "attack-ssh-key-exfiltration",
  "expect": "pass" | "block",
  "detectors": ["S4"],                      // optional: which must fire
  "estate_names": { "get_balance": "spiffe://…" },   // optional: for S2
  "note": "why this case is in the corpus",
  "tools": [ /* an MCP tools/list array */ ]
}
```

`expect` is the verdict a **calibrated ruleset in enforce mode** must reach.
Cases labelled `pass` may still produce flag-class findings — `S5`–`S8` hits do
not make a case a false positive, only a block does.

## Adding cases

The benign half is the half that matters. Real false positives come from honest
servers that talk about credentials, files, other services and conversation
context because that is genuinely what they do — so prefer cases drawn from
public MCP servers over invented ones, and record where each came from in
`note`.

Every attack case should name the primitive it represents rather than being a
variation on one already present. Twenty phrasings of the same exfiltration
sentence measure nothing.

## Files

| File | Contents |
|---|---|
| `corpus.json` | Labelled cases, versioned by `corpus_version`. |
