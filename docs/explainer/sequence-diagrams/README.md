# Sequence diagrams — business capability → technical capability

One file per L1 business domain from
[`03-business-capability-matrix.md`](../../03-business-capability-matrix.md), and
**one section per L2 capability** inside it. Each section carries:

1. **The outcome, owner and KPI**, quoted from
   [`03-business-capability-matrix.md`](../../03-business-capability-matrix.md).
2. **The mapping** — the technical capabilities from
   [`04-technical-capability-matrix.md`](../../04-technical-capability-matrix.md)
   that realise it, with each one's failure mode, and the owning component from
   [`07-hld.md`](../../07-hld.md).
3. **One UML sequence diagram** for that capability alone.
4. **What the diagram argues** — the single design decision it exists to show, since
   a diagram that only depicts a happy path is not worth the space.

## Index

| Domain | Intent | File |
|---|---|---|
| **B1** Agent & Tool Estate Management | know what we run | [`B1-estate-management.md`](B1-estate-management.md) · 6 diagrams |
| **B2** Admission & Onboarding | nothing joins unproven | [`B2-admission.md`](B2-admission.md) · 6 diagrams |
| **B3** Connection Governance | relationships have terms and owners | [`B3-connection-governance.md`](B3-connection-governance.md) · 6 diagrams |
| **B4** Exposure & Trust-Zone Management | who may reach whom, across boundaries | [`B4-exposure-and-zones.md`](B4-exposure-and-zones.md) · 5 diagrams |
| **B5** Continuous Assurance | trust decays; re-earn it | [`B5-continuous-assurance.md`](B5-continuous-assurance.md) · 5 diagrams |
| **B6** Containment & Resilience | cut it, fast, provably | [`B6-containment.md`](B6-containment.md) · 5 diagrams |
| **B7** Regulatory Evidence & Reporting | hand the register over | [`B7-regulatory-evidence.md`](B7-regulatory-evidence.md) · 4 diagrams |
| **B8** Consumption & Cost Control | bound the graph, charge it back | [`B8-consumption-and-cost.md`](B8-consumption-and-cost.md) · 4 diagrams |

## Conventions

**Participants** are the seven components of the HLD — `registry`, `admission`,
`broker`, `contract`, `assurance`, `evidence`, `mediator` — plus the actors outside
them. `mediator` is the only data-plane component and the only one that links Warden
core; everything else is control plane. A diagram that shows no mediator is
describing a flow that works in a **control-plane-only** deployment.

**Failure branches are drawn, not implied.** Every `alt` rejection path is quoted
from the "Failure mode" column of the technical matrix, because that column is the
part a reviewer is actually checking.

**Rendering.** The diagrams are authored in Mermaid and **committed as SVG**, with
the source kept beside each one in a collapsed block. [`render.py`](render.py) does
both halves — it reads the source out of the markdown, renders it, and writes the
image back into the same file:

```sh
python3 render.py            # re-render everything after editing a diagram
python3 render.py --check    # render only; non-zero exit if any diagram is broken
```

Run it whenever a diagram changes; the markdown is the source of truth and the
`img/` directory is generated. The rewrite is idempotent, so running it twice is a
no-op rather than a second layer of markup.

Committing images rather than letting GitHub render the Mermaid is deliberate, for
two reasons that are documented at length in `render.py` and summarised here:

- GitHub overlays a **pan/zoom/copy toolbar** on every Mermaid block it renders, and
  there is no way to suppress it from the source.
- Each SVG carries **both themes in one file** — the dark palette lives behind a
  `prefers-color-scheme: dark` media query inside the SVG. The obvious alternative,
  a `<picture>` with a light and a dark source, is broken on GitHub: it rewrites a
  relative `<img src>` to `raw.githubusercontent.com` but leaves a relative
  `<source srcset>` alone, and `<picture>` does not fall back when a matching source
  fails to load. The light rendering is given a white ground so that a viewer which
  ignores the media query gets a legible card rather than dark text on a dark page.

Three syntax traps, all of which produce a *parse failure* rather than a wrong
picture, so run the renderer before committing:

- **`;` is a statement separator.** A semicolon inside note or message text
  truncates the line and fails the parse. Use an em dash.
- **Line breaks are `<br/>`**, not newlines, inside a note or message.
- **Activation is tracked linearly, not per branch.** Deactivating the same
  participant in two arms of an `alt` double-deactivates and fails. Activate before
  the block and deactivate once after it.

**41 diagrams, one per L2 capability.** Every one is rendered before commit, which
is what makes the traps above cheap: they fail the render rather than producing a
wrong picture.
