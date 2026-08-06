# Explainers

Self-contained HTML pages explaining warden-connect: one hub, one page per use
case, plus the adoption explainer. Each is a single file with inlined CSS and no
external requests — open any of them directly in a browser, or serve the folder.

## The set

| File | Subject |
|---|---|
| [`hub.html`](hub.html) | **Start here.** The two-layer model, all ten use cases, what is built |
| [`adoption.html`](adoption.html) | How an estate adopts this: the five-rung ladder, six team readings, seven topologies |
| [`uc-01.html`](uc-01.html) | Register and admit an internal agent |
| [`uc-02.html`](uc-02.html) | Onboard a tool server and pin its surface |
| [`uc-03.html`](uc-03.html) | Mediated capability discovery |
| [`uc-04.html`](uc-04.html) | Establish a connection — the core loop |
| [`uc-05.html`](uc-05.html) | Cross-organisation federation |
| [`uc-06.html`](uc-06.html) | Detect and respond to surface drift |
| [`uc-07.html`](uc-07.html) | Emergency quarantine |
| [`uc-08.html`](uc-08.html) | Shadow agent and shadow MCP detection |
| [`uc-09.html`](uc-09.html) | Renewal, review and offboarding |
| [`uc-10.html`](uc-10.html) | Regulatory register and evidence export |

## Journey videos

[`video/`](video/) holds five animated explainers, one per persona in
[`../06-journey-maps.md`](../06-journey-maps.md) — 1080p, 53 seconds each, no
audio. Same palette and typography as the pages above. See
[`video/README.md`](video/README.md) for the beat structure and how to regenerate.

Source of truth for the content is [`../05-use-cases.md`](../05-use-cases.md) and
[`../08-lld.md`](../08-lld.md). These pages are a rendering, not a second
specification — if they disagree with the design documents, the design documents
are right and these need regenerating.

## Regenerating

`src/journeys.py` renders the videos (Pillow draws frames, ffmpeg encodes);
`src/gen.py` holds the shared design system and the per-use-case content;
`src/hub.py` builds the hub and patches cross-links. Both write into
`explainers/` beside themselves, so copy the output back here:

```sh
cd src && python3 gen.py && python3 hub.py
cp explainers/*.html ..
```

Editing the HTML directly works but means editing eleven copies of the same CSS.
The generator exists so the set stays one system rather than eleven pages that
happen to look alike.

### The cross-links are baked in

Pages link to each other by absolute URL, patched in at generation time. The URLs
currently in the files point at the published artifacts:

| Page | URL |
|---|---|
| hub | `https://claude.ai/code/artifact/6be42646-5d68-4880-ab65-6594568d263b` |
| uc-01 | `https://claude.ai/code/artifact/9b4d20c2-b93d-4f2e-93fd-d13e3f79ec97` |
| uc-02 | `https://claude.ai/code/artifact/b0f2726c-b781-42d6-b343-486cbc17fb32` |
| uc-03 | `https://claude.ai/code/artifact/5ae9cb75-cff5-4915-ae6f-efc09f6a78ef` |
| uc-04 | `https://claude.ai/code/artifact/bc4e07dd-4e1a-4e7f-96d3-2ac97945fdad` |
| uc-05 | `https://claude.ai/code/artifact/a0e167be-a069-4a7d-8b04-768df8323907` |
| uc-06 | `https://claude.ai/code/artifact/f8444df4-f4de-4a21-b60a-447b3b4b42af` |
| uc-07 | `https://claude.ai/code/artifact/c1643853-4902-4859-a69e-004702d2505a` |
| uc-08 | `https://claude.ai/code/artifact/d7ada431-ced2-48d9-9f5e-6af16f512899` |
| uc-09 | `https://claude.ai/code/artifact/dc803f6c-199b-4eef-971a-7408da20cc4d` |
| uc-10 | `https://claude.ai/code/artifact/83a9ab75-0e86-4d40-9cfa-4fdf2e26b62f` |

To serve them from somewhere else, set the URL maps in `src/hub.py` to relative
filenames (`uc-01.html` and so on) and regenerate. Left absolute deliberately:
these are meant to be shared as links, and a relative href in a page somebody
emailed goes nowhere.

## Design notes

**Warden core appears on every page**, not only the hub. Each use case has a
*where the boundary is* section, and every step in every flow carries a badge
saying which layer owns it — brass for warden-connect, teal for Warden core. Most
confusion about this system is somebody expecting one layer to answer the other's
question, so the pages answer it before it is asked.

**The exception paths get their own band.** A main flow describes the day
everything works. The `A1`/`A2`/`A3` paths describe the days that decide whether
anyone keeps the thing switched on, which is where the design actually lives.

**One shared design system.** Same palette, type scale and components across all
twelve pages, generated from one script. A documentation set should read as one
system rather than as pages that happen to share a subject.

**Both themes, no external requests.** The pages follow the reader's light/dark
preference and inline everything — no font CDN, no analytics, no remote images.
Safe to open from a filesystem, attach to an email, or serve from an air-gapped
host.
