# Journey videos

Five animated explainers, one per persona in
[`../../06-journey-maps.md`](../../06-journey-maps.md). 1920×1080, 30 fps, H.264,
53 seconds each, no audio track.

| Video | Persona | The line it turns on |
|---|---|---|
| [`j1-agent-developer.mp4`](j1-agent-developer.mp4) | **Priya** — agent developer | Friction budget: **net negative** |
| [`j2-security-architect.mp4`](j2-security-architect.mp4) | **Cecil** — security architect | The approval **is** the enforcement |
| [`j3-secops-analyst.mp4`](j3-secops-analyst.mp4) | **Sam** — SecOps analyst, 03:00 | Explicit non-confirmation |
| [`j4-risk-compliance-officer.mp4`](j4-risk-compliance-officer.mp4) | **Anika** — risk & compliance | A register that declares its gaps |
| [`j5-partner-agent-operator.mp4`](j5-partner-agent-operator.mp4) | **Marcus** — partner operator | Neither side exposes a catalogue |

Each `-poster.jpg` is the title frame, for embedding without autoplay.

## Structure

Six beats, identical across all five so the set reads as a series:

1. **Title** — persona, role, the sentence they would actually say
2. **Today** — the goal, then three lines of the current pain
3. **Stage by stage** — five stages, each striking out *today* and replacing it
   with the mechanism, then landing the metric
4. **Emotional arc** — three words along a line that draws itself
5. **The moment that matters** — the one thing that decides whether the journey
   works at all
6. **Friction budget** — the verdict

## Regenerating

```sh
cd ../src && python3 journeys.py          # all five
cd ../src && python3 journeys.py j3       # one
cp out/*.mp4 ../video/
```

Needs Pillow and ffmpeg, both of which are the only dependencies —
`../src/journeys.py` is a self-contained animation framework (easing, staggered
reveals, a text/rule/strike-through vocabulary) rather than a Manim project. Manim
would be the conventional choice for this visual style; it needs a LaTeX install
that Pillow and ffmpeg do not.

## Two things worth knowing

**Every metric on screen is quoted from `06-journey-maps.md`.** The editorial
choice is *which stages appear* — eight table rows is a document and five is a
video, so the five with the strongest before/after deltas were kept. If a metric
here disagrees with the journey map, the journey map is right.

**The font is Iowan Old Style, and that was not the first choice.** Apple's New
York renders beautifully and **silently drops hyphens, en-dashes and
underscores** — `max_depth` came out as `max depth`, `low-risk` as `low risk`.
Typographically perfect, factually wrong, and invisible unless you read the frame
rather than glance at it. `check_fonts()` in the generator now refuses to render
if any face cannot draw a character it will be asked to, and it runs before a
single frame is drawn.

That failure is worth recording because it is the same species this whole project
keeps defending against: not a mechanism that is *wrong*, but one that **reads as
working and quietly produces the wrong output**. It was found by looking at a
frame, not by the renderer complaining — and the guard exists so the next one does
complain.
