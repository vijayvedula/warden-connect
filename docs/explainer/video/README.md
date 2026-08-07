# Videos

## The film, vertical — for phones

[`warden-connect-mobile.mp4`](warden-connect-mobile.mp4) · 1080×1920 · 9:16 ·
30 fps · **2:29** · no audio track. Poster:
[`warden-connect-mobile-poster.jpg`](warden-connect-mobile-poster.jpg).

The web presentation *"Why agent connections need a control plane"* as a video a
phone can actually show. Same script, same palette, same figures — three things
change, and all three are about how it is *seen* rather than what it says:

**Re-composed, not letterboxed.** The web stage is 1200×560, a 2.14:1 strip. Fitted
into 9:16 that is a 1080×504 band with 70% of the frame empty and labels eight pixels
tall. Every scene is authored portrait instead, and three of them read *better* for
it — an agent above a service with the in-path check between them is what the request
path actually looks like, which the landscape version had to lay out sideways.

**Captions are the primary channel, and they are burned in.** Phone video is watched
muted, so the narration is 56 px serif in a fixed band rather than a thin strip under
the figure. The test it is built to pass: sound off, picture ignored, script still
lands.

**Fixed pacing, derived from the words.** The web version has a transport bar and is
self-paced. Here each beat is held for its own reading time — 3.8 words/second,
floored at 2.0 s so short beats do not flash and capped at 4.4 s so long ones do not
stall. A viewer who needs longer can scrub; one who is bored leaves.

Platform-safe margins throughout: feed UI covers roughly the top 8% and bottom 12% of
a 9:16 frame, and nothing that carries meaning goes there.

```sh
cd ../src && python3 film_mobile.py
cp out/warden-connect-mobile.mp4 ../video/
```

### What the frames taught, which is the useful part

Every collision below was invisible in the code and obvious in a still. The habit
worth keeping is extracting frames and *looking at them* — the same habit that found
five defects in the Rust this week.

- **Text over line art is a smudge.** Three labels landed on the very connection
  curves they described. `Canvas.plate()` draws them on an opaque ground; red serif
  over a red 11 px stroke had no contrast ratio that would save it.
- **Paint order is not source order in your head.** The `AGENT` label got its plate,
  and then the link line was drawn *after* it, straight back through the text. The
  scene now draws the line first and everything that must sit on top of it second.
- **Two things fading in the same place is one illegible thing.** *On the Path* drew
  the agent/check/service trio and the forty-connection swarm simultaneously. The
  trio now fades as the swarm arrives.
- **The first cut was 3:45.** Not because there was too much content but because the
  reading-time formula was tuned for a document. Two passes on words-per-second and a
  cap got it to 2:29 with nothing removed.

## Journey videos

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
