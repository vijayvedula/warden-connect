# Videos

## The film, vertical — for phones

[`warden-connect-mobile.mp4`](warden-connect-mobile.mp4) · 1080×1920 · 9:16 ·
30 fps · **6:55** · no audio track. Poster:
[`warden-connect-mobile-poster.jpg`](warden-connect-mobile-poster.jpg).

The web presentation *"Why agent connections need a control plane"* as a video a
phone can actually show. Same script, same palette, same figures — three things
change, and all three are about how it is *seen* rather than what it says:

**Re-composed, not letterboxed.** The web stage is 1200×560, a 2.14:1 strip. Fitted
into 9:16 that is a 1080×504 band with 70% of the frame empty and labels eight pixels
tall. Every scene is authored portrait instead, and three of them read *better* for
it — an agent above a service with the in-path check between them is what the request
path actually looks like, which the landscape version had to lay out sideways.

**Captions are the primary channel, and they lead.** Phone video is watched muted, so
the narration is 56 px serif — and it sits at the **top** of the frame, where reading
starts, with the picture beneath it. The chapter name, which used to hold that spot, is
now a quiet footer: it orients, it does not lead. The test it is built to pass: sound
off, picture ignored, script still lands.

**Read first, then watch.** Every content shot is **10 seconds**: the sentence is on
screen *alone* for the first five, and only then does the picture cross-fade in and
hold for five. A viewer is never asked to read and watch at the same time, and because
every shot is the same length the rhythm stops being something to wonder about. The
cross-fade is the same frame drawn with and without the stage, blended — so the text
does not flicker when the picture arrives.

**Fixed pacing.** The web version has a transport bar and is self-paced; this cannot
be. Shot length is now a constant `SHOT = 10.0` rather than a reading estimate. The
per-caption estimates are still computed and still in the source, so returning to
text-length pacing is a one-line change in `Video.scene`.

**A scene builds; it never fades itself out.** `p` completes at the end of the build,
not the end of the shot, so a scene that faded itself at `p → 1` went dark for the
entire still. The title did exactly that and left **3.8 seconds of blank frame** at the
head of the film. The shot shape owns both edges; scenes only build.

**Every shot is a build, a still, and a dip.** The animation completes in the first
two thirds; the last third is the *same frame*, held. The first cut animated across
the whole shot and cut on the final frame of the build, which meant the finished
slide was never actually on screen — the viewer was always reading something
mid-assembly. The still is carved out of the existing duration rather than added to
it, so almost all of it is free; only a flat 0.3 s per shot is new, and that is the
part that lets a slide land before the next one arrives.

The cut itself is a short dip through the **page colour**, not through black. Blending
toward the ground means the content fades and the ground stays put, which reads as a
soft cut rather than a dropped frame — and on a dark single-theme film there is
nothing for a black flash to hide behind.

**And the shot arrives, rather than appearing.** The dip tells you a shot ended; it
does not tell you a new one has your attention. Each shot now eases up from 0.945 while
it builds and drifts to 1.045 as it fades, so a section pushes in, sits **dead still**
while it is read, then recedes. The push-in overlaps the build and so costs no runtime;
only the longer fade-out does, and that is added on top of the still rather than taken
out of it — which is why the film grew by ten seconds and the reading time per slide
did not shrink by a frame. The 1.045 ceiling is set by the safe margins: it crops 41 px
top and bottom, and nothing meaningful is drawn there.

Platform-safe margins throughout: feed UI covers roughly the top 8% and bottom 12% of
a 9:16 frame, and nothing that carries meaning goes there.

```sh
cd ../src && python3 film_mobile.py
cp out/warden-connect-mobile.mp4 ../video/
```

### It opens by asking, not explaining

*Four Questions With No Owner* — the chapter that has to work hardest, because
everything after it is a solution to a problem the viewer has not yet agreed exists.

Two earlier versions got the audience wrong. The first stated facts about software;
the second (*Software Used To Be Predictable*) argued that agents are
non-deterministic and that the old assumption had died. Both are lectures, and anyone
already operating an agent estate has heard them. The audience for this film is
experienced: they do not need to be told what an agent is, and being told is a reason
to stop watching.

So the chapter argues nothing. It asks four questions about the viewer's **own
estate** and, each time, draws the empty slot where the answer should be. An
experienced viewer supplies the argument themselves, which is the only way they will
accept it.

0. **The three controls you already run.** Identity, policy, audit — each drawn
   solid, each ticked, because each of them works. Beneath them, a bordered region
   with nothing in it: *nothing owns this one.*
1. **Which of these parties are allowed to talk to each other at all?** Twelve edges
   across a small mesh, every one identical. One is picked out and marked with a
   question mark — not *can* it, but *is it permitted*, and no system holds the answer.
2. **Who approved that, when, and against what justification?** An approval record
   with three fields — WHO, WHEN, WHY — and a dashed empty rule where each value
   should be. The ticket was closed; the approver changed teams.
3. **What is the most this connection could ever do?** The policy engine
   misconfigured, the token over-scoped, the agent compromised — three red crosses —
   and then the ceiling that remains: *everything the callee exposes.* This is the
   contract-as-ceiling argument stated negatively, before the idea has a name.
4. **When something goes wrong, what else did that party reach?** One agent turns
   red, its reachable set resolves to question marks, and the counter reads
   `REACHED: ?`

### The scenes are portrait-native, not portrait-fitted

The first attempt moved the web version's figures around and some of them never
fitted. A forty-node network and a thirteen-lane array are **wide** ideas; a 936 px
stage gives them 78 px of separation, which is a smudge on a phone. So the second
attempt threw the compositions away and built five motifs for a tall frame instead —
each used more than once, so the film has a vocabulary rather than a scene-by-scene
scramble.

| Motif | Replaces | Why it suits a tall frame |
|---|---|---|
| **plane** — a boundary seen almost edge-on | two columns side by side | The layers can be *stacked*, which is what they are, with one call descending through both. It is the only composition that makes "neither can widen the other" self-evident |
| **threads** — cables running down the frame | the node graph | A tall frame has depth rather than breadth, so the mess is expressed as *crossing*. Forty-four cables that drift laterally read as a tangle at any size |
| **wall** — a barrier with one door | nine lanes bending sideways | You can see the whole width of the wall and the single door in it, and the traffic that bows out to the margins to get past |
| **document** — the contract as a page | a card of bullet points | A signed document is already a portrait shape. It carries three scenes: the idea, the ceiling, and all five readings |
| **readout** — a vertical status list | thirteen ticks in a row | Thirteen ticks across 936 px is thirteen specks. Thirteen rows down a tall frame is the status page an operator actually reads at 03:00 |

Two of these do double duty as an argument. The cables appear twice — red and
crossing in *The Connection*, then the same forty-four green and parallel in *On the
Path*. Nothing about the number changed, only whether anybody knows what they are,
and that is the whole pitch in one cut. And the five role readings are now **one
document with a different field group lit each time**, rather than five cards: the
section's claim is *the same artifact, read five ways*, so it should be visibly the
same artifact.

### The five readings are five pictures

One document with a different row lit was conceptually tidy and visually five
identical slides. Each role cares about a genuinely different property of the same
object, so each gets the image that states its property in a glance — and the caption
becomes confirmation rather than explanation.

The test each one is built to pass: **cover the caption and the slide still says which
role it is for.**

| Role | The image | Why it is the right one |
|---|---|---|
| **Group Chief Architect** | Three systems stacked with **no line between them**, and one artifact in its own column that all three read | The message is an *absence*. Drawing the missing connectors is what "not a shared library, cluster or release train" looks like |
| **AI / Agent Architect** | The same tool description on **Tuesday and Friday**, one clause different, two different digests | Nine-into-two is the headline everyone quotes; the hash is the part only this role cares about, and it needs the one image nothing else in the film uses |
| **CTO** | **Twenty-one day-marks against one**, and `MANIFESTS CHANGED 0` | The asymmetry *is* the argument. Nothing has to be read for it to land |
| **CIO** | Three columns of acknowledgements, one stopping early, with a **measurement bracket around the empty space** | The idea is that a missed update is a number, not an absence — so the picture has to show the absence with a measurement on it |
| **CISO** | The blast radius as an actual radius — agent, three services, nine downstream — then **one red line cutting every edge at once** | Blast radius and the kill switch are the same picture, which is the point: you see the cost before you pay it |

Two of the chapter motifs do the same double duty. The cables appear twice — red and
crossing in *The Connection*, then the same forty-four green and parallel in *On the
Path*. Nothing about the number changed, only whether anybody knows what they are,
and that is the whole pitch in one cut.

### What the frames taught, which is the useful part

Every one of these was invisible in the code and obvious in a still. The habit worth
keeping is extracting frames and *looking at them* — the same habit that found five
defects in the Rust this week.

- **A four-second blank stage that the code said was fine.** The scene functions get
  progress across the whole *chapter*, and two of them faded in against that raw
  value instead of converting it with `sub()`. At beat 0 of a nine-beat chapter that
  is `p ≈ 0.05`, so the planes drew at 3% alpha. The code read correctly and the
  frame was empty.
- **And then the opposite mistake.** Fixed to fade per beat, the stage went blank at
  *every* cut inside a chapter. Consecutive beats share a scene, so the stage fades
  in once — keyed to beat 0 — while only the thing being demonstrated restarts.
- **Text over line art is a smudge.** Labels landed on the very cables they
  described. `Canvas.plate()` puts them on an opaque ground; red serif over a red
  11 px stroke has no contrast ratio that saves it.
- **Paint order is not source order in your head.** The `AGENT` label got its plate,
  and then the link line was drawn *after* it, straight back through the text.
- **A reveal that lags its own caption reads as a bug.** The caption said "Four." and
  the fourth bar was still at 2% opacity, because a stagger tuned to finish by the
  end of a beat is invisible at the start of it. Builds now land in the first third.
- **The font guard earned its keep again.** The narrowing diagram was drawn with `∩`,
  and the mono face has no U+2229 — caught before a frame was rendered rather than
  discovered as three missing symbols. Replaced with "narrowed by", which is plainer
  on a phone anyway.
- **Ninety-six cables were worse than forty-four.** The dense version filled the
  frame with a flat red mesh; halving the count and staggering the endpoints made it
  a tangle. More is not busier, it is flatter.
- **A capped label list measured no faster than an uncapped one**, so that complexity
  never got written. Measuring first is how you avoid building things.
- **A label centred on the frame is not centred on the thing it describes.** The
  CIO figure's `LAG 4m 12s` measured the right-hand column and sat over the middle
  one, because `plate()` always centres on the frame. `plate_at()` takes an x.
- **Three arrows pointing at where an object used to be say the opposite of the
  intended thing.** The architect's read-lines were drawn to a moving artifact, so two
  of them addressed empty space — "they never agree" rather than "they agree on one
  object". A dotted spine at the artifact's own column fixed the sentence.
- **An early return keyed to a fade, not to a beat.** The hop chain's block returned
  when its fade was non-zero — and `sub()` reads 1 for every *later* beat too, so the
  chain stayed on screen through the closing beat and the two questions never drew at
  all. Gated on the beat instead.
- **A fixed offset under wrapped text puts a rule through it.** The second question
  wraps to two lines, so its bracket landed on the second line. `centred()` already
  returns the y after the last line; use it.
- **A shrinking container does not shrink its contents.** `document()` spaces its
  rows by `(height - 150) / rows`, so when the page collapsed to a lintel that became
  12 px of step for 25 px type — eight lines of contract in an unreadable pile. The
  rows now fade at better than twice the shrink rate, so they are gone before the
  spacing gets tight. Found only because a longer hold meant the frame was on screen
  long enough to notice.
- **The same number twice is one number wasted.** The CISO slide showed
  `12 / 13 confirmed` in both the figure and the tagline; the figure now carries the
  half people do not expect — *nothing is assumed successful*.

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
