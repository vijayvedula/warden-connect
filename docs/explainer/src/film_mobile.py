#!/usr/bin/env python3
"""Render the warden-connect film as a vertical video for phones.

1080x1920, 9:16, 30 fps, H.264, no audio track.

Source is the web presentation "Why agent connections need a control plane" — the
same script, the same palette, the same figures. What changes is everything about
how it is *seen*:

* **Re-composed, not letterboxed.** The web stage is 1200x560, a 2.14:1 strip. Fit
  into 9:16 that is a 1080x504 band with 70% of the frame empty, and the labels land
  at eight pixels tall. Every scene here is authored portrait instead. Three of them
  read better for it — an agent above a service with the check between them is what
  the path actually looks like.
* **Captions are the primary channel, and they are burned in.** Phone video is
  watched muted, so the narration is 56px serif in a fixed band rather than a thin
  strip under the figure. If the video is watched with the sound off and the picture
  ignored, the script still lands.
* **Platform-safe margins.** Feed UI covers roughly the top 8% and bottom 12% of a
  9:16 frame. Nothing that carries meaning goes there.

Timing is fixed rather than self-paced: a beat is held for a reading time derived
from its own word count, floored and capped, so long beats get the room they need and
short ones do not drag.

Shares `check_fonts` and the easings with `journeys.py`. The palette and the frame
differ, so `Canvas` does not.
"""
import math
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw

from journeys import check_fonts, clamp, ease_out, ease_in_out, font, hold, stagger

OUT = Path(__file__).parent / "out"
OUT.mkdir(exist_ok=True)

W, H, FPS = 1080, 1920, 30

# --- palette: the presentation's, unchanged --------------------------------
BG = (0x0d, 0x11, 0x17)
BG2 = (0x12, 0x18, 0x1f)
INK = (0xe9, 0xed, 0xf2)
DIM = (0x8a, 0x94, 0xa3)
FAINT = (0x56, 0x5f, 0x6d)
RULE = (0x23, 0x2b, 0x35)
BLUE = (0x5b, 0xc5, 0xe0)
YELLOW = (0xf3, 0xc9, 0x69)
GREEN = (0x7f, 0xc9, 0x7f)
RED = (0xf2, 0x6b, 0x5b)

# --- layout zones ----------------------------------------------------------
# Chosen against a phone in a feed, not against a design grid.
PAD = 72
TOP_SAFE = 150          # feed chrome lives above this
EYEBROW_Y = 168         # the chapter title
STAGE_Y0, STAGE_Y1 = 262, 1120
CAP_Y = 1188            # narration band, the part that must survive muting
PROG_Y = 1636
MARK_Y = 1706
BOT_SAFE = 1790         # nothing meaningful below


def blend(fg, a, bg=BG):
    a = clamp(a)
    return tuple(int(bg[i] + (fg[i] - bg[i]) * a) for i in range(3))


def lerp(a, b, t):
    return a + (b - a) * t


def smooth(t):
    """manim's default rate function, as the web version uses."""
    t = clamp(t)
    return t * t * t * (t * (t * 6 - 15) + 10)


def sub(p, n, i):
    """Local progress of beat i, given global progress p over n beats."""
    return clamp(p * n - i)


class Canvas:
    def __init__(self):
        self.im = Image.new("RGB", (W, H), BG)
        self.d = ImageDraw.Draw(self.im)

    # -- type ---------------------------------------------------------------
    def text(self, xy, s, kind="serif", size=44, fill=INK, a=1.0, anchor="la"):
        if a <= 0.01:
            return
        self.d.text(xy, s, font=font(kind, size), fill=blend(fill, a), anchor=anchor)

    def lines(self, s, width, kind="serif", size=44):
        f = font(kind, size)
        out, line = [], ""
        for word in s.split():
            trial = f"{line} {word}".strip()
            if self.d.textlength(trial, font=f) <= width:
                line = trial
            else:
                out.append(line)
                line = word
        if line:
            out.append(line)
        return out

    def centred(self, y, s, width, kind="serif", size=44, fill=INK, a=1.0,
                leading=1.30):
        """Word-wrapped and centre-aligned. Returns the y after the last line."""
        if a <= 0.01:
            return y
        step = int(size * leading)
        for i, ln in enumerate(self.lines(s, width, kind, size)):
            self.text((W // 2, y + i * step), ln, kind, size, fill, a, anchor="ma")
        return y + len(self.lines(s, width, kind, size)) * step

    # -- primitives ---------------------------------------------------------
    def line(self, p1, p2, fill=RULE, a=1.0, w=2, dash=None):
        if a <= 0.01:
            return
        col = blend(fill, a)
        if not dash:
            self.d.line([p1, p2], fill=col, width=w)
            return
        (x1, y1), (x2, y2) = p1, p2
        total = math.hypot(x2 - x1, y2 - y1)
        if total < 1:
            return
        on, off = dash
        t = 0.0
        while t < total:
            t2 = min(t + on, total)
            self.d.line([(lerp(x1, x2, t / total), lerp(y1, y2, t / total)),
                         (lerp(x1, x2, t2 / total), lerp(y1, y2, t2 / total))],
                        fill=col, width=w)
            t = t2 + off

    def rect(self, xy, outline=RULE, a=1.0, w=2, fill=None, r=6):
        if a <= 0.01:
            return
        self.d.rounded_rectangle(
            xy, radius=r,
            fill=None if fill is None else blend(fill, a),
            outline=None if outline is None else blend(outline, a), width=w)

    def dot(self, x, y, r, fill=INK, a=1.0):
        if a <= 0.01:
            return
        self.d.ellipse((x - r, y - r, x + r, y + r), fill=blend(fill, a))

    def ring(self, x, y, r, fill=INK, a=1.0, w=2):
        if a <= 0.01:
            return
        self.d.ellipse((x - r, y - r, x + r, y + r), outline=blend(fill, a), width=w)

    def arrow(self, p1, p2, fill=INK, a=1.0, w=3):
        if a <= 0.01:
            return
        self.line(p1, p2, fill, a, w)
        ang = math.atan2(p2[1] - p1[1], p2[0] - p1[0])
        for s in (-0.42, 0.42):
            self.line(p2, (p2[0] - math.cos(ang + s) * 22,
                           p2[1] - math.sin(ang + s) * 22), fill, a, w)

    def cross(self, x, y, r, fill=RED, a=1.0, w=6):
        self.line((x - r, y - r), (x + r, y + r), fill, a, w)
        self.line((x + r, y - r), (x - r, y + r), fill, a, w)

    def tick(self, x, y, r, fill=GREEN, a=1.0, w=6):
        self.line((x - r, y), (x - r * 0.25, y + r * 0.8), fill, a, w)
        self.line((x - r * 0.25, y + r * 0.8), (x + r, y - r * 0.8), fill, a, w)

    # -- the cast -----------------------------------------------------------
    def agent(self, x, y, s, fill=BLUE, a=1.0):
        if a <= 0.01:
            return
        self.rect((x - 30 * s, y - 24 * s, x + 30 * s, y + 24 * s), fill, a,
                  max(2, int(4 * s)), r=int(8 * s))
        self.dot(x - 11 * s, y - 2 * s, 5 * s, fill, a)
        self.dot(x + 11 * s, y - 2 * s, 5 * s, fill, a)
        self.line((x, y - 24 * s), (x, y - 44 * s), fill, a, max(2, int(4 * s)))
        self.dot(x, y - 48 * s, 5.5 * s, fill, a)

    def service(self, x, y, s, fill=DIM, a=1.0):
        if a <= 0.01:
            return
        self.rect((x - 44 * s, y - 52 * s, x + 44 * s, y + 52 * s), fill, a,
                  max(2, int(4 * s)), r=int(8 * s))
        for i in (1, 2, 3):
            yy = y - 52 * s + 26 * s * i
            self.line((x - 30 * s, yy), (x + 30 * s, yy), fill, a * 0.45,
                      max(1, int(3 * s)))

    def shield(self, x, y, s, fill=YELLOW, a=1.0):
        if a <= 0.01:
            return
        w, h = 34 * s, 42 * s
        pts = [(x - w, y - h * 0.7), (x, y - h), (x + w, y - h * 0.7),
               (x + w * 0.7, y + h * 0.5), (x, y + h), (x - w * 0.7, y + h * 0.5)]
        self.d.line(pts + [pts[0]], fill=blend(fill, a), width=max(2, int(5 * s)),
                    joint="curve")

    def plate(self, y, s, kind="serif", size=46, fill=INK, a=1.0, pad=(30, 14)):
        """Centred text on an opaque ground.

        Necessary rather than decorative: three of these labels land on top of forty
        connection curves, and antialiased serif over a thicket of 3px lines is
        unreadable at phone size no matter what the contrast ratio says.
        """
        if a <= 0.01:
            return
        f = font(kind, size)
        tw = self.d.textlength(s, font=f)
        self.d.rounded_rectangle(
            (W // 2 - tw / 2 - pad[0], y - pad[1], W // 2 + tw / 2 + pad[0],
             y + size + pad[1]), radius=6, fill=BG)
        self.text((W // 2, y), s, kind, size, fill, a, anchor="ma")

    # -- furniture ----------------------------------------------------------
    def eyebrow(self, s, a=1.0):
        if a <= 0.01:
            return
        self.text((W // 2, EYEBROW_Y), s, "serif", 46, YELLOW, a, anchor="ma")
        f = font("serif", 46)
        tw = self.d.textlength(s, font=f)
        self.line((W // 2 - tw / 2, EYEBROW_Y + 66), (W // 2 + tw / 2, EYEBROW_Y + 66),
                  YELLOW, a * 0.38, 2)

    def caption(self, main, sub_=None, a=1.0, accent=None):
        """The band that has to work with the sound off.

        `accent` maps a substring to a colour, the way the web version's <em> and <b>
        do. Rendered by drawing the line in pieces, because Pillow has no rich text —
        which is fine, and considerably more predictable.
        """
        if a <= 0.01:
            return
        y = CAP_Y
        width = W - PAD * 2 - 40
        for ln in self.lines(main, width, "serif", 56):
            self._accented(y, ln, accent or {}, 56)
            y += int(56 * 1.28)
        if sub_:
            y += 14
            self.centred(y, sub_, width, "sans", 34, DIM, a * 0.92, leading=1.42)

    def _accented(self, y, ln, accent, size):
        f = font("serif", size)
        total = self.d.textlength(ln, font=f)
        x = W // 2 - total / 2
        # Split on the accent phrases, keeping them, so each piece is one colour.
        pieces = [(ln, INK)]
        for phrase, col in accent.items():
            nxt = []
            for txt, c in pieces:
                if c is INK and phrase in txt:
                    head, _, tail = txt.partition(phrase)
                    if head:
                        nxt.append((head, INK))
                    nxt.append((phrase, col))
                    if tail:
                        nxt.append((tail, INK))
                else:
                    nxt.append((txt, c))
            pieces = nxt
        for txt, col in pieces:
            self.d.text((x, y), txt, font=f, fill=col)
            x += self.d.textlength(txt, font=f)

    def progress(self, done, n, within=0.0):
        gap, total_w = 8, W - PAD * 2
        seg = (total_w - gap * (n - 1)) / n
        for i in range(n):
            x = PAD + i * (seg + gap)
            self.d.rounded_rectangle((x, PROG_Y, x + seg, PROG_Y + 7), radius=3,
                                     fill=RULE)
            fill = 1.0 if i < done else (within if i == done else 0.0)
            if fill > 0:
                self.d.rounded_rectangle(
                    (x, PROG_Y, x + max(3, seg * clamp(fill)), PROG_Y + 7),
                    radius=3, fill=blend(YELLOW, 1.0 if i == done else 0.45))

    def mark(self, a=0.5):
        self.text((W // 2, MARK_Y), "warden-connect", "mono", 26, FAINT, a,
                  anchor="ma")


# --- the timeline ----------------------------------------------------------

class Video:
    def __init__(self, path):
        self.path = path
        self.scenes = []

    def scene(self, seconds):
        def deco(fn):
            self.scenes.append((max(1, int(seconds * FPS)), fn))
            return fn
        return deco

    def render(self):
        total = sum(n for n, _ in self.scenes)
        proc = subprocess.Popen(
            ["ffmpeg", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
             "-c:v", "libx264", "-preset", "slow", "-crf", "20",
             # yuv420p and +faststart: what phones and feed players actually decode.
             "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(self.path)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        for count, fn in self.scenes:
            for i in range(count):
                c = Canvas()
                fn(c, i / max(1, count - 1))
                proc.stdin.write(c.im.tobytes())
        proc.stdin.close()
        proc.wait()
        return total / FPS


def reading_seconds(*parts):
    """Hold a beat for as long as it takes to read, floored.

    Phone video gets one pass and no rewind, so the caption sets the pace rather
    than the animation. 3.8 words/second is a brisk silent read, the floor stops
    three-word beats from flashing past, and the ceiling stops the longest ones from
    stalling — a viewer who needs longer can scrub, and one who is bored leaves.
    """
    words = sum(len(p.split()) for p in parts if p)
    return max(2.0, min(4.4, 0.75 + words / 3.8))


# ---------------------------------------------------------------------------
# Content — the presentation's script, verbatim where it fits a phone
# ---------------------------------------------------------------------------

CAPS = {
    "two_layers": [
        ("Two layers, asking two different questions.",
         "One of them you already have.", {}),
        ("Warden answers: may this specific call proceed, right now?",
         "The action boundary — decided every single call.",
         {"Warden": BLUE, "this specific call": YELLOW}),
        ("warden-connect asks what Warden never does: may these two parties "
         "be introduced at all?",
         "The relationship boundary — decided once, and it arrives as five "
         "capabilities.",
         {"warden-connect": YELLOW}),
    ],
    "caps": [
        ("One. Pin the tool surface.",
         "A hash over exactly what was contracted, so a silent change is "
         "detected rather than trusted.", {"One.": BLUE}),
        ("Two. Know what you actually have.",
         "Agents and services, with named owners, in a tamper-evident log.",
         {"Two.": BLUE}),
        ("Three. Turn an approval into an artifact.",
         "Signed, expiring, machine-checkable. Not a ticket.", {"Three.": BLUE}),
        ("Four. Put the contract on the path.",
         "Only contracted tools are visible; everything else is refused before "
         "the service is called.", {"Four.": BLUE}),
        ("Five. Contain the whole estate in one verb.",
         "With per-node proof — and honest reporting when a node cannot confirm.",
         {"Five.": BLUE}),
    ],
    "caps_end": ("Each capability is independently valuable. You can stop on any "
                 "of them.",
                 "And neither layer can ever widen the other.",
                 {"You can stop on any of them.": YELLOW}),
}

LADDER = [
    ("Pin the tool surface", "ONE COMMAND"),
    ("Know what you have", "A PIPELINE STEP"),
    ("Approval as an artifact", "AN ISSUER KEY"),
    ("The contract on the path", "A SIDECAR"),
    ("Contain in one verb", "A SERVICE"),
]

SNIPS = [
    ["$ connect canon tools.json --kind mcp",
     "surface_digest  sha256:230c1f4a..."],
    ["$ connect register agent --card recon.json",
     "    --owner team:payments --zone internal"],
    ["$ connect request --from agent:recon",
     "    --to server:payments --ttl 30d"],
    ['$ connect-mediate --upstream "payments.py"',
     "    --contract contract.jws --observe"],
    ["$ connect quarantine agent:recon",
     "12 / 13 confirmed - 41s - 1 unconfirmed"],
]

PERSONAS = [
    ("GROUP CHIEF ARCHITECT", "A boundary that composes",
     "Two signed artifacts and one identifier. Not a shared library, cluster or "
     "release train.", "no lock-in to our data plane", BLUE),
    ("AI / AGENT ARCHITECT", "A smaller, explicit surface",
     "Tool descriptions are hashed, so a description that changes silently — "
     "where an injection payload lives — is detected rather than trusted.",
     "9 tools offered - 2 in the list", YELLOW),
    ("CTO", "Delivery gets faster",
     "Low-risk access moves from weeks to seconds. Application teams change no "
     "manifests and no configuration.", "3 weeks -> seconds", GREEN),
    ("CIO", "Honest when degraded",
     "Nodes pull with acknowledgement, so a missed update surfaces as measurable "
     "lag rather than as silence.", "a missed pull is lag you can alert on", BLUE),
    ("CISO", "Blast radius, and a kill switch",
     "One dual-controlled command with per-node confirmation. Nodes that cannot "
     "confirm are reported unconfirmed, never assumed successful.",
     "12 / 13 confirmed - 41s", RED),
]

CHAPTERS = ["The Two Layers", "The Connection", "The Obvious Fix", "The Idea",
            "On the Path", "Five Readings", "Plainly"]


# --- the deterministic swarm, re-laid out for a tall frame -----------------

def _swarm():
    def rng(seed):
        a = seed & 0xFFFFFFFF

        def nxt():
            nonlocal a
            a = (a + 0x6D2B79F5) & 0xFFFFFFFF
            t = (a ^ (a >> 15)) * (1 | a) & 0xFFFFFFFF
            t = (t + ((t ^ (t >> 7)) * (61 | t) & 0xFFFFFFFF)) ^ t & 0xFFFFFFFF
            return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296
        return nxt

    r = rng(424242)
    # Portrait: agents in a band across the top, services across the bottom, so the
    # tangle runs down the frame rather than across a strip.
    agents, svcs, links = [], [], []
    for i in range(40):
        agents.append((PAD + 30 + r() * (W - 2 * PAD - 60),
                       STAGE_Y0 + 40 + r() * 210))
    for i in range(11):
        svcs.append((PAD + 50 + (i / 10) * (W - 2 * PAD - 100),
                     STAGE_Y1 - 90 - r() * 60))
    for i, _ in enumerate(agents):
        for _ in range(1 + int(r() * 3)):
            links.append((i, int(r() * len(svcs)), r()))
    return agents, svcs, links


AGENTS, SVCS, LINKS = _swarm()


def draw_swarm(c, appear, colour=None, lw=2):
    n = len(LINKS)
    for i, (ai, si, bow) in enumerate(LINKS):
        t = clamp(appear * n * 1.6 - i * 0.6)
        if t <= 0:
            continue
        ax, ay = AGENTS[ai]
        sx, sy = SVCS[si]
        e = ease_out(t)
        col, a = (colour(i) if colour else (RED, 0.30))
        # A quadratic bow, sampled — Pillow has no quadratic curve primitive.
        cx, cy = (ax + sx) / 2 + (bow - 0.5) * 150, (ay + sy) / 2
        prev = (ax, ay)
        steps = 9
        for k in range(1, steps + 1):
            u = (k / steps) * e
            x = (1 - u) ** 2 * ax + 2 * (1 - u) * u * cx + u * u * sx
            y = (1 - u) ** 2 * ay + 2 * (1 - u) * u * cy + u * u * sy
            c.line(prev, (x, y), col, a, lw)
            prev = (x, y)
    for i, (ax, ay) in enumerate(AGENTS):
        t = clamp(appear * 3 - i / len(AGENTS))
        if t > 0:
            c.dot(ax, ay, 8, BLUE, t * 0.95)
    for sx, sy in SVCS:
        if appear > 0.05:
            c.dot(sx, sy, 10, DIM, clamp(appear * 3))


# ---------------------------------------------------------------------------
# Scenes
# ---------------------------------------------------------------------------

def scene_two_layers(c, p, beat, n_beats):
    """Stacked cards, then the ladder. Side-by-side does not survive 9:16."""
    if beat < 3:
        a = smooth(clamp(p * 1.6))
        # warden-connect on top: it is the subject, and the eye starts there.
        for i, (name, kicker, q, when, col) in enumerate([
            ("warden-connect", "THE RELATIONSHIP BOUNDARY",
             "may these two parties be introduced at all?",
             "DECIDED ONCE - ADOPTED ONE AT A TIME", YELLOW),
            ("warden", "THE ACTION BOUNDARY",
             "may this specific call proceed right now?",
             "DECIDED EVERY CALL - DEPLOYED TODAY", BLUE),
        ]):
            y = STAGE_Y0 + 60 + i * 390
            live = 1.0 if beat == 0 else (1.0 if (beat == 2) == (i == 0) else 0.34)
            aa = a * live
            c.rect((PAD, y, W - PAD, y + 330), col, aa * 0.55, 2, BG2, r=8)
            c.text((W // 2, y + 46), name, "serif", 62, col, aa, anchor="ma")
            c.text((W // 2, y + 132), kicker, "mono", 26, DIM, aa, anchor="ma")
            c.centred(y + 186, q, W - PAD * 2 - 80, "serif", 42, INK, aa)
            c.text((W // 2, y + 286), when, "mono", 22, FAINT, aa, anchor="ma")
        return

    # The ladder: five rungs, arriving one at a time, with the command below.
    active = beat - 3
    summing = beat >= n_beats - 1
    for i, (title, cost) in enumerate(LADDER):
        t = smooth(clamp((p * n_beats) - (i + 3)))
        if t <= 0:
            continue
        y = STAGE_Y0 + 40 + i * 104
        live = summing or i == active
        a = t * (1.0 if live else 0.42)
        c.ring(PAD + 34, y + 26, 26, YELLOW, a, 3)
        c.text((PAD + 34, y + 26), str(i + 1), "serif", 36, YELLOW, a, anchor="mm")
        c.text((PAD + 84, y + 4), title, "serif", 44,
               INK if live else DIM, a)
        c.text((PAD + 84, y + 58), cost, "mono", 22, FAINT, a)
        c.line((PAD, y + 92), (PAD + (W - 2 * PAD) * t, y + 92), YELLOW, a * 0.28, 2)

    if 0 <= active < len(SNIPS) and not summing:
        # One card, cleared before the next arrives, so two never double-expose.
        inn = smooth(clamp((sub(p, n_beats, active + 3) - 0.28) / 0.42))
        out = smooth(clamp(sub(p, n_beats, active + 4) / 0.25))
        a = inn * (1 - out)
        y = STAGE_Y0 + 596
        c.rect((PAD, y, W - PAD, y + 168), RULE, a, 2, BG2, r=8)
        for k, ln in enumerate(SNIPS[active]):
            col = GREEN if ln[0] not in "$ " and k else YELLOW
            if ln.startswith("$"):
                col = YELLOW
            elif ln.startswith("  "):
                col = DIM
            elif k:
                col = GREEN
            c.text((PAD + 34, y + 40 + k * 58), ln, "mono", 27, col, a)


def scene_connection(c, p, beat, n_beats):
    """Agent above, service below — which is what a request actually looks like."""
    zoom = smooth(sub(p, n_beats, 3))
    if beat < 3:
        fade = 1 - smooth(clamp(sub(p, n_beats, 3) * 1.4))
        ay, sy = STAGE_Y0 + 200, STAGE_Y1 - 150

        # The link goes down first, then everything that must sit on top of it.
        # Painted the other way round, the line drew straight through the labels
        # describing it — which is the one thing this beat has to be able to read.
        g = smooth(sub(p, n_beats, 1))
        if g > 0:
            y1, y2 = ay + 62, sy - 118
            bad = smooth(sub(p, n_beats, 2))
            c.line((W // 2, y1), (W // 2, lerp(y1, y2, g)),
                   RED if bad > 0.05 else BLUE, fade * (1.0 if bad > 0.05 else 0.8),
                   int(lerp(5, 11, bad)))

        c.agent(W // 2, ay, 2.1, BLUE, fade)
        c.plate(ay + 118, "AGENT", "mono", 28, DIM, fade, pad=(22, 8))
        c.service(W // 2, sy, 2.1, DIM, fade)
        c.text((W // 2, sy + 145), "PAYMENTS SERVICE", "mono", 28, DIM, fade,
               anchor="ma")

        b2 = sub(p, n_beats, 2)
        if b2 > 0:
            # Plated: these land on the very line they describe, and red serif over
            # a red 11px stroke is a smudge at phone size.
            for k, s in enumerate(["a shared credential", "no expiry",
                                   "no record it exists"]):
                t = smooth(clamp(b2 * 3 - k * 0.7))
                c.plate(ay + 178 + k * 60, s, "serif", 40, RED, t * fade)
        return

    draw_swarm(c, zoom, lw=2)
    b4 = sub(p, n_beats, 4)
    if b4 > 0:
        pulse = 0.35 + 0.3 * math.sin(b4 * 12)
        draw_swarm(c, 1.0, colour=lambda i: (RED, 0.16 + pulse * 0.22), lw=3)
        a = smooth(b4)
        c.plate(STAGE_Y1 - 140, "400+ CONNECTIONS", "serif", 54, RED, a)
        c.plate(STAGE_Y1 - 68, "0 RECORDED ANYWHERE", "serif", 54, RED, a)


def scene_gate(c, p, beat, n_beats):
    """Traffic runs down the frame; the gate is a bar across it."""
    gy = (STAGE_Y0 + STAGE_Y1) // 2
    g = smooth(sub(p, n_beats, 0))
    lanes = 11
    for i in range(lanes):
        x = PAD + 40 + i * ((W - 2 * PAD - 80) / (lanes - 1))
        through = i == 5
        appear = clamp(g * 2 - i * 0.05)
        if appear <= 0:
            continue
        bend = 0.0 if through else smooth(clamp(sub(p, n_beats, 2) * 1.6
                                               - abs(i - 5) * 0.06))
        dodge = (-1 if x < W / 2 else 1) * bend * (170 + abs(i - 5) * 16)
        col = GREEN if through else BLUE
        a = 0.85 if through else (0.30 + bend * 0.32)
        c.dot(x, STAGE_Y0 + 20, 7, BLUE, appear * 0.8)
        prev = (x, STAGE_Y0 + 28)
        for k in range(1, 13):
            u = k / 12
            xx = (1 - u) ** 2 * x + 2 * (1 - u) * u * (x + dodge) + u * u * x
            yy = lerp(STAGE_Y0 + 28, STAGE_Y1 - 20, u)
            c.line(prev, (xx, yy), col, a, 5 if through else 3)
            prev = (xx, yy)
        c.dot(x, STAGE_Y1 - 14, 8, DIM, appear * 0.7)

    if g > 0:
        c.line((PAD, gy), (W - PAD, gy), YELLOW, 0.5, 4, dash=(18, 20))
        dim = smooth(sub(p, n_beats, 3))
        col = FAINT if dim > 0.05 else YELLOW
        c.rect((W // 2 - 190, gy - 78, W // 2 + 190, gy + 78), col,
               g if dim <= 0.05 else 0.7, 4, BG, r=8)
        c.text((W // 2, gy - 52), "APPROVAL", "serif", 46, col, g, anchor="ma")
        c.text((W // 2, gy + 4), "GATE", "serif", 46, col, g, anchor="ma")

    b1 = sub(p, n_beats, 1)
    if b1 > 0:
        f = smooth(b1)
        c.plate(gy - 210, "3 WEEKS", "serif", 56, RED, f)
        c.plate(gy - 132, "UNCLEAR APPROVER", "mono", 26, DIM, f)
        c.plate(gy + 176, "SHARED CREDENTIAL AT THE END", "mono", 26, DIM, f)

    b2 = sub(p, n_beats, 2)
    if b2 > 0.35:
        f = smooth(clamp((b2 - 0.35) / 0.65))
        c.plate(STAGE_Y1 - 56, "1 THROUGH   ·   12 AROUND", "serif", 44, GREEN, f)


def scene_idea(c, p, beat, n_beats):
    """The contract, then the ceiling it describes."""
    lift = smooth(sub(p, n_beats, 3))
    pair_y = lerp(STAGE_Y0 + 210, STAGE_Y0 + 70, lift)
    f0 = smooth(sub(p, n_beats, 0))
    c.agent(PAD + 130, pair_y, 1.7, BLUE, f0 * (1 - lift * 0.55))
    c.service(W - PAD - 130, pair_y, 1.7, DIM, f0 * (1 - lift * 0.55))
    c.line((PAD + 200, pair_y), (W - PAD - 210, pair_y), BLUE,
           f0 * 0.5 * (1 - lift * 0.6), 4)

    b1 = smooth(sub(p, n_beats, 1))
    if b1 > 0 and lift < 0.2:
        c.plate(pair_y + 140, "GOVERN THE RELATIONSHIP", "serif", 46, YELLOW, b1)

    b2 = smooth(sub(p, n_beats, 2))
    if b2 > 0:
        y = lerp(STAGE_Y0 + 380, STAGE_Y0 + 210, lift)
        c.rect((PAD + 30, y, W - PAD - 30, y + 250), YELLOW, b2 * 0.8, 3, BG2, r=8)
        c.text((PAD + 66, y + 34), "CONNECTION CONTRACT", "mono", 24, YELLOW, b2)
        for k, ln in enumerate([
                "caller   agent:recon",
                "callee   server:payments",
                "surface  get_balance, list_transactions",
                "expires  30d - signed - revocable"]):
            t = clamp(b2 * 3 - k * 0.4)
            c.text((PAD + 66, y + 86 + k * 40), ln, "mono", 26,
                   GREEN if k == 3 else INK, t)

    # The narrowing: three bands, each inside the last.
    b4 = smooth(sub(p, n_beats, 4))
    if b4 > 0:
        y0 = STAGE_Y0 + 520
        for k, (label, wfrac, col) in enumerate([
                ("what the contract allows", 1.00, YELLOW),
                ("intersected with the token's scope", 0.72, BLUE),
                ("intersected with policy, per call", 0.44, GREEN)]):
            t = clamp(b4 * 3 - k * 0.55)
            if t <= 0:
                continue
            half = (W - 2 * PAD - 60) * wfrac / 2
            yy = y0 + k * 100
            c.rect((W // 2 - half, yy, W // 2 + half, yy + 74), col, t * 0.85, 3,
                   None, r=6)
            c.text((W // 2, yy + 22), label, "mono", 24, col, t, anchor="ma")
        t = clamp(b4 * 3 - 2.0)
        c.text((W // 2, y0 + 322), "EACH LAYER ONLY NARROWS", "serif", 44, INK, t,
               anchor="ma")


def scene_path(c, p, beat, n_beats):
    """Agent, check, service — stacked. Portrait suits this better than landscape."""
    ay, gyy, sy = STAGE_Y0 + 130, STAGE_Y0 + 420, STAGE_Y1 - 160
    # The trio fades out as the swarm arrives. Drawing both at once put a shield on
    # top of forty connections and neither could be read.
    a0 = smooth(sub(p, n_beats, 0)) * (1 - smooth(clamp(sub(p, n_beats, 3) * 1.5)))
    c.agent(W // 2, ay, 1.9, BLUE, a0)
    c.shield(W // 2, gyy, 1.9, YELLOW, a0)
    c.text((W // 2, gyy + 104), "IN-PATH CHECK", "mono", 26, YELLOW, a0, anchor="ma")
    c.service(W // 2, sy, 1.9, DIM, a0)
    c.text((W // 2, sy + 134), "OFFERS NINE TOOLS", "mono", 26, DIM, a0, anchor="ma")

    b1 = sub(p, n_beats, 1)
    if b1 > 0 and beat < 3:
        rows = [("get_balance", True), ("list_transactions", True),
                ("wire_funds", False)]
        for k, (name, ok) in enumerate(rows):
            t = smooth(clamp(b1 * 2 - k * 0.3))
            if t <= 0:
                continue
            y = sy - 200 + k * 62
            col = GREEN if ok else FAINT
            c.text((PAD + 20, y), name, "mono", 30, col, t)
            c.arrow((W - PAD - 210, y + 14), (W - PAD - 60, y + 14), col, t, 3)
            if not ok:
                b2 = smooth(sub(p, n_beats, 2))
                if b2 > 0:
                    c.cross(W - PAD - 135, y + 14, 20, RED, b2, 6)
                    c.text((PAD + 20, y + 44), "WC-4002  REFUSED HERE", "mono", 22,
                           RED, b2)

    if beat >= 3:
        fade = smooth(sub(p, n_beats, 3))
        draw_swarm(c, fade, colour=lambda i: (GREEN, 0.22), lw=2)
        c.plate(STAGE_Y1 - 132, "EVERY ONE HAS AN OWNER", "serif", 46, GREEN, fade)
        c.plate(STAGE_Y1 - 66, "A SCOPE, AND AN EXPIRY", "serif", 46, GREEN, fade)

    b4 = sub(p, n_beats, 4)
    if b4 > 0:
        f = smooth(b4)
        # Thirteen nodes; twelve tick, one says it could not confirm.
        for i in range(13):
            x = PAD + 30 + i * ((W - 2 * PAD - 60) / 12)
            t = clamp(f * 3 - i * 0.12)
            if t <= 0:
                continue
            y = STAGE_Y0 + 250
            if i == 12:
                c.cross(x, y, 15, RED, t, 5)
            else:
                c.tick(x, y, 14, GREEN, t, 5)
        c.plate(y + 54, "12 / 13 CONFIRMED IN 41s", "serif", 48, GREEN, f)
        c.plate(y + 130, "THE 13th SAYS IT COULD NOT CONFIRM", "mono", 26, RED, f)


SCENES = {0: scene_two_layers, 1: scene_connection, 2: scene_gate, 3: scene_idea,
          4: scene_path}


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def build():
    v = Video(OUT / "warden-connect-mobile.mp4")
    chapter_caps = [CAPS["two_layers"] + CAPS["caps"] + [CAPS["caps_end"]],
                    None, None, None, None]

    CH1 = [("An agent needs to read a customer's balance.", None, {}),
           ("So someone connects it to the payments service.", None, {}),
           ("But look at what that connection actually is.",
            "A credential copied from a wiki page. No expiry. No record anywhere "
            "that it exists.", {}),
           ("Now do that four hundred times.",
            "Different teams, different quarters, nobody keeping a list.", {}),
           ("Which of these is allowed to exist?",
            "Nobody can answer. There is no list to answer from.",
            {"Which of these is allowed to exist?": RED})]

    CH2 = [("The obvious answer is to put a gate in front of it.", None, {}),
           ("But the gate costs three weeks and an unclear approver.",
            "And it hands out a shared credential at the end of it anyway.", {}),
           ("So engineers route around it. Quietly, and quite reasonably.",
            "A control that can be bypassed is a control that will be.",
            {"route around it": RED}),
           ("What if the control made them faster?", None,
            {"What if the control made them faster?": YELLOW})]

    CH3 = [("Start again, with one connection.", None, {}),
           ("Do not try to govern every call. Govern the relationship.", None,
            {"Govern the relationship.": YELLOW}),
           ("Write down what it is allowed to be.", None, {}),
           ("This is not permission to act.",
            "It is a ceiling on what acting could possibly mean.",
            {"not permission to act.": YELLOW}),
           ("Every layer can only narrow the one above it.",
            "Remove any of them and the set gets smaller — never larger.",
            {"never larger": BLUE})]

    CH4 = [("Now put it where the traffic actually is.", None, {}),
           ("The service offers nine tools. The agent is shown two.",
            "The wrong tool cannot be called by accident, because it is not in "
            "the list.", {"shown two": YELLOW}),
           ("A call outside the contract is refused before the service is ever "
            "spoken to.", None, {"refused": RED}),
           ("Four hundred connections again — but now every one has an owner, a "
            "scope and an expiry.", None, {"an owner": GREEN}),
           ("So when one goes bad, containment is a single command.",
            "Twelve of thirteen confirmed in forty-one seconds — and the "
            "thirteenth says it could not confirm, rather than reporting success.",
            {"a single command": YELLOW})]

    chapter_caps[1], chapter_caps[2] = CH1, CH2
    chapter_caps[3], chapter_caps[4] = CH3, CH4

    n_ch = len(CHAPTERS)

    # --- title ---
    @v.scene(3.6)
    def _title(c, p):
        a = smooth(clamp(p * 2.4))
        out = 1 - smooth(clamp((p - 0.86) / 0.14))
        c.text((W // 2, 700), "INTRODUCING", "mono", 30, YELLOW, a * out, anchor="ma")
        c.text((W // 2, 790), "warden-connect", "serif", 104, INK, a * out,
               anchor="ma")
        c.line((W // 2 - 200, 950), (W // 2 + 200, 950), YELLOW, a * out * 0.5, 2)
        c.centred(1010, "The connection control plane for AI agents",
                  W - PAD * 2 - 60, "serif", 44, DIM, a * out)
        c.mark(a * out * 0.6)

    # --- the five chapters ---
    for ci, caps in enumerate(chapter_caps):
        for bi, (main, sub_, accent) in enumerate(caps):
            secs = reading_seconds(main, sub_)

            def make(ci=ci, bi=bi, caps=caps, main=main, sub_=sub_, accent=accent):
                n_beats = len(caps)

                def fn(c, p):
                    # Global chapter progress, so a scene animates across its beats
                    # rather than restarting each one.
                    gp = (bi + p) / n_beats
                    a_in = smooth(clamp(p * 5))
                    c.eyebrow(CHAPTERS[ci], 1.0 if bi else a_in)
                    SCENES[ci](c, gp, bi, n_beats)
                    c.caption(main, sub_, 1.0, accent)
                    c.progress(ci, n_ch, (bi + p) / n_beats)
                    c.mark(0.45)
                return fn
            v.scene(secs)(make())

    # --- the five readings ---
    for pi, (who, head, body, line, col) in enumerate(PERSONAS):
        @v.scene(reading_seconds(head, body))
        def _p(c, p, who=who, head=head, body=body, line=line, col=col, pi=pi):
            a = smooth(clamp(p * 4))
            c.eyebrow("Five Readings", a)
            y = STAGE_Y0 + 150
            c.rect((PAD, y, W - PAD, y + 560), col, a * 0.5, 2, BG2, r=8)
            c.text((W // 2, y + 52), who, "mono", 28, col, a, anchor="ma")
            c.centred(y + 122, head, W - PAD * 2 - 90, "serif", 58, INK, a)
            c.centred(y + 270, body, W - PAD * 2 - 100, "sans", 34, DIM, a,
                      leading=1.44)
            c.line((PAD + 60, y + 486), (W - PAD - 60, y + 486), col, a * 0.35, 2)
            c.text((W // 2, y + 512), line, "mono", 26, col, a, anchor="ma")
            # Which of the five, so the section has a shape.
            for k in range(5):
                x = W // 2 - 68 + k * 34
                c.dot(x, STAGE_Y1 - 30, 7, col if k == pi else RULE,
                      a if k == pi else a * 0.8)
            c.caption("The same artifact, read five different ways.",
                      "Nobody adopts anybody else's workflow. They agree on one "
                      "object.", 1.0,
                      {"five different ways.": YELLOW})
            c.progress(5, n_ch, (pi + p) / 5)
            c.mark(0.45)

    # --- close ---
    CLOSE = [("A signed, expiring contract for every agent-to-service "
              "relationship.",
              "Enforced in the request path, and revocable across the estate in "
              "under a minute with per-node proof that it landed.",
              {"signed, expiring contract": YELLOW}),
             ("A control that reports success while doing nothing is worse than "
              "no control.",
              "Because nobody investigates something that looks fine. In "
              "visibility-only mode it enforces nothing — and says so, loudly.",
              {"worse than no control.": RED}),
             ("One team, one week.",
              "The first two steps need no infrastructure, no budget line and no "
              "approval.", {"One team, one week.": YELLOW})]

    for k, (main, sub_, accent) in enumerate(CLOSE):
        @v.scene(reading_seconds(main, sub_))
        def _c(c, p, k=k, main=main, sub_=sub_, accent=accent):
            a = smooth(clamp(p * 4))
            c.eyebrow("Plainly", a)
            if k == 0:
                y = STAGE_Y0 + 210
                for i, (t, cost) in enumerate(LADDER):
                    tt = clamp(p * 2.2 - i * 0.14)
                    yy = y + i * 96
                    c.ring(PAD + 40, yy, 24, YELLOW, tt, 3)
                    c.text((PAD + 40, yy), str(i + 1), "serif", 32, YELLOW, tt,
                           anchor="mm")
                    c.text((PAD + 92, yy - 20), t, "serif", 42, INK, tt)
                    c.text((PAD + 92, yy + 26), cost, "mono", 22, FAINT, tt)
            elif k == 1:
                gy = STAGE_Y0 + 330
                c.rect((PAD + 40, gy, W - PAD - 40, gy + 150), RED, a * 0.7, 3, BG2,
                       r=8)
                c.text((W // 2, gy + 40), "STATUS: GREEN", "mono", 40, GREEN, a,
                       anchor="ma")
                c.text((W // 2, gy + 96), "ENFORCING: NOTHING", "mono", 32, RED, a,
                       anchor="ma")
                c.cross(W // 2, gy + 260, 40, RED, smooth(clamp(p * 1.6)), 7)
            else:
                c.text((W // 2, STAGE_Y0 + 330), "connect register", "mono", 40,
                       YELLOW, a, anchor="ma")
                c.text((W // 2, STAGE_Y0 + 400), "connect canon", "mono", 40,
                       YELLOW, a, anchor="ma")
                c.line((W // 2 - 240, STAGE_Y0 + 480), (W // 2 + 240,
                       STAGE_Y0 + 480), YELLOW, a * 0.4, 2)
                c.centred(STAGE_Y0 + 520,
                          "A register with owners that can prove it was not "
                          "edited afterwards.", W - PAD * 2 - 80, "serif", 42, INK,
                          a)
            c.caption(main, sub_, 1.0, accent)
            c.progress(6, n_ch, (k + p) / 3)
            c.mark(0.45)

    return v


if __name__ == "__main__":
    # Every string that will reach a glyph, before a frame is drawn. The guard
    # exists because a missing glyph paints nothing rather than raising — see
    # journeys.py, where New York silently ate every hyphen.
    strings = list(CHAPTERS) + ["INTRODUCING", "warden-connect", "AGENT",
                                "PAYMENTS SERVICE", "APPROVAL", "GATE",
                                "3 WEEKS", "UNCLEAR APPROVER",
                                "SHARED CREDENTIAL AT THE END", "1 THROUGH",
                                "12 AROUND", "400+ CONNECTIONS",
                                "0 RECORDED ANYWHERE", "IN-PATH CHECK",
                                "OFFERS NINE TOOLS", "WC-4002  REFUSED HERE",
                                "EVERY ONE HAS AN OWNER", "A SCOPE, AND AN EXPIRY",
                                "12 / 13 CONFIRMED IN 41s",
                                "THE 13th SAYS IT COULD NOT CONFIRM",
                                "GOVERN THE RELATIONSHIP", "CONNECTION CONTRACT",
                                "EACH LAYER ONLY NARROWS", "STATUS: GREEN",
                                "ENFORCING: NOTHING", "connect register",
                                "connect canon", "The connection control plane "
                                "for AI agents", "12345"]
    for a, b, q, wn, _ in [("warden-connect", "THE RELATIONSHIP BOUNDARY",
                            "may these two parties be introduced at all?",
                            "DECIDED ONCE - ADOPTED ONE AT A TIME", 0),
                           ("warden", "THE ACTION BOUNDARY",
                            "may this specific call proceed right now?",
                            "DECIDED EVERY CALL - DEPLOYED TODAY", 0)]:
        strings += [a, b, q, wn]
    for t, cost in LADDER:
        strings += [t, cost]
    for sn in SNIPS:
        strings += sn
    for who, head, body, line, _ in PERSONAS:
        strings += [who, head, body, line]
    for group in (CAPS["two_layers"], CAPS["caps"], [CAPS["caps_end"]]):
        for main, sub_, acc in group:
            strings += [main, sub_ or "", *acc.keys()]
    strings += ["caller   agent:recon", "callee   server:payments",
                "surface  get_balance, list_transactions",
                "expires  30d - signed - revocable",
                "what the contract allows",
                "intersected with the token's scope",
                "intersected with policy, per call",
                "get_balance", "list_transactions", "wire_funds",
                "The same artifact, read five different ways.",
                "Nobody adopts anybody else's workflow. They agree on one object.",
                "A register with owners that can prove it was not edited "
                "afterwards."]
    n = check_fonts([s for s in strings if s])
    print(f"  font check ok — {n} distinct glyphs across 3 faces")

    v = build()
    secs = v.render()
    mins = int(secs // 60)
    print(f"  {v.path.name}  {W}x{H}  {mins}:{int(secs % 60):02d}  "
          f"({len(v.scenes)} shots)")
