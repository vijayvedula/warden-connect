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

# ---------------------------------------------------------------------------
# Portrait-native motifs
# ---------------------------------------------------------------------------
# The first cut of this film took the web version's figures and moved them about.
# Some of them never fitted: a forty-node network and a thirteen-lane array are
# *wide* ideas, and a 936px-wide stage gives them 78px of separation, which is a
# smudge on a phone. These five motifs are built for a tall frame instead — and
# each is used more than once, so the film has a visual vocabulary rather than a
# scene-by-scene scramble.
#
#   plane      a full-width horizontal boundary, seen slightly edge-on
#   threads    connections as cables descending the frame
#   wall       a barrier across the frame with one door in it
#   document   the contract as what it is — a tall page with a seal
#   readout    a vertical status list, one row per node

STAGE_X0, STAGE_X1 = PAD, W - PAD
STAGE_W = STAGE_X1 - STAGE_X0


def plane(c, y, label, sub_, col, a=1.0, lit=1.0):
    """A boundary, drawn as a plane seen almost edge-on.

    Two offset lines rather than one: a single rule reads as a divider, and a pair
    reads as a surface with a thickness — which is what a boundary is.
    """
    if a <= 0.01:
        return
    c.line((STAGE_X0, y), (STAGE_X1, y), col, a * lit, 4)
    c.line((STAGE_X0 + 26, y + 13), (STAGE_X1 - 26, y + 13), col, a * lit * 0.35, 2)
    # 46px serif set at y-58 has its descender at y-12, which is exactly where the
    # sub-label was. Two lines of type need the height of the first one between them.
    c.text((STAGE_X0, y - 96), label, "serif", 46, col, a * lit)
    c.text((STAGE_X0, y - 34), sub_, "mono", 22, DIM, a * lit * 0.9)


def threads(c, appear, n=44, seed=7, col=RED, a=0.30, lw=2, tangle=1.0, y0=None,
            y1=None):
    """Connections as cables running down the frame.

    This is the replacement for the network graph. A tall frame has room for depth
    rather than breadth, so the mess is expressed as *crossing* — every cable drifts
    laterally on the way down, and forty of them crossing reads as a tangle at any
    size. `tangle=0` gives parallel cables, which is the same picture under control
    and is exactly the contrast chapter four needs.
    """
    y0 = STAGE_Y0 + 40 if y0 is None else y0
    y1 = STAGE_Y1 - 30 if y1 is None else y1
    r = _rand(seed)
    for i in range(n):
        t = clamp(appear * 2.2 - (i / n) * 1.2)
        if t <= 0:
            continue
        # Ends are staggered vertically as well as horizontally. Ninety-six cables
        # between two perfectly straight rows read as a flat mesh, not a tangle — the
        # variation is what makes it look like cabling nobody planned.
        x_top = STAGE_X0 + 14 + r() * (STAGE_W - 28)
        drift = (r() - 0.5) * 700 * tangle
        bow = (r() - 0.5) * 340 * tangle
        x_bot = clamp(x_top + drift, STAGE_X0 + 10, STAGE_X1 - 10)
        jt = r() * 70 * tangle
        jb = r() * 70 * tangle
        # A touch of per-cable weight variation. Forty-four identical strokes read as
        # a barcode; the same forty-four at mixed weights read as cabling.
        wob = lw if r() > 0.45 else max(1, lw - 1)
        prev = None
        steps = 10
        for k in range(steps + 1):
            u = (k / steps) * ease_out(t)
            x = ((1 - u) ** 2 * x_top + 2 * (1 - u) * u * ((x_top + x_bot) / 2 + bow)
                 + u * u * x_bot)
            y = lerp(y0 + jt, y1 - jb, u)
            if prev:
                c.line(prev, (x, y), col, a, wob)
            prev = (x, y)
        c.dot(x_top, y0 + jt, 5, BLUE, t * 0.7)
        if ease_out(t) > 0.98:
            c.dot(x_bot, y1 - jb, 6, DIM, 0.6)


def _rand(seed):
    a = seed & 0xFFFFFFFF

    def nxt():
        nonlocal a
        a = (a * 1103515245 + 12345) & 0x7FFFFFFF
        return a / 0x7FFFFFFF
    return nxt


def wall(c, y, door_x, door_w, a=1.0, col=YELLOW, dim=0.0):
    """A barrier across the frame with one opening.

    Chapter two's traffic used to bend sideways in a narrow frame, which looked
    squashed. A wall you can see the whole width of, with one visible door, says the
    same thing in a shape a phone can hold.
    """
    if a <= 0.01:
        return
    c.rect((STAGE_X0, y, door_x, y + 104), col, a * (1 - dim * 0.55), 3, BG2, r=4)
    c.rect((door_x + door_w, y, STAGE_X1, y + 104), col, a * (1 - dim * 0.55), 3,
           BG2, r=4)


CONTRACT = [
    ("caller", "agent:recon", "id"),
    ("callee", "server:payments", "id"),
    ("surface", "get_balance", "surface"),
    ("", "list_transactions", "surface"),
    ("expires", "30 days, then nothing", "expiry"),
    ("approval", "human:cecil + human:dana", "approval"),
    ("mediator", "warden:mediator:apac", "mediator"),
    ("revocable", "one verb, per-node proof", "revoke"),
]


def document(c, top, height, a=1.0, written=1.0, highlight=None, seal=1.0):
    """The contract, drawn as the thing it is: a page.

    A signed document is already a portrait shape, which is why it carries three
    scenes here. `highlight` dims every field group except one — which is how the
    five readings are shown, on one object, without drawing five different pictures.
    """
    if a <= 0.01:
        return
    x0 = STAGE_X0 + 64
    x1 = STAGE_X1 - 64
    c.rect((x0, top, x1, top + height), YELLOW, a * 0.75, 3, BG2, r=8)
    c.line((x0, top + 74), (x1, top + 74), YELLOW, a * 0.3, 2)
    c.text((x0 + 34, top + 24), "CONNECTION CONTRACT", "mono", 26, YELLOW, a)
    c.text((x1 - 34, top + 24), "conn_7f3a91c4", "mono", 24, DIM, a, anchor="ra")

    rows = len(CONTRACT)
    step = (height - 150) / rows
    for i, (label, value, group) in enumerate(CONTRACT):
        t = clamp(written * (rows + 2) - i)
        if t <= 0:
            continue
        y = top + 104 + i * step
        lit = 1.0 if (highlight is None or group == highlight) else 0.40
        if label:
            c.text((x0 + 34, y), label, "mono", 23, DIM, a * t * lit)
        col = GREEN if group in ("expiry", "revoke") else INK
        c.text((x0 + 210, y), value, "mono", 25, col, a * t * lit)
        if highlight and group == highlight:
            c.line((x0 + 200, y + 34), (x1 - 34, y + 34), YELLOW, a * t * 0.45, 2)
    # the seal: a signature is what makes this an artifact rather than a row
    if seal > 0.01:
        sx, sy = x1 - 84, top + height - 74
        c.ring(sx, sy, 40, YELLOW, a * seal, 3)
        c.ring(sx, sy, 27, YELLOW, a * seal * 0.6, 2)
        c.text((sx, sy - 12), "ES256", "mono", 19, YELLOW, a * seal, anchor="ma")


def readout(c, y0, rows, appear, step=52):
    """A vertical status list — one row per node.

    Thirteen ticks in a row across 936px is thirteen specks. Thirteen rows down a
    tall frame is a status page, which is the thing an operator actually reads at
    03:00 anyway.
    """
    for i, (name, ok, note) in enumerate(rows):
        t = clamp(appear * (len(rows) + 3) * 1.6 - i)
        if t <= 0:
            continue
        y = y0 + i * step
        col = GREEN if ok else RED
        if ok:
            c.tick(STAGE_X0 + 30, y + 4, 13, GREEN, t, 5)
        else:
            c.cross(STAGE_X0 + 30, y + 4, 13, RED, t, 5)
        c.text((STAGE_X0 + 72, y - 12), name, "mono", 26, INK if ok else RED, t)
        c.text((STAGE_X1, y - 12), note, "mono", 24, col, t, anchor="ra")


# ---------------------------------------------------------------------------
# Scenes
# ---------------------------------------------------------------------------

def scene_planes(c, p, beat, n_beats):
    """Two boundaries as two planes, then the five capabilities as full-width bars.

    The web version put the layers side by side. In portrait they can be what they
    actually are: one above the other, with a call descending through both — which
    is also the only picture that makes "neither can widen the other" obvious.
    """
    if beat < 3:
        # `p` is progress across the whole chapter, so a fade written against it is
        # ~0 for the whole of beat 0. Every entry here goes through `sub()`, which is
        # what converts chapter progress into this beat's progress. The first cut of
        # this scene rendered an empty stage for four seconds and the code looked
        # right, which is why the frames get looked at.
        a = smooth(clamp(sub(p, n_beats, 0) * 2.4))
        rel_lit = 1.0 if beat != 1 else 0.3
        act_lit = 1.0 if beat != 2 else 0.3
        plane(c, STAGE_Y0 + 280, "warden-connect", "MAY THESE TWO PARTIES MEET AT ALL",
              YELLOW, a, rel_lit)
        plane(c, STAGE_Y0 + 620, "warden", "MAY THIS CALL PROCEED, RIGHT NOW",
              BLUE, a, act_lit)

        # A call, descending through both. It is stopped by whichever plane is lit.
        # The descending call restarts per beat — it is the thing being demonstrated,
        # unlike the planes, which must simply stay put.
        d = smooth(clamp((sub(p, n_beats, beat) - 0.18) / 0.5))
        top = STAGE_Y0 + 40
        stop = (STAGE_Y0 + 280 if beat == 2 else
                STAGE_Y0 + 620 if beat == 1 else STAGE_Y1 - 30)
        if d > 0:
            c.arrow((W // 2, top), (W // 2, lerp(top, stop, d)), INK, a * 0.8, 4)
        if beat and d > 0.9:
            col = YELLOW if beat == 2 else BLUE
            c.ring(W // 2, stop, 26, col, a, 4)
            c.text((W // 2, stop + 46), "CHECKED HERE", "mono", 24, col, a,
                   anchor="ma")
        if beat == 0:
            c.plate(STAGE_Y1 - 44, "ONE CALL, TWO BOUNDARIES", "mono", 26, DIM, a)
        return

    # Five full-width bars, stacking. Chunky on purpose: a thin ladder rung is a
    # hairline on a phone.
    active = beat - 3
    summing = beat >= n_beats - 1
    for i, (title, cost) in enumerate(LADDER):
        # ×2.4: the caption says "Four." at the start of the beat, so the fourth bar
        # has to be there by then. A build that finishes as the beat ends reads as a
        # frame that failed to draw.
        t = smooth(clamp(((p * n_beats) - (i + 3)) * 2.4))
        if t <= 0:
            continue
        y = STAGE_Y0 + 30 + i * 122
        live = summing or i == active
        a = t * (1.0 if live else 0.34)
        c.rect((STAGE_X0, y, STAGE_X0 + STAGE_W * ease_out(t), y + 104),
               YELLOW if live else RULE, a, 3, BG2 if live else None, r=6)
        c.ring(STAGE_X0 + 56, y + 52, 28, YELLOW, a, 3)
        c.text((STAGE_X0 + 56, y + 52), str(i + 1), "serif", 38, YELLOW, a,
               anchor="mm")
        c.text((STAGE_X0 + 108, y + 14), title, "serif", 46, INK if live else DIM, a)
        c.text((STAGE_X0 + 108, y + 68), cost, "mono", 22, FAINT, a)

    if 0 <= active < len(SNIPS) and not summing:
        inn = smooth(clamp((sub(p, n_beats, active + 3) - 0.16) / 0.26))
        out = smooth(clamp(sub(p, n_beats, active + 4) / 0.22))
        a = inn * (1 - out)
        y = STAGE_Y0 + 660
        c.rect((STAGE_X0, y, STAGE_X1, y + 152), RULE, a, 2, BG2, r=8)
        for k, ln in enumerate(SNIPS[active]):
            col = (YELLOW if ln.startswith("$") else
                   DIM if ln.startswith("  ") else GREEN)
            c.text((STAGE_X0 + 30, y + 34 + k * 56), ln, "mono", 26, col, a)


def scene_threads(c, p, beat, n_beats):
    """One cable, then the frame full of them."""
    ay, sy = STAGE_Y0 + 130, STAGE_Y1 - 110
    if beat < 3:
        fade = 1 - smooth(clamp(sub(p, n_beats, 3) * 1.8))
        g = smooth(sub(p, n_beats, 1))
        bad = smooth(clamp(sub(p, n_beats, 2) * 1.6))
        if g > 0:
            c.line((W // 2, ay + 58), (W // 2, lerp(ay + 58, sy - 112, g)),
                   RED if bad > 0.05 else BLUE, fade * 0.9, int(lerp(6, 14, bad)))
        c.agent(W // 2, ay, 2.0, BLUE, fade)
        c.plate(ay + 108, "AGENT", "mono", 26, DIM, fade, pad=(22, 8))
        c.service(W // 2, sy, 2.0, DIM, fade)
        c.text((W // 2, sy + 138), "PAYMENTS SERVICE", "mono", 26, DIM, fade,
               anchor="ma")
        if bad > 0:
            for k, txt in enumerate(["a shared credential", "no expiry",
                                     "no record it exists"]):
                t = smooth(clamp(bad * 3 - k * 0.7))
                c.plate(ay + 190 + k * 62, txt, "serif", 40, RED, t * fade)
        return

    app = smooth(sub(p, n_beats, 3))
    threads(c, app, n=44, seed=11, col=RED, a=0.32, lw=2)
    b4 = sub(p, n_beats, 4)
    if b4 > 0:
        # A second pass, brighter and pulsing: the same cables, now the problem.
        pulse = 0.30 + 0.26 * math.sin(b4 * 11)
        threads(c, 1.0, n=44, seed=11, col=RED, a=pulse * 0.55, lw=3)
        a = smooth(b4)
        c.plate(STAGE_Y0 + 300, "400+ CONNECTIONS", "serif", 58, RED, a)
        c.plate(STAGE_Y0 + 392, "0 RECORDED ANYWHERE", "serif", 58, RED, a)


def scene_wall(c, p, beat, n_beats):
    """A wall across the frame with one door, and the traffic that goes round it."""
    wy = STAGE_Y0 + 430
    door_x, door_w = W // 2 - 62, 124
    g = smooth(clamp(sub(p, n_beats, 0) * 2.2))
    bend = smooth(sub(p, n_beats, 2))
    dim = smooth(sub(p, n_beats, 3))

    lanes = 9
    for i in range(lanes):
        x = STAGE_X0 + 60 + i * ((STAGE_W - 120) / (lanes - 1))
        through = i == 4
        appear = clamp(g * 2 - i * 0.06)
        if appear <= 0:
            continue
        # The ones that cannot pass bow out to the margins and rejoin below: the
        # wall spans most of the frame, so "around" has to be visible as going wide.
        out = 0.0 if through else bend
        side = -1 if x < W / 2 else 1
        edge = (STAGE_X0 - 40) if side < 0 else (STAGE_X1 + 40)
        col = GREEN if through else BLUE
        a = 0.9 if through else (0.28 + out * 0.34)
        prev = (x, STAGE_Y0 + 30)
        c.dot(x, STAGE_Y0 + 24, 7, BLUE, appear * 0.85)
        for k in range(1, 15):
            u = k / 14
            xx = x + (edge - x) * out * math.sin(u * math.pi) ** 1.4
            yy = lerp(STAGE_Y0 + 30, STAGE_Y1 - 20, u)
            c.line(prev, (xx, yy), col, a, 6 if through else 3)
            prev = (xx, yy)
        c.dot(x, STAGE_Y1 - 16, 8, DIM, appear * 0.7)

    wall(c, wy, door_x, door_w, g, YELLOW, dim)
    if g > 0:
        col = FAINT if dim > 0.5 else YELLOW
        c.text((STAGE_X0 + 34, wy + 32), "APPROVAL GATE", "serif", 40, col, g)
        c.text((W // 2, wy - 76), "ONE DOOR", "mono", 24, col, g, anchor="ma")

    b1 = smooth(clamp(sub(p, n_beats, 1) * 2.2))
    if b1 > 0:
        c.plate(wy + 150, "3 WEEKS  ·  UNCLEAR APPROVER", "serif", 46, RED, b1)
        c.plate(wy + 226, "SHARED CREDENTIAL AT THE END", "mono", 25, DIM, b1)
    if bend > 0.4:
        f = smooth(clamp((bend - 0.4) / 0.6))
        c.plate(STAGE_Y1 - 76, "1 THROUGH  ·  8 AROUND", "serif", 44, RED, f)


def scene_document(c, p, beat, n_beats):
    """The pair becomes a page; the page becomes a ceiling."""
    shrink = smooth(sub(p, n_beats, 3))

    if beat < 2:
        a = smooth(clamp(sub(p, n_beats, 0) * 2.4))
        y = STAGE_Y0 + 260
        c.agent(STAGE_X0 + 150, y, 2.0, BLUE, a)
        c.service(STAGE_X1 - 150, y, 2.0, DIM, a)
        c.line((STAGE_X0 + 214, y), (STAGE_X1 - 240, y), BLUE, a * 0.5, 5)
        b1 = smooth(sub(p, n_beats, 1))
        if b1 > 0:
            c.plate(y + 170, "GOVERN THE RELATIONSHIP", "serif", 48, YELLOW, b1)
        return

    if beat == 2:
        # The page writes itself in, full height. A contract is a portrait object.
        lp = sub(p, n_beats, 2)
        document(c, STAGE_Y0 + 20, 820, 1.0, smooth(clamp(lp * 2.1)), None,
                 smooth(clamp(lp * 2.0 - 0.75)))
        return

    # It becomes the ceiling: shrunk to the top, three apertures beneath it.
    document(c, STAGE_Y0 + 10, lerp(820, 250, shrink), 1.0, 1.0, None,
             1 - shrink * 0.9)
    b4 = smooth(sub(p, n_beats, 4))
    y0 = STAGE_Y0 + 300
    for k, (label, wfrac, col) in enumerate([
            # Words, not set notation: the mono face has no U+2229, which the font
            # guard caught — and "narrowed by" is plainer on a phone regardless.
            ("the contract's ceiling", 1.00, YELLOW),
            ("narrowed by the token's scope", 0.66, BLUE),
            ("narrowed again by policy, per call", 0.38, GREEN)]):
        t = clamp((b4 if beat >= 4 else shrink) * 3.2 - k * 0.6)
        if t <= 0:
            continue
        half = (STAGE_W - 40) * wfrac / 2
        yy = y0 + k * 150
        # An aperture: two bars with a gap, and the beam that gets through it.
        c.rect((STAGE_X0, yy, W // 2 - half, yy + 26), col, t * 0.9, 0, col, r=3)
        c.rect((W // 2 + half, yy, STAGE_X1, yy + 26), col, t * 0.9, 0, col, r=3)
        c.text((W // 2, yy - 44), label, "mono", 26, col, t, anchor="ma")
        if k < 2:
            nxt = [0.66, 0.38][k] * (STAGE_W - 40) / 2
            for sgn in (-1, 1):
                c.line((W // 2 + sgn * half, yy + 26),
                       (W // 2 + sgn * nxt, yy + 150), col, t * 0.35, 2)
    t = clamp((b4 if beat >= 4 else shrink) * 3.2 - 2.4)
    if t > 0:
        c.plate(y0 + 470, "EACH LAYER ONLY NARROWS", "serif", 46, INK, t)


NODES = [("mediator apac-01", True, "0.4s"), ("mediator apac-02", True, "0.6s"),
         ("mediator apac-03", True, "0.9s"), ("mediator emea-01", True, "1.2s"),
         ("mediator emea-02", True, "2.0s"), ("mediator emea-03", True, "3.1s"),
         ("mediator us-01", True, "4.8s"), ("mediator us-02", True, "7.2s"),
         ("mediator us-03", True, "11s"), ("mediator apj-01", True, "19s"),
         ("mediator apj-02", True, "28s"), ("mediator apj-03", True, "41s"),
         ("mediator dc-legacy", False, "UNCONFIRMED")]

TOOLS = [("get_balance", 1), ("list_transactions", 1), ("wire_funds", -1),
         ("create_payee", 0), ("reverse_posting", 0), ("close_batch", 0),
         ("set_limit", 0), ("void_transaction", 0), ("export_ledger", 0)]


def scene_path(c, p, beat, n_beats):
    """Agent, check, service — and the manifest, which is the whole point."""
    if beat >= 4:
        # Containment as a status page, not thirteen specks in a row.
        readout(c, STAGE_Y0 + 40, NODES, smooth(sub(p, n_beats, 4)))
        return

    if beat == 3:
        # The same cables as chapter one, parallel instead of crossing. The contrast
        # is the argument: nothing about the number changed, only whether it is known.
        # The same forty-four cables, parallel instead of crossing. Nothing about
        # the number changed — only whether anybody knows what they are.
        threads(c, smooth(clamp(sub(p, n_beats, 3) * 1.8)), n=44, seed=11,
                col=GREEN, a=0.40, lw=3, tangle=0.13)
        f = smooth(clamp(sub(p, n_beats, 3) * 2.2))
        c.plate(STAGE_Y0 + 320, "EVERY ONE HAS AN OWNER", "serif", 50, GREEN, f)
        c.plate(STAGE_Y0 + 404, "A SCOPE, AND AN EXPIRY", "serif", 50, GREEN, f)
        return

    a0 = smooth(clamp(sub(p, n_beats, 0) * 2.4))
    ay, gyy = STAGE_Y0 + 90, STAGE_Y0 + 250
    c.agent(W // 2, ay, 1.7, BLUE, a0)
    c.shield(W // 2, gyy, 1.7, YELLOW, a0)
    c.text((W // 2, gyy + 92), "IN-PATH CHECK", "mono", 25, YELLOW, a0, anchor="ma")

    # The manifest: nine rows, because "nine offered, two shown" is a list, and a
    # list down a tall frame is the one thing portrait does better than anything.
    b1 = sub(p, n_beats, 1)
    b2 = smooth(sub(p, n_beats, 2))
    if b1 > 0:
        c.text((STAGE_X0 + 20, STAGE_Y0 + 372), "THE SERVICE OFFERS NINE", "mono", 24,
               DIM, smooth(clamp(b1 * 2.2)))
        for i, (name, kind) in enumerate(TOOLS):
            t = smooth(clamp(b1 * 3.2 - i * 0.16))
            if t <= 0:
                continue
            y = STAGE_Y0 + 414 + i * 47
            if kind == 1:
                c.tick(STAGE_X0 + 34, y + 14, 13, GREEN, t, 5)
                c.text((STAGE_X0 + 80, y), name, "mono", 30, GREEN, t)
                c.text((STAGE_X1, y), "IN THE LIST", "mono", 22, GREEN, t,
                       anchor="ra")
            elif kind == -1:
                c.cross(STAGE_X0 + 34, y + 14, 13, RED, t * b2, 5)
                c.text((STAGE_X0 + 80, y), name, "mono", 30,
                       RED if b2 > 0.1 else FAINT, t)
                c.text((STAGE_X1, y), "WC-4002 REFUSED", "mono", 22, RED, t * b2,
                       anchor="ra")
            else:
                c.dot(STAGE_X0 + 34, y + 14, 5, FAINT, t * 0.7)
                c.text((STAGE_X0 + 80, y), name, "mono", 30, FAINT, t * 0.55)
                c.text((STAGE_X1, y), "NOT VISIBLE", "mono", 22, FAINT, t * 0.55,
                       anchor="ra")


SCENES = {0: scene_planes, 1: scene_threads, 2: scene_wall, 3: scene_document,
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
    HILITE = ["id", "surface", "approval", "mediator", "revoke"]
    for pi, (who, head, body, line, col) in enumerate(PERSONAS):
        @v.scene(reading_seconds(head, body))
        def _p(c, p, who=who, head=head, body=body, line=line, col=col, pi=pi,
               hl=HILITE[pi]):
            a = smooth(clamp(p * 4))
            c.eyebrow("Five Readings", a)
            # The same page every time, with one field group lit. Five cards would
            # have been five pictures; this is the claim itself — one artifact, read
            # five ways — and the viewer can see it is the same object.
            document(c, STAGE_Y0 + 10, 520, a, 1.0, hl, 0.8)
            c.text((W // 2, STAGE_Y0 + 570), who, "mono", 28, col, a, anchor="ma")
            c.centred(STAGE_Y0 + 616, head, W - PAD * 2 - 90, "serif", 54, INK, a)
            c.centred(STAGE_Y0 + 730, line, W - PAD * 2 - 120, "mono", 26, col, a)
            for k in range(5):
                x = W // 2 - 68 + k * 34
                c.dot(x, STAGE_Y1 - 20, 7, col if k == pi else RULE,
                      a if k == pi else a * 0.8)
            c.caption("The same artifact, read five different ways.", body, 1.0,
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
    # Every string added by the portrait rewrite. The guard is only worth what it
    # covers, and a rewrite that adds copy without adding it here turns the guard
    # into decoration — which is the failure it was written to prevent.
    strings += ["MAY THESE TWO PARTIES MEET AT ALL",
                "MAY THIS CALL PROCEED, RIGHT NOW", "CHECKED HERE",
                "ONE CALL, TWO BOUNDARIES", "APPROVAL GATE", "ONE DOOR",
                "3 WEEKS  ·  UNCLEAR APPROVER", "1 THROUGH  ·  8 AROUND",
                "CONNECTION CONTRACT", "conn_7f3a91c4", "ES256",
                "THE SERVICE OFFERS NINE", "IN THE LIST", "WC-4002 REFUSED",
                "NOT VISIBLE", "UNCONFIRMED",
                "the contract's ceiling", "narrowed by the token's scope",
                "narrowed again by policy, per call"]
    for label, value, _ in CONTRACT:
        strings += [label, value]
    for name, _, note in NODES:
        strings += [name, note]
    for name, _ in TOOLS:
        strings.append(name)
    n = check_fonts([s for s in strings if s])
    print(f"  font check ok — {n} distinct glyphs across 3 faces")

    v = build()
    secs = v.render()
    mins = int(secs // 60)
    print(f"  {v.path.name}  {W}x{H}  {mins}:{int(secs % 60):02d}  "
          f"({len(v.scenes)} shots)")
