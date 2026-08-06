#!/usr/bin/env python3
"""Render the five warden-connect journey videos.

Pillow draws the frames, ffmpeg encodes them. 1920x1080, 30 fps, H.264.

Source of truth is docs/06-journey-maps.md. Every metric on screen is quoted from
it — the editorial choice here is *which* stages appear, because eight table rows
is a document and five is a video.
"""
import math
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).parent / "out"
OUT.mkdir(exist_ok=True)

W, H, FPS = 1920, 1080, 30

# --- palette ---------------------------------------------------------------
# The explainers' dark theme, single-theme on purpose: a video is watched, not
# read in a bright room, and offering both would mean shipping two of everything.
GROUND = (21, 24, 22)
INK = (231, 234, 229)
MUTED = (146, 154, 145)
FAINT = (111, 119, 110)
RULE = (47, 53, 47)
BRASS = (216, 166, 62)
TEAL = (100, 179, 189)
ALARM = (224, 112, 90)
SURFACE = (29, 33, 30)

# Iowan Old Style, not Apple's New York. New York renders beautifully and
# **silently drops hyphens, en-dashes and underscores** — `max_depth` came out as
# `max depth`, and "low-risk" as "low risk". Typographically perfect, factually
# wrong, and invisible unless you read the frame. `check_fonts()` below is the
# guard that catches the next one.
FONTS = {
    "serif": "/System/Library/Fonts/Supplemental/Iowan Old Style.ttc",
    "mono": "/System/Library/Fonts/SFNSMono.ttf",
    "sans": "/System/Library/Fonts/SFNS.ttf",
}
_cache = {}


def font(kind, size):
    key = (kind, size)
    if key not in _cache:
        _cache[key] = ImageFont.truetype(FONTS[kind], size)
    return _cache[key]


def check_fonts(strings):
    """Refuse to render if any font cannot draw a character it will be asked to.

    A missing glyph produces blank ink rather than an error, so the corruption is
    invisible in the output — which is the whole reason this exists rather than a
    comment saying "use a font with hyphens".
    """
    chars = {c for s in strings for c in s if not c.isspace()}
    problems = []
    for kind in FONTS:
        f = font(kind, 64)
        for c in sorted(chars):
            if f.getmask(c).getbbox() is None:
                problems.append(f"{kind} cannot render {c!r} (U+{ord(c):04X})")
    if problems:
        raise SystemExit("font check failed:\n  " + "\n  ".join(problems))
    return len(chars)


# --- easing ----------------------------------------------------------------

def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def ease_out(p):
    """Cubic ease-out. Things arrive quickly and settle — the motion that reads
    as deliberate rather than mechanical."""
    p = clamp(p)
    return 1 - (1 - p) ** 3


def ease_in_out(p):
    p = clamp(p)
    return 3 * p * p - 2 * p * p * p


def stagger(p, i, n, overlap=0.55):
    """Per-item progress for a staggered reveal.

    `overlap` keeps items entering while earlier ones are still settling, which is
    what stops a list from feeling like a slideshow.
    """
    if n <= 1:
        return clamp(p)
    span = 1.0 / (n - (n - 1) * overlap)
    start = i * span * (1 - overlap)
    return clamp((p - start) / span)


def blend(fg, bg, a):
    a = clamp(a)
    return tuple(int(bg[i] + (fg[i] - bg[i]) * a) for i in range(3))


def hold(p, up=0.15, down=0.9):
    """Fade in, hold, fade out — for elements that come and go within one beat."""
    if p < up:
        return ease_out(p / up)
    if p > down:
        return 1 - ease_out((p - down) / (1 - down))
    return 1.0


# --- drawing helpers -------------------------------------------------------

class Canvas:
    def __init__(self):
        self.im = Image.new("RGB", (W, H), GROUND)
        self.d = ImageDraw.Draw(self.im)

    def text(self, xy, s, kind="serif", size=40, fill=INK, alpha=1.0, anchor="la",
             spacing=None):
        if alpha <= 0.01:
            return
        self.d.text(xy, s, font=font(kind, size), fill=blend(fill, GROUND, alpha),
                    anchor=anchor)

    def wrap(self, x, y, s, width, kind="serif", size=40, fill=INK, alpha=1.0,
             leading=1.42):
        """Word-wrap to a pixel width. Returns the y after the last line."""
        if alpha <= 0.01:
            return y
        f = font(kind, size)
        words, line, lines = s.split(), "", []
        for w in words:
            trial = f"{line} {w}".strip()
            if self.d.textlength(trial, font=f) <= width:
                line = trial
            else:
                lines.append(line)
                line = w
        if line:
            lines.append(line)
        step = int(size * leading)
        for i, ln in enumerate(lines):
            self.text((x, y + i * step), ln, kind, size, fill, alpha)
        return y + len(lines) * step

    def rule(self, x1, y, x2, fill=RULE, alpha=1.0, w=1):
        if alpha <= 0.01:
            return
        self.d.line([(x1, y), (x2, y)], fill=blend(fill, GROUND, alpha), width=w)

    def vrule(self, x, y1, y2, fill=RULE, alpha=1.0, w=1):
        if alpha <= 0.01:
            return
        self.d.line([(x, y1), (x, y2)], fill=blend(fill, GROUND, alpha), width=w)

    def box(self, xy, fill=SURFACE, outline=RULE, alpha=1.0, r=4):
        if alpha <= 0.01:
            return
        self.d.rounded_rectangle(xy, radius=r, fill=blend(fill, GROUND, alpha),
                                 outline=blend(outline, GROUND, alpha), width=1)

    def chip(self, x, y, s, fill=BRASS, alpha=1.0, size=24, pad=(16, 8)):
        if alpha <= 0.01:
            return x
        f = font("mono", size)
        tw = self.d.textlength(s, font=f)
        box = (x, y, x + tw + pad[0] * 2, y + size + pad[1] * 2)
        self.d.rounded_rectangle(box, radius=(size + pad[1] * 2) // 2,
                                 outline=blend(fill, GROUND, alpha), width=2)
        self.d.text((x + pad[0], y + pad[1]), s, font=f,
                    fill=blend(fill, GROUND, alpha))
        return box[2]

    def strike(self, x, y, s, kind="sans", size=30, fill=MUTED, alpha=1.0, cut=0.0):
        """Muted text with a strike-through that draws itself in as `cut` rises.

        Used for the 'today' column: crossing it out is more legible than fading
        it, because the reader needs to still be able to read what was replaced.
        """
        if alpha <= 0.01:
            return
        f = font(kind, size)
        self.text((x, y), s, kind, size, fill, alpha * (1 - 0.35 * cut))
        if cut > 0.01:
            tw = self.d.textlength(s, font=f)
            self.d.line([(x, y + size * 0.62), (x + tw * ease_out(cut), y + size * 0.62)],
                        fill=blend(ALARM, GROUND, alpha), width=3)

    def bar(self, x, y, w, h, p, fill=BRASS, alpha=1.0):
        if alpha <= 0.01:
            return
        self.d.rounded_rectangle((x, y, x + w, y + h), radius=2,
                                 fill=blend((40, 45, 41), GROUND, alpha))
        if p > 0:
            self.d.rounded_rectangle((x, y, x + max(2, w * clamp(p)), y + h), radius=2,
                                     fill=blend(fill, GROUND, alpha))

    def footer(self, s, alpha=0.55):
        self.text((110, H - 74), s, "mono", 22, FAINT, alpha)


# --- the timeline ----------------------------------------------------------

class Video:
    def __init__(self, path):
        self.path = path
        self.scenes = []

    def scene(self, seconds):
        def deco(fn):
            self.scenes.append((int(seconds * FPS), fn))
            return fn
        return deco

    def render(self):
        total = sum(n for n, _ in self.scenes)
        proc = subprocess.Popen(
            ["ffmpeg", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
             "-c:v", "libx264", "-preset", "slow", "-crf", "19",
             "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(self.path)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        done = 0
        for count, fn in self.scenes:
            for i in range(count):
                c = Canvas()
                fn(c, i / max(1, count - 1))
                proc.stdin.write(c.im.tobytes())
                done += 1
        proc.stdin.close()
        proc.wait()
        return total / FPS


# ---------------------------------------------------------------------------
# Journey content — every metric quoted from docs/06-journey-maps.md
# ---------------------------------------------------------------------------

JOURNEYS = [
    dict(
        key="j1", n="J1", who="Priya", role="Agent Developer",
        quote="I need my agent to talk to the payments service",
        persona="Senior engineer on reconciliation. Ships weekly. Measures success in merged PRs, not controls.",
        goal="Get a reconciliation agent reading balances from the payments MCP server, in production, this sprint.",
        pain=["Ask in Slack. Three contradictory answers.",
              "Raise a ticket. Unclear approver.",
              "Two to three weeks. Chased in standups."],
        stages=[
            ("1 Discover", "Ask in Slack; two teams point at each other",
             "connect discover --capability …", "days", "< 2 min"),
            ("3 Request", "A ticket, and a threat model she has never written",
             "one command, with the justification", "hours", "1 command"),
            ("4 Approve", "2–3 weeks, chased in standups",
             "read-only same-zone auto-approves", "~14 days", "< 1 day"),
            ("5 Connect", "An endpoint and a shared credential from a wiki",
             "contract distributed; the mediator is already there", "config edits", "0"),
            ("6 Build", "Every tool the server exposes is visible",
             "tools/list shows exactly the two contracted", "accidents", "0"),
        ],
        arc=["frustrated", "relieved", "in control"],
        moment_n="Stage 4",
        moment="Auto-approval for the low-risk majority is the single feature that decides adoption.",
        moment_why="If every connection needs a human, this becomes the ticket queue it replaced.",
        budget="NET NEGATIVE",
        budget_line="She spends less total time than today. A CI step she does not perform by hand, traded against weeks she no longer waits.",
    ),
    dict(
        key="j2", n="J2", who="Cecil", role="Security Architect",
        quote="Should these two be introduced?",
        persona="Covers four business units. Reviews 40–60 requests a month across all technologies.",
        goal="Approve safe connections in minutes, and spend real attention only on the ones that deserve it.",
        pain=["A ticket saying “need access to payments API”.",
              "Everything looks the same. Reviews by arrival order.",
              "Approval lives in a ticket. Enforcement is somebody else's problem."],
        stages=[
            ("1 Intake", "A ticket with four words in it",
             "both parties, tiers, zones, exact surface", "3 round-trips", "0"),
            ("2 Triage", "Everything looks the same",
             "risk-ranked; the low-risk majority never arrives", "100% reviewed", "~20%"),
            ("3 Assess", "Guesswork — no way to know what it exposes",
             "screened surface, pin, provenance, graph", "~45 min", "~5 min"),
            ("4 Shape", "Binary approve or deny; rejection is an argument",
             "counter-offer: narrower, shorter, tighter", "—", "> 50% shaped"),
            ("5 Decide", "Approval is filed; enforcement is elsewhere",
             "the signed contract IS the mechanism", "weeks", "0"),
        ],
        arc=["overwhelmed", "equipped", "confident"],
        moment_n="Stage 5",
        moment="The approval and the enforcement artifact must be the same object.",
        moment_why="Every security process that separates them decays.",
        budget="STRONGLY NEGATIVE",
        budget_line="Fewer reviews, better inputs, shorter each.",
    ),
    dict(
        key="j3", n="J3", who="Sam", role="SecOps Analyst",
        quote="Contain it now, prove it later",
        persona="On-call SOC analyst. 03:00. An agent is exfiltrating.",
        goal="Stop the bleeding in seconds, and be able to prove exactly what was cut and when.",
        pain=["Ask three teams. Grep deployment repos. Guess.",
              "Scale the deployment to zero and hope.",
              "No way to confirm the cut landed. Watch the SIEM."],
        stages=[
            ("2 Scope", "Ask three teams; grep repos; guess",
             "connect blast-radius agent:x", "hours", "seconds"),
            ("3 Contain", "Scale to zero and hope nothing else holds its keys",
             "every contract revoked, all mediators", "hours", "< 60 s"),
            ("4 Verify", "No way to confirm; watch and hope",
             "per-mediator confirmations, unconfirmed named", "assumed", "proven"),
            ("5 Notify", "Manual emails to partners",
             "signed CAEP SETs; partners cut their own", "hours", "seconds"),
            ("8 Restore", "Redeploy and hope",
             "clearing quarantine re-runs full admission", "re-compromise", "0"),
        ],
        arc=["alarmed", "powerful", "trusted"],
        moment_n="Stage 4",
        moment="Explicit non-confirmation.",
        moment_why="A containment tool that silently assumes success is worse than none, because it manufactures false confidence.",
        budget="HUGELY NEGATIVE",
        budget_line="On the paths that matter — and deliberately POSITIVE on restore. Restoring should be harder than cutting.",
    ),
    dict(
        key="j4", n="J4", who="Anika", role="Risk & Compliance Officer",
        quote="Show me the register",
        persona="Operational risk lead. Owns the CPS 230 and DORA response. Has been asking for an agent inventory for three quarters.",
        goal="Produce a complete, defensible register and evidence of oversight — without a project.",
        pain=["A spreadsheet built from a survey, stale on arrival.",
              "Screenshots of ticket approvals as oversight evidence.",
              "A three-week reconstruction project, every cycle."],
        stages=[
            ("1 Inventory", "A survey spreadsheet, stale on arrival",
             "the registry IS the inventory", "quarterly", "live"),
            ("3 Contract", "Nothing at all for internal agent relationships",
             "machine-readable terms on every connection", "partial", "100%"),
            ("4 Oversee", "Screenshots of ticket approvals",
             "signed approvals bound to the connection", "assertion", "proof"),
            ("7 Report", "A 3-week reconstruction project per cycle",
             "connect export --format dora --as-of …", "weeks", "< 1 hour"),
            ("8 Defend", "“We believe this is complete”",
             "anchored, verifiable, honest about gaps", "findings", "0"),
        ],
        arc=["resigned", "surprised", "confident"],
        moment_n="Stage 7",
        moment="The explicit exceptions section.",
        moment_why="An export that declares its gaps is defensible. One that quietly omits them destroys trust in the whole artifact the first time an auditor finds one.",
        budget="NEAR ZERO ONGOING",
        budget_line="She consumes. She does not maintain.",
    ),
    dict(
        key="j5", n="J5", who="Marcus", role="Partner Agent Operator",
        quote="Integrate with them without exposing ourselves",
        persona="Platform lead at a fintech whose agent must serve a bank's agent. His deal depends on passing the bank's security review.",
        goal="Get connected quickly, without handing over his catalogue or accepting unbounded obligations.",
        pain=["A 300-row questionnaire, bespoke per customer.",
              "Exchange API keys over email.",
              "Expose the whole API and hope."],
        stages=[
            ("1 Qualify", "A 300-row spreadsheet questionnaire",
             "a published, machine-checkable assurance bar", "weeks", "an afternoon"),
            ("2 Prepare", "Bespoke evidence for every customer",
             "sign the card, ship provenance from CI", "weeks", "days"),
            ("4 Scope", "Expose the whole API and hope",
             "only contracted skills resolve; the rest is invisible", "whole API", "contracted"),
            ("5 Operate", "Unpredictable volume, unclear liability",
             "explicit mutual ceilings; max_depth: 1", "surprises", "0"),
            ("6 Change", "Breaks the customer silently",
             "card change is drift, with a defined re-approval path", "silent breaks", "0"),
        ],
        arc=["defensive", "reassured", "cooperative"],
        moment_n="Stage 1",
        moment="A published, machine-checkable bar converts security review from negotiation into conformance.",
        moment_why="That is the sell-through motion: the vendor adopts it to pass their customer's review.",
        budget="POSITIVE BUT BOUNDED",
        budget_line="Real work once, then amortised across every future customer that speaks the same contract.",
    ),
]


# ---------------------------------------------------------------------------
# The six beats
# ---------------------------------------------------------------------------

def build(j):
    v = Video(OUT / f'{j["key"]}-{j["role"].lower().replace(" & ", "-").replace(" ", "-")}.mp4')
    L = 250   # left margin
    RW = 1420  # text measure

    @v.scene(5.0)
    def title(c, p):
        a = hold(p, up=0.12, down=0.92)
        c.text((L, 330), f'{j["n"]} · {j["role"].upper()}', "mono", 26, BRASS, a * ease_out(p * 3))
        # The name rises into place; the quote follows it.
        dy = int(28 * (1 - ease_out(clamp((p - 0.06) * 3.5))))
        c.text((L, 392 + dy), j["who"], "serif", 132, INK,
               a * ease_out(clamp((p - 0.06) * 3.5)))
        c.wrap(L, 574, f'“{j["quote"]}”', RW, "serif", 54, MUTED,
               a * ease_out(clamp((p - 0.22) * 3)))
        c.rule(L, 704, L + 420, RULE, a * ease_out(clamp((p - 0.34) * 4)))
        c.wrap(L, 748, j["persona"], RW - 200, "sans", 30, FAINT,
               a * ease_out(clamp((p - 0.4) * 3)))
        c.footer("warden-connect · journey maps")

    @v.scene(6.0)
    def today(c, p):
        a = hold(p, up=0.09, down=0.9)
        c.text((L, 286), "TODAY", "mono", 26, ALARM, a)
        c.wrap(L, 340, j["goal"], RW, "serif", 46, INK, a * ease_out(clamp(p * 2.4)))
        y = 560
        for i, line in enumerate(j["pain"]):
            q = stagger(clamp((p - 0.18) / 0.62), i, len(j["pain"]))
            dx = int(34 * (1 - ease_out(q)))
            c.vrule(L, y + i * 104 - 6, y + i * 104 + 58, ALARM, a * q * 0.8, 3)
            c.wrap(L + 30 + dx, y + i * 104, line, RW - 60, "sans", 34, MUTED, a * q)
        c.footer(f'{j["n"]} · the pain today')

    # The core beat: five stages, each replacing "today" with a mechanism.
    stages = j["stages"]
    per = 4.6

    @v.scene(1.2)
    def table_head(c, p):
        a = ease_out(p)
        c.text((L, 250), "WITH WARDEN-CONNECT", "mono", 26, BRASS, a)
        c.rule(L, 320, L + RW, RULE, a)
        c.footer(f'{j["n"]} · stage by stage')

    def stage_beat(idx):
        def draw(c, p):
            st, before, after, m_before, m_after = stages[idx]
            a = hold(p, up=0.1, down=0.93)
            c.text((L, 250), "WITH WARDEN-CONNECT", "mono", 26, BRASS, 0.55)
            c.rule(L, 320, L + RW, RULE, 0.5)
            c.text((L + RW, 250), f"{idx + 1} / {len(stages)}", "mono", 26, FAINT, 0.5,
                   anchor="ra")

            c.text((L, 412), st, "serif", 72, INK, a * ease_out(clamp(p * 3)))

            # today, struck through as the mechanism arrives
            cut = ease_in_out(clamp((p - 0.3) / 0.3))
            c.strike(L, 566, before, "sans", 36, MUTED, a * ease_out(clamp((p - 0.1) * 4)),
                     cut=cut)

            # the mechanism
            q = ease_out(clamp((p - 0.34) / 0.34))
            dx = int(26 * (1 - q))
            c.vrule(L, 672, 672 + 52, BRASS, a * q, 3)
            c.wrap(L + 28 + dx, 666, after, RW - 60, "sans", 40, INK, a * q)

            # the metric, arriving last and holding
            r = ease_out(clamp((p - 0.56) / 0.3))
            if r > 0.01:
                x = L
                c.text((x, 838), m_before, "mono", 44, MUTED, a * r)
                wb = c.d.textlength(m_before, font=font("mono", 44))
                c.d.line([(x, 862), (x + wb * ease_out(clamp((p - 0.62) / 0.2)), 862)],
                         fill=blend(ALARM, GROUND, a * r), width=3)
                c.text((x + wb + 48, 838), "→", "mono", 44, FAINT, a * r)
                s = ease_out(clamp((p - 0.68) / 0.28))
                c.text((x + wb + 122, 836 - int(10 * (1 - s))), m_after, "mono", 58,
                       BRASS, a * s)
            c.footer(f'{j["n"]} · {st}')
        return draw

    for i in range(len(stages)):
        v.scene(per)(stage_beat(i))

    @v.scene(5.5)
    def arc(c, p):
        a = hold(p, up=0.1, down=0.9)
        c.text((L, 250), "EMOTIONAL ARC", "mono", 26, BRASS, a)
        y = 590
        xs = [L + 60, L + RW // 2 - 60, L + RW - 240]
        colours = [ALARM, MUTED, TEAL]
        # The line draws itself left to right, and each word lands as it is reached.
        prog = ease_in_out(clamp((p - 0.1) / 0.6))
        c.rule(xs[0], y + 70, int(xs[0] + (xs[-1] + 160 - xs[0]) * prog), RULE, a, 2)
        for i, (word, col) in enumerate(zip(j["arc"], colours)):
            reached = clamp((prog - i * 0.42) * 3.2)
            q = ease_out(reached)
            c.d.ellipse((xs[i] - 7, y + 63, xs[i] + 7, y + 77),
                        fill=blend(col, GROUND, a * q))
            c.text((xs[i], y - int(20 * (1 - q))), word, "serif", 58, col, a * q,
                   anchor="ls")
        c.footer(f'{j["n"]} · how it feels')

    @v.scene(7.0)
    def moment(c, p):
        a = hold(p, up=0.08, down=0.92)
        c.text((L, 250), "THE MOMENT THAT MATTERS", "mono", 26, BRASS, a)
        c.text((L, 336), j["moment_n"], "mono", 34, TEAL, a * ease_out(clamp(p * 3)))
        y = c.wrap(L, 424, j["moment"], RW, "serif", 62, INK,
                   a * ease_out(clamp((p - 0.1) * 2.4)))
        q = ease_out(clamp((p - 0.4) * 2.2))
        c.vrule(L, y + 50, y + 170, BRASS, a * q, 3)
        c.wrap(L + 30, y + 44, j["moment_why"], RW - 80, "sans", 36, MUTED, a * q)
        c.footer(f'{j["n"]} · why it decides everything')

    @v.scene(5.5)
    def budget(c, p):
        a = hold(p, up=0.1, down=0.88)
        c.text((L, 336), "FRICTION BUDGET", "mono", 26, BRASS, a)
        s = ease_out(clamp(p * 2.2))
        c.text((L, 410 - int(18 * (1 - s))), j["budget"], "serif", 104, BRASS, a * s)
        c.rule(L, 576, L + 520, RULE, a * ease_out(clamp((p - 0.2) * 3)))
        c.wrap(L, 618, j["budget_line"], RW - 120, "sans", 40, MUTED,
               a * ease_out(clamp((p - 0.26) * 2.4)))
        c.text((L, 872), f'{j["n"]} · {j["who"]} · {j["role"]}', "mono", 26, FAINT,
               a * ease_out(clamp((p - 0.5) * 3)))
        c.footer("docs/06-journey-maps.md")

    return v


if __name__ == "__main__":
    # Every string that will reach a glyph, checked before a single frame is drawn.
    strings = []
    for j in JOURNEYS:
        strings += [j["n"], j["who"], j["role"], j["role"].upper(), j["quote"],
                    j["persona"], j["goal"], j["moment"], j["moment_why"],
                    j["moment_n"], j["budget"], j["budget_line"],
                    "WITH WARDEN-CONNECT", "TODAY", "EMOTIONAL ARC",
                    "THE MOMENT THAT MATTERS", "FRICTION BUDGET", "→",
                    "warden-connect · journey maps", "docs/06-journey-maps.md"]
        strings += j["pain"] + j["arc"]
        for st in j["stages"]:
            strings += list(st)
    n = check_fonts(strings)
    print(f"  font check ok — {n} distinct glyphs across 3 faces")

    only = sys.argv[1] if len(sys.argv) > 1 else None
    for j in JOURNEYS:
        if only and j["key"] != only:
            continue
        v = build(j)
        secs = v.render()
        print(f'  {j["key"]}  {v.path.name:<44} {secs:.1f}s')
