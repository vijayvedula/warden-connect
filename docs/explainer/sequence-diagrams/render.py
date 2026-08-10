#!/usr/bin/env python3
"""Render every sequence diagram to a self-theming SVG and embed it in the markdown.

Why not just use ```mermaid fences? Because GitHub wraps every block it renders
itself in a pan/zoom/copy toolbar that sits on top of the diagram, and there is no
way to suppress it from the source — it is a rendering decision GitHub makes, and an
open feature request rather than a setting. Pre-rendered images get no chrome.

Why one SVG rather than a `<picture>` with a light and a dark source? Because GitHub
rewrites a relative `<img src>` to raw.githubusercontent.com but leaves a relative
`<source srcset>` alone — on a blob page it then resolves against the HTML page URL
and loads a web page as an image. `<picture>` does not fall back when a matching
source fails, so every dark-mode reader would get a broken image. Verified against
GitHub's own rendered HTML, not assumed.

So each diagram is rendered twice and merged into one file: the light render carries
the dark render's stylesheet inside a `prefers-color-scheme: dark` media query. That
works because both renders are byte-identical apart from the stylesheet and a handful
of inline colours, and because mermaid names the root `my-svg` in both — the two rule
sets therefore target the same elements. Inline colours cannot be overridden by a
stylesheet, so any that differ get an `!important` rule keyed on the exact attribute
value; the pairs are discovered by comparison rather than hardcoded, so a mermaid
upgrade that colours something new is picked up automatically.

The light render is given a white ground on purpose. A browser that does not apply
`prefers-color-scheme` inside an SVG loaded via `<img>` falls back to the light
rendering, and on GitHub's dark canvas a transparent ground would leave dark text on
a dark page. A white card is unremarkable; unreadable text is not.

The Mermaid source stays in the same file, in a collapsed block, so the markdown
remains the single source of truth and still diffs sensibly. It is fenced as `text`
rather than `mermaid` on purpose: a `mermaid` fence would be rendered by GitHub when
expanded, bringing the toolbar back with it.

    python3 render.py            # re-render everything, rewrite the markdown
    python3 render.py --check    # render only, fail if any diagram is broken

Needs mermaid-cli. Override the binary with MMDC if it is not on the path:

    MMDC=/path/to/mmdc python3 render.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
IMG = HERE / "img"
MMDC = os.environ.get("MMDC", "")

# A diagram is named for the L2 capability whose section it sits in.
HEADING = re.compile(r"^## (B\d\.\d) · (.+)$", re.M)
# Either form is accepted as the source, so a first run migrates and later runs are
# idempotent.
LEGACY = re.compile(r"```mermaid\n(.*?)```\n", re.S)
CANON = re.compile(
    r"<img [^>]*?src=\"img/B\d\.\d\.svg\">\s*\n\s*"
    r"<details>.*?```text\n(.*?)```\s*\n\s*</details>\n", re.S)

STYLE = re.compile(r"<style>(.*?)</style>", re.S)
INLINE = re.compile(r'style="([^"]*)"')


def mmdc(args):
    if MMDC:
        return [MMDC] + args
    if shutil.which("mmdc"):
        return ["mmdc"] + args
    return ["npx", "-y", "@mermaid-js/mermaid-cli"] + args


def render_one(path, theme, background):
    out = Path(tempfile.mkdtemp()) / "d.svg"
    r = subprocess.run(
        mmdc(["-i", str(path), "-o", str(out), "-t", theme, "-b", background, "-q"]),
        capture_output=True, text=True)
    if not out.exists() or out.stat().st_size == 0:
        lines = (r.stderr or r.stdout or "").strip().splitlines()
        detail = "\n".join(l for l in lines if "rror" in l or "xpect" in l)
        raise RuntimeError(detail[:400] or "mermaid produced no output")
    return out.read_text()


def merge(light, dark):
    """Fold the dark render's styling into the light one, behind a media query."""
    dark_css = STYLE.search(dark).group(1)
    bodies = [STYLE.sub("", s) for s in (light, dark)]
    inline = [INLINE.findall(b) for b in bodies]
    if len(inline[0]) != len(inline[1]):
        # The two renders diverged structurally, so positional pairing would map
        # unrelated elements onto each other. Ship the light one rather than a
        # confidently wrong recolouring.
        raise RuntimeError("light and dark renders differ in structure")

    overrides = ""
    for want, got in sorted(set(zip(*inline))):
        if want == got:
            continue
        decls = " ".join(d.strip() + " !important;" for d in got.split(";") if d.strip())
        # Two selectors because the root <svg> carries the id itself, so a descendant
        # selector would miss it — that is where the background colour lives.
        overrides += '#my-svg[style="%s"]{%s}#my-svg [style="%s"]{%s}' % (
            want, decls, want, decls)

    return light.replace(
        "</style>",
        "@media (prefers-color-scheme: dark){%s%s}</style>" % (dark_css, overrides), 1)


def embed(cap, title):
    return (
        '<img alt="%s %s — sequence diagram" src="img/%s.svg">\n'
        "\n"
        "<details>\n"
        "<summary>Mermaid source</summary>\n"
        "\n"
        "```text\n"
        "%s"
        "```\n"
        "\n"
        "</details>\n"
    ) % (cap, title, cap, "%s")


def main():
    check_only = "--check" in sys.argv
    IMG.mkdir(exist_ok=True)
    files = sorted(HERE.glob("B*.md"))
    if not files:
        sys.exit("no B*.md files found next to render.py")

    total = failed = 0
    for md in files:
        text = md.read_text()
        caps = [(m.start(), m.group(1), m.group(2)) for m in HEADING.finditer(text)]

        def replace(m):
            nonlocal total, failed
            prior = [c for c in caps if c[0] < m.start()]
            cap, title = prior[-1][1:] if prior else (md.stem, md.stem)
            src = m.group(1)
            total += 1

            tmp = Path(tempfile.mkdtemp()) / "d.mmd"
            tmp.write_text(src)
            try:
                svg = merge(render_one(tmp, "default", "white"),
                            render_one(tmp, "dark", "transparent"))
            except RuntimeError as e:
                failed += 1
                print("  FAIL %s\n    %s" % (cap, e))
            else:
                (IMG / ("%s.svg" % cap)).write_text(svg)
                print("  ok   %s" % cap)
            return embed(cap, title) % src

        print(md.name)
        out = CANON.sub(replace, text)
        if out == text:                      # not migrated yet
            out = LEGACY.sub(replace, text)
        if not check_only and out != text:
            md.write_text(out)

    print("\n%d diagrams, %d failed" % (total, failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
