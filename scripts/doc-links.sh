#!/usr/bin/env bash
# Every relative link in every tracked Markdown file must resolve to a file that exists.
#
# Nine were broken before this existed, all of them pointing at documents retired in the
# 2026-08-21 rewrite — `limitations.md`, `releasing.md`, `conformance.md`, `key-custody.md`,
# `observability.md`, `identity-without-spire.md`. They had been dead for over a week in the
# README of the conformance vectors, the attestation fixtures and the Python SDK: the three
# places a newcomer is most likely to follow a link from.
#
# Nothing failed when they broke, which is the point. A dead link costs a reader their trust in
# every other link on the page, and it is the cheapest possible thing to check.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, subprocess, pathlib, urllib.parse, sys

files = subprocess.check_output(["git", "ls-files", "*.md"]).decode().split()
link = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
broken, checked = [], 0

for f in files:
    p = pathlib.Path(f)
    for m in link.finditer(p.read_text(errors="replace")):
        target = m.group(1)
        # External links and pure anchors are somebody else's problem; a relative path is ours.
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = urllib.parse.unquote(target.split("#")[0])
        if not target:
            continue
        checked += 1
        if not (p.parent / target).exists():
            broken.append(f"{f} -> {target}")

if broken:
    print(f"FAIL  {len(broken)} relative link(s) point at files that do not exist:")
    for b in broken:
        print(f"      {b}")
    sys.exit(1)
print(f"ok    {checked} relative links across {len(files)} markdown files all resolve")
PY
