#!/usr/bin/env bash
# Render every committed Mermaid source to SVG.
#
# GitHub renders ```mermaid fences with a pan/zoom control cluster overlaid on the
# diagram, and there is no document-level way to suppress it
# (github/community#178929). So the docs ship images instead, with the .mmd source
# committed beside each one so a diagram stays reviewable in a pull request.
#
# This is the only part of the toolchain that needs Node, and it runs only when a
# diagram changes. CI never runs it — the SVGs are committed.
set -euo pipefail
cd "$(dirname "$0")/.."

rendered=0
for src in docs/diagrams/*.mmd docs/use-cases/diagrams/*.mmd; do
  out="${src%.mmd}.svg"
  npx -y @mermaid-js/mermaid-cli@11 --quiet -i "$src" -o "$out" -b white
  rendered=$((rendered + 1))
  echo "  $out"
done
echo "rendered $rendered diagrams"
