#!/usr/bin/env python3
"""Flatten the mediator scenarios into unit-separated records for the harness.

A sibling of `.conformance-plan.py`, and separate from it for the same reason that one
exists: the records are read by `while IFS=$'\x1f' read`, and building them inline in the
shell put a heredoc inside a command substitution, which does not parse.

**Unit separator, not tab.** Tab is IFS whitespace, so a run of them collapses and an empty
field disappears — that silently shifted every column right for the vectors that must be
admitted and reported a conformant implementation as broken.
"""

import json
import sys

US = "\x1f"


def main() -> None:
    d = json.load(open(sys.argv[1]))
    for name, s in sorted(d.get("scenarios", {}).items()):
        v = d["vectors"][s["contract"]]
        print(
            US.join(
                [
                    name,
                    s["contract"],
                    s["expect"],
                    v["trust_kid"],
                    v["trust_alg"],
                    d["keys"][v["trust_kid"]],
                    s["description"],
                ]
            )
        )


if __name__ == "__main__":
    main()
