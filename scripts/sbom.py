#!/usr/bin/env python3
"""Generate a CycloneDX SBOM of warden-connect itself.

    python3 scripts/sbom.py > warden-connect.cdx.json
    python3 scripts/sbom.py --check           # verify without writing

# Why this exists

`export::cyclonedx_bom` produces a CycloneDX BOM of a *tool surface* — the capabilities an
MCP server exposes. So this repository ships a BOM generator and, until now, shipped no BOM
of itself. That is not merely embarrassing: a component that asks an estate to inventory its
agents while being uninventoriable is asking for a trust it does not extend.

# Why not cargo-cyclonedx

It would do this better. It is also a build-time dependency on a tool that has to be
installed, and §8.3's whole argument is that this tree builds with a stock toolchain and
nothing else. `cargo metadata` is part of cargo, so this script needs Python and a
checkout. The cost is that the output is CycloneDX 1.5 core fields rather than everything
the specification allows — components, licences, purls and the dependency graph, which is
what a consumer actually reads.

# What is in it, and what is deliberately not

**In:** every crate in the resolved build graph for the two shipped binaries, with its
version, licence and `pkg:cargo/...` purl, plus the dependency edges.

**Not in:** dev-dependencies. They are not in a shipped artifact, and listing them makes
the BOM's answer to "what is in the thing you gave me" wrong in the direction that matters
— it inflates the surface a consumer thinks they are exposed to, and a BOM that cries wolf
gets filtered.

**Not in:** `warden` core's version as a registry version, because it is not one. It is a
path dependency (§8.3), so the BOM records it as such and names the commit if git can be
asked. An SBOM that reported a path dependency as `pkg:cargo/warden@0.1.0` would be
claiming a crates.io provenance that does not exist.
"""
import argparse
import json
import subprocess
import sys

# CycloneDX 1.5 is what most consumers read today; 1.6 adds fields this script does not
# populate, so claiming it would overstate the document.
SPEC_VERSION = "1.5"

# Only the crates that end up in something we ship. A dev-dependency is not in the artifact.
# Package names, not directory names — the crate rename left these as `wc-*` and the root
# lookup below would then raise `StopIteration` rather than say what was wrong.
SHIPPED_ROOTS = ["warden-connect-cli", "warden-connect-mediator"]


def run(args: list) -> str:
    return subprocess.run(
        args, check=True, capture_output=True, text=True, cwd=None
    ).stdout


def git_describe() -> str:
    """The commit this BOM describes, or 'unknown' outside a checkout."""
    try:
        return run(["git", "rev-parse", "HEAD"]).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def metadata() -> dict:
    # `--all-features` is deliberately absent: the BOM must describe what is built, and the
    # workspace builds with default features. A BOM of a configuration nobody ships is a
    # BOM of nothing.
    raw = run(["cargo", "metadata", "--format-version", "1", "--locked"])
    return json.loads(raw)


def purl(pkg: dict) -> str:
    """A package URL, or None for anything not from a registry.

    A path dependency has no registry coordinates. Emitting one anyway would assert a
    crates.io provenance the crate does not have, which is the one thing an SBOM must not
    do — its whole value is that its identifiers resolve.
    """
    source = pkg.get("source")
    if source and source.startswith("registry+"):
        return f"pkg:cargo/{pkg['name']}@{pkg['version']}"
    return None


def shipped_ids(meta: dict) -> set:
    """Package ids reachable from the shipped binaries through normal + build deps."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    by_name = {p["id"]: p for p in meta["packages"]}

    roots = [
        pid
        for pid, pkg in by_name.items()
        if pkg["name"] in SHIPPED_ROOTS
    ]
    if not roots:
        raise SystemExit(f"none of {SHIPPED_ROOTS} found in the workspace")

    seen = set()
    stack = list(roots)
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes.get(pid, {}).get("deps", []):
            # `dep_kinds` distinguishes normal/build/dev. A dev-dependency is not in the
            # artifact, so following it would inflate what a consumer thinks they run.
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [{}])}
            if kinds and kinds <= {"dev"}:
                continue
            stack.append(dep["pkg"])
    return seen


def ref(pkg: dict) -> str:
    """A stable bom-ref: `name@version`.

    Not cargo's package id. A path dependency's id is `path+file:///Users/someone/...`,
    which would put the build machine's filesystem layout into a published artifact and
    make the BOM differ between two checkouts of the same commit. A BOM that changes
    depending on who generated it cannot be diffed, and a diff is how anyone notices a
    dependency appeared.

    `name@version` is unique within a cargo resolve graph even when two versions of a crate
    coexist, which is the only uniqueness this needs.
    """
    return f"{pkg['name']}@{pkg['version']}"


def component(pkg: dict, is_first_party: bool) -> dict:
    out = {
        "type": "library",
        "bom-ref": ref(pkg),
        "name": pkg["name"],
        "version": pkg["version"],
    }
    p = purl(pkg)
    if p:
        out["purl"] = p
    else:
        # Say why there is no purl, rather than leaving a consumer to guess whether the
        # generator failed or the coordinates genuinely do not exist.
        out["properties"] = [
            {
                "name": "warden-connect:provenance",
                "value": "first-party workspace member"
                if is_first_party
                else "path dependency, vendored beside this repository (§8.3)",
            }
        ]
    if pkg.get("license"):
        # `expression` rather than a licence list: cargo gives an SPDX expression, and
        # splitting `MIT OR Apache-2.0` into two licences changes its meaning from a choice
        # into a conjunction.
        out["licenses"] = [{"expression": pkg["license"]}]
    elif pkg.get("license_file"):
        out["licenses"] = [{"license": {"name": f"see {pkg['license_file']}"}}]
    if pkg.get("description"):
        out["description"] = pkg["description"]
    return out


def build(meta: dict) -> dict:
    workspace = set(meta["workspace_members"])
    ids = shipped_ids(meta)
    by_id = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    components = [
        component(by_id[pid], pid in workspace)
        for pid in sorted(ids)
        if by_id[pid]["name"] not in SHIPPED_ROOTS
    ]

    dependencies = []
    for pid in sorted(ids):
        deps = [
            ref(by_id[d["pkg"]])
            for d in nodes.get(pid, {}).get("deps", [])
            if d["pkg"] in ids
            and not ({k.get("kind") for k in d.get("dep_kinds", [{}])} <= {"dev"})
        ]
        dependencies.append({"ref": ref(by_id[pid]), "dependsOn": sorted(deps)})

    # `StopIteration` from a bare `next` says nothing about which name was missing, which is
    # how the rename turned this into an unexplained traceback.
    root = next(
        (by_id[pid] for pid in ids if by_id[pid]["name"] == SHIPPED_ROOTS[0]),
        None,
    )
    if root is None:
        raise SystemExit(
            f"no package named {SHIPPED_ROOTS[0]!r} in the resolved graph; "
            "SHIPPED_ROOTS is stale (package names, not directory names)"
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            # No timestamp. This has to be reproducible: a BOM whose bytes change every run
            # cannot be diffed, and a diff is how anyone notices a dependency appeared.
            "component": {
                "type": "application",
                "bom-ref": "warden-connect",
                "name": "warden-connect",
                "version": root["version"],
                "description": "The connection control plane for AI agents.",
                "licenses": [{"license": {"name": "FSL-1.1-ALv2"}}],
                "properties": [
                    {"name": "warden-connect:commit", "value": git_describe()},
                    {"name": "warden-connect:binaries", "value": "connect, connect-mediate"},
                ],
            },
            "tools": [{"name": "scripts/sbom.py", "vendor": "warden-connect"}],
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="generate and validate without writing to stdout",
    )
    args = parser.parse_args()

    bom = build(metadata())

    # The checks a consumer would run, run here so CI fails on a malformed BOM rather than
    # publishing one.
    problems = []
    if not bom["components"]:
        problems.append("no components")
    for c in bom["components"]:
        if "licenses" not in c:
            problems.append(f"{c['name']} {c['version']} has no licence")
    # Every edge must land on something the BOM actually describes. A dangling ref is how a
    # BOM ends up asserting a dependency a consumer cannot look up.
    refs = {c["bom-ref"] for c in bom["components"]} | {
        d["ref"] for d in bom["dependencies"]
    }
    for d in bom["dependencies"]:
        for target in d["dependsOn"]:
            if target not in refs:
                problems.append(f"dangling dependency edge to {target}")
    if any("file://" in json.dumps(c) for c in bom["components"]):
        problems.append("a local filesystem path leaked into the BOM")
    if problems:
        for p in sorted(set(problems)):
            print(f"sbom: {p}", file=sys.stderr)
        return 1

    if args.check:
        print(
            f"sbom: {len(bom['components'])} components, every one with a licence",
            file=sys.stderr,
        )
        return 0

    json.dump(bom, sys.stdout, indent=2, sort_keys=False)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
