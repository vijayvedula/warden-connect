<!--
Thanks for contributing to warden-connect. No special access is needed — fork,
branch, and open this PR. A maintainer will review. See
.github/CONTRIBUTING.md.
-->

## What & why

<!-- What does this change, and why? Link the issue it addresses. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] New enforcement-point binding or source-host shim
- [ ] Docs
- [ ] Refactor / chore

## Checklist

- [ ] `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` pass
- [ ] `cargo test --workspace --no-fail-fast` passes, and behaviour changes come with tests
- [ ] `./scripts/ci-local.sh` passes, or I name the gate I could not run locally
- [ ] For a new error code: it is emitted, or marked `RESERVED:` — `./scripts/code-emission.sh`
- [ ] For a docs change: `./scripts/doc-links.sh` and `./scripts/doc-claims.sh` pass
- [ ] For SDK changes: `pytest` and `ruff check .` pass under `sdk/python/`
- [ ] This is **not** a security vulnerability (those go through [private reporting](https://github.com/vijayvedula/warden-connect/security/advisories/new))

## The defect class this repository keeps producing

<!-- Delete if it does not apply. -->

- [ ] If this adds a control, something fails when I delete its body — a flag that
      is parsed and never read, a role required and never checked, or a gate that
      passes with its body removed, is the bug this project keeps finding.
