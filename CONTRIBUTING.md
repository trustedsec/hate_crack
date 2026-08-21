# Contributing to hate_crack

Thanks for your interest. hate_crack is a wrapper around hashcat, so most useful
contributions are new attack modes, corrections to how an existing attack drives
hashcat, or fixes to the API integrations.

Please read the two short sections below first — one is about engagement data,
which matters more here than in most projects, and the other is about which
branch to target, which is easy to get wrong.

## Never include real engagement data

hate_crack is used on authorized penetration tests, so the files it touches are
hash dumps and cracked passwords belonging to somebody else. **Do not put any of
it in an issue, a pull request, a commit, a test fixture, or a screenshot.** That
includes hashes, plaintexts, basewords, partial passwords, potfiles, NTDS
extracts, wordlists built from a client corpus, and hostnames or usernames that
identify an organization.

When you need example data, invent it. Synthetic hashes of synthetic strings are
fine, and every existing test uses them. When you need to describe a result,
report aggregates that cannot be reversed — "3 of 200 hashes cracked", not the
plaintexts.

The repository's `.gitignore` covers the artifacts hate_crack itself writes —
`*.out`, `*.passwords`, `*.ntds`, `*.pot`, `*.potfile`, `hashcat_debug/`,
`wordlists/` and more — and `tests/test_repo_hygiene.py` fails the build if one
is ever tracked. Do not weaken those patterns to commit something.

Some of those patterns are narrow on purpose, because a broader glob would
swallow real source: `*.hashes` rather than `*hashes*`, which would match
`tests/test_upload_cracked_hashes.py`. If you need to widen one, the tracked-file
assertion in that test file will tell you whether it is safe.

If you find an artifact the patterns miss, that is a bug worth reporting on its
own — two such gaps were found and closed in August 2026, so more may exist.

## Target `nightly-dev`, not `main`

`main` is the default branch, so GitHub will preselect it — **change the base to
`nightly-dev`.** `main` holds the last released state and receives work only
through a batch integration merge, so a pull request landing there directly
breaks that and creates cleanup for the maintainers.

```bash
git clone https://github.com/<you>/hate_crack
cd hate_crack
git checkout -b my-change origin/nightly-dev
# ... work ...
git push -u origin my-change     # then open a PR with base: nightly-dev
```

Two exceptions go straight to `main`: a change to a file in
`.github/workflows/`, because GitHub only dispatches a workflow that exists on
the default branch, and a security fix that must ship immediately. Say which one
applies in the PR body.

`CLAUDE.md` describes the same flow from the maintainer side, so it is worth a
read if you want the reasoning. One difference in mechanics, and it is not
something you need to do anything about: maintainers merge an approved branch
with a local fast-forward rather than with GitHub's merge button, because every
button leaves either a merge commit or rewritten SHAs and this repository keeps
its history linear. GitHub marks your pull request merged either way.

## Setting up

Requires **Python 3.13 or newer** and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --dev          # dependencies
make submodules        # builds the bundled binaries; needed to *run* the tool
prek install --hook-type pre-push --hook-type pre-commit
```

`make submodules` also handles the Apple Silicon princeprocessor rename, so
prefer it over building by hand. You do not need it to run the tests, because
`HATE_CRACK_SKIP_INIT=1` bypasses the binary checks.

Hooks are managed by [prek](https://github.com/j178/prek)
(`uv tool install prek`) and configured in `prek.toml`. Some of the pre-commit
hooks rewrite files in place, so re-stage and re-commit after they fire.

## Before you open a pull request

Run everything below and make sure it passes. These are the same gates CI runs,
so running them locally is faster than waiting.

```bash
# Tests
HATE_CRACK_SKIP_INIT=1 uv run pytest

# Lint, format, types
uv run ruff check hate_crack tests tools packaging hate_crack.py
uv run ruff format --check hate_crack tests tools packaging hate_crack.py
uv run ty check --exit-zero-on-warning hate_crack

# Security
uvx --from 'bandit[toml]==1.9.4' bandit -r hate_crack -c pyproject.toml -b .bandit-baseline.json
uv run --with pip-audit==2.10.0 pip-audit --ignore-vuln PYSEC-2026-2447
```

Do not narrow the ruff paths — that list is the full scope from `prek.toml`. `ty`
is deliberately scoped to `hate_crack` only, because the test suite's
monkeypatching produces a large volume of warning-level diagnostics.

Some suites are opt-in and skipped by default: end-to-end
(`HATE_CRACK_RUN_E2E=1`), Docker (`HATE_CRACK_RUN_DOCKER_TESTS=1`) and the live
API tests (`HASHMOB_TEST_REAL=1`, `HASHVIEW_TEST_REAL=1`,
`WEAKPASS_TEST_REAL=1`). You are not expected to run those.

## Commit messages and the changelog

Commits follow [Conventional Commits](https://www.conventionalcommits.org/),
because the release version is derived from them: any `feat` in a batch moves the
minor version, while `fix`, `docs`, `chore` and friends move the patch. A `!` or
a `BREAKING CHANGE:` footer counts as a feature — the major version is only ever
bumped by hand.

**Add an entry to the `[Unreleased]` section of `CHANGELOG.md`.** Say what
changed and why it was wrong before; if there is an issue, cite it inline as
`(#NNN)`. Those inline references are how the maintainers assemble the closing
keywords when the batch is released, so an entry without one may leave your issue
open.

Entries here tend to be long, and that is deliberate — the useful part is usually
the reasoning, or the piece of hashcat behaviour that forced the design. Match
what is already there rather than writing a one-liner.

## Adding a new attack mode

An attack spans three files, and the wiring is easy to get half-right — in
particular `hate_crack.py` keeps a menu mapping that duplicates the one in
`hate_crack/main.py`, and both need updating. The six steps are written out in
`.claude/skills/adding-an-attack/SKILL.md`, and the surrounding architecture is
described in `CLAUDE.md`.

## Reporting a bug

Useful reports say what you ran, what happened, and what you expected — plus your
hashcat version (`hashcat --version`), your OS, and the hash *mode* number you
were attacking. Please do not paste hashes or cracked passwords; the mode number
and a description are enough.

If the bug involves a crash, the traceback is the most valuable thing you can
include. Check it for file paths that name a client engagement before pasting it.

## Questions

Open an issue. If you are unsure whether an idea fits, asking first is welcome
and cheaper than building it.
