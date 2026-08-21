# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

hate_crack is a menu-driven Python wrapper for hashcat that automates password cracking methodologies. It provides 16 attack modes, API integrations (Hashview, Weakpass, Hashmob), and utilities for wordlist/rule management.

## Commands

```bash
# Run tests (requires HATE_CRACK_SKIP_INIT=1 in worktrees without hashcat-utils)
HATE_CRACK_SKIP_INIT=1 uv run pytest -v

# Run a single test
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_x.py::test_y -v

# Lint / format / type gates (mirrors CI and prek.toml's pre-push stage)
# The ruff steps cover hate_crack, tests, tools, packaging, and hate_crack.py -
# this is the full prek scope (prek.toml), not just hate_crack+tests - do not
# narrow it. ty stays scoped to hate_crack: the test suite's monkeypatching
# produces a large volume of warning-level diagnostics.
uv run ruff check hate_crack tests tools packaging hate_crack.py
uv run ruff format --check hate_crack tests tools packaging hate_crack.py
uv run ty check --exit-zero-on-warning hate_crack

# Security gates (mirrors CI)
uvx --from 'bandit[toml]==1.9.4' bandit -r hate_crack -c pyproject.toml -b .bandit-baseline.json
uv run --with pip-audit==2.10.0 pip-audit --ignore-vuln PYSEC-2026-2447
```

The pip-audit gate ignores `PYSEC-2026-2447` (diskcache) until an upstream fix
ships. Regenerate the bandit baseline after intentionally adding flagged code with:
`uvx --from 'bandit[toml]==1.9.4' bandit -r hate_crack -c pyproject.toml -f json -o .bandit-baseline.json`.

**Test environment variables**: `HATE_CRACK_SKIP_INIT=1` skips binary/config validation (essential for worktrees without hashcat-utils). `HASHMOB_TEST_REAL=1`, `HASHVIEW_TEST_REAL=1`, `WEAKPASS_TEST_REAL=1` enable live API tests. `HASHVIEW_TEST_LOCAL=1` (with `HASHVIEW_REPO=<path>`, default `~/projects/hashview`) spins up a local Hashview docker stack, seeds it, and runs the live Hashview tests against it — orchestration in `tests/_hashview_local.py` (via `pytest_configure`), seeding in `tests/hashview_local_seed.py`. The CLI honours `HASHVIEW_URL` / `HASHVIEW_API_KEY` env vars as overrides for the `config.json` values (loaded in `main.py` ~line 275), which is what lets the suite point the CLI at the local stack.

`[tool.pytest.ini_options]` sets only `testpaths = ["tests"]` — there are no markers and
no `addopts`. Opt-in suites (E2E, Docker, live-API) are gated purely by the env vars above
plus `@skipif`, not by marker selection. `pytest-timeout` is installed but unconfigured.

**`requires-python = ">=3.13"`** (`pyproject.toml`).

**Makefile** (default goal `install`): `make submodules` (documented above), `install`,
`dev-install`, `reinstall`, `dev-reinstall`, `update`, `uninstall`, `clean`, `test`,
`coverage`, `ruff`, `ty`, `lint` (= `ruff` + `ty`), `check` (= `lint`).

`Dockerfile.test` (python:3.13-slim + hashcat, pocl, p7zip, transmission, uv) backs
`test_docker_script_install.py`.

## Git Hooks

Git hooks are managed by [prek](https://github.com/j178/prek) (v0.3.3+, installed
via `uv tool install prek`). Install with:

```bash
prek install --hook-type pre-push --hook-type pre-commit
```

There is no longer a `post-commit` hook — see Documentation Auditing below.

Hooks are defined in `prek.toml` using the pre-commit local-repo schema (TOML, not YAML).

The `pre-commit` stage pulls hooks from the `pre-commit/pre-commit-hooks` remote
repo. The auto-fixers among them modify files in place, so re-stage and re-commit
after they run. `detect-private-key` is the pre-commit secret-scanning gate, and
bandit covers `hate_crack/` for SAST; treat both as narrow, and do not assume a
credential in another path would be caught before it lands.

Beware `prek run --all-files`: the auto-fixers will rewrite vendored files
(`PACK/README`, `PACK/ChangeLog`) that are otherwise left alone, so check
`git status` afterwards and revert collateral edits.

**Note**: prek 0.3.3 expects `repos = [...]` at the top level. The old `[hooks.<stage>] commands = [...]` format is not supported and will fail with `missing field 'repos'`.

## Documentation Auditing

The audit scripts live in `.claude/`, which is part of the repo (see Publication
Boundary below). The `audit-docs` post-commit hook was removed from
`prek.toml` along with it, so **nothing audits automatically on commit** —
`prek.toml` has no post-commit stage at all. You have to run it:

```bash
# Manually audit a commit
bash .claude/audit-docs.sh HEAD
bash .claude/audit-docs.sh <commit_sha>

# Check the last N commits for documentation gaps
bash .claude/check-docs.sh 5
```

**Only the trigger is manual — the response is still automatic.** Earlier
revisions of this file said "audits are now manual only," which is wrong.
`.claude/settings.json` still wires a Claude Code `PostToolUse` hook on `Bash`
to `.claude/hooks/doc-audit-trigger.sh`. That hook greps every Bash tool result
for `[Documentation Audit] ... documentation was not updated` and, on a match,
returns `additionalContext` instructing Claude to invoke the
`readme-documentarian` agent. `audit-docs.sh:50` still emits that exact string,
so running the command above on a code-only commit *will* fire it — verified
end-to-end on 2026-08-21 against commit `89121e07`. Removing the prek hook
disabled the scheduling, not the wiring.

The hook is keyed to a **string in stdout**, not to the script, so rewording
that `WARNING:` line silently breaks the trigger and nothing fails loudly.

**The detection heuristic was fixed on 2026-08-21** — it used to count *any*
changed `.md` as "documentation updated", and since this repo touches
`CHANGELOG.md` on most changes, a changelog entry silently satisfied the check.
Two exclusions now apply: `CHANGELOG.md` does not count as documentation, and
`tests/` does not count as code. Measured over the last 100 commits, the audit
flagged 23 before, 61 with the `CHANGELOG.md` fix, and 52 with both. The
original 23 was the misleading figure.

Both patterns are duplicated in `audit-docs.sh` and `check-docs.sh`, so edit the
two together. `tests/test_doc_audit_parity.py` runs every case against both
scripts and fails on drift, so you no longer have to remember — it is
mutation-tested, meaning reverting either exclusion in either script turns it
red. The flag rate is deliberately high (52 of 83 code commits): this is an
advisory reminder, not a gate, and most of those genuinely changed shipped code
without touching a user-facing doc.

See `.claude/DOCUMENTATION-AUDIT.md` for details on the audit system.

## Publication Boundary

`trustedsec/hate_crack` is a **public** repo. These paths are gitignored and
must not be committed; never `git add -f` them:

- `.claude/plans/`, `.claude/specs/`, `docs/plans/`, `docs/superpowers/` — local
  planning notes, not part of the shipped project. **Note that `.claude/` is
  published but these two subdirectories of it are not.** Plans and specs are
  per-task scratch: written in the future tense, stale the moment the work
  lands, and a reader cannot tell a shipped design from an abandoned one. The
  tooling beside them is live, and is published.
- `.claude/settings.local.json` — per-developer, per-machine permission state.
  Claude Code's own docs call it personal and not checked in, and auto-add it to
  global git excludes.

**`CLAUDE.md` and `.claude/` are published deliberately, as of 2026-08-21.**
They were on the list above until then, and were purged from branch history on
2026-07-25 (v2.14.3). The reversal was a decision, not drift: this file is the
only account of the branching, release, tagging and config policies, and an
outside contributor who cannot read it cannot follow them. `.claude/` ships the
tooling this file refers to.

Two consequences follow from that reversal, both of which used to be rules here:

- A shipped doc **may** now cite `CLAUDE.md` or `.claude/`. It still may not
  cite the two paths above.
- A tracked file **may** now execute a script from `.claude/`, because a fresh
  clone has it. That was the stated reason the `audit-docs` prek hook had to go,
  and it no longer applies — `tests/test_doc_audit_parity.py` depends on
  `.claude/audit-docs.sh` existing and is sound only because of this.

The enforcement is mechanical, not prose: `.gitignore`, the pre-commit guard at
`.github/scripts/check-publication-boundary.sh` (wired in `prek.toml`), and the
tests in `tests/test_commit_guards.py` and `tests/test_repo_hygiene.py`. All
four narrowed together on 2026-08-21; the commit-guard tests now assert the
narrowing in *both* directions, so a well-meaning revert that re-forbids
`CLAUDE.md` fails the suite rather than silently un-publishing it.

Two guards exist specifically because these files are published:

- **`test_no_tracked_file_references_unpublished_tooling`** refuses a shipped
  file that points at the local skill library by namespace, since that library
  is not published. The path guard cannot see this, because a skill namespace
  contains no path. Two of the dropped plan files carried such a directive.
  Note that CLAUDE.md is **not** exempt from this one, though it is exempt from
  the path guard — it is precisely the file the guard is for, so the forbidden
  namespace is spelled only in `tests/test_repo_hygiene.py`.
- **`tests/test_agent_instruction_integrity.py`** pins the agent-instruction
  surface. Publishing `.claude/` means a PR can now propose edits to files a
  maintainer's agent *reads as instructions* and, for hooks, *executes*. Every
  hook command, hook script, subagent definition, skill, and shell script under
  `.claude/` is pinned to a literal approved set, so adding one fails the suite
  instead of arriving quietly. It also refuses a `permissions` key in the shared
  `settings.json` (that would propose allow rules for everyone who trusts the
  workspace) and any network verb in a `.claude/` script.

  **Read its module docstring before touching the constants.** It cannot detect
  a cleverly worded instruction and does not pretend to; its value is that a
  change to this surface cannot be silent. When one fails, the question is why a
  PR about something else is editing the repo's agent instructions — not how to
  widen the constant.

**The one thing to carry forward: a gitignore plus a history rewrite does not
unpublish anything on a repo that takes PRs.** GitHub's `refs/pull/N/head` is
server-side and immutable, so `filter-repo` plus a force-push rewrites branches
and leaves PR heads untouched. The 2026-07-25 purge therefore never removed
these files from PRs #78–#137, and an audit on 2026-08-21 confirmed the exposed
blobs held no credentials, internal hostnames, RFC1918 addresses or client data
— which is the only reason it was a non-event. Only GitHub Support can delete a
PR ref; closing or deleting the PR does not. **So the gate has to be "never
commit it", never "purge it later."**

## Branching Policy

**Feature and fix branches stay local. Never push them, and never open a PR for
them.** They are merged into `nightly-dev` locally, and only `nightly-dev` is
pushed. `main` receives work only through a batch integration merge from
`nightly-dev`.

`nightly-dev` may be pushed as often as needed — there is no batching
requirement. Push it whenever a change is merged and verified.

```bash
# Branch from nightly-dev, not main. Local only.
git fetch origin
git worktree add /tmp/hate_crack-<task> -b <branch> origin/nightly-dev

# ... work, then verify inside the worktree (see Worktree Policy) ...

# Rebase onto whatever nightly-dev has become, from inside the worktree.
git fetch origin
git rebase origin/nightly-dev

# ... re-run the gates after rebasing, not before ...

# Merge locally from the main checkout, then push nightly-dev alone.
git checkout nightly-dev
git merge --ff-only origin/nightly-dev     # pick up anything new first
git merge --ff-only <branch>               # linear: no merge commit
git push origin nightly-dev

# Clean up: the branch has served its purpose and has no remote counterpart.
git worktree remove /tmp/hate_crack-<task>   # --force if it has submodules
git branch -d <branch>
```

### History stays linear — always rebase, never a merge commit

**Every integration in this repo is a rebase plus a fast-forward. Nothing
creates a merge commit.** A history full of merge bubbles arcing off and back is
hard to read, hard to bisect, and hides which commit actually introduced a
change.

Two rules follow, and they are not optional:

1. **Rebase the work branch onto `origin/nightly-dev` before merging**
   (`git rebase origin/nightly-dev` inside the worktree), then merge with
   `git merge --ff-only <branch>`.
2. **If `--ff-only` refuses, the rebase was stale** — `nightly-dev` moved after
   you rebased. Re-run the rebase. **Do not fall back to a plain `git merge`**;
   that is precisely the merge commit this policy exists to avoid.

Re-run the gates *after* rebasing. A branch that passed before the rebase has
not been tested against the code it is about to land on.

For the batch integration into `main`, use a fast-forward too:

```bash
git checkout main
git merge --ff-only nightly-dev
```

This keeps `main` and `nightly-dev` sharing identical commit SHAs, which is what
makes the next merge-down trivial. It works as long as every direct-to-`main`
commit (workflow changes, security hotfixes) is merged down into `nightly-dev`
before the next integration. **If the fast-forward refuses, merge `main` down
into `nightly-dev` first and try again** — do not reach for a merge commit, and
do not use GitHub's "Rebase and merge" button on the integration PR: it rewrites
SHAs, which would leave `main` and `nightly-dev` with no commits in common and
turn every subsequent merge-down into a conflict.

Note that history before 2026-07-30 contains merge commits. They stay. This
policy applies going forward; shared history is not rewritten.

**Do not run `git push -u origin <branch>` or `gh pr create` for a work
branch.** Pushing a branch that will only ever be merged locally leaves an
orphaned remote branch and, if a PR was opened, a review artifact nobody asked
for. There is no `--base` question to get right anymore, because there is no PR.

Two exceptions still PR directly to `main`, as documented below: workflow file
changes (they must exist on the default branch to fire) and a security fix that
must ship immediately.

Verify before merging, not after pushing. The full suite and the lint, type, and
security gates all run locally — see the Commands section — so a broken
`nightly-dev` is avoidable without waiting on CI.

`main` remains the repo default branch on purpose: it is what the public gets
on `git clone`, and it must stay at the last released state. Do not switch the
default branch to `nightly-dev`.

### Batch integration into main

Once a batch of `nightly-dev` work has accumulated, merge it into `main`:

```bash
gh pr create --base main --head nightly-dev \
  --title "release: integrate nightly-dev batch of <YYYY-MM-DD>"
```

Before merging that PR:

1. Rename the `[Unreleased]` CHANGELOG section to the version being cut. Ask the
   policy rather than guessing — from a `main` checkout of the merge candidate,
   `python3 tools/next_version.py --channel stable` prints the exact tag
   `auto-tag.yml` will create.
2. **Collect the issue references out of the `[Unreleased]` entries and put a
   `Closes #NNN` line in the PR body for each one.** Work branches never get
   their own PR, so a `Closes` in a work-branch commit message closes nothing —
   GitHub only acts on closing keywords that reach the default branch, and the
   batch PR is the single place that happens. An issue fixed weeks ago otherwise
   stays open until somebody notices. Entries carry their issue inline as
   `(#NNN)` for exactly this reason; grep the section rather than trusting
   memory.
3. Confirm the full suite and all three CI checks pass on the merge.

**Merge it with a local fast-forward, not with GitHub's merge button.** The PR
exists for the CI run, the review, and the `Closes #NNN` refs — not for the merge
mechanics. All three of GitHub's buttons break the linear-history rule: "Create a
merge commit" adds the bubble, "Squash and merge" collapses the batch into one
opaque commit, and "Rebase and merge" rewrites SHAs so `main` and `nightly-dev`
end up with no commits in common.

```bash
git fetch origin
git checkout main
git merge --ff-only origin/nightly-dev
git push origin main
```

GitHub marks the PR merged automatically once its commits reach `main`, because
the SHAs are identical. If the fast-forward refuses, `main` has commits
`nightly-dev` lacks (a workflow change or a hotfix): merge `main` down into
`nightly-dev` first, re-verify, then fast-forward.

Merging to `main` triggers `.github/workflows/auto-tag.yml`, which cuts exactly
ONE release for the whole batch — never one per change. Which component moves
depends on what the batch contains: any `feat` in it lands on `X.(Y+1).0`, a
batch of only fixes, docs and chores lands on `X.Y.(Z+1)` (see Tagging below).

### Tagging

Versions are ordinary semver, and the bump is derived from the commits in the
batch. `nightly-dev` publishes **release candidates for the version the batch is
heading toward**; merging down to `main` promotes that same target to its final
release.

    2.20.0  <  2.20.1rc1  <  2.20.1rc2  <  2.20.1  <  2.21.0rc1  <  2.21.0

So a fix-only cycle runs `2.20.0` -> `v2.20.1rc1`, `v2.20.1rc2` -> integration
merge -> `2.20.1`. The first `feat` to land mid-cycle moves the target from
`X.Y.(Z+1)` to `X.(Y+1).0`, and candidate numbering restarts against the new
target — intended, because the number always names what the batch would ship as
today.

| Branch | Workflow | Tag | GitHub release |
|--------|----------|-----|----------------|
| `main` | `auto-tag.yml` | `v2.20.1` / `v2.21.0` (final) | yes |
| `nightly-dev` | `nightly-tag.yml` | `v2.20.1rc1` (candidate) | no |

**`main` is not pinned to `X.Y.0`, and the bump is not forced per branch.** Both
were true until 2026-07-31 and both were bugs: every merge cut a minor
regardless of content, so two bugfix merges took the project from 2.20.0 to
2.22.0 in an hour with no feature between them. Earlier revisions of this file
described that behaviour as deliberate. It was not.

**No workflow computes a version number, and neither calls `cz`.** Both run
`python3 tools/next_version.py --channel {stable,nightly}` and push whatever tag
it prints. That module is the single home of the policy — pure above a thin git
boundary, unit-tested in `tests/test_next_version.py`. Add to it rather than to
YAML; `tests/test_release_versioning.py` fails if version arithmetic *or* a
`cz bump` call reappears in either workflow, and it enforces that by extracting
the step scripts and running them against a real repo, not by substring match.

Two details of that module worth knowing before touching it:

- Its baseline is the highest **final** (`vX.Y.Z`) tag in the repo, deliberately
  not restricted to tags reachable from HEAD. `main`'s release tag can sit on a
  commit `nightly-dev`'s tip does not contain, and a reachability-restricted
  lookup would compute the next nightly from a stale baseline.
- The rc number is counted from existing tags, not a stored counter, so a
  deleted or re-pushed tag cannot make it hand out a number already taken.

Further consequences:

- **A `type!:` subject or a `BREAKING CHANGE:` footer counts as a feature, not a
  major.** Major stays a rare, explicit human act: tag and push it by hand. An
  automatic major is an irreversible published mistake waiting on one mistyped
  subject line.
- **A docs/chore-only merge to `main` still cuts a release** — a patch, because
  a merge to `main` is an explicit release event. Only a genuinely empty batch
  (a workflow re-run on an already-tagged commit) is skipped. `nightly-dev`
  likewise tags every validated push, so each nightly commit stays addressable.
- Nightly tags are **real PEP 440 pre-releases** (`2.20.1rc1`), so anything
  ranking versions sorts them above the release they follow and below the
  release they become. This repo has had two wrong schemes before: `vX.Y.0-rc.N`
  aimed candidates at the *current* version, so they sorted below the release
  they were heading for; replacing them with plain finals dropped the
  pre-release marker, so a nightly looked like the latest release. Aiming one
  version forward fixes both. The historical `v*-rc.*` and plain-final nightly
  tags stay — do not delete them.

`[tool.commitizen]` in `pyproject.toml` is still load-bearing, but for local
`cz commit` and a hand-run major bump only — no workflow reads it any more.
`version_provider = "scm"` (version comes from git tags, so there is no version
string to rewrite and no bump commit) and `tag_format = "v$version"` (this
repo's tags have always been `v`-prefixed; commitizen's bare default would break
continuity with every existing tag and with `setuptools-scm`).

**After landing a change to these workflows on `main`, merge `main` down into
`nightly-dev` immediately.** `nightly-tag.yml` checks out the validated commit
and runs `tools/next_version.py` *from that checkout*, so until the module and
any change to it reach `nightly-dev`, the nightly tag is computed by whatever
version of the policy that branch happens to carry — or fails outright if the
file is missing there.

**`nightly-tag.yml` must exist on `main`**, even though it only tags
`nightly-dev`. GitHub dispatches `workflow_run` only for workflows present on
the default branch; a copy living solely on `nightly-dev` never fires, silently
— CI passes and no tag appears. Both branches carry byte-identical copies. If
you edit one, edit the other, or the integration merge will conflict on it.
Workflow changes are the one category that legitimately PRs straight to `main`.

`release.yml` is unchanged and remains the path for human-pushed tags: refs
pushed with `GITHUB_TOKEN` do not dispatch workflow events, so it never fires
for the bot tags above.

Two further consequences to keep in mind:

- **Dependabot still targets `main`.** Its PRs are exempt from the branching
  policy unless `target-branch: nightly-dev` is added to each entry in
  `.github/dependabot.yml`. Note that a Dependabot merge to `main` **does** cut
  a release — a patch, since `chore(deps)` is not a feature. Under the older
  no-bump-pattern scheme it cut nothing at all.
- **A security fix that must ship immediately** can go straight to `main` as
  its own PR, then be merged down into `nightly-dev` to keep the branches from
  diverging. Say so explicitly in the PR body when doing this.

## Worktree Policy

**Every agent MUST work in a dedicated git worktree** - never edit files directly in the main repo checkout. This prevents conflicts when multiple agents run in parallel.

### Setup

```bash
# Create a worktree under /tmp (keeps the parent directory clean).
# Branch from origin/nightly-dev - see Branching Policy above.
git worktree add /tmp/hate_crack-<task-name> -b <branch-name> origin/nightly-dev
cd /tmp/hate_crack-<task-name>

# Install dev dependencies in the new worktree
uv sync --dev

# Run tests in the worktree
HATE_CRACK_SKIP_INIT=1 uv run pytest -v
```

`git worktree add` does NOT populate submodules, so a fresh worktree has no
`hashcat-utils/bin/*.bin` and hate_crack refuses to start (`expander not found`).
Tests are unaffected because `HATE_CRACK_SKIP_INIT=1` bypasses the binary checks,
but **running the tool** in a worktree needs the submodules built first:

```bash
# Initializes all submodules and builds the bundled binaries.
# Do this instead of hand-building: the target also handles the Apple Silicon
# princeprocessor rename (src/ppAppleArm64.bin -> princeprocessor/pp64.bin).
make submodules
```

Note that `git worktree remove` refuses a worktree containing submodules
(`working trees containing submodules cannot be moved or removed`) - use
`git worktree remove --force <path>` once you have built them.

### Rules

1. **Always create a worktree** before making any file changes: `git worktree add /tmp/hate_crack-<task> -b <branch> origin/nightly-dev`
2. **All file edits** happen inside the worktree directory, not the main repo
3. **Run tests and lint** inside the worktree before merging — the full suite plus
   the ruff, ty, and bandit gates. This is the only gate the change gets, so it
   is not optional.
4. **Merge back locally**: `git checkout nightly-dev && git merge <branch>`, then
   push `nightly-dev` alone. Never push the work branch; never open a PR for it.
5. **Clean up** when done: `git worktree remove /tmp/hate_crack-<task>` (add
   `--force` if it has submodules), then `git branch -d <branch>`

## Architecture

### Module Map

The package is ~16.6k lines split across a handful of large files and many
small single-purpose ones:

| File | Lines | Role |
|---|---|---|
| `main.py` | 7.0k | hashcat invocation, menus, argparse (see Three-Layer pattern below) |
| `api.py` | 3.0k | all external-service integrations (see below) |
| `attacks.py` | 1.8k | menu handler wrappers |
| `llm.py` | 702 | Ollama / Atomic-Agents attacks — see LLM/Rosetta below |
| `rulegen.py` | 619 | rule-file generation |
| `config_writer.py` | 618 | writes `.env` / `config.json` from prompts |
| `config_loader.py` | 467 | the one config loader (see Config System) |
| `config_schema.py` | 434 | `CONFIG_SCHEMA` source of truth (see Config System) |
| `corpus_stats.py` | 322 | Pipal-adjacent corpus stats |
| `attack_coverage.py` | ~470 | per-target rule/mask/wordlist coverage store — see below |
| `plaintext.py`, `noninteractive.py`, `username_detect.py`, `menu.py`, `formatting.py`, `progress.py`, `cli.py`, `hashview_cache.py` | 60–165 each | small, single-purpose helpers |
| `notify/` | 871 total | Pushover notifications — see below |

**`attack_coverage.py`** (#273) records which rule lines, mask lines and
wordlists have already run against a hash file, so `_run_hcat_cmd` can offer to
skip the overlap. Backed by SQLite at
`~/.hate_crack/coverage/attack_coverage.sqlite3` — deliberately *not* the
append-only key file `hashview_cache.py` uses, because that cache is bounded by
hash-list size while this one is bounded by rules x wordlists (~191k keys from
one Dictionary attack, where an append-only file grows on every repeat).
Two invariants to preserve when touching it: **every failure to establish
identity returns an inert plan** (never filter on a guess — a wrongly filtered
run silently skips untried candidates), and **coverage is recorded only on clean
completion** (hashcat exit 0 or 1, not interrupted). Chained `-r a -r b` runs are
tracked as one all-or-nothing unit because hashcat applies the *cartesian
product* of the two files. Attacks opt in by passing `coverage=` to
`_run_hcat_cmd`; dynamic generators (PRINCE, PCFG, OMEN, Markov, LLM) pass
nothing and are never filtered.

**LLM / Rosetta.** `llm.py` backs menu 12 (LLM Attack, handler
`attacks.ollama_attack`) and menu 23 (Rosetta, `attacks.rosetta_attack`). It
imports `hashcat_rosetta.mask` / `hashcat_rosetta.nlmask` from the
`HashcatRosetta/` submodule behind a try/except, exposing
`rosetta_mask_unavailable_reason()` (mirrors `main.rosetta_unavailable_reason`).
The `atomic-agents`, `instructor`, `openai`, and `pydantic` dependencies exist
solely for this path. `tools/ollama_benchmark.py` supports it and is not wired
into any menu.

**`api.py` at a glance.** Hashmob rate limiting + 429 backoff (`_RateLimiter`,
`_with_hashmob_backoff`), streamed downloads, a full `TransmissionSession`
BitTorrent client (~260 lines) for Weakpass, Weakpass listing scraping with
multithreaded pagination, `HashviewAPI` (`api.py:1257-2211`, ~950 lines), and
the NTLM/MD4 plaintext validation helpers (`_md4`, `_validate_cracked_pair`,
`_wire_field_bytes`) — three separate past bugs (#216 and its siblings) lived
in that last group specifically.

**`notify/`** (`__init__.py`, `settings.py`, `tailer.py`, `pushover.py`,
`_suppress.py`). `notify.init()` runs at `hate_crack.main` **import time**,
which is why `tests/conftest.py` has an autouse `_isolate_notify_state`
fixture — without it, importing `main` during a test fires the per-attack
notification prompt's `input()` call.

### Non-interactive CLI

Alongside the interactive menu, `main.py` exposes scripted entry points:

- **Scripted attacks** — `quick | dict | brute | topmask` subcommands
  (`hate_crack/noninteractive.py`'s `ATTACK_COMMANDS`), with `--wordlist`,
  `--rules` (supports `a+b` chaining and multi-token passes), `--min`/`--max`,
  `--target-time`.
- **`hashview` subparser tree** (`main.py:6439-6520`): `upload-cracked`,
  `upload-wordlist`, `download-left`, `download-rules`, `upload-hashfile-job`.
- **Top-level flags** (`main.py:6297-6430`): `--download-hashview`,
  `--hashview`, `--download-torrent`, `--download-all-torrents`, `--weakpass`,
  `--rank`, `--hashmob`, `--rules`, `--cleanup`, `--update`, `--nightly`,
  `--no-optimized-kernel`/`--no-optimize`, `--debug`/`--no-debug`,
  `--potfile-path`/`--no-potfile-path`, `--restore-potfile`/`--no-restore-potfile`,
  `--rule-debug-mode`.

### Three-Layer Attack Pattern

Every attack spans three files with a specific wiring pattern:

1. **`hate_crack/main.py`** - Low-level hashcat function (e.g., `hcatBruteForce(hcatHashType, hcatHashFile)`)
   - Builds subprocess commands, manages `hcatProcess` global, handles KeyboardInterrupt
   - All hashcat invocations follow: build cmd list -> `cmd.extend(shlex.split(hcatTuning))` -> `_append_potfile_arg(cmd)` -> `subprocess.Popen(cmd)`

2. **`hate_crack/attacks.py`** - Menu handler wrapper (e.g., `def brute_force_crack(ctx: Any)`)
   - Receives `ctx` (the main module itself) via `_attack_ctx()`, which returns `sys.modules['hate_crack.main']`
   - Handles user prompts, then calls `ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile)`

3. **`hate_crack.py`** (root) - Menu registration + dispatcher
   - Has its own `get_main_menu_options()` that maps keys to `_attacks.<handler>`
   - **Important**: `hate_crack.py` has a DUPLICATE menu mapping separate from `main.py`'s `get_main_menu_options()`. Both must be updated when adding attacks.

### Adding a New Attack

Six wiring steps across the three layers — see the `adding-an-attack` skill.

### hate_crack.py <-> main.py Proxy

`hate_crack.py` uses `__getattr__` to proxy attribute access to `hate_crack.main`. It syncs mutable globals via `_sync_globals_to_main()` and `_sync_callables_to_main()`. Tests load `hate_crack.py` as `CLI_MODULE` and exercise both the proxy and direct module paths.

### Config System

Configuration is **split across two files, and every key has exactly one home**
(#217, 2026-07-30). There is no cross-file precedence: a key found in the wrong
file is ignored, with a warning naming the key and its real home.

- **`.env`** owns the 14 **third-party integration** keys — Hashview (url + api
  key), Hashmob (api key), Pushover (token + user), Ollama (seven keys:
  `OLLAMA_HOST`, `_MODEL`, `_NO_CLOUD`, `_NUM_CTX`, `_TIMEOUT`, `_MAX_SAMPLE_LINES`,
  `_AUTO_RESEARCH`), Pipal (path + count). Mode `0600`, gitignored, never
  committed. `.env.example` is tracked, generated from the schema, and ships
  every credential key empty.
- **`config.json`** owns the other 40 settings — wordlists, masks, rules,
  tuning, potfile, hashcat path and binary, pcfg/omen/prince limits, notify
  toggles, and five preferences promoted from CLI flags. It is **first-class
  forever**; it was never deprecated and there is no removal timeline.
- Bundled submodules — `hashcat-utils`, `HashcatRosetta` (bandrel fork),
  `omen`, `princeprocessor`, `pcfg_cracker` (`.gitmodules`, all `ignore =
  dirty`) — and hashcat itself are **not** third-party integrations here — they
  ship with the install, so their settings are local tuning and belong in
  `config.json`. **`PACK` is vendored, not a submodule** — don't add it to
  `.gitmodules` expectations.

Per-key precedence is **CLI flag > `os.environ` > that key's own home file >
schema default**. An environment variable is an ephemeral override, not a home,
which is why it may override anything — and it is what keeps the documented
`HASHVIEW_URL` / `HASHVIEW_API_KEY` overrides and `HASHVIEW_TEST_LOCAL=1`
working.

**`hate_crack/config_schema.py` is the source of truth.** `CONFIG_SCHEMA` holds
one row per key: `env`, `legacy`, `type`, `default`, `choices`, and `home`
(`"env"` or `"json"`) — `choices` is load-bearing for closed-value `str` keys,
not incidental. Seven types — `str`, `path`, `int`, `float`, `bool`, `csv_list`,
`charset`. Adding a config var means adding a row there; a drift-guard test
asserts the `home="json"` subset matches `config.json.example` exactly, so a
mismatch fails loudly rather than silently.

Two byte-identical copies of `config.json.example` exist — repo root and
`hate_crack/config.json.example`. The drift-guard test
(`tests/test_config_schema.py:29`) reads the **package** copy, and that's also
the one `pyproject.toml` ships as package-data. Editing only the root copy
passes no test and ships nothing — edit both, or better, edit the package copy
first and diff it against root.

`charset` exists because `hcatMiddleCombinatorMasks` and
`hcatThoroughCombinatorMasks` are lists of **single characters** that include a
comma, a literal space, a backslash, and both quote types. `csv_list` mangles
them. Do not "simplify" those two keys to `csv_list`.

**One loader.** `main.py`, `api.py`, and the notify package all go through
`config_loader.load_config()`, which returns a `ConfigLoadResult(config,
warnings)` NamedTuple — `.config` is the dict, keyed by legacy JSON names with
values already coerced. `main.py`'s `config_parser` global keeps that exact
shape, and ~180 lines read it unedited. `api.py` delegates rather than merging
on its own: re-adding a parallel merge regresses #153, which has now been fixed
three times in three different places.

`config_loader.candidate_roots()` is the single definition of the search order.
It is **three directories**: the repo root, the package directory, and
`~/.hate_crack`. It does **not** include the current working directory (engagement
directories are deliberately excluded) or `/opt/hate_crack` — earlier revisions
of this file claimed both, and both were wrong.

Two traps worth knowing, which is why startup now prints the resolved paths:

- The repo root outranks `~/.hate_crack`, so a stray `.env` in a checkout
  silently shadows the real one. **Running the tool from a checkout creates one.**
- A `.env` in the current working directory is never read at all, silently.

**Verifying config resolution requires a neutral cwd and no `.env` in the
worktree root.** Ignoring this cost an hour during #217: `HOME=<tmp>` fixtures
were being ignored in favour of a stray checkout `.env`, which looked exactly
like the warning system being broken.

`tests/conftest.py` sets `HATE_CRACK_SKIP_INIT` at import time and empties the
loader's candidate roots per test. Both are deliberate hermeticity guards that
stop the suite reading the developer's real config — **do not remove them as
clutter.** `SKIP_INIT` also guarantees startup writes no files.

Wordlist path handling still lives in `_normalize_wordlist_setting()` in
`main.py`; the loader handles `path`-typed keys (one `expanduser` pass
post-merge, empty string stays empty) but wordlist normalization is separate.

### Path Distinction

- **`hate_path`** - hate_crack assets directory (hashcat-utils, princeprocessor, masks, PACK). All bundled binaries use this.
- **`hcatPath`** - hashcat installation directory. Only used for the hashcat binary itself.

### External Binary Pattern

Binaries are verified at startup via `ensure_binary(path, build_dir, name)`. Non-critical binaries (princeprocessor, hcstat2gen) use try/except around `ensure_binary` with a warning message. The `SKIP_INIT` flag bypasses all binary checks.

## Testing Patterns

- Menu option tests in `test_ui_menu_options.py` use monkeypatching against `CLI_MODULE` (loaded from `hate_crack.py`)
- API tests mock `requests` responses; most are offline-first
- conftest.py provides `hc_module` fixture via `load_hate_crack_module()` which dynamically imports root `hate_crack.py` with SKIP_INIT enabled
- E2E tests (`test_e2e_local_install.py`, `test_docker_script_install.py`) are opt-in via `HATE_CRACK_RUN_E2E=1` and `HATE_CRACK_RUN_DOCKER_TESTS=1`
- Beyond `SKIP_INIT` and the config-root isolation already covered above, conftest.py
  carries two more autouse guards worth knowing before debugging a flaky test: a
  session-scoped `_isolate_git_environment` that strips `GIT_DIR`/`GIT_WORK_TREE`/
  `GIT_INDEX_FILE` (without it, prek's own pre-push stash cycle can leak those into
  pytest and point git-shelling tests at the *outer* repo's index — this has caused
  real fake flakes before) and `_isolate_hashview_cache` (patches `hashview_cache._cache_path`
  per test).
- 123 `test_*.py` files plus `tests/e2e/`; `tests/run_checks.py` and `TESTING.md` are
  separate, narrower entry points into the same suite.
