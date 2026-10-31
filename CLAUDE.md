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
returns `hookSpecificOutput.additionalContext` instructing Claude to invoke the
`readme-documentarian` agent. `audit-docs.sh:50` still emits that exact string,
so running the command above on a code-only commit *will* fire it. Removing the
prek hook disabled the scheduling, not the wiring.

**That last sentence was false from 2026-08-21 until 2026-09-16**, and the way
it was false is the thing to carry forward. The hook returned a *top-level*
`additionalContext`, which Claude Code drops as an unrecognized key for a
`PostToolUse` hook — silently, with a zero exit. The "verified end-to-end"
claim this paragraph used to carry had verified the first three links (warning
printed, grep matched, hook emitted JSON) and stopped one short of the only one
that mattered. **A hook that emits well-formed JSON has proved nothing; the
schema is where these fail, and the failure is always silent.**

Two consequences, both load-bearing:

- The hook is keyed to a **string in stdout**, not to the script, so rewording
  that `WARNING:` line silently breaks the trigger and nothing fails loudly.
- `additionalContext` belongs **inside `hookSpecificOutput`, alongside a
  `hookEventName`**. `tests/test_doc_audit_hook.py` pins that envelope and
  asserts the top-level key is absent, so the broken shape cannot return
  quietly; `tests/test_doc_audit_parity.py` covers the detection half.

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

**Feature and fix branches branch from `nightly-dev` and land on `nightly-dev`.
Never on `main`.** `main` receives work only through a batch integration merge.

**A work branch may be pushed, and normally gets a pull request against
`nightly-dev`.** Revised 2026-08-21: this section used to say branches stay
local and never get a PR, which had stopped being true. Of the six most recent
work-branch PRs, all six targeted `nightly-dev` and five landed as
fast-forwards — so the practice was already settled, and the rule was simply
out of date. Both are legitimate:

- **Open a PR** when the change wants review, or a CI run before it lands, or a
  durable record of the reasoning. This is the default for anything
  non-trivial.
- **Merge locally without one** when the change is small enough that a review
  adds nothing. `ci.yml` runs on every push to `nightly-dev`, so this still
  gets CI — just after the merge rather than before it.

What is *not* optional is the merge mechanics. **However the change is
reviewed, it lands as a local fast-forward — never with a GitHub merge
button.** The PR exists for the CI run, the review, and the record; it is not
the thing that performs the merge. See the linear-history section below, and
note the evidence for the rule: every work-branch PR that was merged through
the GitHub UI (#247, #277, #278, #279) left a merge commit behind.

`nightly-dev` may be pushed as often as needed — there is no batching
requirement. Push it whenever a change is merged and verified.

```bash
# Branch from nightly-dev, not main.
git fetch origin
git worktree add /tmp/hate_crack-<task> -b <branch> origin/nightly-dev

# ... work, then verify inside the worktree (see Worktree Policy) ...

# Rebase onto whatever nightly-dev has become, from inside the worktree.
git fetch origin
git rebase origin/nightly-dev

# ... re-run the gates after rebasing, not before ...

# Optional: push the branch and open a PR against nightly-dev for review/CI.
# Do NOT use --base main, and do NOT merge it with the GitHub button.
git push -u origin <branch>
gh pr create --base nightly-dev --head <branch>

# Merge locally from the main checkout either way, then push nightly-dev alone.
# GitHub marks the PR merged on its own once the commits reach the base branch.
git checkout nightly-dev
git merge --ff-only origin/nightly-dev     # pick up anything new first
git merge --ff-only <branch>               # linear: no merge commit
git push origin nightly-dev

# Clean up. Delete the remote branch too if you pushed one.
git worktree remove /tmp/hate_crack-<task>   # --force if it has submodules
git branch -d <branch>
git push origin --delete <branch>            # only if it was pushed
```

### History on nightly-dev stays linear — always rebase, never a merge commit

**Every integration into `nightly-dev` is a rebase plus a fast-forward. Nothing
creates a merge commit there.** (The one merge commit is the promotion into
`main`, below.) A history full of merge bubbles arcing off and back is
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

`nightly-dev` is protected by a ruleset: no deletion, no force-push, and linear
history is required, so a merge commit can never land there. The rebase plus
`--ff-only` rule above is now enforced, not just policy.

`main` is different, and is covered under Batch integration below: it takes
exactly one kind of change, a reviewed promotion pull request merged with a
**merge commit**. Nothing is ever pushed to `main` directly.

Note that history before 2026-07-30 contains merge commits. They stay. This
policy applies going forward; shared history is not rewritten.

**A work-branch PR takes `--base nightly-dev`. Never `--base main`.** That is
the one thing to get right when opening one, and it is where this has actually
gone wrong: #277, #278 and #279 each pointed a work branch at `main`, which both
bypasses the batch-integration model and — because they were merged through the
UI — left a merge commit in `main`'s history.

**If you pushed the branch, delete the remote copy after merging.** A merged
branch left on the remote is indistinguishable from work in flight; two such
refs sat on the remote for weeks before anyone asked about them, and one turned
out to be work that had already landed under a different SHA after a rebase.
Recognising that case takes `git patch-id` or `git range-diff`, because
`--is-ancestor` reports a rebased-and-merged branch as unmerged.

**Outside contributors are on the same path**, minus push access: they fork,
then open a PR against `nightly-dev`. `CONTRIBUTING.md` says so directly, since
this file is published and read by people who cannot push here. Keep the two in
step if this section changes.

There is no exception that goes straight to `main`: not a security fix, not a
workflow change. A hotfix goes through `nightly-dev` and the same promotion PR,
and can be promoted the moment it lands.

Verify before merging, not after pushing. The full suite and the lint, type, and
security gates all run locally — see the Commands section — so a broken
`nightly-dev` is avoidable without waiting on CI.

`main` remains the repo default branch on purpose: it is what the public gets
on `git clone`, and it must stay at the last released state. Do not switch the
default branch to `nightly-dev`.

### Batch integration into main

`main` sits behind the `main-reviewed-promotion` ruleset. Direct pushes are
rejected; **the only way to change `main` is a pull request from `nightly-dev`**
that passes the required checks (Lint, type-check, and tests; Bandit SAST;
pip-audit; Workflow lint; Promotion source) and is merged with a **merge
commit** — the only allowed method. Squash and rebase are blocked, and nobody,
admins included, can bypass it. `git push origin main` is rejected; do not try.

**No approving review is required (since 2026-10-31).** The ruleset used to
require one approval from someone other than the last pusher. GitHub never lets
a pull request's author approve it, and the maintainer who opens a promotion PR
has usually also pushed its head commit, so in practice every release waited on
the second maintainer. That requirement was dropped deliberately so one
maintainer can release; the ruleset name still says "reviewed" for continuity.
The same change made `Promotion source` a **required** check — it had been
listed in this section as required while the ruleset did not actually list it,
so it was advisory until then. Restoring the two-person rule means setting
`required_approving_review_count` back to 1 and `require_last_push_approval`
to true on that ruleset, and updating this section.

**The ruleset itself cannot say "from `nightly-dev`".** GitHub rulesets have no
rule for a PR's head branch, so until 2026-10-29 a fork PR aimed at `main` could
land with one approval and green checks, and the claim above was enforced only
by a reviewer noticing the base. `.github/workflows/promotion-source.yml` closes
that gap: it fails any PR into `main` whose head is not this repo's
`nightly-dev` (a fork's `nightly-dev` fails too). It is a separate workflow, not
a `ci.yml` job, because it must also run on `edited` — retargeting a PR from
`nightly-dev` to `main` fires only that event, and without it the green result
from the old base would carry over. **It is enforcing only while `Promotion
source` is listed as a required status check in the ruleset**; renaming the job
silently leaves `main` requiring a check that never reports, which
`tests/test_promotion_source.py` pins against.

Once a batch of `nightly-dev` work has accumulated, open the promotion PR:

```bash
gh pr create --base main --head nightly-dev \
  --title "chore(release): promote nightly-dev"
```

Before merging that PR:

1. Rename the `[Unreleased]` CHANGELOG section to the version being cut. Ask the
   policy rather than guessing — from a `main` checkout of the merge candidate,
   `python3 tools/next_version.py --channel stable` prints the exact tag
   the `tag` job in `ci.yml` will create.
2. **Collect the issue references out of the `[Unreleased]` entries and put a
   `Closes #NNN` line in the PR body for each one.** GitHub acts on a closing
   keyword only when it reaches the **default branch**, which is `main` — so a
   `Closes` in a work-branch commit closes nothing, and neither does one in a
   work-branch PR, because those target `nightly-dev`. The promotion PR is the
   single place a closing keyword actually fires. An issue fixed weeks ago
   otherwise stays open until somebody notices. Entries carry their issue
   inline as `(#NNN)` for exactly this reason; grep the section rather than
   trusting memory.
3. Confirm the full suite and every CI job pass on the PR, including Workflow
   lint and Promotion source. No approval is required (see above), so these
   checks and your own read of the batch are the whole gate.

Then merge with **"Create a merge commit"** in the GitHub UI, or
`gh pr merge --merge`. This is the one place in the repo where a merge commit is
correct and required, and the reason is the release tag. The tag lands on the
promotion merge commit, which `nightly-dev` never contains, but every
already-released `nightly-dev` commit is an ancestor of it. So
`git log <last release tag>..nightly-dev` lists only new work, which is exactly
what `tools/next_version.py` needs: its baseline is the highest final tag merged
into `origin/main`. Squash and rebase both rewrite SHAs, so already-released
commits would be re-counted in every later batch, and one old `feat` would keep
forcing minor bumps forever. The merge commit's tree equals the `nightly-dev` tip
it merged, so no merge-down step is needed afterwards.

**Hotfixes use the same path.** A security fix goes onto `nightly-dev` like any
other change, then through a promotion PR, and can be promoted immediately. Say
so in the PR body.

**Emergency path.** An admin can set the `main-reviewed-promotion` ruleset
enforcement to `disabled`; that is audit-logged. It is not for normal use: it
also lifts the required checks and the from-`nightly-dev`-only rule, which the
normal path keeps.

**Release tags are immutable.** A separate tag ruleset stops `v*` tags from being
moved or deleted.

Merging the promotion PR runs `ci.yml` on `main`, whose `tag` job (gated on every other job
passing) cuts exactly
ONE release for the whole batch — never one per change. Which component moves
depends on what the batch contains: any `feat` in it lands on `X.(Y+1).0`, a
batch of only fixes, docs and chores lands on `X.Y.(Z+1)` (see Tagging below).

### Tagging

Versions are ordinary semver, and the bump is derived from the commits in the
batch. `nightly-dev` publishes **release candidates for the version the batch is
heading toward**; promoting to `main` promotes that same target to its final
release.

    2.20.0  <  2.20.1rc1  <  2.20.1rc2  <  2.20.1  <  2.21.0rc1  <  2.21.0

So a fix-only cycle runs `2.20.0` -> `v2.20.1rc1`, `v2.20.1rc2` -> integration
merge -> `2.20.1`. The first `feat` to land mid-cycle moves the target from
`X.Y.(Z+1)` to `X.(Y+1).0`, and candidate numbering restarts against the new
target — intended, because the number always names what the batch would ship as
today.

| Branch | Workflow job | Tag | GitHub release |
|--------|--------------|-----|----------------|
| `main` | `ci.yml` `tag` | `v2.20.1` / `v2.21.0` (final) | yes |
| `nightly-dev` | `ci.yml` `tag` | `v2.20.1rc1` (candidate) | no |

**`main` is not pinned to `X.Y.0`, and the bump is not forced per branch.** Both
were true until 2026-07-31 and both were bugs: every merge cut a minor
regardless of content, so two bugfix merges took the project from 2.20.0 to
2.22.0 in an hour with no feature between them. Earlier revisions of this file
described that behaviour as deliberate. It was not.

**No workflow computes a version number, and none calls `cz`.** The `tag` job in
`ci.yml` runs `python3 tools/next_version.py --channel {stable,nightly}` and
pushes whatever tag it prints. That module is the single home of the policy — pure above a thin git
boundary, unit-tested in `tests/test_next_version.py`. Add to it rather than to
YAML; `tests/test_release_versioning.py` fails if version arithmetic *or* a
`cz bump` call reappears in the `tag` job, and it enforces that by extracting
the step scripts and running them against a real repo, not by substring match.

Two details of that module worth knowing before touching it:

- Its baseline is the highest **final** (`vX.Y.Z`) tag merged into
  `origin/main` (`--release-ref`; it exits 2 if that ref is missing), so a
  final-looking tag pushed anywhere else cannot move the version. It is
  deliberately not relative to HEAD: `main`'s release tag can sit on a commit
  `nightly-dev`'s tip does not contain, and a HEAD-reachability lookup would
  compute the next nightly from a stale baseline.
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

**A change to `tools/next_version.py` reaches nightly tags only once
`nightly-dev` carries it.** Each branch runs its own `ci.yml` and computes its tag
from its own checkout of that module, so until `nightly-dev` has it, the nightly
tag is computed by whatever version of the policy that branch happens to carry,
or fails outright if the file is missing there. Hotfixes land on `nightly-dev`
first, so this does not arise from the promotion path.

**Tagging is a job in `ci.yml`, not a separate workflow.** The `tag` job lists
every other job in `needs:`, so a commit that failed or skipped any of them is
never tagged, and it runs only on pushes to `main` and `nightly-dev`. It is the
only job with `contents: write`, and its checkout is the one deliberate
`persist-credentials: true`. Add any new CI job to its `needs:`;
`tests/test_release_versioning.py` fails if the two drift. **Do not reintroduce
`workflow_run`** — zizmor rates it an error-level dangerous trigger — and do not
reintroduce version math in YAML. `ci.yml` must keep `nightly-dev` in its push
branches, or no candidate is ever cut.

**`workflow-lint` guards the workflow files themselves.** It runs `actionlint`
(YAML and expression errors) and `zizmor --offline` (Actions security findings:
dangerous triggers, credential persistence, unpinned actions, injection) over
all of `.github/workflows`, each pinned to an exact version via `uvx`, so a new
workflow file is covered without editing the job. It is in `tag.needs`, so a
commit with a workflow finding is never tagged, and it becomes a required status
check on `main` once the branch ruleset is applied. Findings are fixed, never
silenced with ignore comments. `tests/test_workflow_hygiene.py` pins the
repo-wide invariants the linters and repo settings rely on: every action
SHA-pinned, top-level `permissions` on every workflow, and
`persist-credentials` off everywhere except the `tag` job.

`release.yml` remains the path for human-pushed tags: refs pushed with
`GITHUB_TOKEN` do not dispatch workflow events, so it never fires for the bot
tags above. It refuses a final `vX.Y.Z` tag that `origin/main` does not contain,
and it creates the GitHub release with `gh release create` (no third-party
action). A candidate (`vX.Y.ZrcN`) is published as a prerelease with
`--latest=false`, so it never becomes "latest".

Two further consequences to keep in mind:

- **Dependabot targets `nightly-dev`, like everything else.** Both entries in
  `.github/dependabot.yml` carry `target-branch: "nightly-dev"`, so its PRs are
  on the same path as any other work branch and get no exemption from the
  branching policy. This section used to say the opposite — that Dependabot
  still targeted `main` and was exempt "unless `target-branch` is added" — and
  that was stale: the key is present on both the `uv` and `github-actions`
  entries.

  Two things follow that are easy to get wrong:

  - **Its PRs land on `nightly-dev` by local fast-forward too, not with the merge button.** A
    Dependabot branch is almost always based on an older `nightly-dev`, so
    `--ff-only` refuses. Comment `@dependabot rebase` on the PR and wait for it
    to force-push, rather than force-pushing its branch yourself or falling back
    to a merge commit. Because each fast-forward moves `nightly-dev`, a batch of
    them is inherently serial: merge one, push, then re-request a rebase on the
    rest.
  - **Promoting a `chore(deps)` batch to `main` does cut a release** — a patch.
    `tools/next_version.py:106` returns `patch + 1` for any non-empty batch
    without a `feat`; it never returns "no bump". What the `chore(deps)` /
    `chore(ci)` prefix buys is that the batch stays a *patch* instead of being
    promoted to a minor — not that it cuts nothing. The comments in
    `.github/dependabot.yml` claimed the latter until 2026-09-22, describing the
    pre-2026-07-31 bump-pattern scheme; they now say the same thing this bullet
    does, so if the two ever disagree again, `tools/next_version.py` is the
    arbiter.
  - **`.github/workflows/dependabot-batch.yml` batches the `uv` PRs weekly.**
    It applies each open Dependabot `uv` bump to `nightly-dev`, keeps the ones
    that pass the local gates, force-pushes `deps/dependabot-batch`, and
    rewrites a tracking issue (label `dependabot-batch`) whose link opens the PR.
    You still review and fast-forward it — the gates catch breakage, not a
    malicious upstream release, and a `GITHUB_TOKEN` push to `nightly-dev`
    would trigger neither `ci.yml` nor the rc tag. If `nightly-dev` moved
    before you got to it and `--ff-only` refuses, re-run the workflow
    (`gh workflow run dependabot-batch.yml`), which re-applies and re-gates
    every bump against the current `nightly-dev`. Rebasing it by hand also
    works, but then run the full gates yourself before merging, as for any
    rebased branch — the batch was only gated against its old base. A bump
    that fails any gate — including on a flaky test — is dropped until the
    next run with no retry, so read the issue's Skipped table before assuming
    a bump is bad. If no bump survives, the job re-gates the untouched
    `nightly-dev` once, and if that fails too the issue says `nightly-dev`
    itself is broken rather than blaming the bumps. A week in which no bump
    survives deletes `deps/dependabot-batch`, unless a pull request from it is
    still open (deleting a PR's head branch closes the PR), and a week with no
    eligible Dependabot PRs closes the issue. It deliberately does **not** open the PR (that needs "Allow GitHub
    Actions to create and approve pull requests", which would let a workflow
    approve a promotion PR into `main`) and does **not** apply Actions bumps
    (`GITHUB_TOKEN` has no `workflows` permission, and that power stays out of
    automation). Triggers are only `schedule` and `workflow_dispatch`. The
    workflow file runs from `main`'s copy, so edits to it take effect only after
    promotion, but both jobs check out `nightly-dev`, so
    `tools/dependabot_batch.py` takes effect as soon as it lands there. Logic
    and trust model: `tools/dependabot_batch.py`.
- **A security fix that must ship immediately** goes through `nightly-dev` and
  the promotion PR like everything else, and can be promoted as soon as it
  lands. There is no direct-to-`main` path.

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
   the ruff, ty, and bandit gates. Run them even when the change is going to a
   PR: CI repeats them, but a red PR wastes a review cycle.
4. **Merge back with a fast-forward**: `git checkout nightly-dev && git merge
   --ff-only <branch>`, then push `nightly-dev` alone. Opening a PR against
   `nightly-dev` first is normal and encouraged — see Branching Policy — but the
   merge itself is always the local fast-forward, never a GitHub button.
5. **Clean up** when done: `git worktree remove /tmp/hate_crack-<task>` (add
   `--force` if it has submodules), then `git branch -d <branch>`, plus
   `git push origin --delete <branch>` if you pushed it

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
| `brain.py` | 388 | hashcat brain oracle, slow/fast policy, session identity, client flags, local server lifecycle — see below |
| `plaintext.py`, `noninteractive.py`, `username_detect.py`, `menu.py`, `formatting.py`, `progress.py`, `cli.py`, `hashview_cache.py` | 60–165 each | small, single-purpose helpers |
| `ui/` | 434 total | UI backend seam: a `UI` Protocol with `PlainUI` and `RichUI` implementations, `resolve_backend_name`/`build_ui`, and `get_ui`/`set_ui`/`reset_ui` — see Config System for `ui_backend` |
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
nothing and are never filtered. **`brain.py` is a separate, complementary
mechanism, not a duplicate of this one**: coverage de-duplicates whole rules,
masks and wordlists before a hashcat invocation is built, while brain
de-duplicates individual candidate passwords inside hashcat itself via a
running brain server — the two catch different overlap and neither subsumes
the other.

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

**Terminal output and prompting (`hate_crack/ui/`).** In `main.py`, `attacks.py`,
`api.py`, `noninteractive.py` and `attack_coverage.py`, output and prompts go
through `get_ui()` (`say`, `warn`, `error`, `success`, `ask`) rather than bare
`print`/`input` — 988 call sites. Severity markers like `[!]` stay inside the
message strings; the method picks styling only. `PlainUI.say` is `print` and
`PlainUI.ask` is `input(prompt) or default`, so the plain backend is
byte-identical to the old behaviour. Non-TTY and non-interactive runs force plain.

**Deliberately NOT converted — do not "finish the job":**

- `formatting.py`, `progress.py`, `menu.py`, `cli.py`: `PlainUI` delegates *to*
  these, so routing them back through `get_ui()` is circular.
- `config_loader.py`: it emits during the import-time `load_config()` that
  produces the value selecting the backend, so no backend can exist yet.
- The 18 module-scope prints in `main.py` run at import, before argparse, and
  stay plain permanently.
- 17 sites pass `print` as a value (`print_fn=print`) and still bypass the seam;
  a known follow-up.

**Invariant:** the backend must be installed before any converted call site
runs. `main()` does this immediately after `non_interactive` is finalised, and
`tests/test_ui_wiring_precedes_output.py` guards the ordering. Installing it
later silently ignores `ui_backend` and nothing else fails.

### Non-interactive CLI

Alongside the interactive menu, `main.py` exposes scripted entry points:

- **Scripted attacks** — 21 subcommands covering all but five of the menu
  attacks (#340). Every one is a row in `hate_crack/noninteractive.py`'s
  **`ATTACK_SPECS`**, which is the source of truth: `ATTACK_COMMANDS` is
  derived from it, and both `add_attack_subparsers` and `_dispatch` iterate
  it. **Add a subcommand by adding a row, never by editing those three
  separately** — `main.py` sets its `non_interactive` global from membership
  in `ATTACK_COMMANDS` (`main.py:9992`), so a name that reached the subparsers
  but not the tuple would run the attack with every interactive prompt still
  live, blocking on a stdin nothing is attached to.
  `tests/test_noninteractive_attacks.py` pins the derivation in both
  directions.

  Still interactive-only, as #340 scoped it: `hcatMarkovBruteForce`,
  `hcatGenerateRules`, `hcatRosetta`, `hcatOllama`, and Extensive Pure_Hate
  (an orchestrator, not a single attack).

  Three things the issue's own tables got wrong, confirmed against the source
  and worth not rediscovering:

  - **Menu 11 "Loopback" is not `hcatRecycle`.** `attacks.loopback_attack`
    runs `hcatQuickDictionary(..., loopback=True)` over an empty wordlist.
    `hcatRecycle`'s third argument is a count of newly cracked passwords used
    as an internal gate by `extensive_crack` only, and is meaningless as a CLI
    argument — so the `loopback` subcommand takes `--rules`.
  - **`hcatBandrel` was the one attack that genuinely could not be scripted**,
    because of a blocking `while True: input()` with no default. It now takes
    `company_name=None`; the prompt runs only when that is unset.
  - **Menu 6 "Combinator Attacks" is a submenu of four** (combinator, YOLO,
    middle, thorough). The `combinator` subcommand covers the first, and
    **routes by wordlist count exactly as `attacks.combinator_crack` does** —
    two to `hcatCombination`, three to `hcatCombinator3`, anything else, or
    any `--separator`, to `hcatCombinatorX`. That routing is not cosmetic:
    `hcatCombination` slices to `wordlists[:2]` (`main.py:4865`), so sending
    it three silently drops the third. YOLO, middle and thorough have no
    subcommand.

  Flags follow the kebab-case of the underlying `hcat*` parameter, and an
  omitted flag passes the function's own default rather than restating it
  here — `corporate` omits `minLen`/`maxLen` entirely when unset so
  `hcatCorporateMasks` applies and clamps its own. The one place that
  distinction is load-bearing is `fingerprint`'s `--dictionary-wordlist`:
  `None` means "fall back to config" and `""` means "skip the step", so
  `--no-dictionary-wordlist` exists to reach the second.
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

- **`.env`** owns 18 keys, home `"env"`. Seventeen of them are genuine
  **third-party integration** credentials — Hashview (url + api key + TLS verification), Hashmob
  (api key), Pushover (token + user), LLM (nine keys: the seven `OLLAMA_HOST`,
  `_MODEL`, `_NO_CLOUD`, `_NUM_CTX`, `_TIMEOUT`, `_MAX_SAMPLE_LINES`,
  `_AUTO_RESEARCH`, plus `LLM_BACKEND` and `LLM_API_KEY`), Pipal (path + count).
  Mode `0600`, gitignored, never committed. `.env.example` is tracked, generated
  from the schema, and ships every credential key empty. **The `OLLAMA_*` keys
  serve all three backends** (`ollama`/`vllm`/`openai`) — `LLM_BACKEND` selects
  only the request shape, and the prefix is kept deliberately; see the comment
  at `config_schema.py:296` before renaming them. **The eighteenth, `BRAIN_PASSWORD`,
  is the one exception to "env means third-party"**: hashcat brain is bundled
  tooling like the submodules below, not a third-party integration, so by the
  rule stated in the next bullet it should live in `config.json`. It is
  env-homed anyway, solely because it is a secret — the shared password a
  remote brain server expects — and `.env` is the one file that is `0600` and
  gitignored. Home is chosen per key by "is this a secret", not by "is this
  bundled vs. third-party"; those two questions usually agree, and
  `BRAIN_PASSWORD` is the key where they don't.
- **`config.json`** owns the other 49 settings — wordlists, masks, rules,
  tuning, potfile, hashcat path and binary, pcfg/omen/prince limits, notify
  toggles, the seven other `brain_*` keys, and five preferences promoted from
  CLI flags. It is **first-class forever**; it was never deprecated and there
  is no removal timeline. `ui_backend` is one of the 49; its `choices` is
  pinned to `ui.BACKENDS` plus `ui.RETIRED_BACKENDS` by
  `tests/test_ui_config_key.py`, so adding a backend without offering it as a
  config value fails the suite.
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

### No full-screen UI backend

A Textual full-screen backend (`ui_backend=textual`) shipped on nightlies and
was **removed on 2026-10-13 at the maintainer's request**: the backends are
`rich` (default) and `plain`. Design and verify UI changes against `RichUI`,
with `PlainUI` kept byte-identical to bare `print`/`input`. Do not reintroduce
a full-screen backend unasked.

`textual` stays a valid config value so an existing config keeps starting:
`hate_crack.ui.RETIRED_BACKENDS` maps it to `rich`, and `main()` prints a
one-line notice. `tests/test_ui_startup_wiring.py` pins that.

**List prompts get arrow keys through readline history.** A prompt that prints
a list and reads free text passes `ask(choices=[(key, label), ...])`; `PlainUI`
and `RichUI` wrap their `input()` in `cli.choice_history`, which swaps readline
history for the listed keys for that one call and restores it afterwards. This
machine's readline is libedit, so `tests/test_readline_choice_history.py` drives
it in a real pty rather than trusting a mock.

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
