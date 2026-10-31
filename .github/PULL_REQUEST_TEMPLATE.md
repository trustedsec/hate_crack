<!--
Base branch: nightly-dev. GitHub preselects main, which only accepts the
maintainers' promotion PR from nightly-dev; a PR into main from anywhere else
fails the "Promotion source" check. If you opened this against main, edit the
PR and change the base. See CONTRIBUTING.md.

Maintainers opening the nightly-dev -> main promotion PR: replace this template
with the release checklist from CLAUDE.md ("Batch integration into main"),
including a "Closes #NNN" line per issue in the [Unreleased] CHANGELOG section.
-->

## Summary

<!-- What changed, and why it was wrong or missing before. -->

Issue: #

<!-- A closing keyword ("Fixes #NNN") does nothing here: GitHub only acts on it
when the change reaches main, the default branch. Reference the issue above
and in your CHANGELOG entry; the maintainers carry it into the promotion PR,
which is where it closes. -->

## Testing

<!-- What you ran and what you saw. For behaviour against real hashes, give
the hash mode and aggregates only ("3 of 200 cracked"), never the data. -->

## Checklist

- [ ] Base branch is `nightly-dev`
- [ ] No engagement data anywhere in this PR: no hashes, plaintexts, basewords, partial passwords, potfiles, client wordlists, or hostnames/usernames that identify an organization (code, tests, screenshots, or this description)
- [ ] Commit subjects follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat` moves the minor version; `fix`/`docs`/`chore` move the patch)
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`, citing the issue inline as `(#NNN)` if there is one
- [ ] The gates in CONTRIBUTING.md's "Before you open a pull request" pass locally:
  - [ ] `HATE_CRACK_SKIP_INIT=1 uv run pytest`
  - [ ] `ruff check`, `ruff format --check`, and `ty check` over the full documented scope
  - [ ] `bandit` against the baseline, and `pip-audit`
- [ ] New attack modes: both menu mappings (`hate_crack.py` and `hate_crack/main.py`) are updated
