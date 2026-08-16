# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are omitted for releases predating this file; see the git tags for exact timing.

## [Unreleased]

### Added
- **`--migrate-hashcat-home`** copies the contents of a legacy `~/.hashcat` into the directory hashcat 7 actually uses, and startup now names what is stranded there. It never overwrites and never deletes: a colliding name is copied as `<name>.from-legacy` (merging two potfiles is the operator's call, not a startup helper's), and removing the old directory is left to you.

### Fixed
- **hate_crack no longer pins hashcat's pre-7 data directory, and no longer resurrects it.** hashcat 7 moved per-user state to `$XDG_DATA_HOME/hashcat` (default `~/.local/share/hashcat`) and its kernel cache to `~/.cache/hashcat`, and prints a seven-line notice for as long as `~/.hashcat` exists. hate_crack shipped the old path as the `hcatPotfilePath` default *and* `os.makedirs()`'d it on every hashcat invocation, with three consequences. The notice could never be cleared — deleting the directory as hashcat instructs was undone by the next run. `--potfile-path` pointed at a potfile hashcat had stopped writing, so cracks made outside hate_crack were invisible to `--show` and to the Hashview upload paths, and the two potfiles silently diverged. And because the notice goes to *stdout* as well as stderr, it polluted the output of every `hashcat --stdout` the test suite parsed: `test_every_builtin_charset_is_ascii_only` saw `?a` as 102 characters rather than 95 and failed, which read as hashcat having gained non-ASCII charsets. (Shipped `--show` parsing was unaffected — its `":" in line` filter happens to reject all seven notice lines.) The default is now the `auto` sentinel, resolved per run by the new `hate_crack/hashcat_paths.py` against the installed hashcat's major version, so hashcat 6 installs keep `~/.hashcat` and 7+ installs follow it — including a non-default `XDG_DATA_HOME`, which hardcoding `~/.local/share` would have missed. `""` keeps its existing meaning of "pass no `--potfile-path`". The two test helpers that probed `~/.hashcat/sessions` for writability now resolve the directory too; they were both testing the wrong location and recreating the directory the tool asks users to delete.
- The `config.json.example` drift guards now reject duplicate keys. `json.load` accepts a repeated object key and keeps the last one, so a doubled line parsed cleanly and every existing guard still passed — the key set collapses the pair, so the counts and the type tallies all matched. A malformed example could ship with the suite green, which is exactly what happened while adding `hcatCorpusProfileMaxLines` (an edit written through both the root path and the package symlink that points at it). Loading now goes through `tests/_json_strict.py`, which raises on a duplicate at any nesting depth, and a mutation test duplicates a real line from the real example to prove the guard fires rather than assuming it does.
- The corpus-profiling pass behind the LLM attacks is now bounded and reports live progress. Selecting a large pattern source printed `Analyzing pattern source...` with only an elapsed counter while `corpus_stats.summarize()` read *every* line at roughly 135k lines/s — on the 29 GB hashmob `official.found` corpus (~3.57B lines) that is over seven hours of pure-Python work, and the exact distinct-password set it builds would exhaust memory long before finishing. Past `hcatCorpusProfileMaxLines` (new `config.json` key, default 5,000,000) the pass now samples evenly across the file's whole byte range instead of reading it end to end, finishing that corpus in ~51s. Sampling is spread across ~2,000 anchor points rather than truncated to a head slice, because large wordlists are ordered and their first N lines describe the ordering rather than the corpus. A sampled summary no longer tells the model its figures "cover the ENTIRE corpus"; it states the estimated corpus size and the coverage percentage instead.
- The spinner message for that pass now reads `Profiling <source> locally (no LLM yet)...` and carries a live line counter. The old wording read as though the model had stalled, when in fact `corpus_stats` never contacts Ollama at all. `progress.spinner()` now yields a `SpinnerHandle` whose `set_detail()` updates the text in place, so any long local operation can report progress without owning the repaint loop.

## [2.27.0] - 2026-08-14

### Added
- **Corporate Masks Brute Force attack (option 24)** — statistical 8-14 character hashcat masks derived from analysis of 3.2M NTLM hashes cracked on real engagements, powered by [Corporate_Masks](https://github.com/golem445/Corporate_Masks). Prompts for min/max length, runs each as a separate hashcat invocation, gracefully handles missing mask files, and supports optimized kernels (#269).

### Fixed
- The startup update check no longer offers a downgrade on `nightly-dev`. That branch publishes release candidates aimed at the version the batch is heading toward, so its version sorts *below* the release it becomes (`2.26.2rc1` < `2.26.2` under PEP 440). Once the target release shipped, a checkout that already contained it — plus every commit since — still compared as older, and the notice fired on every start until the branch's target moved past it. The guard now asks whether HEAD *contains* the release commit (`git merge-base --is-ancestor`) rather than whether it *equals* it; equality is the degenerate case, so the previous behaviour is preserved. Non-git installs still fall back to the version comparison (#271).
- Startup now warns when `optimizedKernelAttacks` in `config.json` is missing attacks that use `-O` by default, naming each one and the file it came from. That setting is a whole-list opt-in, so a `config.json` written before an attack existed pins the list without it and the attack never gets the optimized kernel — silently, since the only symptom is reduced speed. `hcatRosettaMask` shipped degraded for eleven days before this surfaced, and `hcatCorporateMasks` was degraded the day it landed. The list is also how an attack is deliberately opted out, and the two cases are indistinguishable, so this warns rather than repairing the list (#270).

## [2.26.2] - 2026-08-13

### Fixed
- Fresh git worktrees' first `pytest` run would fail ~23 tests in hashcat_rosetta-dependent test files, all with "AssertionError: hcmask validity check failed". The issue: `git submodule update --init` was deferred to a test body, which runs *after* collection, but `hate_crack.main`'s module-level imports cache the ImportError if HashcatRosetta is not found at import time (collection phase). Submodule initialization is now part of `pytest_configure`, which runs *before* collection, so the import always sees populated submodules on the first run. Additionally fixed: the guard logic now correctly detects git worktrees (where `.git` is a file, not a directory), checks submodule status before running update (so developers can intentionally move a submodule to a different commit/branch without pytest silently resetting it), adds a 600s timeout with network stalling protection and opt-out via `HATE_CRACK_SKIP_SUBMODULE_INIT=1` for CI environments, and avoids potential hangs from unresponsive networks or credential prompts (#266).

## [2.26.1] - 2026-08-13

### Fixed
- `tests/test_random_rules_attack.py`'s `load_cli_module()` now purges only `hate_crack.main`/`hate_crack` from `sys.modules` instead of deleting every `hate_crack.*` module except a hand-maintained preserve list. The old approach let any name-bound import (e.g. `hate_crack.api`'s `load_cache`/`append_to_cache`) drift out of sync with a reloaded module, which would silently defeat `tests/conftest.py`'s isolation fixtures and risk writes to the operator's real `~/.hate_crack` cache file (#264).

## [2.26.0] - 2026-08-12

### Added
- A regression test locking in that `upload_cracked_hashes` preserves leading/trailing whitespace in cracked plaintexts (#244).
- LLM target research now also recalls a parent company / acquisition history for the named organization, alongside industry and location, and uses it when generating password candidates (#263).

### Fixed
- OMEN training now decompresses gzip-compressed training wordlists, matching the N-gram attack's existing behavior (#257).
- Config resolution now warns when a `config.json`/`.env` at a higher-priority candidate root (the repo checkout, or the installed package directory) is shadowing one at a lower-priority root (`~/.hate_crack`), instead of silently ignoring the shadowed file forever. A stray file left behind in a checkout could otherwise make a real, hand-configured `~/.hate_crack/config.json` (hashcat path, wordlist/rules directories, etc.) look like it had been silently replaced with schema-default placeholders on first run — which file wins is unchanged, this only makes the shadowing visible (#246).

## [2.25.1] - 2026-08-04

### Fixed
- **`--update`/`--nightly` refused to run on an install that had ever built the
  bundled binaries**, printing `Cannot auto-upgrade: uncommitted changes` even
  though the operator had not touched a single tracked file. `make
  submodules`/`make install` build hashcat-utils, princeprocessor, OMEN and the
  other bundled binaries inside their own submodule working trees, leaving
  generated sources, object files, and a touched `Makefile` there — content
  `git status --porcelain` reports as `M <submodule>` on the superproject. The
  pre-upgrade dirty check now passes `--ignore-submodules=dirty`, so build
  byproducts inside a submodule no longer block the upgrade; a submodule
  actually pinned to a different commit than recorded still does, since
  `checkout -B` on the superproject cannot fix that anyway.

## [2.25.0] - 2026-08-04

### Added
- **`upload_cracked_hashes` now batches uploads into 10,000-line chunks per
  POST to Hashview's `/v1/hashes/import/<hash_type>` endpoint, instead of
  sending the whole file as one single request.** Large submissions (e.g.
  800k hashes) were failing outright, with no partial progress retained on
  failure. Each batch's cache keys are recorded immediately after that
  batch's own successful POST, so a later batch's failure still leaves
  earlier batches deduped for a retry — a re-run resumes instead of
  resending everything. `upload_hashfile` is unchanged.
- **The Rosetta menu (`23`) gained a fourth choice, an LLM Mask Attack**: describe
  the passwords you expect in plain English and a local Ollama model
  (`llm.generate_masks`) turns that description into hashcat brute-force
  masks, which are written to `<hashfile>.hcmask` and run immediately with
  `-a 3` (`hcatRosettaMask`). No corpus statistics are sent to the model —
  this mode is driven entirely by the operator's description, unlike the
  existing rule-mining choices `1`-`3`.

### Changed
- **`.hcmask` files are now removed by `cleanup()` when the session ends.** This
  affects the existing Top Mask attack, which generates `.hcmask` files via PACK's
  `maskgen.py` — previously these generated mask files were left behind after a
  session for re-use or inspection; they are now cleaned up along with other
  session artifacts.
- **`llm.generate_masks` now delegates entirely to
  `hashcat_rosetta.nlmask.generate_masks`** instead of a second, hand-maintained
  Atomic Agents prompt (`_MASK_PROMPT`/`MaskAttackOutput`, both removed). The LLM
  Mask Attack's prompt, output schema, hcmask syntax validation, and the
  one-retry-on-failure behavior all now come from HashcatRosetta itself, so this
  feature can't silently drift from that project's own SYSTEM_PROMPT fixes the
  way it had (HashcatRosetta had already independently fixed a `[...]`
  bracket-syntax hallucination, an arbitrary "always pick 6" category cap, and a
  word-decomposition bug that this module's own prompt never guarded against).
  The practical result is that the LLM Mask Attack now supports custom charsets
  (`?1`-`?8`, up to 8 per HashcatRosetta's own hashcat-verified limit) for the
  first time — every generated mask combines its custom charsets (if any) into
  one canonical hcmask line (e.g. `aeiou,?1?1?1?1?d?d`) via
  `hashcat_rosetta.mask.format_hcmask_line`.
- **`_valid_hcmask` now delegates its grammar check to
  `hashcat_rosetta.mask.parse_hcmask_line`** instead of a hand-rolled
  placeholder-letter scanner, and no longer blanket-rejects a `,` or `\`. Both
  are legitimate hcmask syntax (a custom-charset separator and an escape
  character respectively) that the old checker couldn't tell apart from a
  malformed mask — it had no concept of custom charsets at all. The old
  32-character length cap (a runaway-output guard, not a real hashcat limit) is
  also gone, replaced by hashcat's own real 256-position limit, which
  HashcatRosetta's `parse_hcmask_line` now enforces directly. Embedded
  newline/carriage-return/tab and a leading `#` are still rejected locally —
  those are `.hcmask` *file*-safety concerns `parse_hcmask_line` has no reason
  to know about, not mask grammar.

### Fixed
- **Rule-based attacks no longer die outright against a hashcat build that
  predates `--debug-mode` 5 support.** `_add_debug_mode_for_rules` always
  requested mode 5, so a hashcat older than the one that introduced it
  rejected every `-r` attack with `Invalid --debug-mode value specified.`
  (exit 255) before any cracking started. `_run_hcat_cmd` now captures stderr
  for debug-mode invocations, detects that specific rejection, retries the
  same attack at mode 4, and drops the request to mode 4 for the rest of the
  run so later rule-based attacks ask for it directly instead of failing and
  retrying every time.
- **Added `--rule-debug-mode`/`--no-rule-debug-mode`** (persisted default:
  `rule_debug_mode_enabled` in config.json, `true`) to fully disable the
  `--debug-mode`/`--debug-file` flags rule-based attacks otherwise always add.
  This is unrelated to the existing `--debug`/`--no-debug` flag, which only
  controls hate_crack's own verbose logging and never touched hashcat's
  debug-mode flags.
- **`rosetta_derive` misparsed a batch mixing `--debug-mode` 4 and 5 logs,
  logging one file's lines as `Skipping malformed mode-5 line (missing
  wordlist field)` and dropping them.** It merged every selected log's raw
  lines into one list before handing them to HashcatRosetta, whose format/mode
  detection samples only the start of whatever it's given -- so whichever
  file's lines landed first decided the mode for the whole batch. It now calls
  HashcatRosetta's `analyze_debug_files()`, which detects each file's format
  and mode independently (requires HashcatRosetta >= the commit adding that
  method; bumped alongside this fix).
- **`rosetta_derive` stopped reading debug logs after 1,000,000 lines and
  printed `[!] Stopped at 1000000 debug lines`, silently discarding the
  remainder of large captures.** The cap and its `max_lines` parameter are
  removed; every line of every selected log is now read.
- **A cracked NTLM plaintext that hashcat `$HEX[...]`-wraps for a reason
  unrelated to encoding (an embedded colon, a control character) was
  corrupted before reaching Hashview, which then rejected it with
  `Plaintext for hash <hash>, was found to be invalid` even though
  hate_crack's own local validation had accepted the pair.** `_wire_field_bytes`
  always reconstructed `$HEX[...]`-wrapped bytes for UTF-16LE modes (900,
  1000, 1731) as latin-1 code points needing zero-extend repair — correct
  when hashcat wrapped genuinely non-UTF-8 bytes, but wrong when the wrapped
  bytes were already valid UTF-8 text, which double-encoded them (e.g.
  `café:` became `cafÃ©:`) into a plaintext that no longer hashed to the
  claimed digest. It now mirrors `_digest_for_type`'s UTF-8-first check:
  valid UTF-8 is sent as-is, and the latin-1 zero-extend path is used only
  when the wrapped bytes fail to decode as UTF-8.

## [2.24.0] - 2026-08-02

### Fixed
- **A cracked password with a leading or trailing space was flagged as a
  hash/plaintext mismatch and skipped during Hashview upload.** Both
  `upload_cracked_hashes` and `_read_found_pairs` used a bare `.strip()` on the
  raw `hash:plain` line before splitting on `:`, which strips *all* whitespace,
  not just the line terminator — so a password's own leading/trailing space was
  eaten before validation or before the value reached the potfile/Hashview.
  `upload_cracked_hashes` also had a second, redundant `.strip()` on the
  already-split plaintext field. Both now use `rstrip(b"\r\n")` to drop only
  the newline, mirroring the byte-preserving fix already applied for non-UTF-8
  plaintexts in #216.

- **Wordlist and rule pickers no longer list directories and dot-files as if
  they were files** (#233). `list_wordlist_files()` was a bare `os.listdir` with
  an extension blocklist and a one-off `.DS_Store` exclusion, so subdirectories
  and dot-files were numbered in the pickers as wordlists, and several callers
  joined those names onto a directory and handed the result to hashcat as a
  *file* argument. The same pattern was repeated inline for rule listings.

  Listing is now typed: `list_wordlist_entries()` returns `DirEntry(name,
  is_dir)`, `list_wordlist_files()` and `list_rule_files()` return files only,
  and dot-files are dropped wholesale rather than by name.

  The policy follows what hashcat actually accepts, verified against the binary:
  a straight-mode (`-a 0`) dictionary position takes a directory and consumes
  every file inside it, while a `-r` rulefile and an `-a 1` operand must be
  files. So Quick Crack, the standard Dictionary attack and rule generation keep
  offering directories — marked with a trailing `/` and coloured — while OMEN
  training, Markov training, the rules picker and the LLM attack's unattended
  `-r` loop take files only. The LLM loop was the worst of these: it ran
  `hashcat -r <entry>` over every entry with nobody watching, so one stray
  subdirectory failed the run.

  Also fixed: the rules re-listing after a Hashmob download dropped even the
  `.DS_Store` filter; the rule tab-completer was the only one of six not marking
  directories, and globbed inconsistently once you typed; the Hashmob
  already-downloaded set could let a directory shadow a rule filename and skip a
  real download; and `wordlist_optimize`'s "is this empty" test was defeated by
  a stray `.DS_Store`.

  Colour is passed parallel to the entries and applied after padding, because
  `print_multicolumn_list` pads with `ljust` and truncates on `len()` — an
  escape baked into an entry string would be counted as visible width, leaving
  the grid ragged and a truncated name able to strand an unreset colour.

### Added
- Hashview uploads now skip hashes already uploaded in a previous run, tracked in `~/.hate_crack/hashview_uploaded_cache.txt` (`upload_cracked_hashes`, `upload_hashfile`).

### Fixed
- **Uploading a hashfile and later uploading its cracked results silently
  dropped the cracked-results upload.** Both `upload_hashfile` (send hashes to
  be cracked) and `upload_cracked_hashes` (send plaintexts back) computed the
  same cache key for a given `(hash, hash_type)` pair, so the two operations
  collided: after uploading a hashfile, the follow-up upload of its cracked
  results saw every hash as already "uploaded" and skipped all of them,
  while still printing `✓ Success`. The cache key is now namespaced per
  operation (`cracked` vs. `hashfile:<customer_id>`), so the two paths can no
  longer collide, and re-uploading the same hashlist for a different
  customer is no longer silently skipped either.
- Two call sites in `main.py` checked `"hashfile_id" in result` (presence)
  rather than truthiness, so `upload_hashfile`'s all-cached response
  (`hashfile_id: None`) passed the guard as if a real hashfile was created —
  the interactive menu offered to create a job against `None`, and the
  `upload-hashfile-job` CLI subcommand called `create_job(None, ...)` instead
  of reporting an error. Both now check `result.get("hashfile_id")`.
- `upload_cracked_hashes` raised a misleading "No valid hashes to upload"
  exception when a file mixed already-cached hashes with a genuinely invalid
  line, blaming the invalid line while hiding that the cached hashes were
  actually fine. The graceful early return now fires whenever any hashes were
  cached, regardless of whether others were also invalid.
- **A cracked NTLM (mode 1000) plaintext with a genuine multi-byte UTF-8
  character (e.g. `£`) was rejected as "plaintext does not match hash under
  mode 1000" and skipped during Hashview upload.** `_digest_for_type`
  zero-extended each *UTF-8 byte* of the plaintext before UTF-16LE encoding —
  correct only for raw bytes recovered from a `$HEX[...]` wrapper — instead of
  encoding the actual Unicode codepoints, doubling every non-ASCII character
  into two UTF-16 code units and producing the wrong digest. Mode 1000 now
  prefers decoding the raw bytes as UTF-8 (exact for genuine text, a no-op for
  the zero-extend path since `$HEX`-wrapped bytes are only ever non-UTF-8 by
  construction), falling back to the existing latin-1 zero-extend only when
  that decode fails.

## [2.23.0] - 2026-07-31

### Changed
- **Listing a customer's hashfiles takes one request instead of 26.** Hashview
  had no route to list a customer's files, so `get_all_customer_hashfiles`
  approximated one by querying `/v1/hashfiles/hash_type/<N>` once per entry in a
  26-entry table of common hashcat modes, pulling down every hashfile of each
  type server-wide and discarding the ones belonging to other customers. Against
  a live server a single one of those 26 requests measured 88 seconds. It was
  also incomplete by construction: a hashfile of a type outside the table was
  invisible, which is why the "no hashfiles" message had to hedge about whether
  the server was old or the customer merely had nothing of a common type.

  Hashview v0.8.3-dev added `GET /v1/customers/<id>/hashfiles`, which filters
  server-side and covers every hash type. That route is used when present. Older
  servers answer it with a 404 and fall back to the sweep unchanged, so nothing
  regresses on them; passing `hash_types` explicitly still forces the sweep.

### Fixed
- **`python -m hate_crack --help` no longer calls itself `__main__.py`.** The
  parser took its program name from whatever argparse inferred, which is the
  module filename under `-m`. The console script was unaffected, since argparse
  derives the name from the script basename there, so the wrong name only ever
  showed up on the module invocation path. The name is now stated explicitly.

  The existing coverage in `test_installed_tool_execution.py` could not catch
  this: it invoked the tool through a bare `hate_crack` on `PATH`, which resolves
  to the console script and therefore reads correctly either way. Worse, `PATH`
  is not guaranteed to point at this checkout — an unrelated install elsewhere on
  the machine would silently become the thing under test, and did. Those tests now
  run the console script belonging to the interpreter running them, and a new test
  covers the `-m` path that actually regressed.

## [2.22.2] - 2026-07-31

### Fixed
- **`tools/`, `packaging/`, and the `hate_crack.py` entry point are now linted
  everywhere, and a guard proves it.** No lint entry point named `tools/` or
  `packaging/` at all, so an `F541` and a formatting drift sat unnoticed in
  `tools/ollama_benchmark.py` until someone ran ruff by hand (issue #237). The
  Makefile, `prek.toml`, and `.github/workflows/ci.yml` now all scope ruff to
  `hate_crack tests tools packaging hate_crack.py`, and
  `tests/test_lint_scope.py` reads those files directly so it fails the moment
  any of them drifts from the others.

  `hate_crack.py` -- the documented entry point (README.md) -- was invisible to
  the drift guard itself: it only ever swept directories, so a root-level
  module could never be flagged as unlinted even after the scope above was
  widened. The guard now sweeps root `.py` files too. `hate_crack.py`'s 32
  `F821`s are an intentional consequence of its `globals().setdefault()`
  re-export shim (ruff can't see the runtime copy from `hate_crack/main.py`),
  so they're silenced explicitly via `[tool.ruff.lint.per-file-ignores]` rather
  than left to accumulate unexplained.

  Two more gaps in the guard itself: `test_both_lint_and_format_are_checked_
  everywhere` only asserted a command count, so two `ruff check` lines and zero
  `ruff format --check` lines would still pass -- it now checks the verbs
  actually present. And `test_the_declared_scope_actually_passes` ran `python
  -m ruff` instead of `uv run ruff`, which can resolve a different ruff
  entirely than every real gate uses.

## [2.22.1] - 2026-07-31

### Fixed
- **Release versions now reflect what is in the batch.** `auto-tag.yml` forced
  `cz bump --increment MINOR` on every merge into `main`, so the second component
  moved regardless of content and `main` could never produce an `X.Y.Z` with a
  non-zero patch. Two bugfix merges took the project from 2.20.0 to 2.22.0 inside
  an hour with no feature between them. The forcing was annotated as deliberate
  (*"It is forced rather than inferred from commit messages… Do not add
  breaking-change detection here"*); that annotation described the bug, not a
  requirement.

  The policy is now ordinary semver, derived from the commits since the last
  release: any `feat` means the batch is heading for `X.(Y+1).0`, and a batch of
  only fixes, docs and chores is heading for `X.Y.(Z+1)`. Applied to this
  afternoon's history, the two releases would have been 2.20.1 and 2.21.0 rather
  than 2.21.0 and 2.22.0.

  `nightly-dev` now tags release candidates for whichever version the batch is
  heading toward (`v2.20.1rc1`, `v2.20.1rc2`, …) and merging down to `main`
  promotes that target to its final release. These are real PEP 440
  pre-releases, so they order correctly at both ends --
  `2.20.0 < 2.20.1rc1 < 2.20.1rc2 < 2.20.1 < 2.21.0rc1 < 2.21.0` -- which is the
  property the two previous schemes each missed. Tagging `vX.Y.0-rc.N` aimed
  candidates at the current cycle's version, so a candidate sorted below the
  release it was heading for; replacing them with ordinary final versions dropped
  the pre-release marker entirely, so anything ranking versions saw a nightly as
  the latest release. Aiming one version forward fixes both.

  The major component is still never bumped automatically: a `!` subject or a
  `BREAKING CHANGE:` footer counts as a feature. An automatic major is one
  mistyped subject line away from an irreversible published release, so it stays
  an explicit human act.

  The policy moved out of YAML into `tools/next_version.py`, shared by both
  workflows and unit-tested in `tests/test_next_version.py` (43 tests, including
  the ordering asserted against the real PEP 440 parser). The workflow steps that
  consume it are themselves executed against real repositories in
  `tests/test_release_versioning.py`, so a wrong *value* now fails a test -- the
  previous tests stubbed `uvx` and could only prove the step parsed a fixed
  string, never that the policy was right. Both workflows also now skip cleanly
  when a batch is empty instead of tagging the empty string.

## [2.22.0] - 2026-07-31

### Added
- **Startup now finishes a migration that a later schema change stranded.**
  `write_env_from_legacy()` only runs when there is no `.env` yet -- once both
  files exist, the bootstrap has nothing more to do. So a key that becomes
  env-homed *after* a user's `.env` was written stays in their `config.json`,
  where the loader ignores it and warns about it on every single start, and
  nothing finishes the move except hand-editing JSON. `OLLAMA_HOST` did exactly
  that. On a real install this meant twelve ignored keys, including
  `hashview_api_key` and the whole `ollama*` group, silently inert.

  `finish_stale_migration()` now copies those values into the `.env` and prunes
  them from `config.json`, backing the original up first. It does so without
  asking, matching `write_env_from_legacy()`, which also rewrites `config.json`
  unprompted: a stranded key is already being ignored, so leaving it preserves
  nothing but the warning -- and the warning *was* the prompt. Running
  unprompted also means scheduled and piped runs get repaired, which is exactly
  where a prompt would hang or be dismissed forever.

  A key already set in the `.env` keeps that value -- the `.env` is the live
  source, and copying the stale copy over it would silently revert a setting in
  use -- but is still pruned, since it was being ignored. A wrongly-typed value
  is neither copied nor pruned, matching the first-stage migration: it is the
  only record of what the user meant. Notes name keys only, never values, since
  several are secrets. Skipped entirely under `SKIP_INIT`, and any failure is
  reported and swallowed rather than stopping startup.

### Fixed
- **A second migration no longer overwrites the first one's backup.** The prune
  step wrote to a fixed `<config.json>.pre-split.bak`, which was safe while it
  ran once per install at `.env` creation. Now that `finish_stale_migration()`
  can run again -- any time a further key becomes env-homed -- a plain copy onto
  that path silently replaced the only copy of the genuinely pre-split
  `config.json`. Observed for real: a repair clobbered a `.pre-split.bak` written
  weeks earlier. Backups now fall back to `.pre-split.bak.2`, `.3` and so on, so
  a used name is never reused.

## [2.21.0] - 2026-07-31

### Fixed
- **The update check no longer loops forever when one commit carries two release
  tags.** The 2.20.0 release left commit `e37d568` tagged both `v2.19.15` and
  `v2.20.0`, because `nightly-dev` and `main` pointed at the same commit and both
  tag workflows fired on it. `git describe` breaks a same-commit tie by ref
  iteration order, which is lexicographic, so the *lower* tag wins: setuptools-scm
  reported 2.19.15 while the releases API reported 2.20.0. Every start offered an
  upgrade, and accepting it re-fetched the same tags, landed on the same commit
  and regenerated the same version, so no number of upgrades could clear it. It
  affected every user who upgraded to 2.20.0.

  `check_for_updates()` now treats "the latest release tag points at HEAD" as up
  to date regardless of the version string, since being on the released commit is
  the authoritative answer and a version derived from `describe` is not. Any
  failure to establish that -- no checkout, no such tag locally, no git -- falls
  back to the version comparison, so installs that are not git clones still get
  the notice.

  Covered by `tests/test_upgrade_convergence.py`, which runs real git so the
  version really comes from a real `describe`. It asserts the property the
  existing upgrade tests missed: they cover upgrade *mechanics*, but nothing
  checked that upgrading is a *fixed point*. Both halves of this bug are
  individually correct and only fail composed, so mechanics-only tests could not
  have caught it.

  The release pipeline can still produce the ambiguous state; that half is being
  addressed separately in the versioning-policy work (#221).

## [2.20.0] - 2026-07-31

### Added
- **Spoonman Attack now offers the current session's cracked passwords
  (`<hash file>.out`) as a corpus source**, ahead of the free-form path prompt,
  whenever that file exists and is non-empty. Spoonman derives basewords and
  rules that exactly reconstruct its input corpus, so feeding it the target's
  own recovered plaintexts derives rules describing that target's actual
  conventions rather than a generic wordlist's. Mirrors the picker already
  used by the LLM pattern mode (`_pick_pattern_source` / `ollama_attack`); the
  shared menu logic is now factored into `_offer_cracked_or`. Sessions with no
  `.out` yet see no menu at all -- behaviour is unchanged. (#219)

- **A hashcat-backed correctness oracle for the mask generator, in
  `tests/test_mask_oracle.py`.** Every other `_mask()` test compares against a
  hand-written expected string, which only proves the function agrees with our
  own belief about what `?l`/`?d`/`?s` mean. These tests ask hashcat instead:
  hash a short synthetic plaintext, hand hashcat the mask `_mask()` produced,
  and assert hashcat recovers the plaintext. A negative control asserts a
  deliberately wrong mask is *not* cracked, so a potfile hit or an output-format
  change cannot make the positive cases pass vacuously (`--potfile-disable` is
  passed for the same reason). A third test pins that `?a` is exactly 95
  candidates -- the printable-ASCII set -- which is the fact #230 rests on.
  Skips when hashcat is absent, so it is effectively local-only: CI does not
  install hashcat. This oracle is what found #230. (#230)


- **`OLLAMA_NO_CLOUD`, an opt-in refusal of Ollama's cloud-hosted models.** Ollama
  proxies a `-cloud`-tagged model (`gpt-oss:120b-cloud`, `deepseek-v3.1:671b-cloud`)
  to ollama.com through the same local `/v1` endpoint a local model uses, so nothing
  about the request shape signals that the prompt is leaving the host — and these
  prompts carry recovered plaintexts, corpus statistics, and the client's name,
  industry and location. The model name is the only thing checkable before the data
  is already gone. Set `OLLAMA_NO_CLOUD=1` in `.env` and a cloud model is refused
  before a client is built or a request assembled. It defaults to off, so anyone
  deliberately using a cloud model is unaffected. The check lives at the three
  `hate_crack.llm` entry points rather than at their call sites, and its `no_cloud`
  parameter is keyword-only with no default, so a new call site has to state a
  policy instead of silently inheriting a permissive one.

- **A read-site guard for `.env`-homed keys, in `tests/test_config_json_example.py`.**
  The existing no-inert-knobs test is driven by `config.json.example`, so it only ever
  covered the `home="json"` keys: an integration key could be documented in
  `.env.example`, warned about when placed in the wrong file, and read by nothing at
  all. That gap is what let the `OLLAMA_HOST` bug below survive.

- **`OLLAMA_HOST` is a real config key, so setting it in `.env` now works.** It
  was read straight off `os.environ`, but the loader parses `.env` with
  python-dotenv's `dotenv_values()` — which returns a mapping and deliberately
  does *not* export into the process environment. An `OLLAMA_HOST` written into
  `.env`, which is where every other Ollama setting lives and where `.env.example`
  implies it belongs, was therefore reported as an unrecognized key, ignored, and
  the run silently talked to `localhost:11434` instead of the operator's actual
  Ollama box. It is now a `home="env"` schema key (`ollamaHost`, default
  `localhost:11434`), read through `config_parser` like its neighbours, so it
  resolves from `.env`, and a real exported `OLLAMA_HOST` still overrides that
  for a single run via the environment layer. Both spellings — bare `host:port`
  and a full URL with a scheme — keep working; normalization is unchanged.

- **Two `pre-commit` guards that enforce the publication boundary and catch a
  corrupt index, in `.github/scripts/`.** The boundary was documented but not
  enforced: on 2026-07-30 a prek `pre-push` stash/restore cycle corrupted the
  index and produced a commit that deleted 85,280 lines and staged gitignored
  local-only files, and it reached this public remote before being force-pushed
  away. `detect-private-key` was the only secret-scanning gate and does not look
  at this, and CI has none at all.
  `check-publication-boundary.sh` refuses any commit that adds or modifies a
  local-only development path, reading the staged changeset from the index
  rather than trusting `.gitignore` — `git add -f` past `.gitignore` is exactly
  the failure mode. Deletions stay allowed so an accidentally tracked file can
  still be removed. `check-mass-deletion.sh` aborts a commit deleting more than
  50 tracked files (override: `HATE_CRACK_ALLOW_MASS_DELETE=1`); no commit in
  the last 400 of this repo's history deleted more than one, so the threshold
  cannot fire on real work. Both messages carry the actual recovery
  (`git config core.bare false`, `git reset HEAD`), since the incident's
  symptom is `fatal: this operation must be run in a work tree` and nothing on
  disk is ever lost. They are `pre-commit`, not `pre-push`: by pre-push time the
  bad commit already exists locally, and the pre-push stash is the thing that
  corrupts the index. `tests/test_commit_guards.py` executes the scripts as a
  real hook against throwaway repos and asserts on whether `git commit`
  actually succeeded, rather than grepping `prek.toml` for hook ids. (#224)

- **A defensive `hate_crack` name placeholder for PyPI, in
  `packaging/pypi-placeholder/`.** The name was unclaimed on the index, which is
  a name an operator could plausibly type into `pip install` or `uvx` expecting
  this project — and a squatted package under it would land on a host holding
  client hash material and API credentials. The placeholder is version `0.0.0`
  with no dependencies, no console script, and nothing importable; its in-tree
  PEP 517 backend raises from every wheel and metadata hook, so
  `pip install hate-crack` aborts with source install instructions rather than
  silently succeeding. Publishing is a `workflow_dispatch`-only workflow using
  Trusted Publishing (OIDC, no stored token) that the release tag automation
  cannot reach. Source install remains the only supported path. (#218)

- **A tracked `.env.example` template, and a startup line naming the config
  files actually loaded.** `.env.example` is generated from the configuration
  schema (`uv run python -m hate_crack.config_writer`), so it cannot drift from
  the key set hate_crack understands, and every credential key ships empty — it
  is a committed file in a public repo. Startup now prints the resolved
  `config.json` and `.env` paths, saying so inline when a file was created that
  run. The search order prefers a repo checkout over `~/.hate_crack`, so a stray
  `.env` in a checkout silently outranks the real one, and a `.env` in the
  current working directory is never read at all; two lines of output make both
  visible instead of leaving them to be rediscovered. Nothing is printed under
  `HATE_CRACK_SKIP_INIT`. (#217)
- **`--no-optimized-kernel` (alias `--no-optimize`) disables hashcat's `-O` for
  an entire run.** Until now the only way to turn optimized kernels off was to
  edit `optimizedKernelAttacks` in `config.json`, which persists and has to be
  undone by hand — awkward when a single target has candidates past the length
  ceiling `-O` imposes. The flag overrides the config list for every attack and
  also strips a hand-written `-O` from `hcatTuning`, which is appended verbatim
  to every invocation and would otherwise survive the flag and make it a lie.
  Nothing is written back to `config.json`.

### Changed

- **The `config.json` -> `.env` migration now deletes the keys it copied, instead
  of telling you to.** It used to leave `config.json` byte-identical on the
  principle that the migration did not own that file, which meant the integration
  keys stayed behind where the loader ignores them — and warns about every one of
  them, on every subsequent run, until the user hand-edits JSON. That is a
  permanent nag for a migration the tool could finish itself. The original file is
  copied to `config.json.pre-split.bak` first, and the rewrite is atomic and
  scoped: it drops only the keys named in the migration notes, preserves every
  `home="json"` setting, keeps unrecognized keys the user was using as notes,
  holds the original key order so the diff is reviewable, and carries the original
  file's permissions over. A key whose value had the wrong type is deliberately
  *not* deleted — the `.env` got the schema default rather than the user's value,
  so removing it would destroy the only record of what they meant to set. If the
  rewrite fails, the migration still succeeds and says so, with the manual
  instruction as the fallback.

- **Configuration is now split across two files, each owning a distinct set of
  keys.** `config.json` keeps the 35 local settings (wordlists, masks, rules,
  tuning, potfile, hashcat path, OMEN/PCFG/PRINCE limits, notification toggles,
  update check) and gains the four persisted CLI preference defaults (`debug`,
  `weakpass_min_rank`, `update_channel`, `restore_potfile_on_start`). A new
  untracked `.env`, written at mode `0600`, owns the 12 third-party integration
  keys: Hashview and Hashmob credentials, the Pushover token/user, the Ollama
  settings, and `pipalPath`/`pipal_count`. `config.json` remains first-class and
  is not deprecated. Each key has exactly one home; a key found in the other
  file is ignored with a warning naming the file it belongs in, so there is no
  cross-file precedence to reason about. `os.environ` still overrides any key,
  which is what keeps the documented `HASHVIEW_URL` / `HASHVIEW_API_KEY`
  overrides working. On first run both files are created; an existing
  `config.json` holding integration keys has them copied into a new `.env`, and
  hate_crack names the keys to delete from `config.json` rather than editing
  that file itself. **Breaking** for anyone whose integration settings currently
  live in `config.json`: those keys are no longer read from that file. The
  migration is automatic and non-destructive — nothing is deleted, moved or
  rewritten, and until you remove the stale keys yourself every run reminds you
  which ones they are. Two of the promoted preference keys are namespaced as
  `HATE_CRACK_DEBUG` and `HATE_CRACK_UPDATE_CHANNEL` on purpose: a bare `DEBUG=1`
  exported by some unrelated tool must not switch on debug logging in a tool
  that writes cracked plaintexts to disk. The other two keep their bare spellings
  (`WEAKPASS_MIN_RANK`, `RESTORE_POTFILE_ON_START`). Adds a dependency on
  `python-dotenv`. (#217)
- **The cwd-relative potfile fallback is gone.** When `hcatPotfilePath` was
  absent entirely, hate_crack used to fall back to `./hashcat.potfile` in the
  directory it was launched from if `~/.hashcat/` did not exist. The
  configuration schema now always supplies a value, so the potfile is
  deterministically `~/.hashcat/hashcat.potfile` unless configured otherwise;
  the directory is created on demand. Anyone who relied on picking up a potfile
  from the current working directory should set `hcatPotfilePath` in
  `config.json` or pass `--potfile-path`. (#217)
- **Debug logs now default to `~/.hate_crack/hashcat_debug` instead of the
  checkout-relative `./hashcat_debug`.** The old default resolved against
  whatever directory hate_crack was launched from, which for anyone running it
  out of a clone meant writing cracked plaintext into the repo, and which split
  the logs across directories so the Rosetta picker showed a different set
  depending on where the tool was started. `tests/test_repo_hygiene.py` fails
  the build if the shipped default goes back to being relative.
- **Rule-based attacks now request `--debug-mode 5` rather than mode 4.** Mode 5
  appends the source wordlist to each line
  (`baseword:rule:candidate:wordlist`), so a log from a multi-wordlist run
  records which list is actually producing cracks. HashcatRosetta's parser
  splits on the first two colons only, so it would silently glue that field onto
  the candidate; `_strip_debug_source_field` normalises mode 5 lines back to the
  mode 4 shape before parsing. Detection is per file, so mode 4 logs written
  before this change are still read correctly alongside new ones. Without the
  normalisation the unique-candidate rule metric double-counted a candidate
  reached from two wordlists, misranking rules exactly when several logs were
  mined together.

### Removed

- **The standalone `wordlist_optimizer.py` script.** Its per-length split and
  dedupe is now `wordlist_optimize()` in `hate_crack/main.py`, reachable as
  Wordlist Tools option 8 ("Optimize Wordlists"). Nothing in the tree referenced
  the script — not the README, the tests, or packaging (`pyproject.toml` ships
  `hate_crack*` only, so a root-level module was never installed) — and it had
  drifted behind the in-tree version, which uses `tempfile` instead of the fixed
  `/tmp/splitlen` paths the script would clobber when two runs overlapped, opens
  wordlists in binary mode rather than raising `UnicodeDecodeError` on non-UTF-8
  entries, and skips missing inputs instead of aborting.

### Fixed
- **A silently discarded `ImportError` that turned one missing HashcatRosetta
  submodule into 20 unrelated assertion failures (#231).** `main.py` wrapped the
  HashcatRosetta import in a bare `except ImportError` and threw the exception
  away, leaving `DebugAnalyzer = None`. Because `hate_crack.main` is imported
  once per pytest session, that `None` was sticky for the whole run, and
  `tests/test_main_rosetta.py` failed on assertions like
  `'<candidate>:wl.txt' == '<candidate>'` — a message that points at rule
  parsing and says nothing about a missing submodule, which is why the cause was
  misdiagnosed four times. The exception is now captured in
  `ROSETTA_IMPORT_ERROR` and surfaced by `rosetta_unavailable_reason()`, which
  both `rosetta_derive`'s `RuntimeError` and `analyze_rules`' error path use, so
  a genuinely broken HashcatRosetta is distinguishable from a merely absent one.
  The graceful degradation is unchanged: hate_crack still starts and runs every
  non-Rosetta attack without the submodule. `tests/test_main_rosetta.py` now
  reports the cause once instead of 20 times — it skips when the submodule is
  not checked out (a legitimate worktree state, since `git worktree add` does
  not populate submodules) and fails loudly when it is checked out but the
  import failed anyway, which skipping would hide in CI. The guard deliberately
  does not fire on a healthy checkout; `tests/test_main_rosetta_import_guard.py`
  pins that, because a guard that skips too eagerly would silently delete 20
  tests.
- **Four Hashview tests that passed without ever making a request.**
  `test_get_hashfiles_by_type_success`, `test_get_customer_hashfiles`,
  `test_download_left_hashes` and `test_download_wordlist` each took the `api`
  fixture — which holds `patch("requests.Session")` open for the whole test body
  — and then built a second client inside that body from `config.json`. That
  client's session was a `MagicMock`, so no HTTP happened and the assertions held
  against the mock. `get_hashfiles_by_type`'s own `except Exception: return []`
  made `assert isinstance(result, list)` true for a call that never left the
  process. Each is now split into a mocked test and a `*_live` test built through
  `_live_api()` (added in #223), which takes credentials from the environment
  only and asserts the session is a real `requests.Session`. The
  "real if possible, else mock" shape is gone: it was what hid this, because a
  green dot never said which branch ran. `test_download_wordlist_live` uploads its
  own synthetic wordlist and downloads it back, so it cannot skip for lack of
  seeded data. The `_get_hashview_config()` helper is deleted with its last
  caller — it read `config.json`, and was therefore a path by which a plain
  `pytest` run could reach a developer's real Hashview. (#228)

- **A host-port conflict starting the local Hashview test stack is now named
  instead of surfacing as `exit status 1`.** `docker compose up` is captured, and
  a `Bind for ...: port is already allocated` failure reports the port, the
  `docker ps --filter publish=<port>` command to find the container holding it,
  and the option of pointing the live tests at that instance via
  `HASHVIEW_URL`/`HASHVIEW_API_KEY` instead. hashview's compose file publishes
  fixed host ports and `HASHVIEW_LOCAL_PORT` only moves the app's `SERVER_NAME`,
  so a separate long-running hashview project silently owns them and no
  environment variable routes around it; reported opaquely, the live tests skipped
  for a reason that read like docker being broken. Other `up` failures now
  surface their last output line rather than the exception repr. (#225)


- **Mask statistics claimed coverage hashcat cannot deliver for non-ASCII
  passwords (#230).** `corpus_stats._mask()` mapped any non-ASCII character to
  `?s`, but every hashcat built-in charset is ASCII-only (`?a` is exactly 95
  candidates), and worse, hashcat masks are *byte*-oriented while `_mask()` is
  *character*-oriented — `ab²x` is four characters but five UTF-8 bytes, so no
  four-position mask can describe it under any charset. The reported masks were
  therefore wrong in both charset and length, and `format_summary()` fed them to
  the LLM as if they were usable. Non-ASCII passwords are now excluded from the
  mask counters, and the exclusion is stated on the Masks line, e.g.
  `Masks (over 9,412 of 9,533; 121 excluded as non-ASCII): ...`. Mask shares are
  divided by the mask-eligible count rather than the corpus total, so a corpus
  that is 30% non-ASCII no longer understates every mask by that fraction. Every
  other statistic — lengths, casing, basewords, suffixes, symbols, years — still
  counts the excluded passwords exactly as before, and for an all-ASCII corpus
  the rendered summary is byte-identical to the previous release. The hashcat
  oracle added under this issue now also proves that every mask `summarize()`
  reports for a mixed corpus is crackable by real hashcat.

- **A Unicode digit (e.g. the superscript `²`) in a wordlist crashed corpus
  analysis for the LLM attack modes (#229).** `corpus_stats._years` guarded an
  `int()` call with `str.isdigit()`, which is `True` for Unicode digits that
  `int()` rejects, raising `ValueError` mid-analysis (silently swallowed by a
  broad handler in `main.py`, so the symptom looked like a config error rather
  than a parsing bug). The same wrong notion of "digit" also let `_mask` map
  such characters to hashcat's `?d` — a mask claiming a candidate hashcat's
  `?d` charset (ASCII `0-9`) cannot actually generate — and let the trailing
  digit-suffix stats count them. All three sites now share one
  `_is_ascii_digit` predicate. `str.isdecimal()` alone would have fixed the
  crash but not the mask/suffix correctness, since it is also `True` for
  non-ASCII decimal digits (e.g. Arabic-Indic `١٢٣`) that hashcat's `?d` still
  cannot match; this predicate is ASCII-only for all three sites.
- **A dangling `.env` or `config.json` symlink was read as "no config
  present", so hate_crack silently ran on schema defaults (#227).** Config
  discovery and both file layers gated on `os.path.isfile()`, which is `False`
  for a symlink whose target is missing — the wrong wordlists directory and the
  wrong potfile path, with nothing printed to say so. All four gates now route
  such a path to the existing `ConfigFileUnreadableError` diagnostic, whose
  dangling-symlink branch was previously unreachable through discovery, and
  startup exits 1 naming the link. `os.path.isfile()` remains the positive
  test, so a *directory* called `.env` is still ignored rather than read, and a
  **valid** symlink to a real config file keeps working — sharing one config
  across several checkouts that way is a supported setup.
- **First run printed the config file paths twice, in different words
  (#227).** The bootstrap's own "Initializing / Config source / Config
  destination" block sat directly above the two `[*] config.json:` /
  `[*] .env:` lines that already name the resolved paths. The bootstrap is now
  silent about paths and passes what only it knew — the template or migration
  source — to those two lines, which report it inline (e.g.
  `(created this run, from config.json.example)`). The per-key migration notes
  telling the user which settings to delete from `config.json` are unchanged.
- **No test covered a plain `str` config value with surrounding whitespace
  surviving a `.env` round trip (#227).** `config_writer._needs_quoting` is
  type-agnostic and the `charset` keys exercised it only because their values
  always contain a space. Leading, trailing, both, and interior-double-space
  values now round-trip through a real file read back with `dotenv_values()`
  and through the loader.
- **Three Hashview tests claimed to hit the real API "if possible" but never
  did, and could not fail even when their assertions did (#223).** The `api`
  fixture holds `patch("requests.Session")` open for the whole test body, so a
  client built inside such a test got a `MagicMock` session and never reached
  the server; the surrounding `except Exception` then laundered the resulting
  `AssertionError` into a `pytest.skip` that read like an authorization problem,
  which is what hid the mock leak. `test_upload_cracked_hashes_success`,
  `test_create_customer_success`, and `test_create_job_with_new_customer` are
  now each split into a mocked test and a `*_live` test that never requests the
  mocked fixture, gated on `HASHVIEW_TEST_REAL=1` plus `HASHVIEW_URL` /
  `HASHVIEW_API_KEY` (env only, so a plain run cannot silently reach a real
  Hashview through `config.json`). The live path asserts up front that its
  session is a genuine `requests.Session` and not a `Mock`, which is the
  regression detector for the leak, and only `requests.RequestException` can
  skip — assertion failures propagate. Verified against the local docker stack:
  all three now execute, and each reports FAILED (not SKIPPED) under a
  deliberately broken assertion.
- **Test fixtures used real plaintext passwords as example values in a public
  repository.** Every cracked-pair, hashfile, and format-detection fixture in
  `tests/test_hashview.py` now derives its digests from obviously-synthetic
  plaintexts via the client's own `_digest_for_type`, so hash/plaintext pairs
  stay valid under upload validation (including for whichever hash mode the
  live stack seeds) without embedding known passwords or their digests.
- **`hcatHashFile`, `hcatHashFileOrig`, and `hcatHashType` did not exist until
  `main()` assigned them, so 53 test call sites needed
  `monkeypatch.setattr(..., raising=False)` — a flag that silently creates the
  attribute on a typo instead of failing the test.** They now have
  module-level defaults matching the types `main()` assigns
  (`hcatHashFile = ""`, `hcatHashFileOrig = None`, `hcatHashType = ""`),
  restoring the typo protection at all 53 sites. That exposed a latent
  clobber in the `hate_crack.py` CLI proxy: `_sync_globals_to_main()` only
  pushed a name back to `hate_crack.main` `if name in globals()`, so these
  three were skipped while absent — once present, the proxy's stale
  import-time copy would overwrite whatever `main()` had legitimately set,
  breaking option 95 (Analyze hashes with Pipal) for anyone reaching it
  through the shim. `_sync_globals_to_main()` now snapshots the proxy's
  import-time values and only pushes a name when its current value differs
  from that snapshot, which also closes the same latent clobber for
  `pipalPath`, `debug_mode`, `pipal_count`, and `hcatUsernamePrefix` (#213).
- **Five wordlist call sites decided whether to gunzip a file by checking the
  filename for a `.gz` suffix, so a gzip body under a plain name reached an
  external hashcat-utils binary as raw compressed bytes.** hate_crack
  downloads wordlists as gzip and names them from a server-supplied
  `Content-Disposition` header, and Hashmob/Weakpass ship gzip too, so a
  compressed body routinely lands under a `.txt` name. The binary does not
  error on that — it runs to completion and produces meaningless
  candidates, no `UnicodeDecodeError`, no non-zero exit. The correct
  magic-byte check already existed for `hcatNgramX`; it is now the single
  shared `hate_crack.plaintext.is_gzipped`, used by `hcatCombipow` and
  `combipow_crack`'s pre-flight line count. `hcatMarkovTrain`, `hcatPrince`,
  and `hcatPermute` route through `_wordlist_path` instead — decompressing
  to a real temp file rather than opening a `gzip.GzipFile` handle, because
  `subprocess.Popen(stdin=...)` resolves that handle through `fileno()`,
  which for `GzipFile` is the fd of the *underlying compressed* file. A
  `GzipFile` passed straight to `Popen` therefore feeds the child raw gzip
  bytes even though reading it from Python decompresses correctly — the gap
  the original fix for these three sites missed. `_open_wordlist` remains
  correct for its one remaining caller, which only reads the handle in
  Python, and its docstring now warns against ever handing it to
  `subprocess` (#215).
- **The Spoonman attack and the LLM pattern modes derived garbage basewords
  and rules from a gzipped corpus, with no error.** Both readers opened the
  corpus with `encoding="latin-1"`, under which every byte 0x00-0xFF decodes
  to a valid character, so a gzip stream decodes cleanly into mojibake instead
  of raising `UnicodeDecodeError` — there was nothing to alert anyone that the
  input was wrong. Gzipped corpora are the normal case here, not the
  exception: hate_crack downloads wordlists as gzip, and Hashmob and Weakpass
  ship them that way too. `hcatSpoonman` and the LLM corpus summarizer
  (`_corpus_context`) now decompress through the same `_wordlist_path` helper
  `hcatNgramX` already used, and `rulegen.generate()` /
  `corpus_stats.summarize()` each gained a defensive `ValueError` on a
  gzipped path as a backstop against a caller that forgets to decompress.
  Spoonman's staleness check still compares against the original corpus
  path rather than the decompressed temp file, so its basewords/rules cache
  keeps working across runs (#214).
- **Cracked plaintexts on the Hashview found/upload paths are no longer
  silently rewritten (issue #216).** Three reads of `hash:plaintext` data used
  `errors="ignore"`, which drops an undecodable byte instead of raising: a
  password holding a Latin-1 accent, a Windows-1252 quote, or any byte hashcat
  emitted raw decoded to a *different* password with no error, and the potfile
  append persisted that altered value so a later `--show` reported a plaintext
  that does not hash to the stored hash. All three now read bytes and wrap a
  non-UTF-8 plaintext in `$HEX[...]` via the new
  `hate_crack.plaintext.encode_hex_wrapper`, matching what hashcat itself
  writes and what `_wire_field_bytes` already understood. A line whose *hash*
  field is undecodable is reported to the operator rather than dropped
  silently.
- **Bumped the HashcatRosetta submodule from v0.2.0 to v0.4.0, which parses
  `--debug-mode 5` natively.** The pinned v0.2.0 predated mode 5 support: its
  parser split on the first two colons only, so the trailing wordlist field was
  silently glued onto the candidate rather than rejected. hate_crack worked
  around that by stripping the field before parsing, which fixed the corruption
  but threw the wordlist away. v0.4.0 returns it as its own `wordlist` key, so
  the workaround is gone and the attribution survives -- a log can now say which
  wordlist actually produced each crack. Mode 4 logs written before the switch
  still parse.

- **A POT file lookup that came back empty no longer wipes the cracked output
  file.** `check_potfile()` rewrote `<hashfile>.out` from `hashcat --show`
  unconditionally, so any run where `--show` produced nothing truncated it to
  zero bytes — cracks captured via `-o` only, an empty or stale
  `hcatPotfilePath`, a `--username` parse mismatch, or a hashcat failure that was
  invisible because stderr was discarded. On the pwdump path `cleanup()` reaches
  this before the merged file exists, so that was the only surviving copy.
  `_run_hashcat_show` now preserves a populated output file when it has nothing
  to write, refuses to touch it on a non-zero hashcat exit and reports the error,
  and replaces content atomically. The deliberate rebuild (`--restore-potfile`
  and menu option 93) still overwrites, but only after confirming (#195).
- **Cracked-plaintext artifacts are no longer stageable in a fresh clone.**
  `.out`, `.passwords`, `.working`, `.combined`, `.nt`, `.lm`, `.cracked`,
  `.xlsx`, `hashcat.potfile` and the per-attack scratch directories were ignored
  only by `.git/info/exclude`, which does not clone, or by nothing at all. They
  are now in the tracked `.gitignore` and pinned by `tests/test_repo_hygiene.py`.
- **hashcat debug logs are no longer committable, and one that had been
  committed is now untracked.** `_add_debug_mode_for_rules` appends
  `--debug-mode 4 --debug-file` to every rule-based attack unconditionally, and
  each line of the resulting log pairs a rule with the plaintext it cracked. The
  default `hcatDebugLogPath` was the relative `./hashcat_debug` at the time, so
  any session launched from a checkout wrote them into the working tree of a
  public repo; the default is now absolute, as described under Changed above.
  Nothing had been ignoring them except a `*.log` line in `.git/info/exclude`,
  which is local-only and does not clone, and one such log was already tracked
  on `main`. It was zero bytes, so no plaintext was published. `hashcat_debug/`
  and `hashcat_debug*.log` are now in the tracked `.gitignore`, the tracked file
  is removed from the index, and `tests/test_repo_hygiene.py` fails the build if
  either protection regresses.
- **The Rosetta Attack no longer lists empty debug logs.** hashcat creates the
  debug file when the attack starts but only writes on a crack, so a rule-based
  run that cracks nothing leaves a zero-byte log. `rosetta_debug_logs()`
  returned those alongside real ones; since the picker shows only the newest 20
  by mtime, dead files could crowd out logs that still had something to mine.
- **Pipal analysis (option 95) ran the pwdump-only merge on any NTLM run.** The
  guard tested the hash type but not `pwdump_format`, unlike the identical guard
  in `cleanup()`, so a plain NTLM list took a code path meant for pwdump files —
  which used to truncate the cracked output and produce a report reading
  `Total entries = 0`. Pipal now also says so plainly when there are no cracked
  passwords to analyse, instead of emitting a zeroed report (#196).
- **Excel export (option 96) had the same missing guard as Pipal analysis.** It
  ran the pwdump-only merge for any NTLM hash type, so a plain hash list took a
  path that used to truncate the cracked output, and then produced an empty
  spreadsheet because the pwdump-shaped rows it looks for were not there. All
  three callers of the merge now guard identically, and a test enforces that a
  fourth cannot be added without the guard (#196).
- **Two shipped docstrings cited `docs/superpowers/specs/...` design specs.**
  `docs/superpowers/` is a gitignored local development aid purged from git
  history on 2026-07-25, so the citations in `hate_crack/noninteractive.py` and
  `tests/e2e/noninteractive_harness.py` pointed an outside contributor at a
  path that does not exist in their clone. Both docstrings now keep the prose
  that actually helps a reader and drop the dead pointer, and
  `tests/test_repo_hygiene.py` gained a guard that fails the build if any
  tracked file cites `CLAUDE.md`, `.claude/`, `docs/plans/`, or
  `docs/superpowers/` again, with `CHANGELOG.md` and
  `tests/test_upgrade_real_git.py` as the only exemptions (#212).
### Changed

- **Release versioning is now rolling, and driven by [commitizen](https://commitizen-tools.github.io/commitizen/)
  instead of hand-rolled bash.** `main` is stable and always `X.Y.0`; merging
  `nightly-dev` down cuts the release as a minor bump. `nightly-dev` consumes the
  patch numbers above it — `X.Y.1`, `X.Y.2`, … — one per validated push. So
  stable `2.19.0` is followed by nightlies `2.19.1`, `2.19.2`, and the next merge
  to `main` cuts `2.20.0`.

  This replaces the `-rc.N` pre-release scheme. Both tagging workflows previously
  duplicated the same version arithmetic in shell (`cut -d.` to split the
  version, `$((minor + 1))` to bump it, a `sed`/`sort -n` pipeline to advance the
  rc counter); all of it is deleted. `cz bump --increment {MINOR,PATCH}` does the
  arithmetic, configured under `[tool.commitizen]` with `version_provider = "scm"`
  so the version is read from git tags and there is no version string in a file
  and no version-bump commit.

  Because nightly tags are now ordinary release tags, the `setuptools-scm`
  workaround that the old scheme existed for is retired: `-rc` was chosen only
  because `setuptools-scm` rejects tags ending in `.devN` for `N > 0`, which
  ruled out an incrementing `-dev.N` counter.

- **A merge into `main` now always cuts a release**, including a docs- or
  chore-only one. The old workflow skipped tagging when it found no
  `feat`/`fix`/`perf` commits; a merge to `main` is an explicit release event, so
  that early exit is gone. `nightly-dev` already tagged unconditionally, so that
  every validated nightly commit stays addressable.

- **Transition.** With `v2.18.0` as the baseline on `main`, the first release
  under the new scheme is `v2.19.0`, and `nightly-dev` then rolls `v2.19.1`,
  `v2.19.2`, … Both are monotonic against the highest surviving tag,
  `v2.19.0-rc.11` (`2.19.0rc11 < 2.19.0 < 2.19.1`). The three `v3.0.0-rc.*` tags
  were deleted from the remote as part of this transition, as a deliberate human
  decision — they advertised a `3.0.0` release that is not being cut. All other
  `-rc.N` tags remain as history and must not be deleted.

### Removed

- **Automatic major version bumps.** A `type!:` subject or a `BREAKING CHANGE:`
  footer no longer bumps the major version by itself, because the increment is
  now forced per branch rather than inferred from commit messages. This is
  deliberate — reintroducing breaking-change detection would reintroduce the
  hand-rolled version decisioning this change removes. A major release is instead
  an explicit human act: run `cz bump --increment MAJOR` and push the resulting
  tag.

  Note that four commits already on `nightly-dev` are marked breaking and would
  have cut a major release under the old rules — three `feat(config)!:` and one
  `refactor(config)!:`, all part of the config-file split. Under the new rules
  they do not; they ship inside the next minor release. That is the intended
  trade-off, recorded here so it is a decision rather than a surprise.

### Notes

- **Merge `main` down into `nightly-dev` immediately after this release.** Until
  you do, every validated `nightly-dev` push fails its tagging job with
  `[NO_VERSION_SPECIFIED]` (exit 4), because `nightly-dev`'s `pyproject.toml` has
  no `[tool.commitizen]` section yet — the config arrives with that merge. The
  failure is loud and cannot mistag anything, which is the right failure mode, but
  commitizen's error text says nothing about the cause. Expect a conflict in
  `pyproject.toml` during the merge.
- One transition hazard, on the record: in a hypothetical state where the
  commitizen config had reached `nightly-dev` but the new `v2.19.0` tag was not
  yet reachable from it, the nightly job would compute `v2.19.0` — the same tag
  `main` cuts — and the idempotency guard would then quietly leave that nightly
  commit untagged. In practice this cannot happen, because the config and the tag
  arrive in the same merge-down commit. It is noted because it is the one way the
  two branches could contend for a version number.
- Nightly tags are no longer PEP 440 pre-releases, so any tool that resolves
  "the latest version" from raw version numbers will now treat a nightly as
  latest. hate_crack's own startup update check is unaffected: it reads GitHub's
  "latest release" endpoint and nightly builds publish no GitHub release. The
  package is not published to PyPI (only a defensive name placeholder exists), so
  nothing installs from an index today, but this is a real property of the scheme
  rather than an oversight.
- `release.yml` is unchanged and remains the path for tags pushed by a human;
  tags pushed with `GITHUB_TOKEN` do not dispatch workflow events, so it never
  fires for the bot-pushed tags above.

## [2.18.0] - 2026-07-29

### Added

- **Rosetta Attack (main menu option 23)** — mines hashcat `--debug-mode 4`
  logs for the basewords and rules that already cracked something, then runs
  their full cross product. hate_crack already writes these logs for every
  rule-based attack, so the input accumulates in `hcatDebugLogPath` without any
  setup; a mode 4 log contains only successful candidates, which makes both
  halves known-productive against the target population. The recorded pairs
  themselves are spent, but a rule that worked on one baseword has usually
  never been tried against the others. Rules can be ranked by application
  frequency, by baseword spread, or by unique candidates generated, and both
  the rule and baseword counts are capped interactively (defaults: top 100
  rules, all basewords). Derived files land in `<hash file>.rosetta/` and are
  removed by the existing temp-file cleanup. Powered by HashcatRosetta, the
  same submodule behind the rule opcode analyzer.
- **The Spoonman Attack's rule derivation now bounds its own memory instead of
  being OOM-killed on a very large corpus.** `rulegen.generate()` held every
  distinct baseword and every distinct rule in a `Counter` until the whole
  corpus had been read, and wrote nothing before that point — so a corpus big
  enough to exhaust RAM lost the entire multi-hour pass with no output at all.
  A measured run against a 31 GB corpus reached 14.1 GB resident at 11% of the
  file with the growth rate still climbing. Each counter is now capped at a new
  `max_unique` keyword argument (default `rulegen.MAX_UNIQUE_KEYS`,
  20,000,000 keys, about 1.6 GB per counter at a measured 80 bytes per key);
  once a counter passes the cap its lowest-frequency keys are discarded while
  reading. Pass `max_unique=None` for the previous unbounded behaviour. When
  pruning fires the run reports it: new `pruned`, `pruned_basewords` and
  `pruned_rules` keys in the returned dict, a section in `coverage.txt`, and a
  console warning naming the limit — because the output then reconstructs only
  the retained keys rather than 100% of the corpus, and the coverage
  percentages are relative to those. A password needs both its baseword and
  its rule to survive and the two counters are pruned independently, so the
  report gives the range of passwords still reconstructable rather than a
  number it cannot know. A corpus that never reaches the cap produces
  byte-identical output to before.

- **Spoonman Attack now offers a top-50% and top-75% coverage tier, and top 50%
  is listed first as the recommended choice.** Rule-set coverage against a large corpus is extremely
  long-tailed: on a 98.2M-password sample, 50% coverage needed 4,120 rules
  while 95% needed 16,119,661 and 100% needed 21,029,696. The old menu only
  offered the full set, top 99%, or top 95% — all three sat past the knee of
  that curve, so every option produced a rule file with tens of millions of
  entries on a large corpus. The menu now reads top 50% (smallest, most
  productive rules) / top 75% / top 95% / top 99% / full set, and
  `rulegen.generate()`'s `cover` default changed from `(95, 99)` to
  `(50, 75, 95, 99)` to match.

- **A test that every documented config key is actually read.** The existing
  guard pins the key set, so a key added to `config.json.example` and to the
  expected-key list in one commit passes it while being read by nothing —
  which is how three dead keys shipped. The new test traces each key to the
  global it loads into and then to a read site anywhere in the package,
  including consumption through the attack handlers' `ctx` proxy.


- **`optimizedKernelAttacks` now works for the N-gram, LLM, OMEN, and LM-to-NT
  attacks, and is documented.** All four built their hashcat command without
  ever consulting the setting, so listing them had no effect. They honour it
  now, but stay out of the default set — each feeds candidates that can exceed
  the length ceiling `-O` imposes, so enabling it is opt-in rather than a
  silent keyspace reduction for anyone already running them. An unrecognized
  entry in the list is now reported at startup instead of being ignored, and
  README documents the flag's trade-off along with the delegation rule that
  makes PRINCE-LING follow `hcatPrince` and Spoonman follow
  `hcatQuickDictionary`.

- **The Ad-hoc Mask Attack (option 14) now accepts a mask file.** The attack
  opens with a choice between typing a mask and selecting a `.hcmask` file, the
  latter with tab completion rooted at the bundled `masks/` directory. Mask
  files carry their own charset definitions, so the `-1` through `-4` prompts are
  skipped on that path. This makes the hundreds of masks already shipped in
  `masks/` usable without retyping them, and lets a generated or hand-written
  mask list run without a dedicated menu entry.


- **On-demand regeneration of `<hashfile>.out` from the POT file.** New main
  menu option **93** ("Regenerate .out from POT file") and a matching
  `--restore-potfile` startup flag. `check_potfile()` already rebuilt the
  output file from `hashcat --show`, but it was only reachable as a side effect
  of `combine_ntlm_output()`, and the startup POT lookup ran only when `.out`
  did not already exist — so a truncated or lost output file could not be
  restored without deleting it and restarting. The menu path prints the
  existing cracked-hash count and asks for confirmation before overwriting
  (auto-confirming when stdin is not a TTY); the flag is treated as an explicit
  request and skips the prompt.
- **LLM Pattern Rules mode** (option 4 in the LLM Attack submenu). Mirrors the
  Spoonman Attack's shape — a baseword list run through hashcat rules — but
  infers the basewords rather than extracting them. Spoonman's `rulegen` is
  lossless and therefore literal: it can only emit cores that already appear in
  its corpus. This mode instead asks the local model to identify the word
  families behind a sample (company and products, site names, local teams,
  seasons, mascots) and enumerate members the sample does not contain, then runs
  those basewords against rule file(s) chosen from the rules directory. The
  pattern source is either the session's cracked passwords or a sample wordlist;
  model output is normalized to lowercase letters only, since the rules supply
  case, digits, and punctuation. Basewords land in `<hashfile>.llm_patterns`,
  which `cleanup()` removes on exit.
- Real-git coverage for the upgrade path (`tests/test_upgrade_real_git.py`).
  The existing tests mock `subprocess.run` wholesale, so they only assert which
  command strings get built — a mocked `git pull` always succeeds, which is why
  the two `--update` bugs listed under Fixed reached users with the suite green.
  The new tests construct a remote and a clone whose history has been rewritten
  out from under it, then run the real git commands, and additionally assert
  that `_run_upgrade()` constructs no `pull` at all.

### Changed


- **LLM Pattern Rules (LLM submenu option 4) now generates its own rule file
  instead of prompting for one.** The mode was named for rules it never wrote:
  it inferred basewords and then asked the operator to pick a stock rule file to
  mutate them with, which encodes the internet's password habits rather than the
  target organization's — the one thing a model round trip over that
  organization's own corpus is there to capture. It now makes a second request
  from the same corpus statistics for hashcat rules describing how these users
  decorate a word, and runs the inferred basewords against the inferred rules.
  This completes the parallel with the Spoonman attack, which derives both sides
  from one corpus; the difference is that Spoonman is exact and therefore
  bounded to transformations already present, while this generalizes past them.

  Generated rules are validated against hashcat's op set, per-argument types,
  and 31-function ceiling before the file is written (new
  `rulegen.validate_rule`). Screening is not optional: hashcat drops an invalid
  rule *silently* when the file also holds valid ones, so an unchecked line
  would surface as missing coverage rather than an error. The op table was
  established by testing a hashcat binary across 953 rule cases rather than
  from the rule documentation, which lists ops (the memory and reject-plain
  families) that hashcat then refuses to run.

  Because local-model yield here varies widely between runs, a first answer
  under 25 valid rules is asked again once and the two rounds are merged and
  deduped; a corpus that yields no valid rules at all falls back to running the
  basewords unmutated instead of discarding the run's expensive half.

  Scratch output moves from the `<hashfile>.llm_patterns` file to a
  `<hashfile>.llm_patterns/` directory holding `basewords.txt` and
  `rules.rule`, mirroring `.spoonman/`. Cleanup removes either shape, so
  scratch left by an earlier version is still cleared.


- **Hash-prefix stripping is now based on digest shape rather than the first
  colon.** New module `hate_crack/plaintext.py` holds the single implementation
  shared by the LLM read path, `corpus_stats`, and `rulegen`. A leading field is
  dropped only when it has the shape of a hash — a hex digest at a known length,
  or a crypt-style `$id$` string — so `hash:salt:plain` is handled, a plaintext
  containing colons survives intact, and a wordlist entry that merely contains a
  colon (a URL, a ratio, a time of day) is no longer truncated. Previously the
  LLM modes split unconditionally on the first colon.

- **The LLM modes now describe the whole corpus statistically instead of pasting
  in a sample of it.** New module `hate_crack/corpus_stats.py` aggregates every
  password in the source file — baseword shares (reusing `rulegen.derive`, the
  same extraction the Spoonman attack uses), masks, casing, lengths, trailing
  digits and symbols, and years — and the prompt carries that summary. Output is
  bounded, so a 120,000-password dump costs roughly the prompt space a 500-line
  sample did. Literal plaintexts are still included when the whole corpus fits
  under `ollamaMaxSampleLines`.

  An evenly-spaced sample conveyed no frequency information, so the model could
  not tell a baseword used by 8% of an organization from one used by a single
  person. It also did not reliably fit: at the old `ollamaNumCtx` of 2048, 500
  plaintexts (~2,000–3,500 tokens) plus the system prompt and response exceeded
  the context window, and Ollama silently truncated part of the sample.
  `ollamaMaxSampleLines` keeps its meaning as the "small enough to send
  verbatim" threshold.

- **`ollamaNumCtx` default raised from 2048 to 8192**, so the prompt fits with
  headroom.

- **The LLM modes now warn when the chosen corpus looks like an uncracked hash
  dump.** A raw NTDS dump (`user:rid:lm:nt:::`) and a cracked-output file sit in
  the same working directory with similar names, and the dump produces confident
  nonsense rather than an error: splitting on the first colon yields the rest of
  the hash line, so the statistics describe hex strings. Validated against real
  files — 99% of lines flagged in a 40,765-line NTDS dump, zero flagged in two
  genuine 22k/41k-line cracked-output files.

- **Digit-only basewords are excluded from the baseword list.** `rulegen.derive`
  falls back to the password itself when it holds no letters, so a PIN-heavy
  corpus filled the list with digit strings and crowded out the word families it
  exists to surface. The digit-only share is still reported via the casing and
  mask lines.

- **`$HEX[...]` plaintexts are now decoded** when reading a corpus for the LLM
  modes. hashcat wraps any plaintext holding non-ASCII bytes or the output
  separator; read literally, the wrapper polluted baseword and mask statistics
  with the letters of `$HEX[` and the corpus's hex digits. Malformed wrappers
  pass through unchanged. Note this fixes the LLM read path only — the Spoonman
  attack's `rulegen` reads corpora directly and is unaffected.

### Removed


- **`omenTrainingList` is gone from `config.json.example`.** It was loaded and
  path-normalized but never read: the OMEN attack always shows the wordlist
  picker, which builds its list from the wordlists directory. Setting it had no
  effect. Pick your training corpus in the attack's prompt instead.

- **Three config keys that had no effect are gone from `config.json.example`.**
  `hcatCombinator3Wordlist` and `hcatCombinatorXWordlist` were loaded and
  path-normalized but never read: since the combinator attacks were merged into
  one menu entry, the single handler takes its defaults from
  `hcatCombinationWordlist` and picks the 2-way, 3-way, or N-way path from how
  many entries that list has. `hcatPrinceLing` was listed in
  `optimizedKernelAttacks` but never checked, because PRINCE-LING delegates to
  the PRINCE attack, which tests its own name — use `hcatPrince` to control
  `-O` for both.

- **`combinator3_crack`, `combinatorX_crack`, and `combinator_3plus_crack` are
  gone from `attacks.py`, along with their `main.py` proxies.** They were
  delegation shims left behind when the combinator attacks merged into one
  handler; neither menu mapping nor any test referenced them, so they were
  unreachable dead code.

### Fixed

- **Exiting a `-m 1000` session could crash instead of cleaning up.**
  `pwdump_format` was assigned only inside `main()`'s format-detection block, so
  any run that reached `cleanup()` without executing that block raised
  `NameError: name 'pwdump_format' is not defined` — at the end of the session,
  after the cracking work was done, and skipping the rest of the cleanup. It now
  has a module-level default of `False`.
- **Analysing or exporting a plain hash list destroyed every cracked password.**
  `combine_ntlm_output()` merges cracked passwords back onto pwdump lines, reading
  `<hashfile>.out` and writing `<original>.out`. For a hash file that is not pwdump
  format those are the same path, and the function opened its own input with mode
  `w+`, truncating it, then matched against lines that no longer existed — so a
  populated `.out` became 0 bytes. It now returns early when there is nothing to
  merge onto, and builds the merged file beside its destination and moves it into
  place only once it has content, so a run that matches nothing can no longer
  replace a good result with an empty one.
- **`coverage.txt` now reports the rule count for 75% coverage.** Its milestone
  list ran 50/80/90/95/99/100, so an operator picking the new top-75% tier
  could not look its cost up in the one file meant to answer that question.

- **The LLM Pattern Rules attack hid why it had no rules to run.** When every
  rule the model returned was rejected as invalid, the fallback message said
  only that no usable rules were inferred. It now reports how many were
  rejected, which distinguishes "the model returned nothing" from "the model
  returned rules and all of them were malformed" — a difference that decides
  whether re-running is worth it.

- **`_streamed_download` accepted a `chunk_size` and ignored it.** The value
  was never forwarded to the function that does the writing, which hardcoded
  8192, so tuning it had no effect. No caller passed a non-default value, so
  nothing was mis-downloading; the knob simply did not work.

- **Cancelling the no-hashfile menu was reported as an invalid selection.**
  `interactive_menu` returns `None` for a bare Enter in numbered mode and for
  Escape in arrow-key mode. Every other menu treats that as its cancel option,
  but the menu shown when no hash file is given fell through to
  `[!] Invalid selection` and re-prompted, so a deliberate cancel looked like a
  typo. It now re-shows the menu silently, matching the main menu; an answer
  that matches no menu key still warns.


- **"Leave blank to skip" skipped every remaining custom charset, not just
  one.** The Ad-hoc Mask Attack prompts for charsets `-1` through `-4`, but a
  blank answer broke out of the loop, so a mask using `?1` and `?3` without
  `?2` could not be entered and hashcat failed on the undefined token. Each
  slot is now independently skippable.
- **README documented a menu environment variable that does not exist.** It
  named `HATE_CRACK_PLAIN_MENU=1` (read by nothing) and claimed arrow-key
  navigation is the default. Numbered menus are the default; arrow keys are
  opt-in through `HATE_CRACK_ARROW_MENU=1`, which was undocumented.
- **README told contributors to install a `post-commit` hook that does not
  exist, and omitted the `pre-commit` stage that does.** `prek.toml` defines six
  local `pre-push` hooks (the documented list was missing `ruff-format` and
  `bandit`) plus six `pre-commit` hooks from `pre-commit/pre-commit-hooks`,
  including the repo's only secret-scanning gate. Following the old
  instructions left `detect-private-key` uninstalled.


- **`--download-hashview` prompted for a menu choice and then ignored it.** The
  no-hashfile menu's first branch was guarded by `or args.download_hashview`,
  so with the flag set, choosing Wordlist Tools, Rule File Tools, or even Exit
  all opened the Hashview flow. The flag now skips the menu entirely, and the
  menu's own choices are honoured when it is absent.

- **The Random Rules and LLM rule attacks wrote no hashcat debug log.** Five of
  the seven attacks that pass `-r` to hashcat call `_add_debug_mode_for_rules`,
  which wires `--debug-mode`/`--debug-file` to `hcatDebugLogPath`;
  `hcatGenerateRules` and `hcatOllama`'s per-rule pass did not, so there was no
  way to see which rule cracked which hash for exactly those two. A new test
  pins the invariant for every future rule-based attack.

- **`hashview download-hashes --hash-type` did nothing.** The flag existed only
  to feed `download_left_hashes`, whose `hash_type` parameter had been unused
  since the download flow was overhauled and its `hashcat -m` verification run
  removed. Both the flag and the parameter are gone; the `--hash-type` flags on
  `upload-cracked` and `upload-hashfile-job` are unaffected.

- **The same attack could run with or without `-O` depending only on whether a
  `config.json` existed.** `hcatPCFG` was listed in the example's
  `optimizedKernelAttacks` but missing from the `DEFAULT_OPTIMIZED_ATTACKS`
  fallback in code, so a user with no config file got un-optimized kernels for
  it. The default now matches the example, and two new tests assert that the
  two lists stay equal and that every name in the list actually reaches
  `_should_use_optimized_kernel`.

- **The Spoonman attack derived basewords and rules from the hash as well as the
  password.** `rulegen.generate` treated each corpus line as a password in full,
  but the corpus the attack is built for — and that its own menu text recommends
  — is a previous engagement's cracked output, whose lines are `hash:password`.
  The digest's hex digits were therefore prepended to every baseword, and 20–30
  of the 31 available rule functions were spent rebuilding them.

  The damage compounded. Because every hash is unique, every derived baseword and
  rule was unique too, which destroyed the property the attack exists for: a rule
  file ranked by productivity and safe to truncate. And because rebuilding the
  prefix nearly exhausted `MAX_RULE_FUNCTIONS`, real transformations tipped over
  the limit into the literal fallback — emitting the password as its own
  baseword, so the corpus became its own wordlist.

  Measured on a 22,283-line cracked-output file: distinct basewords 22,284 →
  9,912 (previously one per line, i.e. no deduplication at all), literal
  fallbacks 5,388 → 31, rules needed for 95% coverage 15,783 → 11,730.

  `$HEX[...]` plaintexts are now decoded here too, and a corpus that looks like
  an uncracked dump rather than cracked output is reported in `coverage.txt` and
  warned about.

- **`notify_suppress_in_orchestrators` did nothing.** The key was parsed into
  `NotifySettings` and unit-tested for parsing, but `suppressed_notifications()`
  set its thread-local flag unconditionally, so there was no way to get a
  notification per attack inside Extensive Crack. The context manager now
  consults the setting. README also overstated the scope: only Extensive Crack
  suppresses, and Quick Crack with N rule chains has always sent N
  notifications.
- **`--update` (and the startup upgrade prompt) no longer dead-ends on a clone
  whose tags diverge from the remote's.** If any local tag pointed at a
  different object than `origin`'s, `git fetch --tags` exited non-zero with
  `would clobber existing tag`; `_run_upgrade()` treated that as fatal and
  aborted, so the affected clone could never upgrade itself again. Worse, the
  manual recovery commands the tool printed omitted `--force` too, so following
  its own advice failed the same way. Both fetches in the upgrade path — the
  pre-checkout one and the one inside the final shell chain — now pass
  `--tags --force`, as do the four printed fallback command strings. `--force`
  affects tag updates only and cannot discard commits or working-tree state.
- **`--update` now advances the checkout by resetting to `origin`, not by
  merging, so it also works on a clone whose history was rewritten.** Forcing
  the tag fetch alone was not enough: the upgrade went on to run
  `git pull origin <branch>`, and a clone predating the July 2026 history
  rewrite shares no ancestor with `origin/main`, so the pull aborted with
  `Need to specify how to reconcile divergent branches` and the upgrade never
  reached `make install`. `_run_upgrade()` now runs `git checkout -B <branch>
  origin/<branch>` on every upgrade — previously only when HEAD was on some
  other branch, which is why users already sitting on `main` were the ones who
  hit this — and the final shell chain is reduced to `make install`. The
  uncommitted-changes guard became unconditional to match, since the reset now
  fires on every run; the printed recovery commands use the reset form too.
  Users stranded by the earlier versions need a one-time manual recovery,
  documented under Troubleshooting in the README.

## [2.17.2] - 2026-07-29

### Security

- **`config.json` backups are now gitignored.** Only the exact name
  `config.json` was ignored, so a timestamped or editor backup
  (`config.json.bak-<date>`, `config.json.orig`, `config.json~`) sat untracked
  but stageable in a checkout while holding the same populated
  `hashview_api_key` / `hashmob_api_key` values as the live config. Since this
  is a public repo and CI has no secret scanning, a `git add -A` was the only
  step between a local backup and published credentials. `.playwright-mcp/`
  scratch output is ignored for the same reason. (#191)

### Changed

- **CI now lints and format-checks `tests/` alongside `hate_crack/`.** The ruff
  gates previously covered only the package, so the test suite had accumulated
  21 unused imports, one unused binding, and 51 unformatted modules — all of
  which are now fixed and gated. `ty` still checks `hate_crack/` only. (#190)
- **`ty` dev dependency raised** to 0.0.65. Dev-only; does not affect the
  installed package. (#185)
- **Spoonman Attack output is now ephemeral.** Derived basewords and rules are
  written to `<hash file>.spoonman/` beside the hash file, matching the other
  ephemeral wordlists (`.expanded`, `.combined`), instead of persisting under
  `<hcatOptimizedWordlists>/spoonman/<corpus name>/`. The directory is removed
  by the temp-file cleanup on exit. Derivation is still skipped when the corpus
  has not changed since a prior run against the same hash file. This also
  removes the collision between two different corpora that share a filename. (#186)

### Fixed

- **Temp-file cleanup no longer breaks when a hashfile is switched via the
  Hashview API.** Accepting "Switch to this hashfile for cracking?" rebound
  `hcatHashFile` but left `hcatHashFileOrig` pointing at the previous hashfile
  (or, when reached before the startup fallback, unset). `cleanup()` keys every
  removal and the cracked-vs-original comparison off the original, so switching
  from the main menu stranded the new hashfile's `.combined`, `.lm`,
  `.lm.cracked`, `.working` and `.passwords` artifacts and wrote the `.out`
  comparison against the wrong file. The switch now rebinds both, and
  `cleanup()` falls back to the live hashfile when the original is unset, so a
  future missed assignment degrades to "skips the pwdump comparison" rather
  than silently cleaning up nothing at all. (#187)
- **Flaky notify burst-cap tests.** `TestCrackTailerBurstCap` asserted on
  aggregate counts that a split burst could satisfy in more than one way, so the
  tests failed intermittently under load. Replaced with five deterministic
  assertions on per-tick semantics. Test-only; no runtime behaviour changed.
  (#188)

## [2.17.1] - 2026-07-29

### Changed

- **Dependency floors raised.** `openai` >=2.50.0, `openpyxl` >=3.1.5,
  consolidating #178 and #179. (#180)
- **`instructor` excluded from Dependabot as a durable policy, not a
  temporary skip.** `atomic-agents` 2.9.1 pins `instructor==1.14.5` exactly
  and imports internals (`instructor.core.client`,
  `instructor.processing.multimodal`, `instructor.dsl.partial`,
  `instructor.processing.schema`) that `instructor` 1.15.x reorganized.
  Forcing the bump with an override resolves but fails at import with
  `AttributeError: module 'instructor' has no attribute 'core'`, so the
  `.github/dependabot.yml` `ignore` entry stays until `atomic-agents`
  relaxes its pin. (#141)

## [2.17.0] - 2026-07-29

### Added

- **`--nightly` update channel.** `--nightly` (or `--update --nightly`) updates
  from the `nightly-dev` branch instead of `main`, for work that has passed CI
  but has not been cut into a release. `--update` is unchanged and still tracks
  releases on `main`. The startup update check only ever offers releases: it
  reads GitHub's "latest release" endpoint, which excludes pre-releases, and
  nightly builds publish no GitHub release at all.

- **Spoonman Attack (main menu `22`).** Derives a baseword list and a
  frequency-sorted hashcat rule file from a corpus of known plaintext
  passwords, such that the baseword x rule cross product reconstructs the
  corpus. Rules are ordered most-productive-first so the file is truncatable;
  the menu offers the full set, top 99%, or top 95% coverage. Output is cached
  per corpus under `<hcatOptimizedWordlists>/spoonman/` and reused until the
  corpus changes. Contributed by @Spoonman1091. (#169)

  The derivation enforces hashcat's limit of 31 functions per rule, falling
  back to emitting the password as its own literal baseword. hashcat drops
  over-long rules *silently* when valid rules share the file, so without the
  guard a corpus containing such passwords would quietly fall short of the
  coverage it reported.

### Changed

- **No-hash-file menu no longer duplicates the download entries.** The Weakpass
  and Hashmob wordlist downloads already live in Wordlist Tools, and the Hashmob
  rule download already lives in Rule File Tools, so the three top-level copies
  were removed. The menu is now `1` Hashview API, `2` Wordlist Tools, `3` Rule
  File Tools, `4` Exit. The `--weakpass`, `--hashmob`, and `--rules` CLI flags
  are unaffected; they short-circuit before this menu is drawn.

## [2.16.0] - 2026-07-29

### Changed

- **Wordlist and rule downloads moved into their tool submenus.** The Hashmob
  and Weakpass wordlist downloads are now options `9` and `10` of Wordlist
  Tools (main menu `80`), and the Hashmob rule download and rule analyzer are
  options `4` and `5` of Rule File Tools (main menu `81`). The main menu's
  `90`–`93` block is gone. If you had those keys in muscle memory: `90` is now
  Rule File Tools option 4, `91` is Rule File Tools option 5, `92` is Wordlist
  Tools option 9, and `93` is Wordlist Tools option 10. The `--hashmob`,
  `--weakpass`, and `--rules` non-interactive flags are unchanged. (#166)
- **Duplicate menu mapping divergence.** `hate_crack.py`'s copy of the main
  menu had key `91` wired to the Weakpass menu while both its own label and
  `main.py` said "Analyze Hashcat Rules", so that key ran the wrong handler
  through the proxy path. The key is now retired and both mappings agree.
  (#166)

## [2.15.1] - 2026-07-28

### Fixed

- **PCFG ruleset casing on case-insensitive filesystems.** The exact-match
  fast path in `_resolve_pcfg_ruleset_dir` used `os.path.isdir()`, which
  returns true for a wrong-cased path on macOS and Windows, so a
  `pcfgRuleset` of `"DEFAULT"` was handed back verbatim instead of resolving
  to the real `Default` directory — defeating the case-insensitive fallback
  scan added in 2.14.8. Resolution now tries a real case-sensitive match
  before falling back. This was also the root cause of the intermittent
  `test_regenerates_when_cache_stale` failure. (#165)

## [2.15.0] - 2026-07-28

### Added

- **End-to-end test suite for the non-interactive CLI.** Adds the e2e harness,
  shared fixtures (hashes, wordlists, rules), and coverage for the four
  non-interactive subcommands. Opt-in via `HATE_CRACK_RUN_E2E=1`. The NTLM
  fixture generator uses a pure-Python MD4 implementation, since `hashlib`'s
  MD4 is unavailable on OpenSSL builds that disable legacy providers. (#164)

### Changed

- **Weakpass listings parsed as JSON instead of scraped HTML.**
  `hate_crack/api.py` now reads weakpass.com's Inertia `data-page` payload
  with the standard library rather than parsing the rendered page, and the
  `beautifulsoup4` runtime dependency is dropped — `api.py` was its only
  consumer. (#139)
- Dependency bumps: `openai` >=2.49.0, `atomic-agents` >=2.9.1, `ty` 0.0.64,
  `setuptools-scm` >=10.2.1.

## [2.14.9] - 2026-07-28

### Fixed

- **Unwritable install tree crashed wordlist and rule downloads.**
  `get_hcat_wordlists_dir`/`get_rules_dir` now guard their `os.makedirs` call
  with `try/except OSError` and fall back to the cwd-relative default.
  Follow-up to #153 (shipped in 2.14.8), which started resolving these
  defaults against the install tree and dropped the broad `except Exception`
  that had been masking the failure — so an unprivileged user on a root-owned
  or read-only install got a raw `PermissionError` traceback. (#163)

## [2.14.8] - 2026-07-28

### Fixed

- **PCFG ruleset default casing.** `pcfgRuleset` now defaults to `"Default"`,
  matching the on-disk `pcfg_cracker/Rules/Default` directory, and both
  `hcatPCFG` and `hcatPrinceLing` resolve the configured ruleset name
  case-insensitively against whatever casing actually exists on disk. This
  covers both a fresh install (prior default `"DEFAULT"` only worked by
  accident on case-insensitive filesystems like macOS) and anyone whose
  `config.json` already has `"DEFAULT"` backfilled to disk from before this
  fix. (#148)
- **PCFG silent candidate truncation on non-TTY stdin.** `hcatPCFG` now keeps
  the `pcfg_guesser.py` child's stdin open (`stdin=subprocess.PIPE`) instead
  of inheriting hate_crack's own stdin. Previously, any non-TTY stdin (cron,
  CI, detached runs, piped input) caused the guesser's keypress-listener
  thread to hit `EOFError` and shut the generator down after tens of
  thousands of candidates, silently ignoring `--limit`/`pcfgMaxCandidates`.
  (`prince_ling.py` was checked for the same exposure and doesn't have a
  keypress thread, so it needed no change.) (#146)
- **Uncaught OSError loading config.json.example defaults.** A missing or
  unreadable defaults file (e.g. a dangling symlink surviving a
  git-archive tarball or docker COPY) now surfaces the existing "package
  installation issue" message instead of a raw traceback. (#155)
- **Brittle config.json.example test guards.** Replaced a symlink-ness
  assertion (fails outside the source tree, since builds dereference the
  symlink) and a same-inode tautology with an explicit expected-key-set
  check and a content-parity check that's exercised in built/flattened
  trees. (#154)
- **api.py/main.py config default divergence.** `api.py`'s
  `get_hcat_wordlists_dir`/`get_rules_dir`/`get_hcat_tuning_args`/
  `get_hcat_potfile_path` now merge `config.json.example` the same way
  `main.py` does, instead of falling back to their own hardcoded,
  cwd-relative defaults for any key absent from `config.json`. (#153)

## [2.14.7] - 2026-07-28

### Fixed

- **PCFG/PRINCE-LING interpreter drift.** `hcatPCFG`/`hcatPrinceLing` now
  launch `pcfg_guesser.py`/`prince_ling.py` via `sys.executable` instead of
  a bare `python3` resolved from `PATH`, so they run under the same pinned
  interpreter and environment as hate_crack itself. (#149)

## [2.14.6] - 2026-07-28

### Changed

- **Narrower config.json search path.** `_candidate_roots()` in both `main.py`
  and `api.py` now checks only the repo/package directory and
  `~/.hate_crack`, dropping the current working directory and its parent,
  `/opt/hate_crack`, `/usr/local/share/hate_crack`, and the
  `~/hate_crack`/`~/hate-crack` variants. This makes which config file is in
  effect predictable rather than dependent on where you happened to run the
  tool from. README updated to match. (#152)

## [2.14.5] - 2026-07-28

### Fixed

- **config.json.example drift between the root and packaged copies.** Ten keys
  were missing from the packaged copy, four dead PassGPT keys were still
  shipped, and `hcatPath` disagreed. The packaged copy is now a symlink to the
  root file, with a test asserting both parse to identical JSON so drift fails
  CI instead of shipping silently. (#150, #151)
- **Stale defaults persisted into user configs.** hate_crack no longer writes
  missing keys back into your `config.json` on load. Previously a wrong default
  in the example file got permanently baked into every user's config on the
  next run; defaults are now merged in memory only. (#151)

## [2.14.4] - 2026-07-28

### Fixed

- **OMEN finished in seconds instead of doing real work.** The in-code fallback
  default for `omenMaxCandidates` (used when the key is absent from
  `config.json`) was 1,000,000. Raised to 100,000,000 in both `main.py` and
  the shipped `config.json.example`. (#145, #147)
- **Flaky `test_main_pcfg`.** A leaked `hate_path` global let test ordering
  decide the outcome.

### Changed

- **README menu block synced with the code.** The documented main menu still
  showed pre-consolidation numbering (LLM at 15, OMEN at 16) and omitted
  Notifications, PCFG, and PRINCE-LING entirely. Also adds the missing N-gram,
  PCFG, and PRINCE-LING attack sections and a PCFG configuration section.
  (#138)
- Dependency bumps: `ruff` 0.16.0 (with the lint rule set pinned to pre-0.16
  defaults), `ty` 0.0.63, `setuptools` >=83.0.0, `beautifulsoup4` >=4.15.0.

## [2.14.3] - 2026-07-25

### Added

- **Private-key commit gate.** `prek.toml` now runs the `detect-private-key`
  hook at the pre-commit stage. The repo previously had no secret-scanning gate
  of any kind — bandit only covers `hate_crack/`, so nothing inspected config
  files, docs, or test fixtures for committed key material.

### Removed

- **Local agent tooling is no longer published.** `CLAUDE.md`, `.claude/`,
  `docs/plans/`, and `docs/superpowers/` were development aids rather than part
  of the shipped project. They are now gitignored and were removed from the
  repository, including from its history.
- **`audit-docs` post-commit hook.** Dropped from `prek.toml` along with the
  `.claude/audit-docs.sh` script it invoked.

## [2.14.2] - 2026-07-25

### Fixed

- **Pipal base-word parsing.** `pipal()` built one rigid regex that required
  *exactly* `pipal_count` consecutive base-word lines, so any cracked set with
  fewer unique base words than `pipal_count` (default 10 — the common case on
  small cracks) matched nothing and returned no base words. The `Top N base
  words` section is now parsed line by line, returning up to `pipal_count`
  words and stopping at the end of the section.
- **Shell-safe pipal invocation.** The pipal subprocess is now spawned with
  list-form arguments instead of a `shell=True` formatted string, so hash-file
  paths containing shell metacharacters can no longer be interpreted as
  commands.

### Changed

- Renamed the internal `_omen_pick_training_wordlist` helper to
  `_pick_training_wordlist`, since it is shared by the OMEN, Markov-adjacent,
  and LLM (wordlist mode) attacks rather than being OMEN-specific.

## [2.14.1] - 2026-07-25

### Fixed

- **Tab completion on custom file-path prompts.** The `p. Enter a custom path`
  branches of the OMEN and Markov training pickers, the combipow wordlist
  prompt, and the rule cleanup/optimize output-path prompts used a bare
  `input()` with no readline completer, so TAB did nothing. They now route
  through `select_file_with_autocomplete` for consistent path autocompletion.
- **Stale completer leak.** `select_file_with_autocomplete` and the
  `_configure_readline`-based pickers now drop the path completer after a
  selection, so later numeric-menu and y/n prompts no longer inherit file-path
  tab completion.

## [2.14.0] - 2026-07-24

### Added

- **Non-interactive attack subcommands** for scripting (issue #17). Launch a
  single attack without the menu: `quick` (wordlist + optional `--rules`),
  `dict` (configured-wordlist methodology), `brute` (`--min`/`--max`), and
  `topmask` (`--target-time`). Preprocessing prompts auto-accept their
  defaults, and the process returns a clean exit code (0 on success, non-zero
  on a bad hash file, hash type, wordlist, or rule name).

## [2.13.1] - 2026-07-24

### Fixed

- **`OLLAMA_HOST` values that include a scheme no longer produce a malformed URL**
  (issue #119). The Ollama base URL was built as `"http://" + OLLAMA_HOST`, so a value in
  the form Ollama's own tooling accepts — `http://box:11434` or
  `https://ollama.example.com` — became `http://http://box:11434` and the LLM attack could
  not connect. `http://` is now prepended only when no scheme is present, and trailing
  slashes are stripped because callers append paths (`f"{ollamaUrl}/v1"`). Reaching a remote
  Ollama over TLS works as a result. The bare `host:port` default is unchanged.

## [2.13.0] - 2026-07-24

### Added

- **Cracked-password generation mode** for the LLM attack. Once a session has recovered
  plaintexts, option 3 feeds them back to the model, which infers the organization's own
  password conventions and generates new candidates in that style. Offered only when
  `<hashfile>.out` has content, and it uses a dedicated prompt that tells the model not to
  re-emit passwords already cracked.
- **Target research pre-fills the industry and location prompts.** In target mode, entering
  the company name asks the local model to recall that organization's industry and location,
  then offers them as editable defaults (Enter accepts, typing overrides). Values are
  labelled as model guesses rather than verified OSINT, whitespace-collapsed, and capped at
  80 characters. Research runs entirely against the local Ollama server, so the client name
  is never sent to a third party. Any failure or timeout falls back to blank prompts and
  never blocks the attack. Disable with `ollamaAutoResearch: false`.
- **Live progress spinner** with an elapsed-seconds counter during Ollama generation, so a
  model loading into VRAM is distinguishable from a hang. Automatically suppressed when
  stdout is not a TTY.
- **`ollamaMaxSampleLines`** (default 500) caps how many sample passwords are sent to the
  model, for both wordlist and cracked-password modes.

### Fixed

- **A large sample wordlist no longer stalls the LLM attack.** Wordlist mode read every line
  into memory and pasted all of them into the prompt, so pointing it at `rockyou.txt`
  materialized hundreds of megabytes and overran the model's context window — which looked
  like a hang. The file is now streamed and evenly sampled across its whole length, and the
  count actually used is reported (`Sampled 500 of 14,344,391 passwords from wordlist.`).
- **`HATE_CRACK_ARROW_MENU=1` now works in the LLM and OMEN submenus.** They hand-rolled
  `print()` + `input()` instead of the shared menu helper, so arrow-key navigation silently
  did nothing there.
- **A typo in a wordlist or generation-mode prompt no longer aborts the whole attack.** The
  pickers and submenus re-prompt instead of dropping back to the main menu, and offer an
  explicit cancel.

### Changed

- **Interactive prompt formatting normalized** — the `[*] ` marker is no longer used on
  input prompts (it denotes status output elsewhere), and default-value hints use a single
  form.

### Build

- **Local `uv` Python pinned to 3.13** via `.python-version`. `requires-python = ">=3.13"`
  meant a fresh worktree picked CPython 3.15.0a7 and failed to build pyo3 0.26 (via
  `jiter`/`fastuuid`/`pydantic-core`). CI already pinned 3.13.

## [2.12.0] - 2026-07-24

### Changed

- **LLM attack now uses the Atomic Agents framework** for structured (JSON) candidate
  generation instead of raw HTTP + regex line-parsing. Candidate generation lives in the
  new `hate_crack/llm.py` module.
- **Default Ollama model is now `qwen2.5:32b`** (was `mistral`), chosen for reliable
  structured-output adherence.

### Added

- **Wordlist (denylist) generation mode** for the LLM attack is now reachable from the
  menu: select the LLM attack (option 12), then choose "Wordlist" to derive basewords from
  a sample wordlist.

### Fixed

- **The LLM attack no longer hangs forever waiting on Ollama.** Generation requests are now
  bounded by a configurable timeout (`ollamaTimeout` in `config.json`, default 300 seconds).
  Previously, if Ollama accepted the connection but never replied — most commonly a large
  model still loading into VRAM — hate_crack sat at a frozen prompt with no recourse but
  Ctrl-C. When the timeout fires you now get a specific message naming the elapsed timeout
  and the setting to raise, instead of a misleading "ensure Ollama is running" hint.

### Removed

- **Automatic model pulling.** hate_crack no longer pulls missing Ollama models; pull them
  yourself with `ollama pull <model>`.

## [2.11.4] - 2026-07-24

### Added

- **CI now runs lint, type checks, and tests on every pull request and push to `main`.**
  Previously these ran only in local `prek` pre-push hooks, so a commit pushed without hooks
  installed (or with `--no-verify`) reached `main` unvalidated — and the auto-tag workflow
  would then cut a release from it. The new `ci.yml` runs `ruff`, `ty`, and `pytest` on
  Python 3.13, and tagging is gated on it passing.
- **Dependabot configuration** for Python (`uv`) and GitHub Actions dependencies, weekly.
  Action pins are updated automatically instead of drifting. Bumps use `chore` commit
  prefixes so they never auto-cut a release.

### Fixed

- **Auto-tagged versions now actually get a GitHub release.** The tag was pushed using the
  default `GITHUB_TOKEN`, and GitHub suppresses workflow triggers for `GITHUB_TOKEN`-created
  events, so the tag-triggered release workflow never fired — `v2.11.3` was tagged with no
  release to show for it. The auto-tag workflow now creates the release itself, idempotently.
- **Breaking changes no longer ship as a minor bump.** The version logic matched the `!`
  breaking-change marker but only ever bumped the minor version, and `BREAKING CHANGE:`
  footers were invisible because only commit subjects were inspected. Both now correctly
  trigger a major bump.
- **Concurrent merges to `main` no longer collide.** Two merges in quick succession both
  computed the same new tag and the second push failed; tagging is now serialized. A re-run
  against an already-tagged commit is also a clean no-op instead of a hard error.
- **`softprops/action-gh-release` is pinned to a real release** (`v2.6.2`) rather than an
  arbitrary mid-development `master` commit, and all workflows now pin the same
  `actions/checkout` version with accurate version comments.
- **`ty` type error in the crack tailer.** `_read_new_lines` read `self._file_pos`
  (`int | None`) while its only None-guard lived in the caller, so the position is now
  passed in explicitly as an `int`. Behavior is unchanged.

## [2.11.3] - 2026-07-24

### Fixed

- **Rule file cleanup no longer errors out.** `rules_cleanup` (Rule File Tools → "Clean
  rule file" / "Clean and optimize") invoked `cleanup-rules.bin` with no arguments, but the
  binary requires a `mode` argument (`1` = CPU, `2` = GPU) and exits with usage text
  otherwise — so cleanup always failed. It now passes the mode (defaulting to GPU) so the
  cleanup actually runs.

## [2.11.2] - 2026-07-23

### Added

- **Hashview cracked-hash upload now reports how many hashes landed.** After an upload the
  CLI prints the number of pairs the client sent and how many it skipped by validation —
  available regardless of the server version — and, against a Hashview that reports import
  counts, also shows how many were newly cracked, verified, and left unmatched (already
  cracked or not present). `upload_cracked_hashes` surfaces `uploaded`/`skipped` in its
  return value alongside any server-provided counts. Previously the upload only printed
  `✓ Success: OK` with no indication of how many hashes were accepted.

## [2.11.1] - 2026-07-23

### Fixed

- **Hashview cracked-hash uploads no longer choke on hashcat `$HEX[...]` plaintexts.**
  hashcat emits `$HEX[...]` for recovered passwords containing leading/trailing
  whitespace or non-UTF-8 bytes. `upload_cracked_hashes` forwarded those verbatim, so a
  Hashview that verifies the plaintext against the hash rejected the entire batch with
  `Plaintext for hash ... was found to be invalid.` The uploader now decodes `$HEX[...]`
  to the exact bytes the server must re-hash — latin-1→UTF-8 for the UTF-16LE modes
  (NTLM 1000, MSSQL 1731), raw bytes for the raw-byte modes (0/100/300/900/1400/1700) —
  and keeps the `$HEX` wrapper verbatim when inlining would be unsafe (embedded CR/LF) so
  a `$HEX`-aware server can still handle it. Verified end-to-end against an unpatched
  Hashview.

### Added

- **Client-side validation of cracked hash:plaintext pairs before Hashview upload.**
  `upload_cracked_hashes` now filters each pair against the declared hashcat mode: a
  length check for wrong-width hashes, plus a plaintext recompute for the reproducible
  fast modes (MD5, SHA1, MD4, NTLM, SHA2-256/512). Mismatched lines (e.g. a stray MD5
  hash mixed into an NTLM list) are skipped with a per-line warning instead of failing
  the whole upload server-side, and it raises clearly if nothing valid remains. Bundles a
  pure-Python MD4 since OpenSSL 3 dropped it from `hashlib`. Opt out with `validate=False`.

## [2.11.0] - 2026-07-23

### Changed

- **Shard Wordlist (Wordlist Tools option 7) now produces all shards in a single run.**
  Instead of prompting for a modulus + offset and emitting one file per invocation, it
  prompts for an output *base path* and a shard count (N), then writes all N interleaved
  parts named with zero-padded part numbers (`base.001`…`base.00N`). This matches the
  intended distributed-cracking workflow — split once, copy one part per node — without
  re-running the tool for each offset. README usage docs updated accordingly.

## [2.10.10] - 2026-07-21

### Security

- **Bumped the pinned dev/test dependency `pytest` from 9.0.2 to 9.0.3** to clear the
  vulnerable tmpdir-handling advisory GHSA-6w46-j5rx-g56g (affects pytest < 9.0.3;
  Dependabot alert #1). Development-scope test runner only — no runtime dependency change.
  The full test suite passes under 9.0.3. (`uv.lock` is gitignored, so only the
  `pyproject.toml` pin is tracked.)

## [2.10.9] - 2026-07-21

### Fixed

- **Quick Crack default wordlist stays on `hcatOptimizedWordlists`.** The numbered list and
  tab-completion browse `hcatWordlists`, but pressing Enter still falls back to
  `hcatOptimizedWordlists` as before.

## [2.10.8] - 2026-07-21

### Fixed

- **Hashview `list_customers` crashed against current servers.** The `/v1/customers`
  response now returns its `users` array as native JSON (Hashview issue #229), but the
  client still ran `json.loads()` on it unconditionally, raising `TypeError` and breaking
  the entire customer → hashfile enumeration flow. Both the native-array and the legacy
  double-encoded-string shapes are now accepted.
- **Hashview hash-type parsing mis-read MD5 (mode 0).** `get_hashfile_details` selected the
  hash type with an `or` fallthrough, so the falsy `0` fell through to the response
  envelope's `type` field and returned the string `"message"`. Hash type is now read by key
  presence, and the bogus `type` fallback was removed.
- **Hashview `get_hashfile_hash_type` always returned an empty list.** It looked for
  `file_ids`/`ids`/`hashfile_ids` keys the endpoint never sends; it now reads the actual
  `hashfiles` envelope array and extracts each file id.

### Added

- **Download Hashview rule files.** New `HashviewAPI.list_rules()` and `download_rules()`
  wrap `GET /v1/rules` and `GET /v1/rules/{id}`. The server gzip-compresses plaintext rules
  on the fly, so downloads are decompressed before saving — the resulting file is usable
  directly with `hashcat -r`. Exposed via the interactive Hashview menu ("Download Rule")
  and the CLI: `hate_crack.py --hashview download-rules --rules-id <id> [--output <file>]`.

## [2.10.7]

- Auto-upgrade (`hate_crack --update` / the in-menu upgrade) now survives the historical `master` → `main` default-branch rename. Old clones made before the rename sit on a local `master` whose upstream (`branch.master.merge`) still points at the now-deleted `refs/heads/master`, so a bare `git pull` failed with "Your configuration specifies to merge with the ref 'refs/heads/master' from the remote, but no such ref was fetched" — and `_run_upgrade()`'s `git checkout main` also failed on stale clones that had never fetched `origin/main`. The updater now fetches from `origin` *before* switching branches, checks out `main` via `git checkout -B main origin/main` (creating/resetting it from the remote regardless of local state), repairs the upstream with `git branch --set-upstream-to=origin/main main` so future manual `git pull`s work too, and pulls explicitly with `git pull origin main` so it never consults the dangling `branch.*.merge` config. Existing safety guards (dirty-branch bail, detached-HEAD skip) are unchanged.

## [2.10.6]

- Fixed the Hashview integration calling API routes that don't exist in Hashview (verified against v0.8.3-dev), which 404'd as soon as a customer ID was entered ("Could not list hashfiles"). The customer→hashfile listing relied on a phantom `GET /v1/hashfiles` list-all route; it now enumerates via the real `GET /v1/hashfiles/hash_type/<type>` endpoint where available — the download flow sweeps common hashcat modes to display a customer's uploaded hashfiles. That listing route only exists on Hashview builds from 2026-06-08+ (the `v0.8.3-dev` branch); on `main`/older servers there is no hashfile-listing API at all, so the flow now degrades gracefully to entering the hashfile ID directly (looked up in the Hashview web UI) and resolving its type via `GET /v1/getHashType/<id>`. Additional client-side route fixes: hashfile hash-type lookup now uses `GET /v1/getHashType/<id>`; "left" (uncracked) hash download uses `GET /v1/hashfiles/<id>`; `delete_job` uses `DELETE /v1/jobs/<id>`; `start_job` uses `POST`. Hashview exposes no stop-job route, so `stop_job` now raises with guidance to use `delete_job`; and no bulk cracked-hash export exists, so the best-effort "found" merge degrades gracefully.
- The Hashview CLI now honours `HASHVIEW_URL` / `HASHVIEW_API_KEY` environment variables as overrides for the `config.json` values, so the client can be pointed at a different Hashview instance (e.g. a local dev stack) without editing the persisted config.
- Added an opt-in local Hashview integration-test harness: `HASHVIEW_TEST_LOCAL=1` (with `HASHVIEW_REPO=<path>`) spins up and seeds a local Hashview docker stack, runs the live Hashview tests against it, and tears it down (`HASHVIEW_KEEP=1` keeps it). This is what surfaced and verified the route fixes above against `v0.8.3-dev`. See the README testing section for details.

## [2.10.5]

- Pipal analysis no longer corrupts its input when cracked passwords contain `$HEX[...]` rows. `binascii.unhexlify().decode()` returned the bytes without the trailing newline that normal rows inherit from `password[-1]`, so every HEX-encoded password got concatenated with the next one in the `.passwords` file fed to pipal (e.g. three cracks → two lines, one of them a bogus mashup). Pipal then under-counted entries and reported wrong top base words. The HEX branch now re-appends `\n` so each cracked password lands on its own line.

## [2.10.4]

- Pushover notifications fire correctly for Quick Crack, Loopback, Combinator, PRINCE-LING, and N-gram attacks (#110). The handlers prompted the user under one name (e.g. "Quick Crack") while the underlying hashcat wrapper passed a different `attack_name` to `_should_fire` ("Quick Dictionary"), so the per-run consent lookup always missed. The prompt name now flows down to `_run_hcat_cmd` for both the job-done summary and the per-crack tailer.

## [2.10.3]

- Auto-upgrade no longer loops infinitely when invoked from a non-main branch (e.g. `dev`). Release tags live on main-side merge commits, so `git pull` on `dev` was a no-op and setuptools-scm kept regenerating the version as `X.Y.Z.postN.devM` — the update check then re-fired forever. `_run_upgrade()` now switches to `main` before pulling, with safety guards: refuses to clobber uncommitted work, surfaces clear errors when `main` is checked out in another worktree, and leaves detached-HEAD checkouts untouched.

## [2.10.2]

- Fingerprint Attack no longer launches hashcat against empty wordlists when no candidates exist; prints a "no candidates to expand" message and skips the attack (plus the secondary hybrid pass that previously fired six wasted hashcat sessions).
- Forced `LC_ALL=C` on every `sort -u` subprocess (fingerprint expander pipeline, `_write_field_sorted_unique`, LM-to-NT combinator dedupe) — fixes "sort: Illegal byte sequence" on macOS when cracked passwords contain non-UTF-8 bytes, which was silently emptying the fingerprint candidate list.

## [2.10.1]

- Bumped `HashcatRosetta` submodule to v0.2.0, dropping a vulnerable transitive `pytest` (< 9.0.3, GHSA tmpdir handling) from its requirements.
- Added `click>=8.0.0` to runtime dependencies (now required by HashcatRosetta v0.2.0's formatting module).

## [2.9.3]

- Transmission daemon now watches `/tmp/hate_crack/` for new `.torrent` files; wordlist content still downloads to the configured wordlist directory.
- Suppressed `transmission-daemon` stdout/stderr so daemon log output no longer appears in the terminal.
- Increased watch-dir polling window to 30s to account for transmission's ~10s scan interval.
- Store downloaded `.torrent` files in `/tmp/hate_crack/` instead of `/tmp/` root.

## [2.5.0]

- Added tab autocomplete to all file and directory path prompts in the Wordlist Tools submenu (option 80).
- Restored `hcatOptimizedWordlists` config key (directory for pre-optimized wordlists); defaults to `./optimized_wordlists`, falls back to `hcatWordlists` if not found.
- Quick Crack now defaults to `hcatOptimizedWordlists` instead of `hcatWordlists`.

## [2.0+]

- Added Random Rules Attack (option 20) using `generate-rules.bin` to generate random mutation rules (#87).
- Added Ad-hoc Mask Attack (option 17) for user-typed hashcat masks with optional custom character sets.
- Added Markov Brute Force Attack (option 18) using `hcstat2` statistical tables for password generation.
- Consolidated Combinator Attacks (formerly options 10/11/12) into interactive submenu under option 6.
- Markov attack supports training from cracked passwords or any wordlist, with table reuse/regeneration menu.
- Fixed OMEN attack failing silently when model files were incomplete or enumNG errors occurred.
- OMEN attack now validates all 5 required model files, captures enumNG stderr, and provides a train/use/cancel menu with wordlist picker.
- Filtered `.7z`, `.torrent`, and `.out` files from wordlist selection menus (#80).
- Parallelized Hashmob rule downloads using a thread pool with success/failure summary (#81).
- Added dynamic optimized kernel (`-O`) flag per attack type via `optimizedKernelAttacks` config (#82).
- Replaced `uv tool install` with a bash shim for reliable config and asset resolution from any working directory.
- Fixed config resolution to search the repo root and package directory in addition to CWD.
- Fixed bare NTLM hash detection failing when hash files contain leading blank lines, BOM characters, or null bytes from UTF-16 encoding.
- Improved error message for unrecognized hash formats to show the actual first-line content and list expected formats.
- Fixed rule file path construction in Quick Crack and Loopback Attack using `os.path.join()` instead of string concatenation.
- Added automatic update checks on startup (check_for_updates config option).
- Added `packaging` dependency for version comparison.
- Added OMEN Attack (option 16) using statistical model-based password generation.
- Added OMEN configuration keys (omenTrainingList, omenMaxCandidates).
- Added LLM Attack (option 15) using Ollama for AI-generated password candidates.
- Added Ollama configuration keys (ollamaModel, ollamaNumCtx).
- Auto-versioning via setuptools-scm from git tags.

## [2.0]

- Modularized codebase into CLI/API/attacks modules.
- Unified CLI options with config overrides (hashview, hashcat, wordlists, pipal).
- Added Hashview API integration.
- Added Weakpass torrent download helpers and Hashmob download wrapper.
- Improved test coverage and snapshot-based menu validation.
- Updated documentation and versioning.

## [1.9]

- Revamped the hate_crack output to increase processing speed exponentially; `combine_ntlm_output` function for combining.
- Introducing new attack mode "Bandrel Methodology".
- Updated pipal function to output top x number of basewords.

## [1.08]

- Added a Pipal menu option to analyze hashes. https://github.com/digininja/pipal

## [1.07]

- Minor bug fixes with pwdump formatting and unhexify function.

## [1.06]

- Updated the quick crack and recycling functions to use user-customizable rules.

## [1.05]

- Abstraction of rockyou.txt so that you can use whatever dictionary you would like, specified in the config.json.
- Minor change to quickcrack that allows you to specify 0 for the number of times best64 is chained.

## [1.04]

- Two new attacks: Middle Combinator and Thorough Combinator.

## [1.03]

- Introduction of new feature to use session files for multiple concurrent sessions of hate_crack.
- Minor bug fix.

## [1.02]

- Introduction of new feature to export the output of pwdump-formatted NTDS outputs to Excel with clear-text passwords.

## [1.01]

- Minor bug fixes.

## [1.00]

- Initial public release.
