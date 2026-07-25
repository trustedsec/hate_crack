# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are omitted for releases predating this file; see the git tags for exact timing.

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
