# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are omitted for releases predating this file; see the git tags for exact timing.

## [2.10.11] - 2026-07-23

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
