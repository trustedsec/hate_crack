# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are omitted for releases predating this file; see the git tags for exact timing.

## [Unreleased]

### Fixed

- **Pipal analysis (option 95) ran the pwdump-only merge on any NTLM run.** The
  guard tested the hash type but not `pwdump_format`, unlike the identical guard
  in `cleanup()`, so a plain NTLM list took a code path meant for pwdump files —
  which used to truncate the cracked output and produce a report reading
  `Total entries = 0`. Pipal now also says so plainly when there are no cracked
  passwords to analyse, instead of emitting a zeroed report.
- **Excel export (option 96) had the same missing guard as Pipal analysis.** It
  ran the pwdump-only merge for any NTLM hash type, so a plain hash list took a
  path that used to truncate the cracked output, and then produced an empty
  spreadsheet because the pwdump-shaped rows it looks for were not there. All
  three callers of the merge now guard identically, and a test enforces that a
  fourth cannot be added without the guard.

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
