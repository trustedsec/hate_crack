```
  ___ ___         __             _________                       __
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    <
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
```

## Installation

Installing from source is the only supported path. hate_crack is **not**
distributed on PyPI: `pip install hate-crack` resolves to a `0.0.0` placeholder
that fails on purpose and points back here. The name is held only so nobody else
can publish a lookalike under it — see
[`packaging/pypi-placeholder/`](packaging/pypi-placeholder/).

### 1. Install hashcat

Hashcat must be installed and available in your PATH:

Ubuntu/Kali:
```bash
sudo apt-get install -y hashcat
```

macOS (Homebrew):
```bash
brew install hashcat
```

Or download a pre-built binary from https://hashcat.net/hashcat/ and set `hcatPath` in `config.json` to its location.

### 2. Download hate_crack

Clone with submodules (required for hashcat-utils, princeprocessor, pcfg_cracker, Corporate_Masks, and optionally omen):

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
```

If you cloned without submodules, initialize them:

```bash
git submodule update --init --recursive
```

Then customize configuration if needed. hate_crack uses two config files, each owning a distinct set of settings:

- **`config.json`** — wordlist paths, masks, rules, tuning, potfile, hashcat path, candidate limits, notification toggles, CLI preference defaults (35 settings).
- **`.env`** — third-party integration settings only: Hashview and Hashmob credentials, Pushover credentials, Ollama, and pipal (14 settings). Not tracked by git, created at mode `0600`.

The line falls there for one reason: `.env` is the file that can hold secrets. Credentials for, and configuration of, third-party services go in the untracked, `0600` file; everything hate_crack does locally stays in `config.json`, which is safe to share, diff and check into your own notes. That is also why the Pushover *credentials* are in `.env` while the Pushover on/off *toggles* are in `config.json` — the toggles are local preferences, not secrets.

Each key has exactly one home. A key placed in the other file is ignored, and hate_crack prints a warning naming the file it belongs in. Any key can still be overridden for a single run by exporting its environment variable. Most users can skip this step as default paths work out-of-the-box.

`config.json` is permanent and first-class — it is not deprecated and there is no removal timeline for it. Only the integration settings moved.

**Upgrading from a single `config.json`?** hate_crack migrates it for you on first run: the integration settings are copied into a new `0600` `.env`, then removed from `config.json` so the two files do not both claim them. It prints which keys moved (never their values), and saves your original as `config.json.pre-split.bak` before touching it. Everything else in `config.json` is left exactly as it was, key order included.

**First run:** hate_crack creates both files for you, so there is nothing to do. To set up `.env` by hand instead, copy the tracked template:

```bash
cp .env.example .env
chmod 600 .env
```

`.env.example` is committed and ships with every credential key empty. `.env` itself must **never** be committed — it is gitignored, along with its usual backup spellings, and hate_crack always creates it at mode `0600` (owner read/write only). `.env.example` is generated from the schema; regenerate it after changing `hate_crack/config_schema.py` with `uv run python -m hate_crack.config_writer`.

### 3. Install dependencies and hate_crack

The easiest way is to run `make` (or `make install`), which auto-detects your OS and installs:
- External dependencies (p7zip, transmission-daemon / transmission-remote)
- Builds submodules (hashcat-utils, princeprocessor, pcfg_cracker, and optionally omen) and checks out the data-only Corporate_Masks mask set
- Python dependencies via uv and a CLI shim at `~/.local/bin/hate_crack`

```bash
make
```

This is idempotent - it skips tools already installed. To force a clean reinstall:

```bash
make reinstall
```

**Or install dependencies manually:**

### External Dependencies
These are required for certain download/extraction flows:

- `7z`/`7za` (p7zip) — used to extract `.7z` archives.
- `transmission-daemon` / `transmission-remote` — used to download Weakpass torrents.

Manual install commands:

Ubuntu/Kali:
```bash
sudo apt-get update
sudo apt-get install -y p7zip-full transmission-daemon
```

macOS (Homebrew):
```bash
brew install p7zip transmission-cli  # provides transmission-daemon and transmission-remote
```

Then install the Python dependencies and CLI shim:
```bash
uv sync
mkdir -p ~/.local/bin
printf '#!/usr/bin/env bash\nset -euo pipefail\nexec uv run --directory %s python -m hate_crack "$@"\n' "$(pwd)" > ~/.local/bin/hate_crack
chmod +x ~/.local/bin/hate_crack
```

-------------------------------------------------------------------
## Project Structure
Core logic is now split into modules under `hate_crack/`:

- `hate_crack/cli.py`: argparse helpers and config overrides.
- `hate_crack/api.py`: Hashview, Weakpass, and Hashmob integrations (downloads/menus/helpers).
- `hate_crack/attacks.py`: menu attack handlers.
- `hate_crack/hashmob_wordlist.py`: Hashmob wordlist utilities (thin wrapper; calls into api.py).
- `hate_crack/corpus_stats.py`: whole-corpus password statistics used to describe a corpus to the LLM.
- `hate_crack/plaintext.py`: recovers the password from a corpus line (hash-prefix stripping, `$HEX[...]` decoding); shared by the LLM modes, corpus_stats, and rulegen.
- `hate_crack/llm.py`: structured (JSON) LLM candidate generation via Atomic Agents.
- `hate_crack/menu.py`: shared menu renderer, including optional arrow-key navigation.
- `hate_crack/noninteractive.py`: dispatcher for the scripted attack subcommands.
- `hate_crack/notify/`: notification package (Pushover backend, per-crack tailer).
- `hate_crack/username_detect.py`: detects `username:hash` input files to decide on hashcat's `--username`.
- `hate_crack/formatting.py`, `hate_crack/progress.py`: output formatting and progress display helpers.
- `hate_crack/main.py`: main CLI implementation.

The top-level `hate_crack.py` remains the main entry point and orchestrates these modules.

-------------------------------------------------------------------
## References and Thanks

This project depends on and is inspired by a number of external projects and services. Thanks to:

- Hashview (http://github.com/hashview/)
- Weakpass (https://weakpass.com)
- Hashmob (https://hashmob.net)

-------------------------------------------------------------------
## Usage

After installing with `make`, run hate_crack from anywhere:

```bash
hate_crack
# or with arguments:
hate_crack <hash_file> <hash_type> [options]
```

Alternatively, run via `uv`:

```bash
uv run hate_crack.py <hash_file> <hash_type>
```

### Run as a tool (recommended)

Install using `make` from the repository root - this builds submodules and bundles assets:

```bash
cd /path/to/hate_crack
make
hate_crack
```

The `make install` command creates a bash shim at `~/.local/bin/hate_crack` that runs from the repo directory, so config and assets are always found regardless of your current working directory.

Config is also searched in:
- The repo root and package directory
- `~/.hate_crack`

**Note:** The `hcatPath` in `config.json` is for the hashcat binary location only (optional if hashcat is in PATH). Hate_crack assets (hashcat-utils, princeprocessor, pcfg_cracker, Corporate_Masks, omen) are loaded from the repository directory and bundled automatically by `make install`.

### Run as a script
The script uses a `uv` shebang. Make it executable and run:

```bash
chmod +x hate_crack.py
./hate_crack.py
```

You can also use Python directly:

```bash
python hate_crack.py
```

### Non-interactive / scripted usage

For automation you can launch a single attack directly, bypassing the menu. The attack name is the first argument, followed by the hash file and hashcat hash type. Preprocessing prompts (computer-account filtering, LM-first brute force, duplicate-account dedup) auto-accept their defaults in this mode. The process exits `0` on success and non-zero on error (missing hash file, non-numeric hash type, missing wordlist, or an unknown rule filename).

```bash
# Quick crack: one wordlist + optional rule(s) from the rules directory
hate_crack quick hashes.txt 1000 --wordlist rockyou.txt --rules best64.rule

# Chain two rules in a single run
hate_crack quick hashes.txt 1000 --wordlist rockyou.txt --rules best64.rule+d3ad0ne.rule

# Run two rules as two separate passes
hate_crack quick hashes.txt 1000 --wordlist rockyou.txt --rules best64.rule d3ad0ne.rule

# Canned dictionary methodology (uses your configured wordlists)
hate_crack dict hashes.txt 1000

# Brute force lengths 1-8
hate_crack brute hashes.txt 1000 --min 1 --max 8

# Top-mask attack targeting ~4 hours
hate_crack topmask hashes.txt 1000 --target-time 4
```

-------------------------------------------------------------------
## Troubleshooting

### Error: "would clobber existing tag" when updating

An older clone can refuse to update, printing a long list of lines like:

```
 ! [rejected]        v2.5.0     -> v2.5.0  (would clobber existing tag)
```

This affects clones created before July 2026. Published history was rewritten
then to remove some files that should never have been committed, which gave
every commit a new ID; an older clone's tags therefore point at objects this
repository no longer contains, and git refuses to move a tag it already has.
Nothing is wrong with your checkout and no cracking data is at risk.

Recover with a one-time reset. This discards local commits and edits in the
checkout, so if you have customized anything tracked by git (as opposed to
`config.json`, which is not tracked), commit it to a branch first:

```bash
cd /path/to/hate_crack
git fetch --tags --force origin
git checkout -B main origin/main
make install
```

`--force` here only updates tags; it cannot touch your commits. Afterwards the
built-in updater works normally. Versions before 2.18 could not perform this
recovery themselves, which is why it has to be done by hand once.

### Error: Build directory does not exist

If you see an error like:
```
Error: Build directory /opt/hashcat/hashcat-utils does not exist.
Expected to find expander at /opt/hashcat/hashcat-utils/bin/expander.
```

This means the hate_crack assets were not bundled into the installed package.

**Understanding the paths:**
- `hcatPath` in config.json → points to **hashcat binary location** (optional, can be in PATH)
- `hashcat-utils/` and `princeprocessor/` → bundled into the package by `make install`

**Solution:**
Reinstall using the Makefile, which builds submodules and installs the tool:
```bash
cd /path/to/hate_crack  # the repository checkout
make install
```

**Default configuration (config.json.example):**

Most users can use defaults without customization:
- `hcatWordlists`: `./wordlists` (relative to repo root or HOME/.hate_crack)
- `hcatOptimizedWordlists`: `./optimized_wordlists` (directory used by Quick Crack; falls back to `hcatWordlists` if not found)
- `rules_directory`: `./hashcat/rules` (includes submodule rules)
- `hcatTuning`: `` (empty string - no default tuning flags)

**Example config.json customizations:**
```json
{
  "hcatPath": "/usr/local/bin",          # Location of hashcat binary (optional, auto-detected from PATH)
  "hcatBin": "hashcat",                  # Hashcat binary name
  "hcatWordlists": "./wordlists",        # Dictionary wordlist directory (relative or absolute)
  "rules_directory": "./hashcat/rules",  # Rules directory (relative or absolute)
  "hcatTuning": "",                      # Additional hashcat flags (empty by default)
  ...
}
```

**Configuration loading:**
- Precedence for each key: `os.environ` > that key's own home file (`.env` or `config.json`) > built-in default
- Missing keys fall back to the built-in defaults; `config.json.example` documents every `config.json` key
- Both files are searched, independently of each other, in this order: **repo root**, then the **installed package directory**, then **`~/.hate_crack`**. First match wins; it is normal for the two files to come from different directories.
- On first run, both are created — `config.json` from `config.json.example`, `.env` from the built-in defaults. If an older `config.json` still holds integration keys, they are copied into the new `.env` and hate_crack tells you which ones to delete from `config.json`; it never edits that file itself.
- On every run, hate_crack prints the two files it actually loaded:

  ```
  [*] config.json: /home/you/.hate_crack/config.json
  [*] .env:        /home/you/.hate_crack/.env
  ```

  Read those two lines before debugging a setting that "isn't taking effect". They exist because of two traps in the search order:

  - **A checkout outranks your home directory.** The repo root is searched first, so a `.env` or `config.json` sitting in *any* checkout you run the tool from wins over the one in `~/.hate_crack` — and running the tool from a checkout is exactly what creates those files there in the first place. If this ever shadows a real `~/.hate_crack` config, hate_crack now says so with a third `[!]` line naming both paths — treat that line as "the file below is being ignored," not as a second, equally-valid config.
  - **The current working directory is never searched.** A `.env` in the directory you happen to be standing in is ignored, deliberately: engagement directories are full of files nobody intended as configuration. Put it in the repo root or `~/.hate_crack`.

### Error: merge with ref 'refs/heads/master' but no such ref was fetched

If you see:
```
Your configuration specifies to merge with the ref 'refs/heads/master'
from the remote, but no such ref was fetched.
```

The default branch was renamed from `master` to `main`. Fix with:
```bash
git remote set-head origin -a
git branch -m master main
git branch --set-upstream-to=origin/main main
git pull
```

-------------------------------------------------------------------
### Makefile Targets

**Default (full installation)** - builds submodules, installs dependencies, and installs the tool:

```bash
make
# or explicitly:
make install
```

This is idempotent - it skips tools already installed.

**Force clean reinstall:**

```bash
make reinstall
```

**Quick update** - rebuilds submodules and reinstalls tool (after pulling changes):

```bash
make update
```

**Uninstall** - removes OS dependencies and tool:

```bash
make uninstall
```

**Build hashcat-utils only:**

```bash
make hashcat-utils
```

**Run tests** - automatically handles HATE_CRACK_SKIP_INIT when needed:

```bash
make test
```

**Coverage report:**

```bash
make coverage
```

**Clean build/test artifacts:**

```bash
make clean
```

-------------------------------------------------------------------
## Development

### Setting Up the Development Environment

Install the project with optional dev dependencies (includes linters and testing tools):

```bash
make dev-install
```

### Running Linters and Type Checks

Before pushing changes, run these checks locally. Use `make lint` for everything, or run individual checks:

**Ruff (linting and formatting):**
```bash
make ruff
# or manually:
uv run ruff check hate_crack tests tools packaging hate_crack.py
```

Auto-fix issues:
```bash
uv run ruff format hate_crack tests tools packaging hate_crack.py
uv run ruff check --fix hate_crack tests tools packaging hate_crack.py
```

**ty (type checking):**
```bash
make ty
# or manually:
uv run ty check hate_crack
```

**Run all checks together:**
```bash
make lint
```

### Running Tests

Tests auto-detect when submodules are not built and set `HATE_CRACK_SKIP_INIT=1` automatically.

```bash
make test
```

Or run pytest directly:

```bash
uv run pytest -v
```

With coverage:

```bash
make coverage
```

Or with pytest:

```bash
uv run pytest --cov=hate_crack
```

### Git Hooks (prek)

Git hooks are managed by [prek](https://github.com/j178/prek) (v0.3.3+). Install hooks with:

```bash
prek install --hook-type pre-push --hook-type pre-commit
```

This installs the hooks defined in `prek.toml` using the pre-commit local-repo
TOML schema:
- **pre-push** (local hooks): ruff, ruff-format, ty, pytest, pytest-lima, bandit
- **pre-commit** (from `pre-commit/pre-commit-hooks`): trailing-whitespace,
  end-of-file-fixer, check-yaml, check-merge-conflict, check-added-large-files,
  detect-private-key

The pre-commit auto-fixers rewrite files in place, so re-stage and commit again
after they run.

Note: prek 0.3.3 expects `repos = [...]` at the top level. The old `[hooks.<stage>] commands = [...]` format is not supported.

### Arrow-Key Menu Navigation

Menus use classic numbered `print()` + `input()` selection by default, which
accepts full multi-digit keys.

To enable arrow-key navigation via `simple-term-menu`, set
`HATE_CRACK_ARROW_MENU=1`. In that mode only single-digit shortcut keys work;
options numbered 10 and above must be reached with the arrow keys. Arrow-key
mode also requires a TTY, so it stays off when output is piped.

### Dev Dependencies

The optional `[dev]` group includes:
- **ty** - Static type checker
- **ruff** - Fast Python linter and formatter
- **pytest** - Testing framework
- **pytest-cov** - Coverage reporting

-------------------------------------------------------------------
Common options:
- `--download-hashview`: Download hashes from Hashview before cracking.
- `--hashview`: Interactive Hashview menu for managing hashes, wordlists, and jobs.
- `--hashview --help`: Show Hashview command-line options.
- `--weakpass`: Download wordlists from Weakpass.
- `--hashmob`: Download wordlists from Hashmob.net.
- `--download-torrent <FILENAME>`: Download a specific Weakpass torrent file.
- `--download-all-torrents`: Download all available Weakpass torrents from cache.
- `--wordlists-dir <PATH>` / `--optimized-wordlists-dir <PATH>`: Override wordlist directories.
- `--pipal-path <PATH>`: Override pipal path.
- `--restore-potfile`: Rebuild `<hashfile>.out` from the hashcat POT file at startup, replacing any existing contents, then continue into the normal menu. Without this flag the POT lookup only runs when `.out` does not already exist. Menu option 93 does the same thing on demand, with a confirmation prompt.
- `--maxruntime <SECONDS>`: Override max runtime.
- `--bandrel-basewords <PATH>`: Override bandrel basewords file.
- `--update`: Update to the latest release and reinstall. Switches the checkout to `main` if it is on another branch, since release tags live there.
- `--nightly`: Update to the latest nightly instead, from the `nightly-dev` branch. Nightlies have passed CI but are not part of a cut release. Can also be written `--update --nightly`.
- `--no-optimized-kernel` (or `--no-optimize`): Never pass `-O` to hashcat for the whole run. Overrides `optimizedKernelAttacks` in `config.json` and strips any `-O` you put in `hcatTuning`. Nothing is written back to the config, so it applies to this run only. With a subcommand, put it before the subcommand: `./hate_crack.py --no-optimize quick hashes.txt 1000 --wordlist words.txt`.
- `--debug`: Enable debug logging (writes to stderr).

### Hashview Integration

hate_crack integrates with Hashview for centralized hash management and distributed cracking.

#### Interactive Menu

Access the interactive Hashview menu:
```bash
hate_crack.py --hashview
```

Menu options:
- **(1) Upload Cracked Hashes** - Upload cracked results from current session to Hashview
- **(2) Upload Wordlist** - Upload a wordlist file to Hashview
- **(3) Download Wordlist** - Download a wordlist from Hashview
- **Download Rule** - Download a rule file from Hashview (decompressed to plaintext, ready for `hashcat -r`)
- **Download All Rules** - Download every rule file listed by Hashview in one pass; per-rule failures are reported without aborting the rest
- **(4) Download Left Hashes** - Download remaining uncracked hashes (prompts to switch for cracking)
- **(5) Download Found Hashes** - Download already-cracked hashes with cleartext passwords (for reference/analysis)
- **(6) Upload Hashfile and Create Job** - Upload new hashfile and create a cracking job
- **(99) Back to Main Menu** - Return to main menu

**Important: Download Found vs Download Left**
- **Download Left Hashes (4)**: Downloads uncracked hashes that need cracking. Automatically merges with any found hashes if available, and prompts to switch to this hashfile for cracking.
- **Download Found Hashes (5)**: Downloads already-cracked hashes in hash:cleartext format. These are for reference and cannot be cracked further. No switch prompt is shown.

#### Command-Line Interface

Hashview operations can also be performed via command-line:

Upload cracked hashes:
```bash
hate_crack.py --hashview upload-cracked --file <output_file>.out --hash-type 1000
```

Upload a wordlist:
```bash
hate_crack.py --hashview upload-wordlist --file <wordlist>.txt --name "My Wordlist"
```

Download a rule file (saved decompressed, ready for `hashcat -r`):
```bash
hate_crack.py --hashview download-rules --rules-id 4 --output best64.rule
```

Download left hashes (uncracked hashes for cracking):
```bash
hate_crack.py --hashview download-left --customer-id 1 --hashfile-id 123
```

Download found hashes (already-cracked hashes with cleartext):
```bash
hate_crack.py --hashview download-found --customer-id 1 --hashfile-id 123
```

Upload hashfile and create job:
```bash
hate_crack.py --hashview upload-hashfile-job --file hashes.txt --customer-id 1 \
  --hash-type 1000 --job-name "NTLM Crack Job" --hashfile-name "Domain Hashes"
```

#### Configuration

Set Hashview credentials in `.env` (they are integration settings, so they do not live in `config.json`):
```
HASHVIEW_URL=https://hashview.example.com
HASHVIEW_API_KEY=your-api-key-here
```

#### Ollama Configuration

The LLM Attack (option 12) uses Ollama to generate password candidates. Configure the model, context window, and request timeout in `.env`:

```
OLLAMA_MODEL=qwen3:4b-instruct
OLLAMA_NUM_CTX=8192
OLLAMA_TIMEOUT=300
```

- **`OLLAMA_MODEL`** — The Ollama model used for candidate generation (default: `qwen3:4b-instruct`). The LLM attack uses structured (JSON) output, so choose a model with good tool/JSON support.
- **`OLLAMA_NUM_CTX`** — Context window size for the model (default: `8192`). This was `2048` before corpus statistics were introduced, which was too small to hold the prompt it was being given: 500 sampled plaintexts run roughly 2,000–3,500 tokens before the system prompt and response, so Ollama silently truncated part of the sample the sampler had carefully spread across the file.
- **`OLLAMA_TIMEOUT`** — Seconds to wait for a generation response before giving up (default: `300`). Raise this if a large model is still loading into VRAM on the first request, which can otherwise exceed the timeout; hate_crack prints the elapsed timeout and this setting's name when it fires.
- **`OLLAMA_MAX_SAMPLE_LINES`** — The threshold below which the LLM modes also paste the literal plaintexts into the prompt (default: `500`). Values ≤ 0 are treated as 500.

  Corpus-derived modes (**Wordlist**, **Cracked passwords**, **Pattern rules**) always describe the *entire* corpus statistically — baseword shares, masks, casing, lengths, trailing digits and symbols, years — rather than pasting in a slice of it. Aggregation is bounded, so a 120,000-password dump costs about the same prompt space as a 500-line one. When the whole corpus fits under this threshold, the raw plaintexts are included as well, since nothing is gained by hiding a small corpus from the model.

  This replaces the previous behaviour of pasting an evenly-spaced sample of up to `ollamaMaxSampleLines` passwords. A sample of a large dump conveyed no frequency information at all: the model could not distinguish a baseword used by 8% of the organization from one used by a single person, which is precisely the signal that makes a guess worth running.
- **`OLLAMA_NO_CLOUD`** — When `true`, refuse to send anything off this host, for any of the three LLM backends (Ollama, vLLM, or a generic OpenAI-compatible server). Two checks are gated by this one setting: Ollama proxies a `-cloud`-tagged model (`gpt-oss:120b-cloud`, `deepseek-v3.1:671b-cloud`) to ollama.com through the same local endpoint a local model uses, so nothing about the request looks different — that's refused by model name. The configured backend URL is also checked: a destination that isn't loopback, private, or link-local (and isn't `localhost` or a `.local`/`.internal`/`.lan`/`.localdomain` name) is refused by destination, and a hostname this check cannot resolve is refused too, fail-closed, rather than let an unverifiable destination through. hate_crack's prompts carry recovered plaintexts, corpus statistics, and the client's name, industry, and location, so either check firing means the request is refused before it is built. Defaults to `false`, so a deliberately-configured cloud model or remote server keeps working; turn it on for engagements where client data must not leave the host.
- **`OLLAMA_AUTO_RESEARCH`** — When `true` (default), **Target info** mode asks the local model to suggest the industry, location, and parent company / acquisition history as soon as you have typed the company name, and offers them as editable prompt defaults. Set to `false` to always get blank prompts (useful with a slow model, since research costs one extra round-trip before the attack starts).
- **`OLLAMA_HOST`** — Where Ollama is listening. Accepts a bare `host:port` (`theplague.lan:11434`) or a full URL with a scheme (`https://ollama.example.com`); either way the base URL is normalized before use. Defaults to `localhost:11434`. Set it in `.env`, or export it as a real environment variable to override that for a single run — it is the same variable name Ollama's own CLI reads.
- Ensure Ollama is running and the model is pulled (`ollama pull qwen3:4b-instruct`) before using the LLM Attack — hate_crack no longer auto-pulls missing models.

The attack offers three generation modes:

1. **Target info** — company / industry / location / parent company; the model derives candidates from those details.

   After you type the company name, hate_crack asks the same local model what it already knows about that organization and pre-fills the **Industry**, **Location**, and **Parent Company** prompts with the answers, shown in parentheses:

   ```
   Company name: Acme Rail Services

   [!] The values in parentheses below are the local model's GUESSES, not verified OSINT.
       Press Enter to accept, or type your own value to override.
   Industry (freight rail maintenance):
   Location (Omaha, Nebraska):
   Parent company / acquired by:
   ```

   Press Enter to accept a suggestion or type over it. These values are the model's recollection, **not OSINT** — treat them as a starting point, not intelligence about the client. The lookup uses only the local Ollama server, so the client name never leaves the host; there are no web or third-party API calls. If the model does not recognize the organization (the common case for small clients), it returns nothing and you get plain blank prompts:

   ```
   Company name: Acme Rail Services
   Industry:
   Location:
   Parent company / acquired by:
   ```

   A research failure — timeout, Ollama not running, empty answer — never blocks the attack; it just falls back to blank prompts. Set `ollamaAutoResearch` to `false` to skip research entirely.
2. **Wordlist** — derive basewords from a sample wordlist.
3. **Cracked passwords** — feed the plaintexts already recovered this session (`<hashfile>.out`) back to the model so it can infer the target organization's own password conventions (basewords, seasons, years, suffixes, leetspeak) and generate *new* candidates in the same style. This option is only listed once at least one hash has been cracked; the whole file is analyzed statistically exactly like Wordlist mode (see `ollamaMaxSampleLines` above).

#### PCFG Configuration

The PCFG Attack (option 20) and PRINCE-LING Attack (option 21) use the `pcfg_cracker` submodule. Configure them in `config.json`:

```json
{
  "pcfgRuleset": "DEFAULT",
  "pcfgMaxCandidates": 50000000,
  "pcfgPrinceLingMaxCandidates": 10000000
}
```

- **`pcfgRuleset`** — Name of the trained grammar to use (default: `DEFAULT`), resolved to `pcfg_cracker/Rules/<name>/`. Train your own with pcfg_cracker's `trainer.py` and set this to the ruleset name.
- **`pcfgMaxCandidates`** — Maximum candidates `pcfg_guesser.py` emits for the PCFG attack (default: `50000000`).
- **`pcfgPrinceLingMaxCandidates`** — Maximum base words `prince_ling.py` writes into the cached PRINCE base wordlist (default: `10000000`).

### Optimized kernels (`optimizedKernelAttacks`)

hashcat's `-O` flag selects optimized kernels, which are substantially faster
but cap candidate length (roughly 31 characters, lower for some modes) and
silently skip anything longer. `optimizedKernelAttacks` in `config.json` lists
the attacks that run with `-O`; omit an attack from the list to run it with
full-length kernels. The list in `config.json.example` matches the built-in
default that applies when no `config.json` exists.

Four attacks honour the setting but are **not** optimized by default, because
they feed candidates that can exceed the `-O` ceiling — add them to the list to
opt in:

- `hcatNgramX`, `hcatOllama`, `hcatOmen`, `hcatLMtoNT`

To turn `-O` off everywhere for a single run without editing the config, pass
`--no-optimized-kernel` (short form `--no-optimize`). It overrides the list for
every attack and also drops an `-O` written into `hcatTuning`, which would
otherwise reach hashcat regardless of the list.

Names are matched exactly, and an unrecognized entry is reported at startup
rather than ignored. Note that attacks which delegate to another attack are
controlled by the attack they delegate to, not by their own name: PRINCE-LING
follows `hcatPrince`, while Spoonman, Rosetta, and the LLM pattern-rule modes
follow `hcatQuickDictionary`.

### Attack coverage tracking (`coverage_enabled`)

Across a long engagement the same hash file gets attacked in many sessions with
a rotating set of wordlists, rule files and mask lists, and it is easy to burn
hours re-running ground you already covered — especially since the same rule
line lives in more than one rule file. hate_crack records what it has already
run against each hash file and offers to skip the overlap.

Coverage is recorded **per entry, not per file**: individual rule lines and
individual `.hcmask` lines, each paired with the wordlist it ran against. That
is what lets it recognise that a custom rule file you run today repeats 40 of
the rules `best64.rule` already covered last week, and it is also why a rule is
only "covered" for the specific wordlist it was tried with — the same rules over
a different corpus try entirely different candidates.

The hash file is identified by a sha256 of its contents, so coverage survives
renaming or moving it between sessions. Wordlists are identified the same way,
with the digest memoized against size and mtime so a multi-gigabyte corpus is
hashed once rather than on every attack.

You are only prompted when there is genuinely something to skip:

```
[*] Coverage: 40 of 45 rules in this Dictionary have already been run against this hash file.
[?] Skip them and run only the 5 new rules? [Y/n]:
```

Answer `Y` and hate_crack builds a temporary rule file holding just the untried
entries; answer `n` to run the whole thing anyway. If *every* entry is a repeat
you are asked whether to skip the attack outright, so deliberately re-running
covered ground never requires restarting the tool.

Attacks that are never filtered are still recorded as having run, which is what
lets you answer "did I already run PRINCE against this target?".

An attack that selects several rule files at once (Quick Crack, Loopback) asks
the skip question **once for the whole batch, up front**, before any hashcat
invocation. That question is deliberately cheap — it does not read or hash any
of the selected rule files, since a YOLO batch can run to millions of lines and
you should not wait through that to answer a yes/no. It asks the store only
whether this attack has already run against this hash file **with one of these
wordlists**; the per-entry diff still happens lazily, one rule file at a time,
and decides what actually gets skipped. So a fresh corpus is never flagged, even
when the rules on it have all run against a different one.

Three deliberate limits:

- **Coverage is recorded only when hashcat exhausts the keyspace** (exit 1). A
  ctrl-C or an error records nothing, and neither does exit 0 — that means every
  hash cracked, which hashcat reports *without* finishing the keyspace, and in
  the degenerate "all hashes found as potfile entries" case without trying a
  single candidate. Under-recording only costs a redundant run later.
- **Dynamic candidate generators are never filtered.** PRINCE, PCFG, OMEN,
  Markov brute force and the LLM modes have no fixed set to diff, so they are
  logged as having run and otherwise left alone. Chained rule files (`-r a -r b`)
  are tracked as a single unit rather than per entry, because hashcat applies the
  *cartesian product* of the two files and dropping an individual line would
  silently remove every combination it took part in.
- **`--loopback` runs are recorded but never filtered.** hashcat feeds freshly
  cracked plaintexts back in as *extra* candidates, so such a run tries the full
  wordlist and rule set plus whatever those recycled plaintexts reach. That makes
  the two directions asymmetric: recording it is sound, so a later ordinary run
  of the same wordlist and rules is correctly recognised as a repeat, but a
  second loopback run has more cracks to recycle and is never skipped.

Set `coverage_enabled` to `false` in `config.json` to turn this off, or pass
`--no-coverage` for a single run — which neither consults nor updates the store.

#### Inspecting and resetting coverage

Main-menu option **85 — Attack Coverage** shows what has been run against the
loaded hash file, its run history, and can clear it. The same three actions are
scriptable:

```bash
# What has already been run against this hash file?
hate_crack coverage status --hashfile hashes.txt

# Every attack that has run against it, oldest first
hate_crack coverage history --hashfile hashes.txt

# Start over for this hash file only (prompts unless --yes)
hate_crack coverage forget --hashfile hashes.txt --yes
```

The hash file is identified by content, so these work regardless of where it has
been moved since. `forget` affects only that one target — the store lives in
`~/.hate_crack/coverage/attack_coverage.sqlite3`, and deleting the file resets
coverage for *every* target.

#### Scripted runs

A scripted attack that coverage skips entirely still exits `0` by default, so
enabling coverage cannot start failing an existing harness. Pass
`--exit-code-on-skip` to get exit code **3** instead when nothing was launched:

```bash
hate_crack --exit-code-on-skip hashes.txt dict
# 0 = ran, 1 = bad input, 2 = unknown command, 3 = everything was already covered
```

Exit 3 means *nothing* ran. A pass that was partially filtered — some entries
skipped, some tried — still exits `0`, because the attack did do work.

### Notifications (menu option 82)

hate_crack can send Pushover push notifications when attacks complete and,
optionally, when individual hashes are cracked. All controls live under
main-menu option `82 — Notifications`:

1. **Toggle Pushover Notifications [ON/OFF]** — master switch. Persists to `config.json` as `notify_enabled`.
2. **Toggle Per-Crack Notifications [ON/OFF]** — when ON, a background tailer watches the `.out` file and pushes a notification per crack (with per-tick burst aggregation). Persists to `config.json` as `notify_per_crack_enabled`. Cannot be enabled while the master switch is OFF — enable option 1 first.
3. **Send Test Pushover Notification** — fires a canned push so you can confirm your Pushover token/user pair works. Works even when the master switch is OFF.

Credentials live in `.env`; the remaining tuning knobs are config-file-only in `config.json`:

- `NOTIFY_PUSHOVER_TOKEN`, `NOTIFY_PUSHOVER_USER` (in `.env`) — required for any push to fire. Nothing in the menu writes these; edit `.env` yourself.
- `notify_attack_allowlist` — attack names that auto-consent without the `[y/N/always]` prompt. Populated automatically when you answer `always`.
- `notify_suppress_in_orchestrators` (default `true`) — silences the individual attacks chained by Extensive Crack, which fires a single summary instead. Set to `false` to get a notification per chained attack. Other menu entries that run several passes (for example Quick Crack with multiple rule chains) are not orchestrators and always notify per pass.
- `notify_max_cracks_per_burst` (default `5`), `notify_poll_interval_seconds` (default `5.0`) — per-crack tailer tuning. See `hate_crack/notify/tailer.py` for the burst aggregation logic.

### Wordlist Tools (menu option 80)

The Wordlist Tools submenu provides wordlist preprocessing utilities backed by hashcat-utils binaries, plus wordlist downloads from Hashmob.net and Weakpass. Access via option **80** in the main menu.

| Option | Binary | What it does |
|--------|--------|--------------|
| 1 | `len.bin` | Filter by length - keep only words between a min and max length |
| 2 | `req-include.bin` | Require character classes - keep only words containing all required character types |
| 3 | `req-exclude.bin` | Exclude character classes - remove words containing any excluded character type |
| 4 | `cutb.bin` | Extract substring - cut a byte range from each word |
| 5 | `splitlen.bin` | Split by length - create separate files per word length (files named `01`-`64` in an output directory) |
| 6 | `rli.bin` / `rli2.bin` | Subtract words - remove entries that appear in one or more other files |
| 7 | `gate.bin` | Shard - extract every N-th word for distributed cracking across multiple machines |
| 8 | - | Optimize wordlists - dedupe and split into per-length files under the optimized wordlists directory |
| 9 | - | Download wordlists from Hashmob.net |
| 10 | - | Download wordlists from Weakpass (via BitTorrent) |

**Character class mask bits** (used by options 2 and 3): `1`=lowercase, `2`=uppercase, `4`=digit, `8`=symbol, `16`=other. Add values together: `7` = lowercase+uppercase+digit.

**How sharding is meant to be used**: sharding splits one wordlist into N equal, non-overlapping parts so the work can be spread across multiple machines or GPUs. Each part is *interleaved* (every N-th line), so every shard is a representative sample of the whole list rather than a contiguous front/back chunk — no single node is stuck cracking only the low-probability tail.

Run option 7 once, give it an input wordlist, an output base path, and a shard count (N). It writes all N parts in a single pass, named with zero-padded part numbers (`base.001`, `base.002`, … up to `base.00N`). Copy one part to each node and point that node's hashcat run at it. On a single-GPU system sharding gives no speedup, but a single part is still a fast, representative sample for a quick triage pass before committing to the full list.

#### Automatic Update Checks

hate_crack can automatically check GitHub for newer releases on startup. This feature is controlled by the `check_for_updates` config option:

```json
{
  "check_for_updates": true
}
```

- **`check_for_updates`** — Enable automatic version checks on startup (default: `true`).
- When enabled, hate_crack fetches the latest release info from GitHub and displays a notice if an update is available.
- The check runs asynchronously and does not block startup. Network errors are silently ignored.

##### Update Channels

| Channel | Flag | Source | What you get |
|---------|------|--------|--------------|
| Release | `--update` | `main` | The latest cut release. This is the default and what the startup check offers. |
| Nightly | `--nightly` | `nightly-dev` | Work that has passed CI but has not been released yet. |

Versions follow ordinary semver, with the bump derived from what is actually in
the batch. The second component moves **only for features**: a cycle containing
any `feat` commit is heading for `X.(Y+1).0`, and a cycle of nothing but fixes,
docs and chores is heading for `X.Y.(Z+1)`.

`nightly-dev` tags release candidates for whichever version the batch is heading
toward — `v2.20.1rc1`, `v2.20.1rc2`, … — and merging down to `main` promotes that
same target to its final release. Candidates are real PEP 440 pre-releases, so
they order correctly at both ends:

    2.20.0  <  2.20.1rc1  <  2.20.1rc2  <  2.20.1  <  2.21.0rc1  <  2.21.0

The target can change mid-cycle: the first `feat` to land moves it from
`X.Y.(Z+1)` to `X.(Y+1).0`, and candidate numbering restarts for the new target.
The number always names what the batch would ship as today.

The major component is never bumped automatically — a `!` subject or a
`BREAKING CHANGE:` footer counts as a feature, because an automatic major is one
mistyped subject line away from an irreversible published release. A major is an
explicit human act: tag and push it by hand.

The policy lives in `tools/next_version.py`, shared by both tagging workflows and
unit-tested in `tests/test_next_version.py`.

The startup check only ever offers releases, because nightly builds publish no
GitHub release at all and the check reads GitHub's "latest release" endpoint — so
enabling `check_for_updates` will never pull you onto a nightly. Two things keep
the channels apart now: that, and the fact that a candidate is a genuine PEP 440
pre-release, so a tool ranking raw version numbers also treats it as older than
the release it becomes.

Either flag switches your checkout to the corresponding branch first (and
refuses to do so if you have uncommitted changes). If you are running a nightly
and want to go back to released code, `--update` moves you back to `main`.

#### Automatic Found Hash Merging (Download Left Only)

When downloading left hashes (uncracked hashes), hate_crack automatically:
1. Attempts to download any found (cracked) hashes from Hashview as an auxiliary operation
2. Merges found hashes with local `.out` files (e.g., `left_1_123.txt.out` or `left_1_123.nt.txt.out` for pwdump format)
3. Removes duplicate entries
4. Cleans up temporary split files after merging

This ensures your local cracking results stay synchronized with Hashview's centralized database when working with uncracked hashes.

**Note:** The download-found option downloads already-cracked hashes separately for reference purposes and does not perform any merging or prompt for cracking.

The <hash_type> is attained by running `hashcat --help`

Example Hashes: http://hashcat.net/wiki/doku.php?id=example_hashes


```
$ hashcat --help |grep -i ntlm
   5500 | NetNTLMv1                                        | Network protocols
   5500 | NetNTLMv1 + ESS                                  | Network protocols
   5600 | NetNTLMv2                                        | Network protocols
   1000 | NTLM                                             | Operating-Systems
```

```
$ ./hate_crack.py <hash file> 1000

  ___ ___         __             _________                       __
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    <
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
                          Version 2.0
```

-------------------------------------------------------------------
## Testing

The test suite is mostly offline and uses mocks/fixtures. Live network checks and
system dependency checks are opt-in via environment variables.

### Running Tests Locally

```bash
# Run all tests
uv run pytest -v

# Run specific test
uv run pytest tests/test_hashview.py -v
```

You can also run the full suite with `make test`.

### Live Tests (Opt-In)

Set any of the following to enable live checks:

- `HASHMOB_TEST_REAL=1` — live Hashmob connectivity/CLI menu check
- `HASHVIEW_TEST_REAL=1` — live Hashview CLI menu check
- `WEAKPASS_TEST_REAL=1` — live Weakpass CLI menu check
- `HATE_CRACK_REQUIRE_DEPS=1` — fail if `7z`, `transmission-daemon`, or `transmission-remote` is missing

### Live Hashview Upload Test

The live Hashview upload test is skipped by default. To run it, set the
environment variable and provide valid credentials in `.env`:

```bash
HATE_CRACK_RUN_LIVE_TESTS=1 uv run pytest tests/test_upload_cracked_hashes.py -v
```

### Live Hashview Tests Against a Local Docker Stack

Instead of pointing the live tests at a remote Hashview server, you can have
the suite spin up a local [Hashview](https://github.com/hashview/hashview)
Docker stack, seed it, run the live tests against it, and tear it down. Set
`HASHVIEW_TEST_LOCAL=1` and point `HASHVIEW_REPO` at a Hashview checkout:

```bash
HASHVIEW_TEST_LOCAL=1 HASHVIEW_REPO=~/projects/hashview \
  HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_hashview_cli_subcommands_subprocess.py -v
```

This brings up `docker compose` in the Hashview repo, seeds an admin API key,
a customer, a hashfile, and cracked "effective task" data, then exports the
`HASHVIEW_*` env vars the tests read. Useful env vars:

- `HASHVIEW_TEST_LOCAL=1` — enable the local stack (no-op otherwise)
- `HASHVIEW_REPO=<path>` — Hashview checkout (default `~/projects/hashview`)
- `HASHVIEW_KEEP=1` — leave containers running after the session (faster re-runs)
- `HASHVIEW_LOCAL_PORT=5000` — host port the app is published on

The hate_crack CLI honours the `HASHVIEW_URL` / `HASHVIEW_API_KEY` environment
variables (overriding the `.env` those two keys live in), which is what lets the
suite point the CLI at the local stack without editing your persisted config.

### End-to-End Install Tests (Local + Docker)

Local uv tool install + script execution (uses a temporary HOME):

```bash
HATE_CRACK_RUN_E2E=1 uv run pytest tests/test_e2e_local_install.py -v
```

Docker-based end-to-end install/run (cached via `Dockerfile.test`):

```bash
HATE_CRACK_RUN_DOCKER_TESTS=1 uv run pytest tests/test_docker_script_install.py -v
```

The Docker E2E test also downloads a small subset of rockyou and runs a basic
hashcat crack to validate external tool integration.

Lima VM end-to-end test (macOS only):

Prerequisites: [Lima](https://lima-vm.io/) and `rsync` must be installed.

```bash
brew install lima
```

The test VM provisions automatically with all Linux dependencies (hashcat, build-essential, curl, git, gzip, p7zip-full, transmission-daemon, ocl-icd-libopencl1, pocl-opencl-icd, uv).

```bash
HATE_CRACK_RUN_LIMA_TESTS=1 uv run pytest tests/test_lima_vm_install.py -v
```

This test validates installation and execution within a lightweight Linux VM on macOS.

### Test Structure

- **tests/test_hashview.py**: Comprehensive test suite for HashviewAPI class with mocked API responses, including:
  - Customer listing and data validation
  - Authentication and authorization tests
  - Hashfile upload functionality
  - Complete job creation workflow

All tests use mocked API calls, so they can run without connectivity to a Hashview server.

-------------------------------------------------------------------

  (1) Quick Crack
  (2) Extensive Pure_Hate Methodology Crack
  (3) Brute Force Attack
  (4) Top Mask Attack
  (5) Fingerprint Attack
  (6) Combinator Attacks
  (7) Hybrid Attack
  (8) Pathwell Top 100 Mask Brute Force Crack
  (9) PRINCE Attack
  (10) Bandrel Methodology
  (11) Loopback Attack
  (12) LLM Attack
  (13) OMEN Attack
  (14) Ad-hoc Mask Attack
  (15) Markov Brute Force Attack
  (16) N-gram Attack
  (17) Permutation Attack
  (18) Random Rules Attack
  (19) Combipow Passphrase Attack
  (20) PCFG Attack
  (21) PRINCE-LING Attack
  (22) Spoonman Attack
  (23) Rosetta Attack
  (24) Corporate Masks Brute Force
  (25) Smart Mask Attack

  (80) Wordlist Tools
  (81) Rule File Tools
  (82) Notifications

  (93) Regenerate .out from POT file
  (94) Hashview API
  (95) Analyze hashes with Pipal
  (96) Export Output to Excel Format
  (97) Display Cracked Hashes
  (98) Display README
  (99) Quit

Select a task:
```

Option `94 — Hashview API` is only listed when `HASHVIEW_API_KEY` is set in `.env`.

The YOLO, Middle, and Thorough Combinator attacks were previously at keys 10-12. They now live in the Combinator Attacks submenu (option 6) along with Combinator3 and CombinatorX.
-------------------------------------------------------------------
#### Quick Crack
Runs a dictionary attack against wordlists in your `hcatOptimizedWordlists` directory (falls back to `hcatWordlists` if not configured) and optionally applies rules. Multiple rules can be selected by comma-separated list, and chains can be created with the '+' symbol. Pressing Enter at the wordlist prompt uses the configured optimized wordlists directory as the default.

Selecting a directory — including that default — expands to the wordlists
directly inside it before hashcat runs. Subdirectories are not searched,
matching hashcat's own behaviour for a directory in the dictionary position, and
dot-files and `.7z`/`.torrent`/`.out` files are skipped, which hashcat would
otherwise try to read. The candidates are the same either way; the expansion is
what lets attack coverage track each wordlist separately, since a directory has
no content fingerprint to key on. If the expansion finds nothing — an empty
directory, or one holding only subdirectories or archives — the attack aborts
rather than launching hashcat with no wordlist, which would put it in stdin
mode and leave it reading the terminal.

```
Which rule(s) would you like to run?
(1) best64.rule
(2) d3ad0ne.rule
(3) T0XlC.rule
(4) dive.rule
(99) YOLO...run all of the rules
Enter Comma separated list of rules you would like to run. To run rules chained use the + symbol.
For example 1+1 will run best64.rule chained twice and 1,2 would run best64.rule and then d3ad0ne.rule sequentially.
Choose wisely:
```




#### Extensive Pure_Hate Methodology Crack
Runs several attack methods provided by Martin Bos (formerly known as pure_hate):
  * Brute Force Attack (7 characters)
  * Dictionary Attack
    * All wordlists in `hcatWordlists` with `best64.rule`
    * `rockyou.txt` with `d3ad0ne.rule`
    * `rockyou.txt` with `T0XlC.rule`
  * Top Mask Attack (Target Time = 4 Hours)
  * Fingerprint Attack
  * Smart Mask Attack
  * Combinator Attack
  * Hybrid Attack
  * Extra - Just For Good Measure
    - Runs a dictionary attack using `rockyou.txt` with chained `combinator.rule` and `InsidePro-PasswordsPro.rule` rules

#### Brute Force Attack
Brute forces all characters with the choice of a minimum and maximum password length.

#### Top Mask Attack
Uses StatsGen and MaskGen from PACK (https://thesprawl.org/projects/pack/) to perform a top mask attack using passwords already cracked for the current session.
Presents the user a choice of target cracking time to spend (default 4 hours).

#### Fingerprint Attack
https://hashcat.net/wiki/doku.php?id=fingerprint_attack

Runs a fingerprint attack using passwords already cracked for the current session. Expander substring length escalates automatically (7, 14, 21, ... up to the chosen ceiling), and an optional wordlist can be combined against the expanded fragments in addition to self-combination. Set `hcatFingerprintWordlist` in `config.json` to a default wordlist path so the prompt offers it instead of asking for a path every time; leave it as `""` to always ask (or skip).

#### Smart Mask Attack
Looks for literal "skeleton" patterns shared by 3+ already-cracked passwords for the current session -- e.g. a fixed stem like `CrawlingHorse` followed by a run of digits, or `ChangeMe2day` followed by digits and symbols drawn from a consistent charset. Every qualifying pattern runs against the full remaining hash list, so other accounts sharing a stem get swept up even though brute-forcing the stem itself was never tried.

Patterns with a fixed run at either end -- nearly all of them -- are grouped by mask and run as hybrid attacks (`-a 6` when the mask trails the stem, `-a 7` when it leads), with every pattern's literal stem a line in that group's wordlist. Dozens of patterns that vary the same way therefore become one hashcat pass over one wordlist rather than one mask line each. Whatever cannot be grouped that way -- variation at *both* ends, which leaves no fixed run to seed a wordlist with -- falls back to a single `-a 3` mask file, and has its charsets widened (up to `?a`) to compensate, as far as the guardrail below allows.

Prompts once, before the attack starts, for an optional per-pattern candidate-count guardrail (default 50,000,000,000; 0 disables it) that excludes any individual pattern whose keyspace is too large without blocking the rest.

#### Combinator Attack
https://hashcat.net/wiki/doku.php?id=combinator_attack

Runs a combinator attack using the "rockyou.txt" wordlist.

#### Hybrid Attack
https://hashcat.net/wiki/doku.php?id=hybrid_attack

* Runs sixteen hybrid passes per wordlist, cheapest first. Each mask length
  from 1 to 4 is tried appended and then prepended, first over `?s?d` and then
  over `?a`, and a single ctrl-C abandons the whole attack rather than only the
  current pass.
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1
  - Hybrid Mask + Wordlist - ?s?d ?1 wordlists/rockyou.txt
  - ... the same for ?1?1, ?1?1?1 and ?1?1?1?1
  - Hybrid Wordlist + Mask - wordlists/rockyou.txt ?a
  - Hybrid Mask + Wordlist - ?a wordlists/rockyou.txt
  - ... the same for ?a?a, ?a?a?a and ?a?a?a?a

  `?a` is every printable character, so the second group is a superset of the
  first plus letters and roughly 24x the work at the longest mask — over
  rockyou.txt those passes alone are ~1.2e15 candidates, about ten hours for
  NTLM on hardware doing 32 GH/s. That is why the cheap `?s?d` group runs first
  and why the attack as a whole is time-bounded:

  - `hcatHybridMaxRuntime` in `config.json`, in seconds, default `3600`, is the
    time the **whole attack** may spend — not the time one pass may spend. All
    sixteen passes share one deadline, and each is handed whatever is left of it
    as hashcat's `--runtime`. Any pass the budget does not reach is reported
    rather than skipped quietly. Set it to `0` for no limit, which runs every
    pass to exhaustion.

  Within each group the order is by mask length across every wordlist rather
  than all lengths of one wordlist and then the next, so a budget that runs out
  has still given every wordlist its cheap passes.

  Each pass declares what it covers to the attack-coverage store, so a repeat
  hybrid against the same hash file offers to skip the passes already run. A
  pass that runs out of budget is not recorded, so it will be retried.
  Wordlist entries may be glob patterns or directories; both are expanded
  before hashcat runs, a directory into the wordlists directly inside it.
  Subdirectories are not searched, matching hashcat's own behaviour, and
  dot-files and `.7z`/`.torrent`/`.out` files are skipped — a Weakpass
  download leaves archives in the wordlists directory and hashcat would
  otherwise try to read them.

#### Pathwell Top 100 Mask Brute Force Crack
Runs a brute force attack using the top 100 masks from KoreLogic:
https://blog.korelogic.com/blog/2014/04/04/pathwell_topologies

#### PRINCE Attack
https://hashcat.net/events/p14-trondheim/prince-attack.pdf

Runs a PRINCE attack using wordlists/rockyou.txt

#### YOLO Combinator Attack
Runs a continuous combinator attack using random wordlists from the configured wordlists directory for the left and right sides.

#### Middle Combinator Attack
https://jeffh.net/2018/04/26/combinator_methods/

Runs a modified combinator attack adding a middle character mask:
wordlists/rockyou.txt + masks + worklists/rockyou.txt

Where the masks are some of the most commonly used separator characters:
2 4 <space> - _ , + . &

#### Thorough Combinator Attack
https://jeffh.net/2018/04/26/combinator_methods/

* Runs many rounds of different combinator attacks with the rockyou list.
  - Standard Combinator attack: rockyou.txt + rockyou.txt
  - Middle Combinator attack: rockyou.txt + ?n + rockyou.txt
  - Middle Combinator attack: rockyou.txt + ?s + rockyou.txt
  - End Combinator attack: rockyou.txt + rockyou.txt + ?n
  - End Combinator attack: rockyou.txt + rockyou.txt + ?s
  - Hybrid middle/end attack: rockyou.txt + ?n + rockyou.txt + ?n
  - Hybrid middle/end attack: rockyou.txt + ?s + rockyou.txt + ?s


#### Bandrel Methodology

Prompts for comma-separated names and creates a pseudo hybrid attack by capitalizing the first letter and adding up to six additional characters at the end. Each word is limited to a total of five minutes.

  - Built-in common words (seasons, months) included as a customizable `config.json` entry (`bandrel_common_basedwords`)
  - The default five-minute time limit is customizable via `bandrelmaxruntime` in `config.json`

#### Loopback Attack
https://hashcat.net/wiki/doku.php?id=loopback_attack

Uses hashcat's loopback mode to feed cracked passwords from the current session back into the attack pipeline with rules applied. This generates new password candidates based on variations of already-cracked passwords, which is particularly effective for finding related passwords that follow similar patterns.

* Prompts for rule selection to apply to the loopback candidates
* Uses an empty wordlist with the --loopback flag to process previously cracked passwords
* Automatically downloads Hashmob rules if no rules are available locally

#### LLM Attack
Uses a local Ollama instance to generate password candidates for a capture-the-flag scenario. Prompts for the fake company name, industry, location, and parent company / acquisition history, then sends these details to the configured LLM model to produce likely password candidates using industry terms and company name permutations. The generated candidates are fed into a hashcat wordlist+rules attack.

* Requires a running Ollama instance (default: `http://localhost:11434`, override with `OLLAMA_HOST` in `.env` or the environment) with the model already pulled — hate_crack does not auto-pull
* Candidate generation uses structured (JSON) output via Atomic Agents, so pick a model with good schema adherence (default: `qwen3:4b-instruct`)
* Configurable model, context window, request timeout, and sample size via `.env` (see Ollama Configuration below)
* Prompts for target company name, industry, location, and parent company / acquisition history. The industry, location, and parent company prompts are pre-filled with the local model's guesses about the named organization (editable, and clearly labelled as guesses rather than verified OSINT); disable with `ollamaAutoResearch: false`
* Alternatively derives basewords from a sample **wordlist**, or from the **cracked passwords** of the current session (`<hashfile>.out`) so the model mirrors the target organization's own password conventions and produces new candidates in that style (only offered once something has been cracked)
* A live spinner with an elapsed-seconds counter runs during generation, and requests are bounded by `ollamaTimeout` so a model stuck loading into VRAM reports a timeout instead of hanging

**Pattern rules mode** (option 4 in the LLM submenu) takes the same shape as the [Spoonman Attack](#spoonman-attack) — a baseword list run through a rule file, both derived from one corpus — but infers each side with the model instead of extracting it. Spoonman is exact and therefore bounded: its basewords all appear in the corpus and its rules only reproduce transformations the corpus already shows. This asks the model to generalize on both axes, so it can name the *word families* behind a sample (the company and its products, site names, local sports teams, seasons, mascots) and write decorations the corpus does not contain.

* Pattern source is either the current session's cracked passwords (offered first, and only once something has been cracked, since those reveal the target's real conventions) or a sample wordlist
* **You are not asked to pick a rule file.** The model writes one, from the same corpus statistics — a stock rule file encodes the internet's habits, and the point of spending a model round trip is to encode *this* organization's
* Basewords are normalized to lowercase letters only, discarding anything under 3 characters, so the generated rules supply case, digits, and punctuation exactly once
* Generated rules are validated before hashcat sees them, and anything using an op hashcat does not have, a position argument outside `0-9A-Z`, more than 31 functions, or a stray comment or non-ASCII character is discarded. hashcat drops an invalid rule *silently* when valid rules share the file, so an unscreened line would become missing coverage rather than an error. The op table was established by testing hashcat itself, not from its rule documentation, which lists ops hashcat will not actually run
* Local-model yield varies a lot run to run, so a thin answer is asked again once and the two rounds are merged — a handful of rules would waste the pass they are spent on
* If no rule survives validation the basewords still run, unmutated, rather than throwing away the expensive half of the run
* Output lands in `<hashfile>.llm_patterns/` as `basewords.txt` and `rules.rule` — per-run scratch, laid out like `.spoonman/` and removed on exit

#### OMEN Attack
Uses the Ordered Markov ENumerator (OMEN) to train a statistical password model from a wordlist and generate password candidates. This attack learns patterns from known passwords and generates new candidates based on those patterns.

* Requires OMEN binaries (createNG and enumNG) to be built from the omen submodule
* Interactive menu: use existing model, train new model, or cancel
* Training wordlist picker shows available wordlists from configured directory or accepts a custom path
* Validates all 5 required model files (createConfig, CP/IP/EP/LN.level) before running
* Captures and reports enumNG errors instead of failing silently
* Generates up to a specified number of password candidates (configurable via `omenMaxCandidates`)
* Pipes generated candidates directly into hashcat for cracking
* Model files and metadata are stored in `~/.hate_crack/omen/` for persistence across sessions

#### Combinator Attacks Submenu
Opens an interactive submenu with six combinator attack variants (formerly at menu keys 10-12). Consolidates related attacks for cleaner menu organization:
- Combinator Attack - combines two wordlists
- YOLO Combinator Attack - combines all permutations of multiple wordlists
- Middle Combinator Attack - combines wordlists with an extra word in the middle
- Thorough Combinator Attack - comprehensive combination of wordlists with rules
- Combinator3 Attack - combines exactly 3 wordlists using `combinator3.bin`, generating all `word1+word2+word3` combinations piped to hashcat
- CombinatorX Attack - combines 2-8 wordlists using `combinatorX.bin` with optional `--sepFill` separator character between word segments

#### Ad-hoc Mask Attack
Runs hashcat mask attack (mode 3) with a user-specified custom mask string. Allows fine-grained control over character-set brute forcing.

* Opens with a choice between typing a mask and selecting a mask file
* Prompts for a hashcat mask (e.g., `?u?l?l?l?d?d` for uppercase + lowercase + lowercase + lowercase + digit + digit)
* Supports custom character sets for specialized character combinations: `-1` through `-4` on any hashcat, plus `-5` through `-8` on hashcat 7 and newer. A mask using `?5`–`?8` against an older hashcat is flagged before the run rather than failing inside it; if the version cannot be read, the mask is passed through and hashcat decides
* Only prompts for the custom slots the mask actually references — `?1?3?d` asks about `-1` and `-3` and nothing else, and a mask with no custom tokens is never asked at all. Detection is token-aware, so the escaped `??1` is a literal `?1` and prompts for nothing. A slot left blank is still skipped, with a warning that hashcat will reject a mask whose charset is undefined
* Mask files (`.hcmask`) can be selected with tab completion, defaulting to the bundled `masks/` directory; hashcat runs every mask in the file in order. Because a mask file defines its own charsets inline, the `-1` through `-4` prompts are skipped when one is chosen
* Optionally runs the mask incrementally (`--increment`), trying shorter lengths before the full mask. Answering yes prompts for an increment minimum and maximum; either can be left blank, and leaving both blank increments over the mask's full keyspace with hashcat choosing the bounds. Offered for typed masks and mask files alike
* Useful for targeted brute forcing when you know password structure patterns

#### Markov Brute Force Attack
Generates password candidates using Markov chain statistical models. Similar to OMEN but simpler and faster.

* Checks for existing `.hcstat2` Markov table from previous sessions (with option to reuse, regenerate, or cancel)
* Generates table from training source if needed:
  - Can use cracked passwords from current session (`.out` file) as training data
  - Or select any wordlist from configured directory or custom path
* Interactive menu: choose minimum and maximum password length
* Uses `--increment` flag to test lengths in sequence
* Markov table persists with hash file (filename.out.hcstat2) for fast subsequent runs
* Faster than OMEN for general-purpose brute forcing

#### N-gram Attack
Generates n-gram candidates from a corpus file using `ngramX.bin` from hashcat-utils and pipes them into hashcat.

* Prompts for a corpus file with tab completion, defaulting to the configured wordlist directory
* Prompts for an n-gram group size (default 3)
* Gzip-compressed corpus files are auto-detected and decompressed on the fly
* Useful when you have target-relevant prose (scraped site copy, leaked documents, internal wiki exports) rather than a password list

#### Permutation Attack
Generates all character permutations of each word in a targeted wordlist and pipes them to hashcat via `permute.bin` from hashcat-utils.

* Prompts for a single wordlist file (not a directory)
* Effective against short targeted wordlists where the character set is known but the order is not (company abbreviations, name fragments, known tokens)
* WARNING: Scales as N! per word - an 8-character word produces 40,320 permutations. Only practical for words up to ~8 characters.
* Uses `permute.bin < wordlist | hashcat` pipeline pattern

#### Random Rules Attack
Generates a set of random hashcat mutation rules using `generate-rules.bin`, writes them to a temporary file, then runs hashcat against a chosen wordlist with those rules.

* Prompts for rule count (default 65536)
* Prompts for wordlist path with tab-completion and numbered selection
* Temporary rules file is cleaned up after the run regardless of outcome
* Useful when known rule sets are exhausted - explores random rule-space for additional cracks

#### Combipow Passphrase Attack
Generates all unique non-empty subset combinations from a short wordlist using `combipow.bin` and pipes them into hashcat. Designed for passphrase cracking when you know the pool of words a password was built from.

* Prompts for a wordlist file (max 63 lines - combipow generates up to 2^n-1 combinations)
* Optional space separator (`-s` flag) to insert spaces between words in each combination
* Warns if the wordlist exceeds 20 lines (output volume may be large)
* Aborts with a clear message if the wordlist exceeds 63 lines (hard limit)
* Candidates are piped directly to hashcat stdin

#### PCFG Attack
Uses [pcfg_cracker](https://github.com/lakiw/pcfg_cracker) to generate candidates from a Probabilistic Context-Free Grammar, piping `pcfg_guesser.py` output directly into hashcat's stdin mode. A PCFG models password *structure* (baseword + digits + symbol, capitalization habits, keyboard walks) with learned probabilities, so candidates come out roughly in descending likelihood order.

* Requires the `pcfg_cracker` submodule. Presence is checked at startup and reported non-fatally: if it is missing, the PCFG attacks are simply unavailable. Run `make` to fetch it.
* Uses the trained grammar named by `pcfgRuleset` in `config.json` (default `DEFAULT`), read from `pcfg_cracker/Rules/<name>/`
* Candidate count is capped by `pcfgMaxCandidates` (default 50,000,000)
* hate_crack does not wrap grammar training. To build a grammar from a target-specific password set, run pcfg_cracker's own `trainer.py` and point `pcfgRuleset` at the resulting ruleset name

#### PRINCE-LING Attack
Uses pcfg_cracker's `prince_ling.py` to derive an optimized PRINCE base wordlist from a trained grammar, then hands it to the existing PRINCE attack. PRINCE-LING picks base words the grammar says are actually productive, so the PRINCE combination space is far less wasteful than pointing PRINCE at a generic wordlist.

* Requires the `pcfg_cracker` submodule and a trained ruleset directory, same as the PCFG attack
* The generated wordlist is cached at `<hcatOptimizedWordlists>/pcfg_prince_ling_<ruleset>.txt` and reused across sessions
* Regenerates only when the ruleset directory is newer than the cached wordlist, so retraining a grammar invalidates the cache automatically
* Generation is written to a temporary file and atomically moved into place; a failed or interrupted run cleans up its partial file and leaves any existing cache intact
* Base wordlist size is capped by `pcfgPrinceLingMaxCandidates` (default 10,000,000)

#### Spoonman Attack
Derives a baseword list and a hashcat rule file from a corpus of known plaintext passwords — a previous engagement's cracked output, a leak dump, or any password list — such that the baseword x rule cross product reconstructs the corpus exactly (see the memory bound below for the one case where it does not). Contributed as issue #169 by @Spoonman1091.

Each password is split into its letters-only lowercased core (the baseword) plus a rule that rebuilds the original from it, using `l`/`u`/`c` for casing, `T{p}` toggles, `${x}`/`^{x}` for trailing and leading characters, and `i{p}{x}` for interior ones.

* When the current session already has cracked plaintexts (`<hash file>.out` exists and is non-empty), a picker offers those as the corpus ahead of a free-form path — the target's own recovered passwords derive rules describing that target's actual conventions, which is exactly what you want to fire back at the remaining uncracked hashes. Deriving from `.out` and then cracking the same hash file appends new plaintexts to that same file, growing the corpus for the next run; that is the intended feedback loop, not corruption. Sessions with no cracked output yet see no picker at all — just today's path prompt
* Prompts for the corpus, then for how much of the rule file to run: top 50% coverage (listed first and recommended), top 75%, top 95%, top 99%, or the full set
* Rules are sorted by how many passwords each one rebuilds, so a truncated file keeps the most productive rules. Coverage is extremely long-tailed: on a 98.2M-password sample, 50% coverage needed 4,120 rules while 95% needed 16,119,661 and 100% needed 21,029,696 — the last few percent typically costs orders of magnitude more rules than the first half, which is why the smallest tier is listed first and is usually the right choice
* Output is written beside the hash file in `<hash file>.spoonman/`, alongside the other ephemeral wordlists: `basewords.txt`, `rules.full.rule`, the capped rule files, and `coverage.txt` with per-milestone rule counts. Derivation is skipped on later runs of the same hash file unless the corpus has been modified since, and the directory is removed on exit by the temp-file cleanup
* Derivation is bounded in memory. Both counters would otherwise grow for the whole read with nothing written until the end, so a corpus large enough to exhaust RAM lost the entire pass to an OOM kill and produced no output; a measured run against a 31 GB corpus reached 14.1 GB resident at 11% of the file and was still accelerating. Each counter is now capped at 20 million distinct keys (about 1.6 GB apiece), and the lowest-frequency keys are discarded once it is exceeded. If that happens, the run says so on the console and in `coverage.txt`, the output reconstructs the retained keys rather than 100% of the corpus, and the coverage percentages are relative to those. Corpora below the cap are unaffected
* Passwords that cannot be expressed as a rule are written verbatim as their own baseword with a `:` no-op, so coverage stays complete. This covers two hashcat limits: rule positions cannot address past index 35, and hashcat rejects any rule with more than 31 functions — silently, when valid rules share the file
* A password carrying a literal CR or LF (which arrives hex-wrapped, as `$HEX[...0a]`) cannot go in a baseword at all, because a wordlist line has no escape syntax for one. The break is lifted out into an insert op instead, spelled `\x0a`/`\x0d` in the rule, which hashcat decodes to the byte. When the break sits past addressable index 35 the rule reverses the word first, inserts from the other end, and reverses back. One frame has to hold every break in the password, so what is still skipped is a password with one break outside the first 36 characters *and* another outside the last 36, or one needing more inserts than the 31-function cap leaves room for. Those are counted as `unwritable basewords` in `coverage.txt` and reported, never dropped silently
* The derivation self-checks every password by reconstructing it in-process, and reports any failures rather than reporting success
* Corpus lines may carry a hash in front of the password, as cracked output does. A leading field is dropped only when it has the shape of a hash (a hex digest at a known length, or a crypt-style `$id$` string), so `hash:salt:plain` is handled while a plaintext or wordlist entry containing a colon survives intact. `$HEX[...]` plaintexts are decoded. If most lines look like an uncracked dump rather than cracked output, `coverage.txt` records the count and the attack warns — the derived basewords and rules would otherwise be meaningless without any error being raised

#### Rosetta Attack
Mines hashcat `--debug-mode 5` logs for the basewords and rules that already cracked something, then runs their full cross product. Powered by [HashcatRosetta](https://github.com/bandrel/HashcatRosetta), the same library behind [Analyze Hashcat Rules](#analyze-hashcat-rules-rule-file-tools-option-5).

No setup is needed to feed it: `_add_debug_mode_for_rules` appends `--debug-mode 5 --debug-file` to every rule-based hashcat invocation hate_crack makes, so the logs accumulate in `hcatDebugLogPath` (`~/.hate_crack/hashcat_debug` by default, one file per session) as a side effect of normal use. A mode 5 log records only candidates that cracked a hash, in the form `baseword:rule:candidate:wordlist`, which is what makes both halves known-productive against this target population; the trailing wordlist field also shows which list is earning its keep on a multi-wordlist run. HashcatRosetta parses mode 4 and mode 5 alike, so logs written before the switch are still read.

The value is in the cross product rather than the recorded pairs. A pair present in a log has already cracked its hash and will not crack another, but a rule that worked on one baseword has usually never been tried against the others — so N basewords and M rules yield close to N x M untried candidates.

The menu first asks how to rank rules — choices 1-3 below, plus a fourth, unrelated mode:

* Rules can be ranked by application frequency, by how many distinct basewords each one worked on, or by how many unique candidates each one generated. Frequency is the default; baseword spread is the better choice when the goal is a rule set that generalizes past the specific words it was learned from
* Only after one of those three is picked does hate_crack list the logs found in `hcatDebugLogPath` newest-first with their sizes; pick one, pick all of them (up to 20), or type a path to a log from elsewhere
* Prompts for how many top rules to keep and how many top basewords. Both default to all — a blank answer keeps every winning rule the logs contain, and zero means the same thing. Enter a number to cap either. The keyspace is the product of the two and is printed before hashcat starts
* Output is written beside the hash file in `<hash file>.rosetta/` as `basewords.txt` and `rules.rule`, alongside the other ephemeral wordlists, and the directory is removed on exit by the temp-file cleanup
* Reading stops at 1,000,000 debug lines, since the analyzer needs the whole batch in memory at once. Truncation is reported on the console rather than assumed harmless — logs from a long run routinely exceed this, in which case the newest log is the one worth selecting
* **LLM Mask Attack** (4) - a different mode entirely, and the only one that needs no debug logs. Prompts for a natural-language description of the passwords you expect (length, character patterns, symbols, etc.), sends it to the locally configured Ollama model, writes the returned masks to `<hash file>.hcmask`, and runs a `-a 3` hashcat mask attack against them

#### Corporate Masks Brute Force
Statistical masks (8-14 characters) derived from analysis of 3.2M NTLM hashes cracked on real engagements. Powered by [Corporate_Masks](https://github.com/golem445/Corporate_Masks), these masks encode realistic password patterns from successful penetration tests.

* Prompts for minimum and maximum mask length (default 8-10)
* Longer lengths cost exponentially more keyspace—start with 8-10 for speed, or 8-12 for thoroughness
* Each mask file is run as a separate hashcat invocation in ascending length order
* Gracefully handles missing mask files (skips them) and absent submodule (prints warning and returns)
* Supports optimized kernels (`-O` flag) for faster cracking
* Ctrl-C during one length aborts remaining lengths

#### Wordlist Tools (option 80)
A submenu of wordlist preprocessing utilities using hashcat-utils binaries. All tools read from and write to files on disk. All file and directory path prompts support tab completion.

| Key | Tool | Description |
|-----|------|-------------|
| 1 | Filter by Length | Keep only words between a min and max length (`len.bin`) |
| 2 | Require Char Classes | Keep words that include all char classes in mask (`req-include.bin`). Mask: 1=lower, 2=upper, 4=digit, 8=symbol (additive) |
| 3 | Exclude Char Classes | Remove words containing any char class in mask (`req-exclude.bin`). Same mask encoding |
| 4 | Extract Substring | Cut bytes from each word at a given offset and optional length (`cutb.bin`) |
| 5 | Split by Length | Create per-length files in an output directory (`splitlen.bin`) |
| 6 | Subtract Wordlist | Remove lines from a wordlist that appear in one or more remove files. Mode 1 uses `rli2.bin` (single file); mode 2 uses `rli.bin` (multiple files) |
| 7 | Shard Wordlist | Split a wordlist into N equal, interleaved parts in one run, written as `base.001`…`base.00N` for distributed cracking (`gate.bin`) |
| 8 | Optimize Wordlists | Dedupe and split the selected wordlists into per-length files under an output directory |
| 9 | Download from Hashmob.net | Browse and download wordlists from Hashmob.net into the configured wordlist directory |
| 10 | Download from Weakpass | Browse and download Weakpass wordlist torrents, with automatic extraction |

All binaries are in `hate_crack/hashcat-utils/bin/`.

#### Rule File Tools (option 81)
Preprocesses hashcat rule files using `cleanup-rules.bin` and `rules_optimize.bin` from hashcat-utils, and downloads rule files from Hashmob.net.

* **Clean** (1) - removes invalid syntax and duplicate rules using `cleanup-rules.bin`. Useful after combining rule files or downloading rules from external sources.
* **Optimize** (2) - consolidates redundant operations using `rules_optimize.bin`. Reduces rule file size and improves cracking speed.
* **Clean and optimize** (3) - runs both operations in sequence via a temporary file, then writes the final result.
* **Download rules from Hashmob.net** (4) - fetches rule files into the configured `rulesDirectory`.
* **Analyze Hashcat rules** (5) - opcode frequency analysis of a rule file, powered by HashcatRosetta.

The three preprocessing operations read from an input file and write to a separate output file (original is never modified).

#### Download Rules from Hashmob.net (Rule File Tools option 4)
Downloads the latest rule files from Hashmob.net's rule repository. These rules are curated and optimized for password cracking and can be used with the Quick Crack and Loopback Attack modes.

* Downloads rule sets in parallel using a thread pool (up to 4 concurrent downloads)
* Skips rules already downloaded locally
* Reports download summary with success/failure counts
* Stores rules in the configured rules directory

#### Analyze Hashcat Rules (Rule File Tools option 5)
Powered by HashcatRosetta (https://github.com/bandrel/HashcatRosetta), this feature analyzes hashcat rule files to provide detailed insights into rule composition and complexity.

* Prompts for a rule file path
* Displays frequency analysis of rule opcodes (operations)
* Helps understand what transformations a rule set performs
* Useful for rule debugging and optimization

#### Download Wordlists from Hashmob.net (Wordlist Tools option 9)
Downloads wordlists from Hashmob.net's collection of cracked passwords and commonly used wordlists.

* Interactive menu for browsing available wordlists
* Progress tracking for large downloads
* Stores wordlists in configured wordlist directory

#### Weakpass Wordlist Menu (Wordlist Tools option 10)
Interactive menu for downloading and managing wordlists from Weakpass.com via BitTorrent.

* Browse available Weakpass wordlist torrents
* Download specific wordlists or entire collections
* Automatic extraction of compressed archives
* Progress tracking for torrent downloads

-------------------------------------------------------------------
### Version History

The full, per-release changelog now lives in [CHANGELOG.md](CHANGELOG.md).
