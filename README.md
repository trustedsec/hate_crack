```
  ___ ___         __             _________                       __    
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    < 
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
```

## Installation

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

Clone with submodules (required for hashcat-utils, princeprocessor, and optionally omen):

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
```

If you cloned without submodules, initialize them:

```bash
git submodule update --init --recursive
```

Then customize configuration in `config.json` if needed (wordlist paths, API keys, etc.). Most users can skip this step as default paths work out-of-the-box.

### 3. Install dependencies and hate_crack

The easiest way is to run `make` (or `make install`), which auto-detects your OS and installs:
- External dependencies (p7zip, transmission-cli)
- Builds submodules (hashcat-utils, princeprocessor, and optionally omen)
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
- `transmission-cli` — used to download Weakpass torrents.

Manual install commands:

Ubuntu/Kali:
```bash
sudo apt-get update
sudo apt-get install -y p7zip-full transmission-cli
```

macOS (Homebrew):
```bash
brew install p7zip transmission-cli
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
- Current working directory and parent directory
- The repo root and package directory
- `~/hate_crack`, `~/hate-crack`, or `~/.hate_crack`

**Note:** The `hcatPath` in `config.json` is for the hashcat binary location only (optional if hashcat is in PATH). Hate_crack assets (hashcat-utils, princeprocessor, omen) are loaded from the repository directory and bundled automatically by `make install`.

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

-------------------------------------------------------------------
## Troubleshooting

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
- Missing config keys are automatically backfilled from `config.json.example` on startup
- Config is searched in multiple locations: repo root, current working directory, `~/.hate_crack`, `/opt/hate_crack`

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
uv run ruff check hate_crack
```

Auto-fix issues:
```bash
uv run ruff format hate_crack
uv run ruff check --fix hate_crack
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
prek install --hook-type pre-push --hook-type post-commit
```

This installs hooks defined in `prek.toml` using the pre-commit local-repo TOML schema:
- **pre-push**: ruff, ty, pytest, pytest-lima
- **post-commit**: audit-docs

Note: prek 0.3.3 expects `repos = [...]` at the top level. The old `[hooks.<stage>] commands = [...]` format is not supported.

### Arrow-Key Menu Navigation (Optional)

Install the `[tui]` extra to enable arrow-key menu navigation via `simple-term-menu`:

```bash
uv pip install '.[tui]'
```

When installed and running in a terminal (TTY), menus render with arrow-key navigation and number-key shortcuts. Without it, the classic numbered `print()` + `input()` menu is used.

To force the plain numbered menu even when `simple-term-menu` is installed, set `HATE_CRACK_PLAIN_MENU=1`.

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
- `--maxruntime <SECONDS>`: Override max runtime.
- `--bandrel-basewords <PATH>`: Override bandrel basewords file.
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

Set Hashview credentials in `config.json`:
```json
{
  "hashview_url": "https://hashview.example.com",
  "hashview_api_key": "your-api-key-here"
}
```

#### Ollama Configuration

The LLM Attack (option 15) uses Ollama to generate password candidates. Configure the model and context window in `config.json`:

```json
{
  "ollamaModel": "mistral",
  "ollamaNumCtx": 2048
}
```

- **`ollamaModel`** — The Ollama model to use for candidate generation (default: `mistral`).
- **`ollamaNumCtx`** — Context window size for the model (default: `2048`).
- The Ollama URL defaults to `http://localhost:11434`. Ensure Ollama is running before using the LLM Attack.

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
- `HATE_CRACK_REQUIRE_DEPS=1` — fail if `7z` or `transmission-cli` is missing

### Live Hashview Upload Test

The live Hashview upload test is skipped by default. To run it, set the
environment variable and provide valid credentials in `config.json`:

```bash
HATE_CRACK_RUN_LIVE_TESTS=1 uv run pytest tests/test_upload_cracked_hashes.py -v
```

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

The test VM provisions automatically with all Linux dependencies (hashcat, build-essential, curl, git, gzip, p7zip-full, transmission-cli, ocl-icd-libopencl1, pocl-opencl-icd, uv).

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
  (13) Bandrel Methodology
  (14) Loopback Attack
  (15) LLM Attack
  (16) OMEN Attack
  (17) Ad-hoc Mask Attack
  (18) Markov Brute Force Attack
  (19) N-gram Attack
  (20) Permutation Attack
  (21) Random Rules Attack

  (90) Download rules from Hashmob.net
  (91) Analyze Hashcat Rules
  (92) Download wordlists from Hashmob.net
  (93) Weakpass Wordlist Menu
  (94) Hashview API
  (95) Analyze hashes with Pipal
  (96) Export Output to Excel Format
  (97) Display Cracked Hashes
  (98) Display README
  (99) Quit

Select a task:
```
-------------------------------------------------------------------
#### Quick Crack
Runs a dictionary attack using all wordlists configured in your `hcatWordlists` path and optionally applies rules. Multiple rules can be selected by comma-separated list, and chains can be created with the '+' symbol.

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

Runs a fingerprint attack using passwords already cracked for the current session.

#### Combinator Attack
https://hashcat.net/wiki/doku.php?id=combinator_attack

Runs a combinator attack using the "rockyou.txt" wordlist.

#### Hybrid Attack
https://hashcat.net/wiki/doku.php?id=hybrid_attack

* Runs several hybrid attacks using the "rockyou.txt" wordlists.
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1?1
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1?1?1
  - Hybrid Wordlist + Mask - ?s?d wordlists/rockyou.txt ?1?1?1?1
  - Hybrid Mask + Wordlist - ?s?d ?1?1 wordlists/rockyou.txt
  - Hybrid Mask + Wordlist - ?s?d ?1?1?1 wordlists/rockyou.txt
  - Hybrid Mask + Wordlist - ?s?d ?1?1?1?1 wordlists/rockyou.txt

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
Uses a local Ollama instance to generate password candidates for a capture-the-flag scenario. Prompts for the fake company name, industry, and location, then sends these details to the configured LLM model to produce likely password candidates using industry terms and company name permutations. The generated candidates are fed into a hashcat wordlist+rules attack.

* Requires a running Ollama instance (default: `http://localhost:11434`)
* Configurable model and context window via `config.json` (see Ollama Configuration below)
* Prompts for target company name, industry, and location

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

* Prompts for a hashcat mask (e.g., `?u?l?l?l?d?d` for uppercase + lowercase + lowercase + lowercase + digit + digit)
* Supports custom character sets (`-1`, `-2`, `-3`, `-4`) for specialized character combinations
* Interactive charset entry with early exit on blank input
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

#### Download Rules from Hashmob.net
Downloads the latest rule files from Hashmob.net's rule repository. These rules are curated and optimized for password cracking and can be used with the Quick Crack and Loopback Attack modes.

* Downloads rule sets in parallel using a thread pool (up to 4 concurrent downloads)
* Skips rules already downloaded locally
* Reports download summary with success/failure counts
* Stores rules in the configured rules directory

#### Analyze Hashcat Rules
Powered by HashcatRosetta (https://github.com/bandrel/HashcatRosetta), this feature analyzes hashcat rule files to provide detailed insights into rule composition and complexity.

* Prompts for a rule file path
* Displays frequency analysis of rule opcodes (operations)
* Helps understand what transformations a rule set performs
* Useful for rule debugging and optimization

#### Download Wordlists from Hashmob.net
Downloads wordlists from Hashmob.net's collection of cracked passwords and commonly used wordlists.

* Interactive menu for browsing available wordlists
* Progress tracking for large downloads
* Stores wordlists in configured wordlist directory

#### Weakpass Wordlist Menu
Interactive menu for downloading and managing wordlists from Weakpass.com via BitTorrent.

* Browse available Weakpass wordlist torrents
* Download specific wordlists or entire collections
* Automatic extraction of compressed archives
* Progress tracking for torrent downloads
  
-------------------------------------------------------------------
### Version History

Version 2.0+
  - Added Random Rules Attack (option 20) using `generate-rules.bin` to generate random mutation rules (#87)
  - Added Ad-hoc Mask Attack (option 17) for user-typed hashcat masks with optional custom character sets
  - Added Markov Brute Force Attack (option 18) using `hcstat2` statistical tables for password generation
  - Consolidated Combinator Attacks (formerly options 10/11/12) into interactive submenu under option 6
  - Markov attack supports training from cracked passwords or any wordlist, with table reuse/regeneration menu
  - Fixed OMEN attack failing silently when model files were incomplete or enumNG errors occurred
  - OMEN attack now validates all 5 required model files, captures enumNG stderr, and provides a train/use/cancel menu with wordlist picker
  - Filtered `.7z`, `.torrent`, and `.out` files from wordlist selection menus (#80)
  - Parallelized Hashmob rule downloads using a thread pool with success/failure summary (#81)
  - Added dynamic optimized kernel (`-O`) flag per attack type via `optimizedKernelAttacks` config (#82)
  - Replaced `uv tool install` with a bash shim for reliable config and asset resolution from any working directory
  - Fixed config resolution to search the repo root and package directory in addition to CWD
  - Fixed bare NTLM hash detection failing when hash files contain leading blank lines, BOM characters, or null bytes from UTF-16 encoding
  - Improved error message for unrecognized hash formats to show the actual first-line content and list expected formats
  - Fixed rule file path construction in Quick Crack and Loopback Attack using `os.path.join()` instead of string concatenation
  - Added automatic update checks on startup (check_for_updates config option)
  - Added `packaging` dependency for version comparison
  - Added OMEN Attack (option 16) using statistical model-based password generation
  - Added OMEN configuration keys (omenTrainingList, omenMaxCandidates)
  - Added LLM Attack (option 15) using Ollama for AI-generated password candidates
  - Added Ollama configuration keys (ollamaModel, ollamaNumCtx)
  - Auto-versioning via setuptools-scm from git tags

Version 2.0
  Modularized codebase into CLI/API/attacks modules
  Unified CLI options with config overrides (hashview, hashcat, wordlists, pipal)
  Added Hashview API integration
  Added Weakpass torrent download helpers and Hashmob download wrapper
  Improved test coverage and snapshot-based menu validation
  Updated documentation and versioning

Version 1.9
  Revamped the hate_crack output to increase processing speed exponentially combine_ntlm_output function for combining
  Introducing New Attack mode "Bandrel Methodology"
  Updated pipal function to output top x number of basewords
     
Version 1.08
  Added a Pipal menu Option to analyze hashes. https://github.com/digininja/pipal

Version 1.07
  Minor bug fixes with pwdump formating and unhexify function

Version 1.06
  Updated the quick crack and recylcing functions to use user customizable rules.

Version 1.05
  Abstraction of rockyou.txt so that you can use whatever dictionary that you would like to specified in the config.json
  Minor change the quickcrack that allows you to specify 0 for number of times best64 is chained

Version 1.04
  Two new attacks Middle Combinator and Thorough Combinator

Version 1.03
  Introduction of new feature to use session files for multiple concurrent sessions of hate_crack
  Minor bug fix

Version 1.02
  Introduction of new feature to export the output of pwdump formated NTDS outputs to excel with clear-text passwords

Version 1.01
  Minor bug fixes

Version 1.00
  Initial public release
