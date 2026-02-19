```
  ___ ___         __             _________                       __    
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    < 
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
```

## Status

**Code Quality & Testing:**

[![ruff](https://github.com/trustedsec/hate_crack/actions/workflows/ruff.yml/badge.svg)](https://github.com/trustedsec/hate_crack/actions/workflows/ruff.yml)
[![ty](https://github.com/trustedsec/hate_crack/actions/workflows/ty.yml/badge.svg)](https://github.com/trustedsec/hate_crack/actions/workflows/ty.yml)
[![pytest](https://github.com/trustedsec/hate_crack/actions/workflows/pytest.yml/badge.svg)](https://github.com/trustedsec/hate_crack/actions/workflows/pytest.yml)

The pytest workflow tests across Python 3.9-3.14 via a matrix build.

## Installation

### 1. Install hashcat
Get the latest hashcat binaries (https://hashcat.net/hashcat/)

```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat/
make
make install
```

### 2. Download hate_crack
```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
```

* Customize binary and wordlist paths in "config.json"
* The hashcat-utils repo is a submodule. If you didn't clone with --recurse-submodules then initialize with:

```bash
git submodule update --init --recursive
```

### 3. Install dependencies and hate_crack

The easiest way is to use `make install` which auto-detects your OS and installs:
- External dependencies (p7zip, transmission-cli)
- Python tool via uv

```bash
make install
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

Then install the Python tool:
```bash
uv tool install .
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
You can run hate_crack as a tool, as a script, or via `uv run`:

```bash
uv run hate_crack.py
# or 
uv run hate_crack.py <hash_file> <hash_type> [options]
```

### Run as a tool (recommended)
Install once from the repo root:

```bash
uv tool install .
hate_crack
```

**Important:** The tool needs access to `hashcat-utils` and `princeprocessor` subdirectories from the hate_crack repository.

The tool will automatically search for these assets in:
- The directory that contains the hate_crack checkout (and includes `config.json`, `hashcat-utils/`, and `princeprocessor/`)
- Current working directory and parent directory
- `~/hate_crack`, `~/hate-crack`, or `~/.hate_crack`

**Option 1 - Run from repository directory:**
```bash
cd /path/to/hate_crack
hate_crack <hash_file> <hash_type>
```

Run `make install` to install the tool with all assets bundled into the package.

**Note:** The `hcatPath` in `config.json` is for the hashcat binary location (optional if hashcat is in PATH), not for hate_crack assets.

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
Reinstall using the Makefile, which vendors the assets into the package:
```bash
cd /path/to/hate_crack  # the repository checkout
make install
```

**Example config.json:**
```json
{
  "hcatPath": "/usr/local/bin",     # Location of hashcat binary (or omit if in PATH)
  "hcatBin": "hashcat",             # Hashcat binary name
  ...
}
```

-------------------------------------------------------------------
### Makefile helpers
Install OS dependencies + tool (auto-detects macOS vs Debian/Ubuntu):

```bash
make install
```

Rebuild submodules and reinstall the tool (quick update after pulling changes):

```bash
make update
```

Reinstall the Python tool in-place (keeps OS deps as-is):

```bash
make reinstall
```

Uninstall OS dependencies + tool:

```bash
make uninstall
```

Build hashcat-utils only:

```bash
make hashcat-utils
```

Clean build/test artifacts:

```bash
make clean
```

Run the test suite:

```bash
make test
```

-------------------------------------------------------------------
## Development

### Setting Up the Development Environment

Install the project with optional dev dependencies (includes linters and testing tools):

```bash
make dev-install
```

### Continuous Integration

The project uses GitHub Actions to automatically run quality checks on every push and pull request.

**Checks that run on each commit:**

1. **Linting (Ruff)** - Code style and quality validation
   - ✅ **PASS**: Code follows style rules and best practices
   - ❌ **FAIL**: Code has style violations or quality issues
   - Run locally: `make ruff`

2. **Type Checking (ty)** - Static type analysis
   - ✅ **PASS**: No type errors detected
   - ❌ **FAIL**: Type mismatches or missing annotations found
   - Run locally: `make ty`

3. **Testing (Multi-Version)** - Tests across Python 3.9 through 3.14
   - ✅ **PASS**: All tests pass on all supported Python versions
   - ⚠️  **PARTIAL**: Tests pass on some versions but fail on others
   - ❌ **FAIL**: Tests fail on one or more Python versions
   - Run locally: `make test`

**View CI/CD Status:**
- Click the badge above to see the full test results
- Each workflow shows which Python version(s) failed or passed
- Details are available in the Actions tab

### Running Linters and Type Checks

Before pushing changes, run these checks locally to catch issues early:

**Ruff (linting and formatting):**
```bash
.venv/bin/ruff check hate_crack
```

Auto-fix issues:
```bash
.venv/bin/ruff check --fix hate_crack
```

**ty (type checking):**
```bash
.venv/bin/ty check hate_crack
```

**Run all checks together:**
```bash
.venv/bin/ruff check hate_crack && .venv/bin/ty check hate_crack && echo "✓ All checks passed"
```

### Running Tests

```bash
.venv/bin/pytest
```

With coverage:
```bash
.venv/bin/pytest --cov=hate_crack
```

### Git Hooks (prek)

Git hooks are managed by [prek](https://github.com/nicholasgasior/prek). Install hooks with:

```bash
prek install
```

This installs hooks defined in `prek.toml`:
- **pre-push**: ruff check, ty check, pytest
- **post-commit**: documentation audit

### Optional Dependencies

The optional `[ml]` group includes ML/AI features required for the PassGPT attack:
- **torch** - PyTorch deep learning framework (for PassGPT attack and training)
- **transformers** - HuggingFace transformers library (for GPT-2 models)
- **datasets** - HuggingFace datasets library (for fine-tuning support)
- **accelerate** - HuggingFace training acceleration library

Install with:
```bash
uv pip install -e ".[ml]"
```

PassGPT (option 17) will be hidden from the menu if ML dependencies are not installed.

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

### Test Structure

- **tests/test_hashview.py**: Comprehensive test suite for HashviewAPI class with mocked API responses, including:
  - Customer listing and data validation
  - Authentication and authorization tests
  - Hashfile upload functionality
  - Complete job creation workflow

All tests use mocked API calls, so they can run without connectivity to a Hashview server. This allows tests to run in CI/CD environments (like GitHub Actions) without requiring actual API credentials.

### Continuous Integration

Tests automatically run on GitHub Actions for every push and pull request (Ubuntu, Python 3.9 through 3.14).

-------------------------------------------------------------------

  (1) Quick Crack
  (2) Extensive Pure_Hate Methodology Crack
  (3) Brute Force Attack
  (4) Top Mask Attack
  (5) Fingerprint Attack
  (6) Combinator Attack
  (7) Hybrid Attack
  (8) Pathwell Top 100 Mask Brute Force Crack
  (9) PRINCE Attack
  (10) YOLO Combinator Attack
  (11) Middle Combinator Attack
  (12) Thorough Combinator Attack
  (13) Bandrel Methodology
  (14) Loopback Attack
  (15) LLM Attack
  (16) OMEN Attack
  (17) PassGPT Attack

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
* Runs a dictionary attack using all wordlists configured in your "hcatOptimizedWordlists" path
and optionally applies a rule that can be selected from a list by ID number. Multiple rules can be selected by using a
comma separated list, and chains can be created by using the '+' symbol.

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
Runs several attack methods provided by Martin Bos (formerly known as pure_hate)
  * Brute Force Attack (7 characters)
  * Dictionary Attack
    * All wordlists in "hcatOptimizedWordlists" with "best64.rule"
    * wordlists/rockyou.txt with "d3ad0ne.rule"
    * wordlists/rockyou.txt with "T0XlC.rule"
  * Top Mask Attack (Target Time = 4 Hours)
  * Fingerprint Attack
  * Combinator Attack
  * Hybrid Attack
  * Extra - Just For Good Measure
    - Runs a dictionary attack using wordlists/rockyou.txt with chained "combinator.rule" and "InsidePro-PasswordsPro.rule" rules
    
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
Runs a continuous combinator attack using random wordlists from the 
optimized wordlists for the left and right sides.

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

* Prompts for input of comma separated names and then creates a pseudo hybrid attack by capitalizing the first letter
and adding up to six additional characters at the end. Each word is limited to a total of five minutes.
  - Built in additional common words including seasons, months has been included as a customizable config.json entry
  - The default five minute time limit is customizable via the config.json

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
* Trains a model from a wordlist (configurable via config.json or prompted)
* Generates up to a specified number of password candidates
* Pipes generated candidates directly into hashcat for cracking
* Model files are stored in `~/.hate_crack/omen/` for persistence across sessions

#### PassGPT Attack
Uses PassGPT, a GPT-2 based password generator trained on leaked password datasets, to generate candidate passwords. PassGPT produces higher-quality candidates than traditional Markov models by leveraging transformer-based language modeling. You can use the default HuggingFace model or fine-tune a custom model on your own password wordlist.

**Note:** This menu item is hidden unless ML dependencies are installed.

**Requirements:** ML dependencies must be installed separately:
```bash
uv pip install -e ".[ml]"
```

This installs PyTorch and HuggingFace Transformers. GPU acceleration (CUDA/MPS) is auto-detected but not required.

**Configuration keys:**
- `passgptModel` - HuggingFace model name (default: `javirandor/passgpt-10characters`)
- `passgptMaxCandidates` - Maximum candidates to generate (default: 1000000)
- `passgptBatchSize` - Generation batch size (default: 1024)
- `passgptTrainingList` - Default wordlist for fine-tuning (default: `rockyou.txt`)

**Supported models:**
- `javirandor/passgpt-10characters` - Trained on passwords up to 10 characters (default)
- `javirandor/passgpt-16characters` - Trained on passwords up to 16 characters
- Any compatible GPT-2 model on HuggingFace
- Locally fine-tuned models (stored in `~/.hate_crack/passgpt/`)

**Training a Custom Model:**
When you select the PassGPT Attack (option 17), the menu presents:
- List of available models (default HF model + any locally fine-tuned models)
- Option (T) to train a new model on a custom wordlist
- Fine-tuned models are automatically saved to `~/.hate_crack/passgpt/<name>/` for reuse

To train a new model:
1. Select option (T) from the model selection menu
2. Choose a training wordlist (supports tab-complete file selection)
3. Optionally specify a base model (defaults to configured `passgptModel`)
4. Training will fine-tune the model on your wordlist and save it locally

Fine-tuned models can be reused in future cracking sessions and appear in the model selection menu alongside the default models.

**Apple Silicon (MPS) Performance Notes:**
- Batch size is automatically capped at 64 to prevent memory errors on MPS devices
- GPU memory watermark ratios are configured for stability (50% high, 30% low)
- Specify `--device cpu` to force CPU generation if MPS has issues

**Standalone usage:**

Generate candidates:
```bash
python -m hate_crack.passgpt_generate --num 1000 --model javirandor/passgpt-10characters
```

Fine-tune a custom model:
```bash
python -m hate_crack.passgpt_train --training-file wordlist.txt --output-dir ~/.hate_crack/passgpt/my_model
```

**Generator command-line options:**
- `--num` - Number of candidates to generate (default: 1000000)
- `--model` - HuggingFace model name or local path (default: javirandor/passgpt-10characters)
- `--batch-size` - Generation batch size (default: 1024)
- `--max-length` - Max token length including special tokens (default: 12)
- `--device` - Device: cuda, mps, or cpu (default: auto-detect)

**Training command-line options:**
- `--training-file` - Path to password wordlist for fine-tuning (required)
- `--output-dir` - Directory to save the fine-tuned model (required)
- `--base-model` - Base HuggingFace model to fine-tune (default: javirandor/passgpt-10characters)
- `--epochs` - Number of training epochs (default: 3)
- `--batch-size` - Training batch size (default: 8)
- `--device` - Device: cuda, mps, or cpu (default: auto-detect)

#### Download Rules from Hashmob.net
Downloads the latest rule files from Hashmob.net's rule repository. These rules are curated and optimized for password cracking and can be used with the Quick Crack and Loopback Attack modes.

* Automatically downloads popular rule sets
* Stores rules in the configured rules directory
* Provides progress feedback during download

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
  - Added automatic update checks on startup (check_for_updates config option)
  - Added `packaging` dependency for version comparison
  - Added PassGPT Attack (option 17) using GPT-2 based ML password generation
  - Added PassGPT fine-tuning capability for custom password models
  - Added PassGPT configuration keys (passgptModel, passgptMaxCandidates, passgptBatchSize, passgptTrainingList)
  - Added `[ml]` optional dependency group for PyTorch, Transformers, and Datasets
  - Added OMEN Attack (option 16) using statistical model-based password generation
  - Added OMEN configuration keys (omenTrainingList, omenMaxCandidates)
  - Added LLM Attack (option 15) using Ollama for AI-generated password candidates
  - Added Ollama configuration keys (ollamaModel, ollamaNumCtx)
  - Auto-versioning via setuptools-scm from git tags
  - Automatic patch version bump (v2.0.1, v2.0.2, ...) on PR merge to main
  - CI test fixes across Python 3.9-3.14

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
