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

To keep `uv tool install .` happy, run the tool from the hate_crack checkout directory or one of the auto-discovered locations below.

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

This means the tool cannot find the hate_crack repository assets. The `hashcat-utils` and `princeprocessor` directories are part of the **hate_crack repository**, not the hashcat installation.

**Understanding the paths:**
- `hcatPath` in config.json → points to **hashcat binary location** (optional, can be in PATH)
- `hashcat-utils/` and `princeprocessor/` → located in the **hate_crack repository directory**

The tool automatically searches for hate_crack assets in these locations:
1. The directory that contains the hate_crack checkout (and includes `config.json`, `hashcat-utils/`, and `princeprocessor/`)
2. Current working directory and parent directory
3. `~/hate_crack`, `~/hate-crack`, or `~/.hate_crack`

**Solution:**
Run `hate_crack` from within the repository directory:
```bash
cd /opt/hate_crack  # or wherever you cloned the repository
hate_crack <hash_file> <hash_type>
```

If the assets live elsewhere, update `"hcatPath"` in `config.json` to point to the directory that contains `hashcat-utils` and `princeprocessor`.

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

Install the project with optional dev dependencies (includes type stubs, linters, and testing tools):

```bash
pip install -e ".[dev]"
```

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

**Mypy (type checking):**
```bash
.venv/bin/mypy hate_crack
```

**Run all checks together:**
```bash
.venv/bin/ruff check hate_crack && .venv/bin/mypy hate_crack && echo "✓ All checks passed"
```

### Running Tests

```bash
.venv/bin/pytest
```

With coverage:
```bash
.venv/bin/pytest --cov=hate_crack
```

### Pre-commit Hook (Optional)

Create `.git/hooks/pre-push` to automatically run checks before pushing:

```bash
#!/bin/bash
set -e
.venv/bin/ruff check hate_crack
.venv/bin/mypy hate_crack
echo "✓ Local checks passed!"
```

Make it executable:
```bash
chmod +x .git/hooks/pre-push
```

### Dev Dependencies

The optional `[dev]` group includes:
- **mypy** - Static type checker
- **ruff** - Fast Python linter and formatter
- **pytest** - Testing framework
- **pytest-cov** - Coverage reporting
- **types-requests** - Type stubs for requests library
- **types-beautifulsoup4** - Type stubs for BeautifulSoup
- **types-openpyxl** - Type stubs for openpyxl library

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
- `--debug`: Enable debug logging (writes `hate_crack.log` in repo root).

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
- **(4) Download Left Hashes** - Download remaining uncracked hashes (automatically merges with found hashes if available)
- **(5) Upload Hashfile and Create Job** - Upload new hashfile and create a cracking job
- **(99) Back to Main Menu** - Return to main menu

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

Download left hashes (automatically merges with found hashes):
```bash
hate_crack.py --hashview download-left --customer-id 1 --hashfile-id 123
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

#### Automatic Found Hash Merging

When downloading left hashes, hate_crack automatically:
1. Attempts to download any found (cracked) hashes from Hashview
2. Merges found hashes with local `.out` files (e.g., `left_1_123.txt.out` or `left_1_123.nt.txt.out` for pwdump format)
3. Removes duplicate entries
4. Deletes the temporary found file after merging

This ensures your local cracking results stay synchronized with Hashview's centralized database.

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

Tests automatically run on GitHub Actions for every push and pull request (Ubuntu, Python 3.13).

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

  (93) Download Wordlists
  (94) Hashview Integration
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
  
-------------------------------------------------------------------
### Version History
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
