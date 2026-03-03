# Testing

## Quick Start

```bash
# Run all tests (auto-sets HATE_CRACK_SKIP_INIT when needed)
make test

# With coverage
make coverage
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HATE_CRACK_SKIP_INIT=1` | Skip binary/config validation at startup. Required in worktrees and CI where submodules are not built. `make test` sets this automatically. |
| `HASHMOB_TEST_REAL=1` | Enable live Hashmob connectivity tests |
| `HASHVIEW_TEST_REAL=1` | Enable live Hashview CLI menu tests |
| `WEAKPASS_TEST_REAL=1` | Enable live Weakpass CLI menu tests |
| `HATE_CRACK_REQUIRE_DEPS=1` | Fail if `7z` or `transmission-cli` are missing |
| `HATE_CRACK_RUN_LIVE_TESTS=1` | Enable live Hashview upload test (requires valid credentials in `config.json`) |
| `HATE_CRACK_RUN_LIVE_HASHVIEW_TESTS=1` | Enable live Hashview wordlist upload test |
| `HATE_CRACK_RUN_E2E=1` | Enable local uv tool install E2E test |
| `HATE_CRACK_RUN_DOCKER_TESTS=1` | Enable Docker-based E2E test |
| `HATE_CRACK_RUN_LIMA_TESTS=1` | Enable Lima VM E2E test (macOS, requires `limactl`) |

## Running Tests Directly

```bash
# All tests
uv run pytest -v

# Single file
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_attacks_behavior.py -v

# Specific test
uv run pytest tests/test_hashview.py::TestHashviewAPI::test_create_job_workflow -v

# With coverage
uv run pytest --cov=hate_crack --cov-report=term-missing
```

## Test Files

### Unit / Offline Tests (always run)

No external services, binaries, or network access required.

| File | What it covers |
|------|---------------|
| `test_attacks_behavior.py` | Attack handler logic via mocked `ctx` |
| `test_hashcat_wrappers.py` | Low-level hashcat subprocess wrappers |
| `test_api.py` | Hashview, Weakpass, Hashmob API clients (mocked HTTP) |
| `test_api_downloads.py` | Download helpers and file extraction |
| `test_cli_menus.py` | CLI argument parsing and menu dispatch |
| `test_cli_weakpass.py` | Weakpass CLI subcommands |
| `test_hashview.py` | HashviewAPI class (mocked responses) |
| `test_hashview_cli_subcommands.py` | Hashview CLI subcommand routing |
| `test_hashview_cli_subcommands_subprocess.py` | Hashview subcommands via subprocess |
| `test_ui_menu_options.py` | Menu option snapshot tests via `CLI_MODULE` |
| `test_proxy.py` | `hate_crack.py` proxy to `hate_crack.main` |
| `test_main_utils.py` | Utility functions in `main.py` |
| `test_utils.py` | Shared utility helpers |
| `test_ntlm_preprocessing.py` | NTLM hash preprocessing |
| `test_ntlm_preprocessing_edge_cases.py` | Edge cases for NTLM preprocessing |
| `test_fingerprint_expander_and_hybrid.py` | Fingerprint and hybrid attack helpers |
| `test_hashcat_rules.py` | Hashcat rule parsing and analysis |
| `test_asset_path_separation.py` | `hate_path` vs `hcatPath` path distinction |
| `test_invalid_hcatpath.py` | Startup error on invalid hashcat path |
| `test_version_check.py` | Update check logic |
| `test_omen_attack.py` | OMEN attack handler |
| `test_pipal.py` | Pipal integration helpers |
| `test_pipal_integration.py` | Pipal menu and output parsing |
| `test_dependencies.py` | External dependency detection |
| `test_hashmob_connectivity.py` | Hashmob connectivity check (mocked by default) |

### Opt-In Tests

#### Live API

```bash
HASHMOB_TEST_REAL=1 uv run pytest tests/test_hashmob_connectivity.py -v
HASHVIEW_TEST_REAL=1 uv run pytest tests/test_cli_menus.py -v
WEAKPASS_TEST_REAL=1 uv run pytest tests/test_cli_weakpass.py -v
```

#### Live Hashview Upload

Requires valid `hashview_url` and `hashview_api_key` in `config.json`.

```bash
HATE_CRACK_RUN_LIVE_TESTS=1 uv run pytest tests/test_upload_cracked_hashes.py -v
HATE_CRACK_RUN_LIVE_HASHVIEW_TESTS=1 uv run pytest tests/test_upload_wordlist.py -v
```

#### Submodules

Requires built submodules (`make` first).

```bash
uv run pytest tests/test_submodule_hashcat_utils.py -v
```

#### End-to-End

```bash
# Local uv tool install (creates a temporary HOME)
HATE_CRACK_RUN_E2E=1 uv run pytest tests/test_e2e_local_install.py -v

# Docker-based full install and basic hashcat crack
HATE_CRACK_RUN_DOCKER_TESTS=1 uv run pytest tests/test_docker_script_install.py -v

# Lima VM install (macOS only, requires: brew install lima)
HATE_CRACK_RUN_LIMA_TESTS=1 uv run pytest tests/test_lima_vm_install.py -v

# Installed tool smoke test
uv run pytest tests/test_installed_tool_execution.py -v
uv run pytest tests/test_uv_tool_install_dryrun.py -v
```

The Lima test provisions a real Ubuntu 24.04 VM via [Lima](https://lima-vm.io/). The first run is slow (VM provisioning + apt-get). The VM is named uniquely per session and deleted in teardown - verify cleanup with `limactl list`.

## Test Architecture

- **`conftest.py`** - Provides the `hc_module` fixture via `load_hate_crack_module()`, which dynamically imports `hate_crack.py` with `HATE_CRACK_SKIP_INIT=1`. Each test gets an isolated module instance.
- **`CLI_MODULE`** - Menu option tests patch against this reference to exercise the proxy layer between `hate_crack.py` and `hate_crack.main`.
- **HTTP mocking** - API tests mock `requests` at the boundary. No real network calls in offline tests.
- **Subprocess mocking** - Hashcat wrapper tests mock `subprocess.Popen`; no hashcat binary required.

## CI

GitHub Actions runs the offline test suite against Python 3.9-3.14 on every push and pull request. Opt-in tests are not run in CI.

Pre-push hooks (via [prek](https://github.com/j178/prek)) run `ruff`, `ty`, and `pytest` locally before each push:

```bash
# Install hooks
prek install --hook-type pre-push --hook-type post-commit

# Run manually
prek run
```
