# Testing Guide

## Overview
The test suite uses mocked API responses and local fixtures so it can run without external services (Hashview, Hashmob, Weakpass). Most tests are fast and run entirely offline. Live network checks and system dependency checks are now opt-in via environment variables.

## Important: Asset Location (hcatPath)

The application requires access to `hashcat-utils` and `princeprocessor` as subdirectories. When running tests or the tool outside the repository directory, configure the asset location in `config.json` by setting `hcatPath`:

```json
{
  "hcatPath": "/path/to/hate_crack",
  ...
}
```

Then run tests or the tool normally:

```bash
uv run pytest -v
# or
hate_crack <hash_file> <hash_type>
```

If `hcatPath` is not set (empty string), the application will search the current directory and parent directory for these assets.

## Changes Made

### 1. Test Files (Current)

**tests/test_hashview.py** (mocked Hashview API tests)
- Added `unittest.mock` imports (Mock, patch, MagicMock)
- Removed dependency on config.json file
- Replaced all real API calls with mocked responses
- Mock responses match the actual API response format (e.g., 'users' field as JSON string)
- Includes comprehensive tests for:
  - Customer listing and validation
  - Authentication and authorization
  - Hashfile upload
  - Complete job creation workflow

**tests/test_api.py**
- Tests for download functionality, 7z extraction triggers, exception handling, and progress bars
- Uses mocked requests and filesystem operations

**tests/test_cli_menus.py**
- Tests CLI menu flags (--hashview, --weakpass, --hashmob)
- Skips by default unless respective TEST_REAL env vars are set

**tests/test_dependencies.py**
- Checks local tool availability (7z, transmission-cli)
- Skips missing dependency failures unless `HATE_CRACK_REQUIRE_DEPS=1` (or true/yes)

**tests/test_ui_menu_options.py**
- Tests all menu option handlers (attacks 1-13, utilities 91-100)
- Validates menu routing and function resolution

**tests/test_pipal.py** and **tests/test_pipal_integration.py**
- Tests pipal analysis functionality and executable integration
- Validates baseword parsing and output handling

**tests/test_submodule_hashcat_utils.py**
- Verifies hashcat-utils submodule is initialized correctly

**tests/test_hashmob_connectivity.py**
- Mocked Hashmob API connectivity test by default
- Set `HASHMOB_TEST_REAL=1` to run against live Hashmob

### 2. Key Mock Patterns

```python
# Example: Mocking list_customers response
mock_response = Mock()
mock_response.json.return_value = {
    'users': json.dumps([  # Note: 'users' is a JSON string in the real API
        {'id': 1, 'name': 'Test Customer'}
    ])
}
mock_response.raise_for_status = Mock()
api.session.get.return_value = mock_response
```

### 3. Documentation

Updated `readme.md` with:
- Testing section explaining how to run tests locally
- Description of test structure

## Environment Variables for Live Tests

By default, external service checks are skipped. Enable them explicitly:

- `HASHMOB_TEST_REAL=1` — run live Hashmob tests (including connectivity and CLI menu flag)
- `HASHVIEW_TEST_REAL=1` — run live Hashview CLI menu test
- `WEAKPASS_TEST_REAL=1` — run live Weakpass CLI menu test
- `HATE_CRACK_REQUIRE_DEPS=1` — fail if required system tools are missing
- `HATE_CRACK_RUN_LIVE_TESTS=1` — run live Hashview upload tests (requires config.json credentials)
- `HATE_CRACK_RUN_LIVE_HASHVIEW_TESTS=1` — run live Hashview wordlist upload tests
- `HATE_CRACK_RUN_E2E=1` — run end-to-end local installation tests
- `HATE_CRACK_RUN_DOCKER_TESTS=1` — run Docker-based end-to-end tests

When `HASHMOB_TEST_REAL` is enabled, tests will still skip if Hashmob returns errors like HTTP 523 (origin unreachable).

## Test Results

✅ 94 tests passing (as of current version, 15 typically skipped)
⚡ Tests run in ~50 seconds on a typical dev machine

### Test Coverage

Highlights:
1. Hashview API workflows (list customers, upload hashfile, create jobs, download left hashes)
2. API download functionality (mocked downloads, 7z extraction, progress bars)
3. CLI menu flags (--hashview, --weakpass, --hashmob)
4. Dependency checks (7z, transmission-cli)
5. Hashmob connectivity (mocked by default, opt-in live tests)
6. Pipal integration and analysis
7. UI menu options (all attack modes)
8. Hashcat-utils submodule verification
9. Docker and E2E installation tests (opt-in)

## Benefits

1. **No Dependencies**: Tests run without needing a Hashview server or API credentials
2. **Fast Execution**: Mocked tests complete in milliseconds
3. **Reliable**: Tests won't fail due to network issues or server downtime
4. **CI/CD Ready**: Can run in GitHub Actions and other CI environments
5. **Portable**: Tests work anywhere Python is installed

## Running Tests

```bash
# Run all tests
uv run pytest -v

# Or via Makefile
make test

# Run tests with coverage
uv run pytest --cov=hate_crack --cov-report=term-missing

# Or via Makefile
make coverage

# Run specific test
uv run pytest tests/test_hashview.py -v

# Run a specific test method
uv run pytest tests/test_hashview.py::TestHashviewAPI::test_create_job_workflow -v

# Run live Hashmob checks
HASHMOB_TEST_REAL=1 uv run pytest tests/test_hashmob_connectivity.py -v

# Require system deps (7z, transmission-cli)
HATE_CRACK_REQUIRE_DEPS=1 uv run pytest tests/test_dependencies.py -v

# Run end-to-end tests
HATE_CRACK_RUN_E2E=1 uv run pytest tests/test_e2e_local_install.py -v

# Run Docker tests
HATE_CRACK_RUN_DOCKER_TESTS=1 uv run pytest tests/test_docker_script_install.py -v
```

## Note on Real API Testing

While these mocked tests validate the code logic, you may still want to occasionally run integration tests against a real Hashview instance to ensure the API hasn't changed. The test files can be easily modified to toggle between mocked and real API calls if needed.
