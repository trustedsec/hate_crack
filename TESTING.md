# Testing Guide

## Overview
The test suite uses mocked API responses and local fixtures so it can run without external services (Hashview, Hashmob, Weakpass). Most tests are fast and run entirely offline.

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

**tests/test_hate_crack_utils.py**
- Unit tests for utility helpers (session id generation, line counts, path resolution, hex conversion)
- Uses `HATE_CRACK_SKIP_INIT=1` to avoid heavy dependency checks

**tests/test_menu_snapshots.py**
- Snapshot-based tests for menu output text
- Uses fixtures in `tests/fixtures/menu_outputs/`

**tests/test_dependencies.py**
- Checks local tool availability (7z, transmission-cli)

**tests/test_module_imports.py**
- Ensures core modules import cleanly (`hashview`, `hashmob_wordlist`, `weakpass`, `cli`, `api`, `attacks`)

**tests/test_hashmob_connectivity.py**
- Mocked Hashmob API connectivity test

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

## Test Results

✅ 25 tests passing  
⚡ Tests run in <1 second on a typical dev machine

### Test Coverage

Highlights:
1. Hashview API workflows (list customers, upload hashfile, create jobs, download left hashes)
2. Utility helpers (sanitize session ids, line count, path resolution, hex conversion)
3. Menu output snapshots
4. Hashmob connectivity (mocked)
5. Module import sanity checks

## Benefits

1. **No Dependencies**: Tests run without needing a Hashview server or API credentials
2. **Fast Execution**: Mocked tests complete in milliseconds
3. **Reliable**: Tests won't fail due to network issues or server downtime
4. **CI/CD Ready**: Can run in GitHub Actions and other CI environments
5. **Portable**: Tests work anywhere Python is installed

## Running Tests

```bash
# Install dependencies
pip install pytest pytest-mock requests

# Run all tests
pytest -v

# Run specific test
pytest tests/test_hashview.py -v

# Run a specific test method
pytest tests/test_hashview.py::TestHashviewAPI::test_create_job_workflow -v
```

## Note on Real API Testing

While these mocked tests validate the code logic, you may still want to occasionally run integration tests against a real Hashview instance to ensure the API hasn't changed. The test files can be easily modified to toggle between mocked and real API calls if needed.
