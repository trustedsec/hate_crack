import json
import os
import subprocess
import sys

import pytest

from hate_crack.api import HashviewAPI


HATE_CRACK_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "hate_crack.py")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _config_has_hashview_key():
    config_path = os.path.join(REPO_ROOT, "config.json")
    if not os.path.isfile(config_path):
        return False
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return bool(data.get("hashview_api_key"))
    except Exception:
        return False


def _ensure_customer_one():
    api = HashviewAPI(os.environ["HASHVIEW_URL"], os.environ["HASHVIEW_API_KEY"])
    try:
        customers_result = api.list_customers()
    except Exception as exc:
        pytest.skip(f"Unable to list customers from HASHVIEW_URL: {exc}")
    customers = customers_result.get("customers", []) if isinstance(customers_result, dict) else customers_result
    if not any(int(cust.get("id", 0)) == 1 for cust in customers or []):
        api.create_customer("Example Customer")
    return 1


@pytest.mark.parametrize(
    "args",
    [
        ["hashview", "upload-cracked", "--file", "dummy.out", "--hash-type", "1000"],
        ["hashview", "upload-wordlist", "--file", "dummy.txt", "--name", "TestWordlist"],
        ["hashview", "download-left", "--customer-id", "1", "--hashfile-id", "2"],
        ["hashview", "download-found", "--customer-id", "1", "--hashfile-id", "2"],
        [
            "hashview",
            "upload-hashfile-job",
            "--file",
            "dummy_hashes.txt",
            "--customer-id",
            "1",
            "--hash-type",
            "1000",
            "--job-name",
            "TestJob",
        ],
    ],
)
def test_hashview_subcommands_require_api_key(tmp_path, args):
    if _config_has_hashview_key():
        pytest.skip("config.json has hashview_api_key set; skip API-key missing checks.")

    # Ensure any dummy files referenced exist to avoid confusion if the code path changes.
    for idx, arg in enumerate(args):
        if arg == "--file":
            path = tmp_path / args[idx + 1]
            path.write_text("dummy\n")
            args[idx + 1] = str(path)

    cli_cmd = [sys.executable, HATE_CRACK_SCRIPT] + args
    result = subprocess.run(
        cli_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    output = result.stdout + result.stderr
    assert "Hashview API key not configured" in output
    assert result.returncode == 1


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_downloads():
    required = ["HASHVIEW_URL", "HASHVIEW_API_KEY", "HASHVIEW_HASHFILE_ID"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    base_cmd = [sys.executable, HATE_CRACK_SCRIPT, "hashview"]
    customer_id = _ensure_customer_one()

    left_cmd = base_cmd + [
        "download-left",
        "--customer-id",
        str(customer_id),
        "--hashfile-id",
        os.environ["HASHVIEW_HASHFILE_ID"],
    ]
    left = subprocess.run(
        left_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    left_out = left.stdout + left.stderr
    assert left.returncode == 0, left_out
    assert "Downloaded" in left_out
    assert "left_" in left_out

    found_cmd = base_cmd + [
        "download-found",
        "--customer-id",
        str(customer_id),
        "--hashfile-id",
        os.environ["HASHVIEW_HASHFILE_ID"],
    ]
    found = subprocess.run(
        found_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    found_out = found.stdout + found.stderr
    assert found.returncode == 0, found_out
    assert "Downloaded" in found_out
    assert "found_" in found_out


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_upload_hashfile_job(tmp_path):
    required = ["HASHVIEW_URL", "HASHVIEW_API_KEY", "HASHVIEW_HASH_TYPE"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    base_cmd = [sys.executable, HATE_CRACK_SCRIPT, "hashview"]
    customer_id = _ensure_customer_one()

    hash_type = os.environ["HASHVIEW_HASH_TYPE"]
    hashfile = tmp_path / "hashes.txt"
    # Provide a simple hash-only line; ensure HASHVIEW_HASH_TYPE matches this format.
    hashfile.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")

    cmd = base_cmd + [
        "upload-hashfile-job",
        "--file",
        str(hashfile),
        "--customer-id",
        str(customer_id),
        "--hash-type",
        hash_type,
        "--job-name",
        "TestJobSubprocess",
    ]
    run = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    output = run.stdout + run.stderr
    assert run.returncode == 0, output
    assert ("Hashfile uploaded" in output) or ("Hashfile added" in output)
    assert ("Job created" in output) or ("Failed to add job" in output)


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_upload_hashfile_job_pwdump(tmp_path):
    required = ["HASHVIEW_URL", "HASHVIEW_API_KEY"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    base_cmd = [sys.executable, HATE_CRACK_SCRIPT, "hashview"]
    customer_id = _ensure_customer_one()

    hashfile = tmp_path / "hashes_pwdump.txt"
    # Pwdump format: user:RID:LM:NTLM:::
    hashfile.write_text(
        "user:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
    )

    cmd = base_cmd + [
        "upload-hashfile-job",
        "--file",
        str(hashfile),
        "--customer-id",
        str(customer_id),
        "--hash-type",
        "1000",
        "--file-format",
        "0",
        "--job-name",
        "TestJobSubprocessPwdump",
    ]
    run = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    output = run.stdout + run.stderr
    assert run.returncode == 0, output
    assert ("Hashfile uploaded" in output) or ("Hashfile added" in output)
    assert ("Job created" in output) or ("Failed to add job" in output)


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_upload_hashfile_job_hashonly(tmp_path):
    required = ["HASHVIEW_URL", "HASHVIEW_API_KEY", "HASHVIEW_HASH_TYPE"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    base_cmd = [sys.executable, HATE_CRACK_SCRIPT, "hashview"]
    customer_id = _ensure_customer_one()

    hash_type = os.environ["HASHVIEW_HASH_TYPE"]
    hashfile = tmp_path / "hashes_hashonly.txt"
    hashfile.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")

    cmd = base_cmd + [
        "upload-hashfile-job",
        "--file",
        str(hashfile),
        "--customer-id",
        str(customer_id),
        "--hash-type",
        hash_type,
        "--file-format",
        "5",
        "--job-name",
        "TestJobSubprocessHashOnly",
    ]
    run = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    output = run.stdout + run.stderr
    assert run.returncode == 0, output
    assert ("Hashfile uploaded" in output) or ("Hashfile added" in output)
    assert ("Job created" in output) or ("Failed to add job" in output)
