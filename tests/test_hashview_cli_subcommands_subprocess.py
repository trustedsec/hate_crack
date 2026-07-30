import os
import subprocess
import sys

import pytest

from hate_crack.api import HashviewAPI


HATE_CRACK_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "hate_crack.py")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _resolved_hashview_config():
    """Ask the real loader what the CLI will actually see.

    ``hashview_url`` and ``hashview_api_key`` live in ``.env``, not
    ``config.json`` — a leftover copy in ``config.json`` is ignored with a
    warning. These helpers used to read ``config.json`` directly, which stopped
    reflecting reality when the two files split: a developer with a legacy
    ``hashview_api_key`` in ``config.json`` silently skipped four of the tests
    below, because the helper reported a key the CLI no longer reads.

    Going through ``config_loader`` rather than re-reading a file by hand is
    also the rule the rest of the codebase follows (see #153): one loader, no
    parallel config readers to drift.
    """
    from hate_crack import config_loader

    env_path, legacy_json_path = config_loader.resolve_config_paths()
    resolved = config_loader.load_config(
        env_path=env_path, legacy_json_path=legacy_json_path
    ).config
    return resolved.get("hashview_url") or "", resolved.get("hashview_api_key") or ""


def _config_has_hashview_key():
    return bool(_resolved_hashview_config()[1])


def _get_hashview_config():
    env_url = os.environ.get("HASHVIEW_URL")
    env_key = os.environ.get("HASHVIEW_API_KEY")
    if env_url and env_key:
        return env_url, env_key
    url, key = _resolved_hashview_config()
    if url and key:
        return url, key
    return env_url, env_key


def _ensure_customer_one():
    url, key = _get_hashview_config()
    if not url or not key:
        pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY in .env or environment.")
    api = HashviewAPI(url, key)

    # Get customer ID from environment or default to 1
    customer_id = int(os.environ.get("HASHVIEW_CUSTOMER_ID", "1"))

    try:
        customers_result = api.list_customers()
    except Exception as exc:
        pytest.skip(f"Unable to list customers from HASHVIEW_URL: {exc}")
    customers = (
        customers_result.get("customers", [])
        if isinstance(customers_result, dict)
        else customers_result
    )
    if not any(int(cust.get("id", 0)) == customer_id for cust in customers or []):
        api.create_customer(f"Example Customer {customer_id}")
    return customer_id


@pytest.mark.parametrize(
    "args",
    [
        ["hashview", "upload-cracked", "--file", "dummy.out", "--hash-type", "1000"],
        [
            "hashview",
            "upload-wordlist",
            "--file",
            "dummy.txt",
            "--name",
            "TestWordlist",
        ],
        ["hashview", "download-hashes", "--customer-id", "1", "--hashfile-id", "2"],
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
        pytest.skip(
            "A Hashview API key is configured (.env or environment); "
            "skip the API-key-missing checks."
        )

    # Ensure any dummy files referenced exist to avoid confusion if the code path changes.
    for idx, arg in enumerate(args):
        if arg == "--file":
            path = tmp_path / args[idx + 1]
            path.write_text("dummy\n")
            args[idx + 1] = str(path)

    # Strip any ambient Hashview credentials (e.g. exported by the local-stack
    # fixture) so this exercises the genuine no-key-configured path. The CLI
    # honours HASHVIEW_URL / HASHVIEW_API_KEY as overrides, so leaving them set
    # would supply a key and defeat the check.
    sub_env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("HASHVIEW_URL", "HASHVIEW_API_KEY")
    }
    sub_env["PYTHONUNBUFFERED"] = "1"
    cli_cmd = [sys.executable, HATE_CRACK_SCRIPT] + args
    result = subprocess.run(
        cli_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=sub_env,
    )
    output = result.stdout + result.stderr
    assert "Hashview API key not configured" in output
    assert result.returncode == 1


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_downloads():
    required = ["HASHVIEW_HASHFILE_ID"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    url, key = _get_hashview_config()
    if not url or not key:
        pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY in .env or environment.")
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "HASHVIEW_URL": url,
        "HASHVIEW_API_KEY": key,
    }
    base_cmd = [sys.executable, HATE_CRACK_SCRIPT, "hashview"]
    customer_id = _ensure_customer_one()

    dl_cmd = base_cmd + [
        "download-hashes",
        "--customer-id",
        str(customer_id),
        "--hashfile-id",
        os.environ["HASHVIEW_HASHFILE_ID"],
    ]
    dl = subprocess.run(
        dl_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    dl_out = dl.stdout + dl.stderr
    assert dl.returncode == 0, dl_out
    assert "Downloaded" in dl_out
    assert "left_" in dl_out


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_upload_hashfile_job(tmp_path):
    required = ["HASHVIEW_HASH_TYPE"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    url, key = _get_hashview_config()
    if not url or not key:
        pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY in .env or environment.")
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "HASHVIEW_URL": url,
        "HASHVIEW_API_KEY": key,
    }
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
    if "Invalid customer ID" in output:
        pytest.skip(
            "HASHVIEW_CUSTOMER_ID does not exist for this API key. Update the env or create the customer."
        )
    # The hashfile upload itself succeeded, but Hashview's task planner refuses
    # to create a job when the server has no cracked-hash history for this hash
    # type. That's a server-side data limitation, not a client defect, so treat
    # it as a skip rather than a failure.
    if "Not enough data to determine effective tasks" in output:
        assert ("Hashfile uploaded" in output) or ("Hashfile added" in output), output
        pytest.skip(
            "Hashview has no cracked-hash history for this hash type; cannot plan job tasks."
        )
    assert run.returncode == 0, output
    assert ("Hashfile uploaded" in output) or ("Hashfile added" in output)
    # Success surfaces the server's job id ("Job ID: N"); a graceful failure
    # surfaces an "Error:" line. The CLI echoes the server's own message ("Job
    # added"), so don't assert on the literal "Job created".
    assert ("Job ID:" in output) or ("Error:" in output)
    if "Job ID:" in output:
        job_id = None
        for line in output.splitlines():
            if line.strip().startswith("Job ID:"):
                try:
                    job_id = int(line.split("Job ID:")[1].strip())
                except Exception:
                    job_id = None
                break
        if job_id:
            try:
                from hate_crack.api import HashviewAPI

                url, key = _get_hashview_config()
                if not url or not key:
                    return
                api = HashviewAPI(url, key)
                try:
                    api.start_job(job_id)
                except Exception:
                    pass
                try:
                    api.stop_job(job_id)
                except Exception:
                    pass
                try:
                    api.delete_job(job_id)
                except Exception:
                    pass
            except Exception:
                pass


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_upload_hashfile_job_pwdump(tmp_path):
    required = []
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    url, key = _get_hashview_config()
    if not url or not key:
        pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY in .env or environment.")
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "HASHVIEW_URL": url,
        "HASHVIEW_API_KEY": key,
    }
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
    if "Invalid customer ID" in output:
        pytest.skip(
            "HASHVIEW_CUSTOMER_ID does not exist for this API key. Update the env or create the customer."
        )
    # The hashfile upload itself succeeded, but Hashview's task planner refuses
    # to create a job when the server has no cracked-hash history for this hash
    # type. That's a server-side data limitation, not a client defect, so treat
    # it as a skip rather than a failure.
    if "Not enough data to determine effective tasks" in output:
        assert ("Hashfile uploaded" in output) or ("Hashfile added" in output), output
        pytest.skip(
            "Hashview has no cracked-hash history for this hash type; cannot plan job tasks."
        )
    assert run.returncode == 0, output
    assert ("Hashfile uploaded" in output) or ("Hashfile added" in output)
    # Success surfaces the server's job id ("Job ID: N"); a graceful failure
    # surfaces an "Error:" line. The CLI echoes the server's own message ("Job
    # added"), so don't assert on the literal "Job created".
    assert ("Job ID:" in output) or ("Error:" in output)
    if "Job ID:" in output:
        job_id = None
        for line in output.splitlines():
            if line.strip().startswith("Job ID:"):
                try:
                    job_id = int(line.split("Job ID:")[1].strip())
                except Exception:
                    job_id = None
                break
        if job_id:
            try:
                from hate_crack.api import HashviewAPI

                url, key = _get_hashview_config()
                if not url or not key:
                    return
                api = HashviewAPI(url, key)
                try:
                    api.start_job(job_id)
                except Exception:
                    pass
                try:
                    api.stop_job(job_id)
                except Exception:
                    pass
                try:
                    api.delete_job(job_id)
                except Exception:
                    pass
            except Exception:
                pass


@pytest.mark.skipif(
    os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
    reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview subprocess tests.",
)
def test_hashview_subcommands_live_upload_hashfile_job_hashonly(tmp_path):
    required = ["HASHVIEW_HASH_TYPE"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        pytest.skip(f"Missing required env vars: {', '.join(missing)}")

    url, key = _get_hashview_config()
    if not url or not key:
        pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY in .env or environment.")
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "HASHVIEW_URL": url,
        "HASHVIEW_API_KEY": key,
    }
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
    # The hashfile upload itself succeeded, but Hashview's task planner refuses
    # to create a job when the server has no cracked-hash history for this hash
    # type. That's a server-side data limitation, not a client defect, so treat
    # it as a skip rather than a failure.
    if "Not enough data to determine effective tasks" in output:
        assert ("Hashfile uploaded" in output) or ("Hashfile added" in output), output
        pytest.skip(
            "Hashview has no cracked-hash history for this hash type; cannot plan job tasks."
        )
    assert run.returncode == 0, output
    assert ("Hashfile uploaded" in output) or ("Hashfile added" in output)
    # Success surfaces the server's job id ("Job ID: N"); a graceful failure
    # surfaces an "Error:" line. The CLI echoes the server's own message ("Job
    # added"), so don't assert on the literal "Job created".
    assert ("Job ID:" in output) or ("Error:" in output)
    if "Job ID:" in output:
        job_id = None
        for line in output.splitlines():
            if line.strip().startswith("Job ID:"):
                try:
                    job_id = int(line.split("Job ID:")[1].strip())
                except Exception:
                    job_id = None
                break
        if job_id:
            try:
                from hate_crack.api import HashviewAPI

                url, key = _get_hashview_config()
                if not url or not key:
                    return
                api = HashviewAPI(url, key)
                try:
                    api.start_job(job_id)
                except Exception:
                    pass
                try:
                    api.stop_job(job_id)
                except Exception:
                    pass
                try:
                    api.delete_job(job_id)
                except Exception:
                    pass
            except Exception:
                pass
