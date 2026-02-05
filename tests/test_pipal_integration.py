import os
import subprocess


import json


def test_pipal_executable_and_runs(tmp_path):
    # Read pipalPath from config.json
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    pipal_path = config.get("pipalPath")
    if not pipal_path or not os.path.isfile(pipal_path):
        import pytest

        pytest.skip("pipalPath not configured or file missing")

    if not os.access(pipal_path, os.X_OK):
        raise AssertionError(
            f"pipalPath exists but is not executable: {pipal_path}. "
            "Ensure pipal is installed/compiled and has execute permissions."
        )

    input_file = tmp_path / "pipal_input.txt"
    input_file.write_text("password\npassword123\nletmein\n")
    output_file = tmp_path / "pipal_output.txt"

    result = subprocess.run(
        [pipal_path, str(input_file), "-t", "3", "--output", str(output_file)],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise AssertionError(
            "pipal did not run successfully. "
            f"returncode={result.returncode}, stdout={result.stdout}, stderr={result.stderr}"
        )

    if not output_file.exists():
        raise AssertionError(
            "pipal did not produce an output file; it may need to be compiled."
        )

    content = output_file.read_text()
    assert "Top 3 base words" in content
