import os
import shutil
import warnings

import pytest


def _require_executable(name):
    if shutil.which(name) is None:
        warnings.warn(f"Missing required dependency: {name}", RuntimeWarning)
        if os.environ.get("HATE_CRACK_REQUIRE_DEPS", "").lower() in (
            "1",
            "true",
            "yes",
        ):
            pytest.fail(f"Required dependency not installed: {name}")
        pytest.skip(f"Missing required dependency: {name}")


def test_dependency_7z_installed():
    _require_executable("7z")


def test_dependency_transmission_cli_installed():
    _require_executable("transmission-cli")
