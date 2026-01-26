import shutil
import warnings

import pytest


def _require_executable(name):
    if shutil.which(name) is None:
        warnings.warn(f"Missing required dependency: {name}", RuntimeWarning)
        pytest.fail(f"Required dependency not installed: {name}")


def test_dependency_7z_installed():
    _require_executable("7z")


def test_dependency_transmission_cli_installed():
    _require_executable("transmission-cli")
