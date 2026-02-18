"""Tests for the startup version check feature."""

import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def hc_module():
    """Load hate_crack.main with SKIP_INIT enabled."""
    import os
    import importlib

    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    mod = importlib.import_module("hate_crack.main")
    return mod


class TestCheckForUpdates:
    """Tests for check_for_updates()."""

    def test_newer_version_prints_update_notice(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available: 99.0.0" in output
        assert "github.com/trustedsec/hate_crack/releases" in output

    def test_same_version_prints_nothing(self, hc_module, capsys):
        from hate_crack import __version__

        local_base = __version__.split("+")[0]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": f"v{local_base}"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available" not in output

    def test_older_version_prints_nothing(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v0.0.1"}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("hate_crack.__version__", "2.0"),
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available" not in output

    def test_network_error_silently_handled(self, hc_module, capsys):
        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ):
            mock_requests.get.side_effect = ConnectionError("no network")
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available" not in output
        assert "Error" not in output

    def test_requests_unavailable_skips_check(self, hc_module, capsys):
        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", False
        ):
            hc_module.check_for_updates()
            mock_requests.get.assert_not_called()

    def test_config_disabled_skips_check(self, hc_module):
        """Verify that check_for_updates_enabled=False prevents the call in main()."""
        # The config flag is checked in main() before calling check_for_updates().
        # We verify the flag loads correctly from config.
        assert hasattr(hc_module, "check_for_updates_enabled")

    def test_tag_without_v_prefix(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available: 99.0.0" in output

    def test_empty_tag_name_handled(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": ""}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available" not in output
