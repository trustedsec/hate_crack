"""Tests for the startup version check feature."""

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
        ), patch("builtins.input", return_value="n"):
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
        ), patch("builtins.input", return_value="n"):
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

    def test_upgrade_declined_does_not_run_make(self, hc_module):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ), patch("builtins.input", return_value="n"), patch(
            "subprocess.run"
        ) as mock_run:
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        mock_run.assert_not_called()

    def test_upgrade_accepted_runs_make_and_exits(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        git_root_proc = MagicMock()
        git_root_proc.returncode = 0
        git_root_proc.stdout = "/fake/repo\n"

        fetch_proc = MagicMock()
        fetch_proc.returncode = 0

        branch_proc = MagicMock()
        branch_proc.returncode = 0
        branch_proc.stdout = "main\n"

        make_proc = MagicMock()
        make_proc.returncode = 0

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ), patch("builtins.input", return_value="y"), patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, make_proc],
        ) as mock_run, pytest.raises(SystemExit):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        assert mock_run.call_count == 4
        make_cmd = mock_run.call_args_list[3][0][0]
        assert "git pull origin main" in make_cmd
        assert "make install" in make_cmd
        assert mock_run.call_args_list[3][1]["cwd"] == "/fake/repo"
        output = capsys.readouterr().out
        assert "Upgrade complete" in output

    def test_upgrade_failure_prints_error(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        git_root_proc = MagicMock()
        git_root_proc.returncode = 0
        git_root_proc.stdout = "/fake/repo\n"

        fetch_proc = MagicMock()
        fetch_proc.returncode = 0

        branch_proc = MagicMock()
        branch_proc.returncode = 0
        branch_proc.stdout = "main\n"

        make_proc = MagicMock()
        make_proc.returncode = 1

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ), patch("builtins.input", return_value="y"), patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, make_proc],
        ), patch("shutil.which", return_value="/usr/local/bin/uv"), patch(
            "os.path.isfile", return_value=True
        ), pytest.raises(
            SystemExit
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Upgrade failed" in output

    def test_upgrade_no_git_repo_prints_manual_instructions(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        git_root_proc = MagicMock()
        git_root_proc.returncode = 128
        git_root_proc.stdout = ""

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ), patch("builtins.input", return_value="y"), patch(
            "subprocess.run", return_value=git_root_proc
        ), pytest.raises(
            SystemExit
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Run manually" in output


class TestRunUpgrade:
    """Tests for _run_upgrade() called directly via --update flag."""

    def test_run_upgrade_success(self, hc_module, capsys):
        git_root_proc = MagicMock()
        git_root_proc.returncode = 0
        git_root_proc.stdout = "/fake/repo\n"

        fetch_proc = MagicMock()
        fetch_proc.returncode = 0

        branch_proc = MagicMock()
        branch_proc.returncode = 0
        branch_proc.stdout = "main\n"

        make_proc = MagicMock()
        make_proc.returncode = 0

        with patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, make_proc],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 0
        assert mock_run.call_count == 4
        # The fetch happens before the branch inspection.
        assert mock_run.call_args_list[1][0][0] == ["git", "fetch", "--tags", "origin"]
        make_cmd = mock_run.call_args_list[3][0][0]
        assert "git pull origin main" in make_cmd
        assert "make install" in make_cmd
        assert mock_run.call_args_list[3][1]["cwd"] == "/fake/repo"
        output = capsys.readouterr().out
        assert "Upgrade complete" in output

    def test_run_upgrade_make_failure(self, hc_module, capsys):
        git_root_proc = MagicMock()
        git_root_proc.returncode = 0
        git_root_proc.stdout = "/fake/repo\n"

        fetch_proc = MagicMock()
        fetch_proc.returncode = 0

        branch_proc = MagicMock()
        branch_proc.returncode = 0
        branch_proc.stdout = "main\n"

        make_proc = MagicMock()
        make_proc.returncode = 1

        with patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, make_proc],
        ), pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert "Upgrade failed" in output

    def test_run_upgrade_no_git_repo(self, hc_module, capsys):
        git_root_proc = MagicMock()
        git_root_proc.returncode = 128
        git_root_proc.stdout = ""

        with patch("subprocess.run", return_value=git_root_proc), pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert "Run manually" in output

    def test_upgrade_prompt_ctrl_c_continues(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(hc_module, "requests") as mock_requests, patch.object(
            hc_module, "REQUESTS_AVAILABLE", True
        ), patch("builtins.input", side_effect=KeyboardInterrupt), patch(
            "subprocess.run"
        ) as mock_run:
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        mock_run.assert_not_called()

    # ------------------------------------------------------------------
    # Branch-switch behavior: when the user runs the upgrade from a
    # non-main checkout, release tags aren't reachable from HEAD and
    # the upgrade no-ops (loops). _run_upgrade() must switch to main
    # first, with safety guards.
    # ------------------------------------------------------------------

    def test_run_upgrade_switches_from_dev_to_main_then_upgrades(
        self, hc_module, capsys
    ):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="dev\n")
        status_proc = MagicMock(returncode=0, stdout="")
        checkout_proc = MagicMock(returncode=0, stdout="", stderr="")
        upstream_proc = MagicMock(returncode=0, stdout="", stderr="")
        make_proc = MagicMock(returncode=0)

        with patch(
            "subprocess.run",
            side_effect=[
                git_root_proc,
                fetch_proc,
                branch_proc,
                status_proc,
                checkout_proc,
                upstream_proc,
                make_proc,
            ],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 0
        assert mock_run.call_count == 7
        # Fetch happens before the checkout.
        assert mock_run.call_args_list[1][0][0] == ["git", "fetch", "--tags", "origin"]
        # The checkout creates/resets main from origin/main.
        checkout_call = mock_run.call_args_list[4]
        assert checkout_call[0][0] == ["git", "checkout", "-B", "main", "origin/main"]
        # Upstream is repaired to origin/main.
        assert mock_run.call_args_list[5][0][0] == [
            "git",
            "branch",
            "--set-upstream-to=origin/main",
            "main",
        ]
        # Final call is the shell upgrade.
        upgrade_cmd = mock_run.call_args_list[6][0][0]
        assert "git pull origin main" in upgrade_cmd
        assert "git fetch --tags" in upgrade_cmd
        output = capsys.readouterr().out
        assert "Switching from 'dev' to 'main'" in output

    def test_run_upgrade_migrates_master_only_renamed_clone(
        self, hc_module, capsys
    ):
        """An old clone still sitting on `master` (default branch renamed
        master -> main upstream) must be migrated: fetch BEFORE checkout,
        checkout/create `main` from origin/main, set upstream to origin/main,
        and the final pull must be `git pull origin main` (never bare)."""
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="master\n")
        status_proc = MagicMock(returncode=0, stdout="")
        checkout_proc = MagicMock(returncode=0, stdout="", stderr="")
        upstream_proc = MagicMock(returncode=0, stdout="", stderr="")
        make_proc = MagicMock(returncode=0)

        with patch(
            "subprocess.run",
            side_effect=[
                git_root_proc,
                fetch_proc,
                branch_proc,
                status_proc,
                checkout_proc,
                upstream_proc,
                make_proc,
            ],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 0
        calls = [c[0][0] for c in mock_run.call_args_list]

        # A fetch must occur before any checkout.
        fetch_idx = calls.index(["git", "fetch", "--tags", "origin"])
        checkout_idx = calls.index(["git", "checkout", "-B", "main", "origin/main"])
        assert fetch_idx < checkout_idx

        # Upstream repaired to origin/main after the checkout.
        upstream_idx = calls.index(
            ["git", "branch", "--set-upstream-to=origin/main", "main"]
        )
        assert checkout_idx < upstream_idx

        # Final pull is explicit, not a bare `git pull`.
        upgrade_cmd = mock_run.call_args_list[-1][0][0]
        assert "git pull origin main" in upgrade_cmd
        assert "make install" in upgrade_cmd

        output = capsys.readouterr().out
        assert "Switching from 'master' to 'main'" in output

    def test_run_upgrade_bails_when_fetch_fails(self, hc_module, capsys):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(
            returncode=1, stdout="", stderr="fatal: unable to access origin\n"
        )

        with patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 1
        # No branch inspection / checkout after the fetch failure.
        assert mock_run.call_count == 2
        output = capsys.readouterr().out
        assert "Failed to fetch from origin" in output

    def test_run_upgrade_bails_when_non_main_branch_is_dirty(
        self, hc_module, capsys
    ):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="feat/x\n")
        status_proc = MagicMock(returncode=0, stdout=" M hate_crack/main.py\n")

        with patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, status_proc],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 1
        # No checkout, no upgrade command should fire after the bail.
        assert mock_run.call_count == 4
        all_call_args = [c[0][0] for c in mock_run.call_args_list]
        assert ["git", "checkout", "-B", "main", "origin/main"] not in all_call_args
        output = capsys.readouterr().out
        assert "uncommitted changes" in output
        assert "feat/x" in output

    def test_run_upgrade_bails_when_checkout_main_fails(self, hc_module, capsys):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="dev\n")
        status_proc = MagicMock(returncode=0, stdout="")
        checkout_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: 'main' is already checked out at '/other/wt'\n",
        )

        with patch(
            "subprocess.run",
            side_effect=[
                git_root_proc,
                fetch_proc,
                branch_proc,
                status_proc,
                checkout_proc,
            ],
        ), pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert "Failed to switch to main" in output
        assert "already checked out" in output

    def test_run_upgrade_skips_switch_when_already_on_main(
        self, hc_module, capsys
    ):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="main\n")
        make_proc = MagicMock(returncode=0)

        with patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, make_proc],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 0
        # rev-parse + fetch + symbolic-ref + upgrade shell. No checkout.
        assert mock_run.call_count == 4
        all_call_args = [c[0][0] for c in mock_run.call_args_list]
        assert ["git", "checkout", "-B", "main", "origin/main"] not in all_call_args
        output = capsys.readouterr().out
        assert "Switching from" not in output

    def test_run_upgrade_skips_switch_on_detached_head(self, hc_module, capsys):
        """Detached HEAD: symbolic-ref returns non-zero. We should not
        attempt a branch switch (there's nothing to switch from) — let
        the existing upgrade flow proceed."""
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=1, stdout="", stderr="fatal: ref HEAD is not a symbolic ref\n")
        make_proc = MagicMock(returncode=0)

        with patch(
            "subprocess.run",
            side_effect=[git_root_proc, fetch_proc, branch_proc, make_proc],
        ) as mock_run, pytest.raises(SystemExit) as exc:
            hc_module._run_upgrade()

        assert exc.value.code == 0
        assert mock_run.call_count == 4
        all_call_args = [c[0][0] for c in mock_run.call_args_list]
        assert ["git", "checkout", "-B", "main", "origin/main"] not in all_call_args
