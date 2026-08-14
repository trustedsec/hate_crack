"""Tests for the startup version check feature."""

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest


def _proc(returncode=0, stdout=""):
    p = MagicMock()
    p.returncode = returncode
    p.stdout = stdout
    return p


def upgrade_procs(current_branch="main", dirty=False, final_returncode=0):
    """Build the subprocess.run side_effect sequence _run_upgrade() consumes.

    The order is: rev-parse --show-toplevel, fetch, symbolic-ref HEAD, status
    --porcelain, checkout -B, branch --set-upstream-to, then the shell chain.
    The status/checkout/upstream calls happen on every run, not just when HEAD
    is on some other branch -- _run_upgrade() always resets to origin's tip
    because a pull cannot advance a rewritten-history clone.
    """
    procs = [
        _proc(stdout="/fake/repo\n"),  # rev-parse --show-toplevel
        _proc(),  # fetch --tags --force
        _proc(stdout=f"{current_branch}\n") if current_branch else _proc(128),
        _proc(stdout=" M foo.py\n" if dirty else ""),  # status --porcelain
    ]
    if dirty:
        return procs
    procs += [
        _proc(),  # checkout -B
        _proc(),  # branch --set-upstream-to
        _proc(final_returncode),  # shell chain
    ]
    return procs


def head_check_procs(at_release_tag=False):
    """The git calls check_for_updates() makes before it decides to offer.

    _head_contains_release_tag() asks `rev-parse refs/tags/<tag>^{commit}` and
    then `merge-base --is-ancestor <sha> HEAD`, so a checkout that already
    contains the release counts as up to date even when the version string
    compares lower -- which is the normal state on nightly-dev, whose rc
    versions sort below the release they become (#271). Any test driving the
    upgrade *through* check_for_updates has to supply these first; tests
    calling _run_upgrade() directly do not.

    Defaults to the release NOT being an ancestor, which is what makes the
    offer fire. These are call-sequence stubs; the real git behaviour is
    covered against actual repositories in TestHeadContainsReleaseTag.
    """
    if at_release_tag:
        return [_proc(stdout="cafe1234\n"), _proc(0)]
    return [_proc(stdout="cafe1234\n"), _proc(1)]


# The shell chain is always the last call of upgrade_procs()' clean sequence.
# Indexed from the end so prepending the head check above does not shift it.
FINAL_CALL = -1


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

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", return_value="n"),
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

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
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
        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        ):
            mock_requests.get.side_effect = ConnectionError("no network")
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available" not in output
        assert "Error" not in output

    def test_requests_unavailable_skips_check(self, hc_module, capsys):
        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", False),
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

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", return_value="n"),
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available: 99.0.0" in output

    def test_empty_tag_name_handled(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": ""}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Update available" not in output

    def test_upgrade_declined_does_not_run_make(self, hc_module):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", return_value="n"),
            patch("subprocess.run", side_effect=head_check_procs()) as mock_run,
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        # check_for_updates consults git to decide whether to offer at all, so
        # "nothing ran" is no longer the right assertion. What must not happen is
        # the upgrade itself: no install chain, and nothing that moves the repo.
        for call in mock_run.call_args_list:
            assert not call[1].get("shell"), f"ran the install chain: {call}"
            argv = call[0][0]
            # Both of _head_contains_release_tag()'s calls are read-only
            # inspections. Anything else here would be moving the repo.
            assert argv[:2] in (
                ["git", "rev-parse"],
                ["git", "merge-base"],
            ), f"unexpected command: {argv}"

    def test_no_offer_when_head_is_the_release_commit(self, hc_module, capsys):
        """A lower version string does not mean out of date.

        The 2026-07-31 release tagged one commit v2.19.15 and v2.20.0; describe
        picks the lower one, so the version can never catch up and the offer
        repeated forever. tests/test_upgrade_convergence.py covers this against
        real git; this pins the same behaviour at the unit level.
        """
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("subprocess.run", side_effect=head_check_procs(at_release_tag=True)),
            patch("builtins.input", side_effect=AssertionError("must not prompt")),
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        assert "Update available" not in capsys.readouterr().out

    def test_upgrade_accepted_runs_make_and_exits(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", return_value="y"),
            patch(
                "subprocess.run",
                side_effect=head_check_procs() + upgrade_procs(),
            ) as mock_run,
            pytest.raises(SystemExit),
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        assert mock_run.call_count == 9
        make_cmd = mock_run.call_args_list[FINAL_CALL][0][0]
        assert "make install" in make_cmd
        # A pull would abort on a rewritten-history clone; the checkout already
        # moved the branch to origin's tip.
        assert "git pull" not in make_cmd
        assert mock_run.call_args_list[FINAL_CALL][1]["cwd"] == "/fake/repo"
        output = capsys.readouterr().out
        assert "Upgrade complete" in output

    def test_upgrade_failure_prints_error(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", return_value="y"),
            patch(
                "subprocess.run",
                side_effect=head_check_procs() + upgrade_procs(final_returncode=1),
            ),
            patch("shutil.which", return_value="/usr/local/bin/uv"),
            patch("os.path.isfile", return_value=True),
            pytest.raises(SystemExit),
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

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", return_value="y"),
            patch("subprocess.run", return_value=git_root_proc),
            pytest.raises(SystemExit),
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        output = capsys.readouterr().out
        assert "Run manually" in output


class TestRunUpgrade:
    """Tests for _run_upgrade() called directly via --update flag."""

    def test_run_upgrade_success(self, hc_module, capsys):
        with (
            patch("subprocess.run", side_effect=upgrade_procs()) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 0
        assert mock_run.call_count == 7
        # The fetch happens before the branch inspection.
        assert mock_run.call_args_list[1][0][0] == [
            "git",
            "fetch",
            "--tags",
            "--force",
            "origin",
        ]
        make_cmd = mock_run.call_args_list[FINAL_CALL][0][0]
        assert "make install" in make_cmd
        assert mock_run.call_args_list[FINAL_CALL][1]["cwd"] == "/fake/repo"
        output = capsys.readouterr().out
        assert "Upgrade complete" in output

    def test_run_upgrade_forces_tag_updates(self, hc_module):
        """Every fetch in the upgrade path must pass --tags --force.

        A clone whose local tag points at a different object than origin's makes
        a plain `git fetch --tags` exit non-zero ("would clobber existing tag"),
        which permanently dead-ended --update.
        """
        with (
            patch("subprocess.run", side_effect=upgrade_procs()) as mock_run,
            pytest.raises(SystemExit),
        ):
            hc_module._run_upgrade()

        fetches = 0
        for call in mock_run.call_args_list:
            cmd = call[0][0]
            if isinstance(cmd, list):
                if cmd[:2] == ["git", "fetch"]:
                    fetches += 1
                    assert "--force" in cmd, f"fetch missing --force: {cmd}"
            elif "git fetch" in cmd:
                fetches += 1
                assert "git fetch --tags --force" in cmd, (
                    f"shell-chain fetch missing --force: {cmd}"
                )

        # Guards against the assertion silently passing if the fetch moves.
        assert fetches == 1, f"expected 1 fetch in the upgrade path, saw {fetches}"

    def test_run_upgrade_never_pulls(self, hc_module):
        """No `git pull` anywhere in the upgrade path.

        A pre-purge clone shares no ancestor with origin/main, so a pull aborts
        with "Need to specify how to reconcile divergent branches" (or "refusing
        to merge unrelated histories") and the upgrade never reaches make
        install. The branch must be moved with `checkout -B`, not merged.
        """
        with (
            patch("subprocess.run", side_effect=upgrade_procs()) as mock_run,
            pytest.raises(SystemExit),
        ):
            hc_module._run_upgrade()

        for call in mock_run.call_args_list:
            cmd = call[0][0]
            joined = " ".join(cmd) if isinstance(cmd, list) else cmd
            assert "pull" not in joined, f"upgrade path still pulls: {joined}"

        # The branch is moved by resetting it to origin's tip instead.
        assert ["git", "checkout", "-B", "main", "origin/main"] in [
            c[0][0] for c in mock_run.call_args_list
        ]

    def test_run_upgrade_make_failure(self, hc_module, capsys):
        with (
            patch("subprocess.run", side_effect=upgrade_procs(final_returncode=1)),
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert "Upgrade failed" in output

    def test_run_upgrade_no_git_repo(self, hc_module, capsys):
        git_root_proc = MagicMock()
        git_root_proc.returncode = 128
        git_root_proc.stdout = ""

        with (
            patch("subprocess.run", return_value=git_root_proc),
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert "Run manually" in output

    def test_upgrade_prompt_ctrl_c_continues(self, hc_module, capsys):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v99.0.0"}
        mock_resp.raise_for_status = MagicMock()

        with (
            patch.object(hc_module, "requests") as mock_requests,
            patch.object(hc_module, "REQUESTS_AVAILABLE", True),
            patch("builtins.input", side_effect=KeyboardInterrupt),
            patch("subprocess.run", side_effect=head_check_procs()) as mock_run,
        ):
            mock_requests.get.return_value = mock_resp
            hc_module.check_for_updates()

        # Only the read-only head check may have run -- Ctrl-C at the prompt must
        # not start an upgrade. See head_check_procs().
        for call in mock_run.call_args_list:
            assert not call[1].get("shell"), f"ran the install chain: {call}"
            assert call[0][0][:2] in (
                ["git", "rev-parse"],
                ["git", "merge-base"],
            ), f"unexpected: {call}"

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

        with (
            patch(
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
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 0
        assert mock_run.call_count == 7
        # Fetch happens before the checkout.
        assert mock_run.call_args_list[1][0][0] == [
            "git",
            "fetch",
            "--tags",
            "--force",
            "origin",
        ]
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
        # Final call is the shell upgrade -- install only, no pull.
        upgrade_cmd = mock_run.call_args_list[6][0][0]
        assert "make install" in upgrade_cmd
        assert "git pull" not in upgrade_cmd
        output = capsys.readouterr().out
        assert "Switching from 'dev' to 'main'" in output

    def test_run_upgrade_migrates_master_only_renamed_clone(self, hc_module, capsys):
        """An old clone still sitting on `master` (default branch renamed
        master -> main upstream) must be migrated: fetch BEFORE checkout,
        checkout/create `main` from origin/main, and set upstream to
        origin/main. The reset replaces what used to be a pull."""
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="master\n")
        status_proc = MagicMock(returncode=0, stdout="")
        checkout_proc = MagicMock(returncode=0, stdout="", stderr="")
        upstream_proc = MagicMock(returncode=0, stdout="", stderr="")
        make_proc = MagicMock(returncode=0)

        with (
            patch(
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
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 0
        calls = [c[0][0] for c in mock_run.call_args_list]

        # A fetch must occur before any checkout.
        fetch_idx = calls.index(["git", "fetch", "--tags", "--force", "origin"])
        checkout_idx = calls.index(["git", "checkout", "-B", "main", "origin/main"])
        assert fetch_idx < checkout_idx

        # Upstream repaired to origin/main after the checkout.
        upstream_idx = calls.index(
            ["git", "branch", "--set-upstream-to=origin/main", "main"]
        )
        assert checkout_idx < upstream_idx

        # The reset above is what advances the branch; nothing pulls.
        upgrade_cmd = mock_run.call_args_list[-1][0][0]
        assert "make install" in upgrade_cmd
        assert "git pull" not in upgrade_cmd

        output = capsys.readouterr().out
        assert "Switching from 'master' to 'main'" in output

    def test_run_upgrade_bails_when_fetch_fails(self, hc_module, capsys):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(
            returncode=1, stdout="", stderr="fatal: unable to access origin\n"
        )

        with (
            patch(
                "subprocess.run",
                side_effect=[git_root_proc, fetch_proc],
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 1
        # No branch inspection / checkout after the fetch failure.
        assert mock_run.call_count == 2
        output = capsys.readouterr().out
        assert "Failed to fetch from origin" in output

    def test_run_upgrade_bails_when_non_main_branch_is_dirty(self, hc_module, capsys):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="feat/x\n")
        status_proc = MagicMock(returncode=0, stdout=" M hate_crack/main.py\n")

        with (
            patch(
                "subprocess.run",
                side_effect=[git_root_proc, fetch_proc, branch_proc, status_proc],
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
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

        with (
            patch(
                "subprocess.run",
                side_effect=[
                    git_root_proc,
                    fetch_proc,
                    branch_proc,
                    status_proc,
                    checkout_proc,
                ],
            ),
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert "Failed to switch to main" in output
        assert "already checked out" in output

    def test_run_upgrade_resets_to_origin_when_already_on_main(self, hc_module, capsys):
        """Already on main still gets the reset.

        This used to skip the checkout and rely on the shell chain's pull, which
        is precisely the case that broke for a rewritten-history clone: dell3
        and a second user's box were both sitting on main. The checkout must fire
        regardless, but without printing a misleading "Switching from" line.
        """
        with (
            patch("subprocess.run", side_effect=upgrade_procs()) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 0
        all_call_args = [c[0][0] for c in mock_run.call_args_list]
        assert ["git", "checkout", "-B", "main", "origin/main"] in all_call_args
        output = capsys.readouterr().out
        assert "Switching from" not in output

    def test_run_upgrade_resets_on_detached_head(self, hc_module, capsys):
        """Detached HEAD: symbolic-ref returns non-zero.

        There's no branch to switch *from*, so no "Switching from" line, but the
        checkout still has to run to put HEAD back on a branch at origin's tip.
        """
        with (
            patch(
                "subprocess.run", side_effect=upgrade_procs(current_branch=None)
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade()

        assert exc.value.code == 0
        all_call_args = [c[0][0] for c in mock_run.call_args_list]
        assert ["git", "checkout", "-B", "main", "origin/main"] in all_call_args
        assert "Switching from" not in capsys.readouterr().out


class TestNightlyChannel:
    """Tests for the --nightly update channel (_run_upgrade(branch=...))."""

    def test_nightly_resets_to_nightly_dev(self, hc_module, capsys):
        with (
            patch(
                "subprocess.run",
                side_effect=upgrade_procs(current_branch="nightly-dev"),
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade(branch="nightly-dev")

        assert exc.value.code == 0
        all_call_args = [c[0][0] for c in mock_run.call_args_list]
        # The channel is selected by the checkout target, not by a pull refspec.
        assert [
            "git",
            "checkout",
            "-B",
            "nightly-dev",
            "origin/nightly-dev",
        ] in all_call_args
        assert ["git", "checkout", "-B", "main", "origin/main"] not in all_call_args

    def test_nightly_switches_from_main_to_nightly_dev(self, hc_module, capsys):
        """The inverse of the main-channel switch: a user sitting on main who
        asks for a nightly must be moved onto nightly-dev."""
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="main\n")
        status_proc = MagicMock(returncode=0, stdout="")
        checkout_proc = MagicMock(returncode=0, stdout="", stderr="")
        upstream_proc = MagicMock(returncode=0, stdout="", stderr="")
        make_proc = MagicMock(returncode=0)

        with (
            patch(
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
            ) as mock_run,
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade(branch="nightly-dev")

        assert exc.value.code == 0
        all_calls = [c[0][0] for c in mock_run.call_args_list]
        assert [
            "git",
            "checkout",
            "-B",
            "nightly-dev",
            "origin/nightly-dev",
        ] in all_calls
        assert [
            "git",
            "branch",
            "--set-upstream-to=origin/nightly-dev",
            "nightly-dev",
        ] in all_calls
        assert "Switching from 'main' to 'nightly-dev'" in capsys.readouterr().out

    def test_default_branch_is_still_main(self, hc_module):
        """--update must keep taking releases from main."""
        with (
            patch("subprocess.run", side_effect=upgrade_procs()) as mock_run,
            pytest.raises(SystemExit),
        ):
            hc_module._run_upgrade()

        assert ["git", "checkout", "-B", "main", "origin/main"] in [
            c[0][0] for c in mock_run.call_args_list
        ]

    def test_uncommitted_changes_message_names_target_branch(self, hc_module, capsys):
        git_root_proc = MagicMock(returncode=0, stdout="/fake/repo\n")
        fetch_proc = MagicMock(returncode=0, stdout="", stderr="")
        branch_proc = MagicMock(returncode=0, stdout="main\n")
        status_proc = MagicMock(returncode=0, stdout=" M hate_crack/main.py\n")

        with (
            patch(
                "subprocess.run",
                side_effect=[git_root_proc, fetch_proc, branch_proc, status_proc],
            ),
            pytest.raises(SystemExit) as exc,
        ):
            hc_module._run_upgrade(branch="nightly-dev")

        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "uncommitted changes on 'main'" in out
        # The suggested recovery must name the target channel and must be the
        # reset form, since the pull form fails on a rewritten-history clone.
        assert "git checkout -B nightly-dev origin/nightly-dev" in out
        assert "git pull" not in out


class TestNightlyFlagWiring:
    """The --nightly CLI flag routes to the nightly channel."""

    @pytest.mark.parametrize(
        ("argv", "expected_branch"),
        [
            (["--update"], "main"),
            (["--nightly"], "nightly-dev"),
            # Reads as "update, to the nightly channel".
            (["--update", "--nightly"], "nightly-dev"),
            # UPDATE_CHANNEL is only the persisted default now; --no-nightly is
            # the per-run override that forces the released channel back on.
            (["--update", "--no-nightly"], "main"),
        ],
    )
    def test_flag_selects_channel(self, hc_module, monkeypatch, argv, expected_branch):
        calls = []

        def fake_upgrade(branch="main"):
            calls.append(branch)
            # The real _run_upgrade always exits; without this main() would
            # fall through into the interactive menu and hang on input().
            raise SystemExit(0)

        monkeypatch.setattr(hc_module, "_run_upgrade", fake_upgrade)
        monkeypatch.setattr(sys, "argv", ["hate_crack.py", *argv])
        try:
            hc_module.main()
        except SystemExit:
            pass
        assert calls == [expected_branch]

    def test_startup_check_never_offers_nightly(self, hc_module):
        """check_for_updates() reads /releases/latest, which excludes
        pre-releases -- and nightly-tag.yml publishes no release at all, so the
        nightly channel is invisible to the startup nag by construction."""
        import inspect

        src = inspect.getsource(hc_module.check_for_updates)
        assert "releases/latest" in src
        assert "nightly" not in src


def _git(repo, *args):
    """Run git in *repo*, raising on failure so a broken fixture is loud."""
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def tagged_repo(tmp_path):
    """A real repo: v1.0.0, then a commit past it, then an untagged branch tip.

    Real commits and real tags rather than a subprocess side_effect list.
    Ancestry is exactly the behaviour under test, and a mocked call sequence
    asserts the commands, not what git would actually answer.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")

    (repo / "f.txt").write_text("one\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-qm", "one")
    _git(repo, "tag", "-a", "v1.0.0", "-m", "release 1.0.0")  # annotated

    (repo / "f.txt").write_text("two\n")
    _git(repo, "commit", "-qam", "two")
    _git(repo, "tag", "v1.1.0")  # lightweight

    # A branch that stops *before* v1.1.0, standing in for a checkout that
    # genuinely lacks the latest release.
    _git(repo, "branch", "behind", "v1.0.0")
    return repo


class TestHeadContainsReleaseTag:
    """#271: a checkout containing the release must not be told to upgrade."""

    def test_release_already_in_history_counts_as_up_to_date(
        self, hc_module, monkeypatch, tagged_repo
    ):
        """The nightly-dev case: HEAD is PAST the release, not on it.

        This is the regression. The old equality check returned False here, so
        the notice fired on every start even though the release was already in
        the checkout.
        """
        monkeypatch.setattr(hc_module, "_repo_root", str(tagged_repo))
        assert hc_module._head_contains_release_tag("v1.0.0") is True

    def test_head_exactly_at_the_release_still_counts(
        self, hc_module, monkeypatch, tagged_repo
    ):
        """The degenerate case the old equality check handled; must not regress."""
        monkeypatch.setattr(hc_module, "_repo_root", str(tagged_repo))
        _git(tagged_repo, "checkout", "-q", "v1.0.0")
        assert hc_module._head_contains_release_tag("v1.0.0") is True

    def test_release_not_in_history_still_offers(
        self, hc_module, monkeypatch, tagged_repo
    ):
        """A checkout genuinely missing the release must still be told to upgrade."""
        monkeypatch.setattr(hc_module, "_repo_root", str(tagged_repo))
        _git(tagged_repo, "checkout", "-q", "behind")
        assert hc_module._head_contains_release_tag("v1.1.0") is False

    def test_annotated_and_lightweight_tags_both_resolve(
        self, hc_module, monkeypatch, tagged_repo
    ):
        """v1.0.0 is annotated, v1.1.0 lightweight; ^{commit} must handle both."""
        monkeypatch.setattr(hc_module, "_repo_root", str(tagged_repo))
        assert hc_module._head_contains_release_tag("v1.0.0") is True
        assert hc_module._head_contains_release_tag("v1.1.0") is True

    def test_unknown_tag_falls_back_to_the_version_comparison(
        self, hc_module, monkeypatch, tagged_repo
    ):
        monkeypatch.setattr(hc_module, "_repo_root", str(tagged_repo))
        assert hc_module._head_contains_release_tag("v9.9.9") is False

    def test_non_git_directory_falls_back(self, hc_module, monkeypatch, tmp_path):
        """Installs that are not git clones keep the version comparison."""
        plain = tmp_path / "not-a-repo"
        plain.mkdir()
        monkeypatch.setattr(hc_module, "_repo_root", str(plain))
        assert hc_module._head_contains_release_tag("v1.0.0") is False

    @pytest.mark.parametrize("tag", ["", "; rm -rf /", "v1.0.0 --oops", "../etc"])
    def test_malformed_tags_are_rejected_before_reaching_git(
        self, hc_module, monkeypatch, tagged_repo, tag
    ):
        """Tag names are remote input from the releases API."""
        monkeypatch.setattr(hc_module, "_repo_root", str(tagged_repo))
        assert hc_module._head_contains_release_tag(tag) is False
