"""The upgrade must converge: upgrading once must stop the offer.

Everything in test_version_check.py and test_upgrade_real_git.py asserts upgrade
*mechanics* -- which commands get built, whether HEAD moves, whether a rewritten
clone recovers. None of it asserts the property users actually care about: after
an upgrade succeeds, the next start must not offer the same upgrade again.

That gap let a real loop ship. On 2026-07-31 the release pipeline left commit
e37d568 carrying two tags, v2.19.15 (cut by nightly-tag.yml) and v2.20.0 (cut by
auto-tag.yml), because main and nightly-dev pointed at the same commit and both
workflow_run triggers fired on it. `git describe` breaks a same-commit tie by ref
iteration order, which is lexicographic, so v2.19.15 wins and setuptools-scm
reports 2.19.15. The releases API reports 2.20.0. Every start offered an upgrade;
accepting it re-fetched the same two tags, landed on the same commit, regenerated
the same 2.19.15, and offered again on the next start. No number of upgrades
could clear it, and it affected every user who upgraded to that release.

The tests here run real git so the version really comes from a real describe.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tests.test_upgrade_real_git import _git, _init


def _release_response(tag):
    """A stand-in for the GitHub releases-latest payload."""
    resp = MagicMock()
    resp.json.return_value = {"tag_name": tag}
    resp.raise_for_status.return_value = None
    return resp


@pytest.fixture
def hc_module():
    import importlib
    import os

    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    return importlib.import_module("hate_crack.main")


@pytest.fixture
def double_tagged_remote_and_clone(tmp_path):
    """A remote whose released commit carries two tags from two version series.

    Returns (remote, clone, describe_version, release_tag). The clone sits on
    main at the released commit, exactly as a user who just upgraded would.
    """
    remote = _init(tmp_path / "remote")
    (remote / "app.py").write_text("print('2.19.14')\n")
    _git("add", "-A", cwd=remote)
    _git("commit", "-qm", "previous release", cwd=remote)
    _git("tag", "v2.19.14", cwd=remote)

    (remote / "app.py").write_text("print('2.20.0')\n")
    _git("add", "-A", cwd=remote)
    _git("commit", "-qm", "docs(changelog): cut the [Unreleased] section", cwd=remote)
    # The collision: nightly-tag.yml cut the patch, auto-tag.yml cut the minor,
    # both on this one commit.
    _git("tag", "v2.19.15", cwd=remote)
    _git("tag", "v2.20.0", cwd=remote)

    clone = tmp_path / "clone"
    _git("clone", "-q", str(remote), str(clone), cwd=tmp_path)

    described = _git(
        "describe", "--tags", "--long", "--match", "*[0-9]*", cwd=clone
    ).stdout.strip()
    return remote, clone, described, "v2.20.0"


def test_describe_picks_the_lower_tag_when_a_commit_carries_two(
    double_tagged_remote_and_clone,
):
    """The precondition, in real git: the version can never reach the release.

    setuptools-scm derives the version from this exact command, so whatever it
    resolves to is what __version__ becomes. Asserted so that a future git
    changing its tie-break is a visible failure here rather than a silent
    behaviour change in the update check.
    """
    _remote, clone, described, _release_tag = double_tagged_remote_and_clone
    assert described.startswith("v2.19.15-0-"), (
        f"expected describe to resolve to the lower co-located tag, got {described}"
    )
    # Both tags really are on HEAD -- the fixture is not just missing v2.20.0.
    points_at = set(_git("tag", "--points-at", "HEAD", cwd=clone).stdout.split())
    assert points_at == {"v2.19.15", "v2.20.0"}


def test_no_offer_when_head_already_carries_the_latest_release_tag(
    hc_module, double_tagged_remote_and_clone, capsys
):
    """The regression: being AT the release means up to date, whatever describe says.

    This is the loop. The version string is genuinely lower than the release, so
    a pure version comparison offers an upgrade that cannot possibly change
    anything, forever.
    """
    _remote, clone, _described, release_tag = double_tagged_remote_and_clone

    with (
        patch.object(hc_module, "_repo_root", str(clone)),
        patch("hate_crack.__version__", "2.19.15"),
        patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        patch.object(
            hc_module.requests, "get", return_value=_release_response(release_tag)
        ),
        patch("builtins.input", side_effect=AssertionError("must not prompt")),
    ):
        hc_module.check_for_updates()

    out = capsys.readouterr().out
    assert "Update available" not in out, (
        "offered an upgrade while already sitting on the release tag: " + out
    )


def test_offer_still_fires_when_the_release_tag_is_not_at_head(
    hc_module, double_tagged_remote_and_clone, capsys
):
    """The guard must not swallow real updates -- the case that matters most.

    Same repository, but the clone is parked one commit back, so there genuinely
    is something to upgrade to.
    """
    _remote, clone, _described, release_tag = double_tagged_remote_and_clone
    _git("checkout", "-q", "v2.19.14", cwd=clone)

    with (
        patch.object(hc_module, "_repo_root", str(clone)),
        patch("hate_crack.__version__", "2.19.14"),
        patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        patch.object(
            hc_module.requests, "get", return_value=_release_response(release_tag)
        ),
        patch("builtins.input", return_value="n"),
    ):
        hc_module.check_for_updates()

    assert "Update available: 2.20.0" in capsys.readouterr().out


def test_offer_still_fires_when_there_is_no_git_repo(hc_module, tmp_path, capsys):
    """A non-checkout install has no HEAD to compare, so fall back to versions.

    Without this, making the tag check authoritative would silence the update
    notice entirely for anyone running from an unpacked tarball.
    """
    plain = tmp_path / "not-a-repo"
    plain.mkdir()

    with (
        patch.object(hc_module, "_repo_root", str(plain)),
        patch("hate_crack.__version__", "2.19.14"),
        patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        patch.object(
            hc_module.requests, "get", return_value=_release_response("v2.20.0")
        ),
        patch("builtins.input", return_value="n"),
    ):
        hc_module.check_for_updates()

    assert "Update available: 2.20.0" in capsys.readouterr().out


def test_upgrade_is_a_fixed_point(hc_module, double_tagged_remote_and_clone, capsys):
    """End to end: upgrade for real, then prove the next start stays quiet.

    The two halves of the loop are only visible together. Each half looks correct
    in isolation -- _run_upgrade does land on origin's tip, and check_for_updates
    does compare versions correctly -- but composed they never terminate.
    """
    _remote, clone, _described, release_tag = double_tagged_remote_and_clone
    # Park the clone one commit back so the upgrade has real work to do.
    _git("checkout", "-q", "-B", "main", "v2.19.14", cwd=clone)

    real_run = subprocess.run

    def stub_install(cmd, *args, **kwargs):
        if kwargs.get("shell"):
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return real_run(cmd, *args, **kwargs)

    with (
        patch.object(hc_module, "_repo_root", str(clone)),
        patch("subprocess.run", side_effect=stub_install),
        pytest.raises(SystemExit) as exc,
    ):
        hc_module._run_upgrade()
    assert exc.value.code == 0, capsys.readouterr().out

    # The upgrade landed on the released commit, and the release tag is here.
    assert (
        _git("rev-parse", "HEAD", cwd=clone).stdout.strip()
        == _git("rev-parse", "main", cwd=_remote).stdout.strip()
    )
    assert release_tag in _git("tag", "--points-at", "HEAD", cwd=clone).stdout.split()

    # setuptools-scm would still regenerate the LOWER version from this tree, so
    # the restarted process is back where it started as far as versions go.
    regenerated = _git(
        "describe", "--tags", "--long", "--match", "*[0-9]*", cwd=clone
    ).stdout.strip()
    assert regenerated.startswith("v2.19.15-0-")

    capsys.readouterr()
    with (
        patch.object(hc_module, "_repo_root", str(clone)),
        patch("hate_crack.__version__", "2.19.15"),
        patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        patch.object(
            hc_module.requests, "get", return_value=_release_response(release_tag)
        ),
        patch("builtins.input", side_effect=AssertionError("must not prompt again")),
    ):
        hc_module.check_for_updates()

    out = capsys.readouterr().out
    assert "Update available" not in out, (
        "upgrade did not converge -- the restarted process offers it again: " + out
    )


def test_tag_name_from_the_api_is_never_shell_interpreted(
    hc_module, double_tagged_remote_and_clone, capsys
):
    """The tag name is remote input and now reaches git, so pin that it is safe.

    A hostile or merely malformed tag_name must not run a command or crash the
    check; the worst it may do is fail to match and fall through to the version
    comparison.
    """
    _remote, clone, _described, _release_tag = double_tagged_remote_and_clone
    canary = clone / "pwned"

    with (
        patch.object(hc_module, "_repo_root", str(clone)),
        patch("hate_crack.__version__", "2.19.15"),
        patch.object(hc_module, "REQUESTS_AVAILABLE", True),
        patch.object(
            hc_module.requests,
            "get",
            return_value=_release_response("v2.20.0; touch pwned"),
        ),
        patch("builtins.input", return_value="n"),
    ):
        hc_module.check_for_updates()

    assert not canary.exists(), "tag name from the API reached a shell"
