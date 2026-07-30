"""_run_upgrade() against real git repositories.

The rest of the upgrade coverage in test_version_check.py mocks subprocess.run
wholesale, so it only asserts which command strings get built -- a mocked
`git pull` always "succeeds". That is why a clone whose history had been
rewritten could dead-end `--update` in the field while the suite stayed green.
These tests run the actual git commands instead, so a command that cannot work
on a real repository fails here.

The scenario reproduced is the 2026-07-25 purge of CLAUDE.md/.claude/docs from
published history: every commit got a new SHA, so a clone predating it shares no
ancestor with origin and holds tags pointing at objects origin no longer has.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest


def _git(*args, cwd, check=True):
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=check,
    )


def _init(path):
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", "-b", "main", cwd=path)
    _git("config", "user.email", "t@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    # Leave pull.rebase unset, matching a default user install: that is what
    # turns a divergent pull into "Need to specify how to reconcile".
    return path


@pytest.fixture
def rewritten_remote_and_clone(tmp_path):
    """A clone whose history was rewritten out from under it.

    Returns (remote, clone). The clone sits on `main` at the pre-rewrite commit
    and carries tag v1.0 pointing at an object the remote no longer contains.
    """
    remote = _init(tmp_path / "remote")
    (remote / "CLAUDE.md").write_text("local-only instructions\n")
    (remote / "app.py").write_text("print('v1')\n")
    _git("add", "-A", cwd=remote)
    _git("commit", "-qm", "release 1.0", cwd=remote)
    _git("tag", "v1.0", cwd=remote)

    clone = tmp_path / "clone"
    _git("clone", "-q", str(remote), str(clone), cwd=tmp_path)
    pre_purge_tag = _git("rev-parse", "v1.0", cwd=clone).stdout.strip()

    # Rewrite the remote's history: an orphan branch reproduces what filter-repo
    # does to SHAs (new objects, no shared ancestry) without the dependency.
    _git("checkout", "-q", "--orphan", "rewritten", cwd=remote)
    (remote / "CLAUDE.md").unlink()
    (remote / "app.py").write_text("print('v2')\n")
    _git("add", "-A", cwd=remote)
    _git("commit", "-qm", "release 1.1 (purged history)", cwd=remote)
    _git("branch", "-qD", "main", cwd=remote)
    _git("branch", "-qm", "main", cwd=remote)
    _git("tag", "-d", "v1.0", cwd=remote)
    _git("tag", "v1.0", cwd=remote)
    _git("tag", "v1.1", cwd=remote)

    post_purge_tag = _git("rev-parse", "v1.0", cwd=remote).stdout.strip()
    assert pre_purge_tag != post_purge_tag, "fixture failed to diverge the tag"
    return remote, clone


def test_plain_fetch_tags_is_rejected(rewritten_remote_and_clone):
    """Establishes the precondition: this is the failure users reported."""
    _remote, clone = rewritten_remote_and_clone
    result = _git("fetch", "--tags", cwd=clone, check=False)
    assert result.returncode != 0
    assert "would clobber existing tag" in result.stderr


def test_plain_pull_cannot_advance_a_rewritten_clone(rewritten_remote_and_clone):
    """Establishes the second precondition, the one --force alone did not fix."""
    _remote, clone = rewritten_remote_and_clone
    _git("fetch", "--tags", "--force", cwd=clone)
    result = _git("pull", "origin", "main", cwd=clone, check=False)
    assert result.returncode != 0, "expected the pull to fail on divergent history"
    combined = result.stderr + result.stdout
    assert (
        "unrelated histories" in combined
        or "Need to specify how to reconcile" in combined
        or "divergent branches" in combined
    ), f"unexpected pull failure mode: {combined}"


def test_run_upgrade_recovers_a_rewritten_clone(
    hc_module_real_git, rewritten_remote_and_clone, capsys
):
    """The whole point: --update must work on such a clone, unattended.

    Only the final install chain is stubbed -- every git command runs for real
    against the fixture repositories.
    """
    _remote, clone = rewritten_remote_and_clone
    real_run = subprocess.run
    shell_calls = []

    def passthrough(cmd, *args, **kwargs):
        if kwargs.get("shell"):
            shell_calls.append(cmd)

            class Ok:
                returncode = 0
                stdout = ""
                stderr = ""

            return Ok()
        return real_run(cmd, *args, **kwargs)

    with (
        patch.object(hc_module_real_git, "_repo_root", str(clone)),
        patch("subprocess.run", side_effect=passthrough),
        pytest.raises(SystemExit) as exc,
    ):
        hc_module_real_git._run_upgrade()

    assert exc.value.code == 0, capsys.readouterr().out

    # The clone is now actually on origin's rewritten tip.
    local_head = _git("rev-parse", "HEAD", cwd=clone).stdout.strip()
    remote_head = _git("rev-parse", "main", cwd=_remote).stdout.strip()
    assert local_head == remote_head

    # The purged file is gone and the new content is present, so setuptools-scm
    # and make install would see the released tree.
    assert not (clone / "CLAUDE.md").exists()
    assert (clone / "app.py").read_text() == "print('v2')\n"

    # Tags were force-updated, so the new release tag is visible.
    assert _git("rev-parse", "v1.1", cwd=clone, check=False).returncode == 0
    assert (
        _git("rev-parse", "v1.0", cwd=clone).stdout.strip()
        == _git("rev-parse", "v1.0", cwd=_remote).stdout.strip()
    )

    assert shell_calls and "make install" in shell_calls[0]


def test_run_upgrade_refuses_to_discard_uncommitted_work(
    hc_module_real_git, rewritten_remote_and_clone, capsys
):
    """The reset is destructive to tracked edits, so the dirty guard must hold.

    This matters more now than when the checkout only ran on a branch switch:
    the reset fires on every upgrade, including one started from main.
    """
    _remote, clone = rewritten_remote_and_clone
    (clone / "app.py").write_text("print('my local edit')\n")

    with (
        patch.object(hc_module_real_git, "_repo_root", str(clone)),
        pytest.raises(SystemExit) as exc,
    ):
        hc_module_real_git._run_upgrade()

    assert exc.value.code == 1
    assert "uncommitted changes" in capsys.readouterr().out
    # The edit survives.
    assert (clone / "app.py").read_text() == "print('my local edit')\n"


@pytest.fixture
def hc_module_real_git():
    import importlib
    import os

    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    return importlib.import_module("hate_crack.main")


def test_upgrade_path_has_no_pull(hc_module_real_git):
    """Guards the source itself: reintroducing a pull here re-breaks the field.

    A future edit could add a pull back without any mocked test noticing, since
    a mocked pull always succeeds.
    """
    import ast

    tree = ast.parse(Path(hc_module_real_git.__file__).read_text())
    func = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_run_upgrade"
    )
    # The raw docstring node, not ast.get_docstring() -- that dedents the text,
    # so it no longer compares equal to the literal in the tree.
    doc_node = None
    if func.body and isinstance(func.body[0], ast.Expr):
        first = func.body[0].value
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            doc_node = first

    # Every string literal the function builds a command from, minus the
    # docstring and comments (comments are not in the AST at all).
    literals = [
        node.value
        for node in ast.walk(func)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node is not doc_node
    ]
    offenders = [lit for lit in literals if "pull" in lit]
    assert not offenders, f"_run_upgrade() must not pull: {offenders}"
