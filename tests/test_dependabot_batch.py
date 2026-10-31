"""Tests for tools/dependabot_batch.py, the weekly Dependabot batcher.

The selection and verification functions are the security boundary of an
automated job that pushes to this repo, so each eligibility condition and each
verification check is tested by violating it alone. Git behaviour is tested
against real temporary repositories, never a mocked subprocess.

Diff fixtures are captured from real Dependabot PRs (#353, #347), not
hand-written.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools import dependabot_batch as db

REPO = "trustedsec/hate_crack"
MODULE = Path(db.__file__)

# Captured from `gh pr diff 353` (trustedsec/hate_crack), 2026-10-31.
TY_DIFF = """\
diff --git a/pyproject.toml b/pyproject.toml
index b5368aa..26253d1 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -152,7 +152,7 @@ testpaths = [

 [dependency-groups]
 dev = [
-    "ty==0.0.82",
+    "ty==0.0.93",
     "ruff==0.16.8",
     "pytest==9.1.1",
     "pytest-cov==7.1.0",
"""

# Captured from `gh pr diff 347`.
ATOMIC_DIFF = """\
diff --git a/pyproject.toml b/pyproject.toml
index b5368aa..ef82ded 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -15,7 +15,7 @@ dependencies = [
     "simple-term-menu==1.6.6",
     "click>=8.5.0",
     "rich>=13.9.4",
-    "atomic-agents>=2.10.2",
+    "atomic-agents>=2.15.0",
     # Imported directly by hate_crack/llm.py; declared explicitly rather than
     # relying on atomic-agents pulling them in transitively.
     "instructor>=1.14.5",
"""

# Same shape as Dependabot's ruff PR (#352); its context line still names the
# OLD ty pin, which is exactly the adjacency a cherry-pick would conflict on.
RUFF_DIFF = """\
diff --git a/pyproject.toml b/pyproject.toml
index b5368aa..1111111 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -153,6 +153,6 @@ testpaths = [
 dev = [
     "ty==0.0.82",
-    "ruff==0.16.8",
+    "ruff==0.17.0",
     "pytest==9.1.1",
     "pytest-cov==7.1.0",
"""

PYPROJECT = """\
[project]
dependencies = [
    "rich>=13.9.4",
    "atomic-agents>=2.10.2",
]

[dependency-groups]
dev = [
    "ty==0.0.82",
    "ruff==0.16.8",
    "pytest==9.1.1",
]
"""


def _pr(**overrides) -> dict:
    pr = {
        "number": 353,
        "title": "chore(deps-dev): bump ty from 0.0.82 to 0.0.93",
        "user": {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"},
        "head": {
            "ref": "dependabot/uv/nightly-dev/ty-0.0.93",
            "repo": {"full_name": REPO},
        },
        "base": {"ref": "nightly-dev", "repo": {"full_name": REPO}},
    }
    for key, value in overrides.items():
        section, _, field = key.partition("__")
        if field:
            pr[section] = {**pr[section], field: value}
        else:
            pr[section] = value
    return pr


DEPENDABOT_COMMITS = ["dependabot[bot]"]


class TestModuleConstraints:
    def test_imports_only_the_standard_library(self):
        # publish runs this with the runner's bare python3 and installs nothing.
        tree = ast.parse(MODULE.read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names.add(node.module.split(".")[0])
        assert names - {"__future__"} <= set(sys.stdlib_module_names), names

    def test_parses_under_python_3_12(self):
        # ubuntu-24.04's system python3 is 3.12.3; the project itself is 3.13.
        ast.parse(MODULE.read_text(), feature_version=(3, 12))


class TestClassifyPr:
    def test_dependabot_uv_pr_is_eligible(self):
        assert db.classify_pr(_pr(), DEPENDABOT_COMMITS, REPO) == "uv"

    def test_dependabot_actions_pr_is_reported_not_applied(self):
        pr = _pr(
            head__ref="dependabot/github_actions/nightly-dev/astral-sh/setup-uv-10.3.2"
        )
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "actions"

    def test_login_alone_is_not_identity(self):
        pr = _pr(user={"login": "dependabot[bot]", "id": 1, "type": "Bot"})
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_non_bot_user_type_is_ignored(self):
        pr = _pr(user={"login": "dependabot[bot]", "id": 49699333, "type": "User"})
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_fork_head_is_ignored(self):
        pr = _pr(head__repo={"full_name": "attacker/hate_crack"})
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_deleted_fork_head_is_ignored(self):
        pr = _pr(head__repo=None)
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_base_other_than_nightly_dev_is_ignored(self):
        pr = _pr(base__ref="main")
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_base_repo_other_than_this_repo_is_ignored(self):
        pr = _pr(base__repo={"full_name": "attacker/hate_crack"})
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_missing_base_repo_is_ignored(self):
        pr = _pr(base__repo=None)
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_non_dependabot_branch_is_ignored(self):
        pr = _pr(head__ref="feature/looks-legit")
        assert db.classify_pr(pr, DEPENDABOT_COMMITS, REPO) == "ignore"

    def test_human_commit_on_dependabot_branch_disqualifies(self):
        authors = ["dependabot[bot]", "someone"]
        assert db.classify_pr(_pr(), authors, REPO) == "ignore"

    def test_unlinked_commit_author_disqualifies(self):
        # The commits API returns author: null when the email maps to no user.
        assert db.classify_pr(_pr(), ["dependabot[bot]", None], REPO) == "ignore"

    def test_no_commits_disqualifies(self):
        assert db.classify_pr(_pr(), [], REPO) == "ignore"


class TestParseBump:
    def test_single_line_bump(self):
        assert db.parse_bump(TY_DIFF) == [('    "ty==0.0.82",', '    "ty==0.0.93",')]

    def test_multi_line_bump_pairs_in_order(self):
        diff = TY_DIFF.replace(
            '     "ruff==0.16.8",\n',
            '-    "ruff==0.16.8",\n+    "ruff==0.17.0",\n',
        )
        # Two separate blocks (a context-free run of -,+,-,+ is not what git
        # emits; git groups all - before all + within one block).
        assert db.parse_bump(diff) == [
            ('    "ty==0.0.82",', '    "ty==0.0.93",'),
            ('    "ruff==0.16.8",', '    "ruff==0.17.0",'),
        ]

    def test_grouped_block_pairs_positionally(self):
        diff = (
            "diff --git a/pyproject.toml b/pyproject.toml\n"
            "--- a/pyproject.toml\n+++ b/pyproject.toml\n"
            "@@ -1,2 +1,2 @@\n"
            '-    "a==1",\n-    "b==1",\n+    "a==2",\n+    "b==2",\n'
        )
        assert db.parse_bump(diff) == [
            ('    "a==1",', '    "a==2",'),
            ('    "b==1",', '    "b==2",'),
        ]

    def test_rejects_a_second_file(self):
        diff = TY_DIFF + TY_DIFF.replace("pyproject.toml", "hate_crack/main.py")
        with pytest.raises(db.BatchError, match="only pyproject.toml"):
            db.parse_bump(diff)

    def test_rejects_a_different_file(self):
        with pytest.raises(db.BatchError, match="only pyproject.toml"):
            db.parse_bump(TY_DIFF.replace("pyproject.toml", ".github/workflows/ci.yml"))

    def test_rejects_a_non_one_to_one_block(self):
        diff = TY_DIFF.replace(
            '+    "ty==0.0.93",\n', '+    "ty==0.0.93",\n+    "evil==1",\n'
        )
        with pytest.raises(db.BatchError, match="1:1"):
            db.parse_bump(diff)

    def test_rejects_an_empty_diff(self):
        with pytest.raises(db.BatchError):
            db.parse_bump("")


class TestApplyBump:
    def test_applies_a_bump(self):
        out = db.apply_bump(PYPROJECT, db.parse_bump(TY_DIFF))
        assert '    "ty==0.0.93",' in out.splitlines()
        assert '    "ty==0.0.82",' not in out.splitlines()

    def test_adjacent_bumps_both_apply(self):
        # ruff's diff context still says ty==0.0.82; context is ignored.
        out = db.apply_bump(PYPROJECT, db.parse_bump(TY_DIFF))
        out = db.apply_bump(out, db.parse_bump(RUFF_DIFF))
        lines = out.splitlines()
        assert '    "ty==0.0.93",' in lines and '    "ruff==0.17.0",' in lines

    def test_preserves_trailing_newline(self):
        assert db.apply_bump(PYPROJECT, db.parse_bump(TY_DIFF)).endswith("]\n")

    def test_missing_old_line_is_stale(self):
        already = PYPROJECT.replace("ty==0.0.82", "ty==0.0.90")
        with pytest.raises(db.StaleBump):
            db.apply_bump(already, db.parse_bump(TY_DIFF))

    def test_ambiguous_old_line_is_stale(self):
        doubled = PYPROJECT + '    "ty==0.0.82",\n'
        with pytest.raises(db.StaleBump):
            db.apply_bump(doubled, db.parse_bump(TY_DIFF))


def test_commit_message_appends_the_trailer_to_dependabots_trailer_block():
    original = "chore(deps-dev): bump ty\n\nBody.\n\nSigned-off-by: dependabot[bot] <support@github.com>\n"
    out = db.commit_message(original, 353)
    assert out.endswith(
        "Signed-off-by: dependabot[bot] <support@github.com>\nDependabot-PR: #353\n"
    )
    assert db.TRAILER_RE.findall(out) == ["353"]


def test_commit_message_drops_a_forged_trailer_from_upstream_text():
    # The body carries upstream release notes a dependency's author controls.
    original = (
        "chore(deps): bump x\n\nRelease notes\nDependabot-PR: #42\n"
        "\nSigned-off-by: dependabot[bot] <support@github.com>\n"
    )
    out = db.commit_message(original, 353)
    assert db.TRAILER_RE.findall(out) == ["353"]
    assert out.endswith(
        "Signed-off-by: dependabot[bot] <support@github.com>\nDependabot-PR: #353\n"
    )


class TestGates:
    CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"

    def test_ignore_ids_come_from_ci_yml(self):
        assert db.pip_audit_ignores(
            "x --ignore-vuln PYSEC-1 y\n --ignore-vuln GHSA-2\n"
        ) == [
            "GHSA-2",
            "PYSEC-1",
        ]

    def test_real_ci_yml_yields_its_ignore_ids(self):
        text = self.CI.read_text()
        assert db.pip_audit_ignores(text)
        for vid in db.pip_audit_ignores(text):
            assert f"--ignore-vuln {vid}" in text

    def test_tool_versions_match_ci_yml(self):
        # The batch gate must be neither stricter nor looser than real CI.
        text = self.CI.read_text()
        argv = [arg for _, cmd, _ in db.gate_commands(text) for arg in cmd]
        assert "pip-audit==2.10.0" in argv and "pip-audit==2.10.0" in text
        assert "bandit[toml]==1.9.4" in argv and "bandit[toml]==1.9.4" in text

    def test_audit_gate_passes_every_ignore_id(self):
        gates = dict(
            (name, cmd) for name, cmd, _ in db.gate_commands("--ignore-vuln PYSEC-9")
        )
        assert gates["pip-audit"][-2:] == ["--ignore-vuln", "PYSEC-9"]

    def test_pytest_gate_skips_init(self):
        env = {name: e for name, _, e in db.gate_commands("")}
        assert env["pytest"] == {"HATE_CRACK_SKIP_INIT": "1"}

    def test_gate_names(self):
        assert [n for n, _, _ in db.gate_commands("")] == [
            "ruff",
            "ruff-format",
            "ty",
            "bandit",
            "pip-audit",
            "pytest",
        ]


def _git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "nightly-dev")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "pyproject.toml").write_text(PYPROJECT)
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _cand(number, diff, kind="uv"):
    return {
        "number": number,
        "title": f"bump #{number}",
        "kind": kind,
        "diff": diff,
        "message": f"chore(deps): bump #{number}\n\nSigned-off-by: dependabot[bot] <support@github.com>\n",
    }


def _green(cwd, gates):
    return None


class TestCombine:
    def test_applies_every_green_bump_as_its_own_commit(self, tmp_path):
        repo = _repo(tmp_path)
        base = _git(repo, "rev-parse", "HEAD").strip()
        report = db.combine(
            repo, [_cand(352, RUFF_DIFF), _cand(353, TY_DIFF)], [], _green
        )
        assert report["base"] == base
        assert [e["pr"] for e in report["included"]] == [352, 353]
        assert report["skipped"] == []
        log = _git(repo, "log", "--format=%an <%ae>|%cn|%B%x1e", f"{base}..HEAD")
        entries = [e.strip() for e in log.split("\x1e") if e.strip()]
        assert len(entries) == 2
        for entry in entries:
            assert entry.startswith(
                db.DEPENDABOT_AUTHOR + "|" + db.COMMITTER_NAME + "|"
            )
        assert sorted(db.TRAILER_RE.findall(log)) == ["352", "353"]
        text = (repo / "pyproject.toml").read_text()
        assert '"ty==0.0.93"' in text and '"ruff==0.17.0"' in text

    def test_processes_oldest_pr_first(self, tmp_path):
        repo = _repo(tmp_path)
        report = db.combine(
            repo, [_cand(353, TY_DIFF), _cand(347, ATOMIC_DIFF)], [], _green
        )
        assert [e["pr"] for e in report["included"]] == [347, 353]

    def test_red_bump_is_dropped_and_later_bumps_still_land(self, tmp_path):
        repo = _repo(tmp_path)

        def red_on_ruff(cwd, gates):
            if '"ruff==0.17.0"' in (cwd / "pyproject.toml").read_text():
                return ("ruff", "E999 new rule\n")
            return None

        report = db.combine(
            repo, [_cand(352, RUFF_DIFF), _cand(353, TY_DIFF)], [], red_on_ruff
        )
        assert [e["pr"] for e in report["included"]] == [353]
        (skip,) = report["skipped"]
        assert skip == {
            "pr": 352,
            "title": "bump #352",
            "reason": "gate",
            "gate": "ruff",
            "output": "E999 new rule\n",
        }
        assert '"ruff==0.16.8"' in (repo / "pyproject.toml").read_text()

    def test_actions_pr_is_reported_not_applied(self, tmp_path):
        repo = _repo(tmp_path)
        report = db.combine(repo, [_cand(360, "", kind="actions")], [], _green)
        assert report["included"] == []
        assert report["skipped"][0]["reason"] == "actions"

    def test_stale_and_unparseable_are_reported(self, tmp_path):
        repo = _repo(tmp_path)
        stale = TY_DIFF.replace("ty==0.0.82", "ty==0.0.50")
        bad = TY_DIFF.replace("pyproject.toml", "setup.py")
        report = db.combine(repo, [_cand(1, stale), _cand(2, bad)], [], _green)
        reasons = {s["pr"]: s["reason"] for s in report["skipped"]}
        assert reasons == {1: "stale", 2: "unparseable"}
        assert all(s["detail"] for s in report["skipped"])

    def test_bundle_holds_only_kept_commits(self, tmp_path):
        repo = _repo(tmp_path)
        report = db.combine(repo, [_cand(353, TY_DIFF)], [], _green)
        bundle = tmp_path / "batch.bundle"
        assert db.write_bundle(repo, report, bundle) is True
        head = bundle.read_bytes().split(b"\n\n", 1)[0].decode()
        assert f"-{report['base']}" in head
        assert db.BUNDLE_REF in head

    def test_no_bundle_when_nothing_kept(self, tmp_path):
        repo = _repo(tmp_path)
        report = db.combine(repo, [_cand(360, "", kind="actions")], [], _green)
        bundle = tmp_path / "batch.bundle"
        assert db.write_bundle(repo, report, bundle) is False
        assert not bundle.exists()


class TestRunGates:
    def test_first_failure_wins_and_reports_its_tail(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "SYNC_COMMAND", ["true"])
        gates = [
            ("ok", ["true"], {}),
            (
                "bad",
                ["sh", "-c", 'for i in $(seq 1 100); do echo "line $i"; done; exit 3'],
                {},
            ),
            ("never", ["sh", "-c", "touch never-ran"], {}),
        ]
        name, tail = db.run_gates(tmp_path, gates)
        assert name == "bad"
        assert tail.splitlines()[-1] == "line 100"
        assert len(tail.splitlines()) == 60
        assert not (tmp_path / "never-ran").exists()

    def test_all_green_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "SYNC_COMMAND", ["true"])
        assert db.run_gates(tmp_path, [("ok", ["true"], {})]) is None

    def test_failed_sync_is_reported_as_a_gate(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            db, "SYNC_COMMAND", ["sh", "-c", "echo unsatisfiable; exit 1"]
        )
        assert db.run_gates(tmp_path, [("ok", ["true"], {})]) == (
            "uv-sync",
            "unsatisfiable\n",
        )

    def test_extra_env_reaches_the_gate(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "SYNC_COMMAND", ["true"])
        gates = [
            (
                "env",
                ["sh", "-c", 'test "$HATE_CRACK_SKIP_INIT" = 1'],
                {"HATE_CRACK_SKIP_INIT": "1"},
            )
        ]
        assert db.run_gates(tmp_path, gates) is None


def _batch(tmp_path, cands):
    """combine in one repo (the combine job); a clone of its base plays publish."""
    work = _repo(tmp_path, "work")
    publish = tmp_path / "publish"
    _git(tmp_path, "clone", "-q", "-b", "nightly-dev", str(work), str(publish))
    # A clone does not inherit repo-local identity, and CI has no global one.
    _git(publish, "config", "user.name", "Test")
    _git(publish, "config", "user.email", "test@example.com")
    _git(publish, "config", "commit.gpgsign", "false")
    report = db.combine(work, cands, [], _green)
    bundle = tmp_path / "batch.bundle"
    assert db.write_bundle(work, report, bundle)
    return work, publish, report, bundle


LIVE = {352: RUFF_DIFF, 353: TY_DIFF, 347: ATOMIC_DIFF}


def _live(n):
    return LIVE[n]


def _forge(work, tmp_path, report, mutate):
    """Rebuild deps-batch with one commit altered by ``mutate(work)``, re-bundle."""
    _git(work, "checkout", "-q", "-B", "deps-batch", report["base"])
    mutate(work)
    bundle = tmp_path / "forged.bundle"
    _git(
        work,
        "bundle",
        "create",
        str(bundle),
        f"{report['base']}..refs/heads/deps-batch",
    )
    return bundle


def _commit(work, message, author=db.DEPENDABOT_AUTHOR):
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "--author", author, "-m", message)


def _bump_ty(work):
    path = work / "pyproject.toml"
    path.write_text(path.read_text().replace("ty==0.0.82", "ty==0.0.93"))


class TestVerifyBundle:
    def test_genuine_batch_verifies_and_returns_tip(self, tmp_path):
        work, publish, report, bundle = _batch(
            tmp_path, [_cand(352, RUFF_DIFF), _cand(353, TY_DIFF)]
        )
        tip = db.verify_bundle(publish, bundle, report, _live)
        assert tip == _git(work, "rev-parse", "deps-batch").strip()

    def test_header_lists_prerequisite_and_ref(self, tmp_path):
        _, _, report, bundle = _batch(tmp_path, [_cand(353, TY_DIFF)])
        prereqs, heads = db.bundle_header(bundle)
        assert prereqs == [report["base"]]
        assert list(heads) == [db.BUNDLE_REF]

    def test_rejects_a_base_that_is_not_on_nightly_dev(self, tmp_path):
        work, publish, report, bundle = _batch(tmp_path, [_cand(353, TY_DIFF)])
        # HEAD moves to an unrelated root; the base object is still present.
        _git(publish, "checkout", "-q", "--orphan", "elsewhere")
        _git(publish, "commit", "-q", "--allow-empty", "-m", "unrelated")
        with pytest.raises(db.BatchError, match="ancestor"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_a_report_base_that_differs_from_the_bundle(self, tmp_path):
        _, publish, report, bundle = _batch(tmp_path, [_cand(353, TY_DIFF)])
        with pytest.raises(db.BatchError, match="prerequisite"):
            db.verify_bundle(publish, bundle, {**report, "base": "0" * 40}, _live)

    def test_rejects_a_second_file(self, tmp_path):
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def evil(w):
            _bump_ty(w)
            (w / "hate_crack.py").write_text("print('pwned')\n")
            _commit(w, "chore(deps): bump ty\n\nDependabot-PR: #353")

        bundle = _forge(work, tmp_path, report, evil)
        with pytest.raises(db.BatchError, match="pyproject.toml"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_batch_level_check_refuses_a_second_file_before_any_commit_is_read(
        self, tmp_path
    ):
        # Pins the batch-wide guard itself: the per-commit parse also names
        # pyproject.toml, so the message alone is what proves this check ran.
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def evil(w):
            _bump_ty(w)
            (w / "hate_crack.py").write_text("print('pwned')\n")
            _commit(w, "chore(deps): bump ty\n\nDependabot-PR: #353")

        bundle = _forge(work, tmp_path, report, evil)
        with pytest.raises(db.BatchError, match="must change only pyproject.toml"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_a_non_dependabot_author(self, tmp_path):
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def human(w):
            _bump_ty(w)
            _commit(
                w,
                "chore(deps): bump ty\n\nDependabot-PR: #353",
                author="Eve <eve@example.com>",
            )

        bundle = _forge(work, tmp_path, report, human)
        with pytest.raises(db.BatchError, match="author"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_a_missing_trailer(self, tmp_path):
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def untagged(w):
            _bump_ty(w)
            _commit(w, "chore(deps): bump ty")

        bundle = _forge(work, tmp_path, report, untagged)
        with pytest.raises(db.BatchError, match="trailer"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_a_trailer_for_a_pr_the_report_did_not_include(self, tmp_path):
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def other(w):
            _bump_ty(w)
            _commit(w, "chore(deps): bump ty\n\nDependabot-PR: #352")

        bundle = _forge(work, tmp_path, report, other)
        with pytest.raises(db.BatchError, match="#352"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_a_version_dependabot_did_not_propose(self, tmp_path):
        # The decisive check: a compromised combine job picks its own version.
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def wrong_version(w):
            path = w / "pyproject.toml"
            path.write_text(path.read_text().replace("ty==0.0.82", "ty==0.0.99"))
            _commit(w, "chore(deps): bump ty\n\nDependabot-PR: #353")

        bundle = _forge(work, tmp_path, report, wrong_version)
        with pytest.raises(db.BatchError, match="does not match"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_an_included_pr_with_no_commit(self, tmp_path):
        _, publish, report, bundle = _batch(tmp_path, [_cand(353, TY_DIFF)])
        padded = {
            **report,
            "included": report["included"] + [{"pr": 347, "title": "x", "changes": []}],
        }
        with pytest.raises(db.BatchError, match="no commit"):
            db.verify_bundle(publish, bundle, padded, _live)

    def test_rejects_a_merge_commit(self, tmp_path):
        work, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])

        def merged(w):
            _git(w, "checkout", "-q", "-b", "side", report["base"])
            _bump_ty(w)
            _commit(w, "chore(deps): bump ty\n\nDependabot-PR: #353")
            _git(w, "checkout", "-q", "deps-batch")
            _git(
                w,
                "merge",
                "-q",
                "--no-ff",
                "-m",
                "merge\n\nDependabot-PR: #353",
                "side",
            )

        bundle = _forge(work, tmp_path, report, merged)
        with pytest.raises(db.BatchError, match="merge"):
            db.verify_bundle(publish, bundle, report, _live)

    def test_rejects_garbage_instead_of_a_bundle(self, tmp_path):
        _, publish, report, _ = _batch(tmp_path, [_cand(353, TY_DIFF)])
        junk = tmp_path / "junk.bundle"
        junk.write_bytes(b"\xff\xfenot a bundle\n")
        with pytest.raises(db.BatchError):
            db.verify_bundle(publish, junk, report, _live)

    def test_cli_exits_nonzero_without_printing_a_sha(
        self, tmp_path, monkeypatch, capsys
    ):
        _, publish, report, bundle = _batch(tmp_path, [_cand(353, TY_DIFF)])
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({**report, "base": "0" * 40}))
        monkeypatch.chdir(publish)
        monkeypatch.setattr(db, "pr_diff", lambda repo, n: LIVE[n])
        rc = db.main(
            [
                "verify",
                "--repo",
                REPO,
                "--report",
                str(report_path),
                "--bundle",
                str(bundle),
            ]
        )
        out = capsys.readouterr()
        assert rc == 1 and out.out == "" and "error:" in out.err
