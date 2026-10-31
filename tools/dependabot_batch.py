#!/usr/bin/env python3
"""Batch the open Dependabot ``uv`` PRs into one gated branch.

Run weekly by .github/workflows/dependabot-batch.yml. The workflow has two jobs,
and this module serves both:

* ``combine`` (read-only token) applies each eligible bump to ``nightly-dev``,
  runs the local gates after each, keeps only the green ones, and writes a git
  bundle plus a JSON report. This is the job that executes new third-party
  code, which is why it never holds a write token.
* ``publish`` (write token) never installs or runs the project. It re-verifies
  the bundle -- including each commit against its PR's *live* diff -- pushes
  ``deps/dependabot-batch``, and rewrites the tracking issue. It trusts nothing
  ``combine`` produced.

Only Dependabot's own PRs are eligible; see ``classify_pr``. GitHub Actions
bumps are reported, never applied: ``GITHUB_TOKEN`` has no ``workflows``
permission, and that power is deliberately kept out of automation.

Stdlib only, and must parse under Python 3.12: ``publish`` runs this with the
runner's system ``python3``. tests/test_dependabot_batch.py enforces both.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

DEPENDABOT_ID = 49699333
DEPENDABOT_LOGIN = "dependabot[bot]"
DEPENDABOT_AUTHOR = (
    "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
)
COMMITTER_NAME = "github-actions[bot]"
COMMITTER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
BASE_BRANCH = "nightly-dev"
BATCH_BRANCH = "deps/dependabot-batch"
BUNDLE_REF = "refs/heads/deps-batch"
TARGET_FILE = "pyproject.toml"
LABEL = "dependabot-batch"
UV_PREFIX = "dependabot/uv/"
ACTIONS_PREFIX = "dependabot/github_actions/"
TRAILER_RE = re.compile(r"^Dependabot-PR: #(\d+)$", re.MULTILINE)
_DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.MULTILINE)
_LINT_SCOPE = ["hate_crack", "tests", "tools", "packaging", "hate_crack.py"]


class BatchError(Exception):
    """Input or verification failure. The job must fail closed on this."""


class StaleBump(BatchError):
    """The bump's old line is not (uniquely) present: nightly-dev moved past it."""


def classify_pr(pr: dict, commit_authors: list[str | None], repo: str) -> str:
    """Return ``"uv"`` (apply), ``"actions"`` (report only) or ``"ignore"``.

    Every condition must hold, and each is tested alone:

    * the author is Dependabot by numeric id -- a login is only a string;
    * head and base are both this repo, so a fork named like Dependabot fails;
    * the base is ``nightly-dev``;
    * every commit is authored by Dependabot, so a human push onto a
      Dependabot branch is never laundered through the bot's identity;
    * the branch is ``dependabot/uv/`` (apply) or ``dependabot/github_actions/``.
    """
    user = pr.get("user") or {}
    if user.get("id") != DEPENDABOT_ID or user.get("type") != "Bot":
        return "ignore"
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (head.get("repo") or {}).get("full_name") != repo:
        return "ignore"
    if (base.get("repo") or {}).get("full_name") != repo:
        return "ignore"
    if base.get("ref") != BASE_BRANCH:
        return "ignore"
    if not commit_authors or any(a != DEPENDABOT_LOGIN for a in commit_authors):
        return "ignore"
    ref = head.get("ref") or ""
    if ref.startswith(UV_PREFIX):
        return "uv"
    if ref.startswith(ACTIONS_PREFIX):
        return "actions"
    return "ignore"


def parse_bump(diff: str) -> list[tuple[str, str]]:
    """Read a Dependabot diff as exact ``(old_line, new_line)`` replacements.

    Re-applying replacements rather than cherry-picking is what lets two bumps
    on adjacent lines (``ty`` then ``ruff``) both land: git treats adjacent-line
    edits as a conflict. Context lines are ignored for the same reason. Anything
    that is not a 1:1 line replacement in pyproject.toml alone is refused.
    """
    files = _DIFF_FILE_RE.findall(diff)
    if files != [(TARGET_FILE, TARGET_FILE)]:
        raise BatchError(f"diff must touch only {TARGET_FILE}, got {files}")
    pairs: list[tuple[str, str]] = []
    removed: list[str] = []
    added: list[str] = []

    def flush() -> None:
        if len(removed) != len(added):
            raise BatchError(
                f"change block is not 1:1 ({len(removed)} removed, {len(added)} added)"
            )
        pairs.extend(zip(removed, added))
        removed.clear()
        added.clear()

    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("@@"):
            flush()
            in_hunk = True
        elif not in_hunk or line.startswith("\\"):
            continue
        elif line.startswith("-"):
            if added:
                flush()
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        else:
            flush()
    flush()
    if not pairs:
        raise BatchError("diff contains no line replacements")
    return pairs


def apply_bump(text: str, pairs: list[tuple[str, str]]) -> str:
    """Apply replacements; each old line must occur exactly once."""
    lines = text.split("\n")
    for old, new in pairs:
        hits = [i for i, line in enumerate(lines) if line == old]
        if len(hits) != 1:
            raise StaleBump(
                f"expected exactly one line {old.strip()!r}, found {len(hits)}"
            )
        lines[hits[0]] = new
    return "\n".join(lines)


def commit_message(message: str, number: int) -> str:
    """Dependabot's own message, plus a trailer naming the PR it came from.

    Any trailer-shaped line already in the message is dropped first: the body
    carries upstream release notes, which a dependency's author controls, and
    a second ``Dependabot-PR:`` line would make the commit unverifiable.
    """
    kept = [line for line in message.splitlines() if not TRAILER_RE.fullmatch(line)]
    return "\n".join(kept).rstrip() + f"\nDependabot-PR: #{number}\n"


def pip_audit_ignores(ci_text: str) -> list[str]:
    """The advisory ids ci.yml ignores -- read from it, never duplicated here."""
    return sorted(set(re.findall(r"--ignore-vuln\s+(\S+)", ci_text)))


def gate_commands(ci_text: str) -> list[tuple[str, list[str], dict[str, str]]]:
    """``(name, argv, extra_env)`` per gate, cheapest first."""
    audit = [
        "uv",
        "run",
        "--with",
        "pip-audit==2.10.0",
        "pip-audit",
        "--progress-spinner",
        "off",
    ]
    for vid in pip_audit_ignores(ci_text):
        audit += ["--ignore-vuln", vid]
    return [
        ("ruff", ["uv", "run", "ruff", "check", *_LINT_SCOPE], {}),
        ("ruff-format", ["uv", "run", "ruff", "format", "--check", *_LINT_SCOPE], {}),
        (
            "ty",
            ["uv", "run", "ty", "check", "--exit-zero-on-warning", "hate_crack"],
            {},
        ),
        (
            "bandit",
            [
                "uvx",
                "--from",
                "bandit[toml]==1.9.4",
                "bandit",
                "-r",
                "hate_crack",
                "-c",
                "pyproject.toml",
                "-b",
                ".bandit-baseline.json",
            ],
            {},
        ),
        ("pip-audit", audit, {}),
        (
            "pytest",
            ["uv", "run", "pytest", "-q", "-p", "no:cacheprovider"],
            {"HATE_CRACK_SKIP_INIT": "1"},
        ),
    ]


SYNC_COMMAND = ["uv", "sync", "--dev"]
_TAIL_LINES = 60


def git(cwd: Path, *args: str, input: str | None = None) -> str:
    """Run git in ``cwd``; raise on failure. Config that could alter output is pinned."""
    return subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        input=input,
    ).stdout


def _tail(text: str) -> str:
    lines = text.splitlines(keepends=True)
    return "".join(lines[-_TAIL_LINES:])


def run_gates(cwd: Path, gates) -> tuple[str, str] | None:
    """Sync, then run each gate; stop at the first non-zero exit.

    Exit codes are read from the process itself -- never through a pipe, which
    would report the pipe's last command instead.
    """
    for name, argv, extra in [("uv-sync", SYNC_COMMAND, {}), *gates]:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env={**os.environ, **extra},
            capture_output=True,
            text=True,
            errors="replace",
        )
        if proc.returncode != 0:
            return name, _tail(proc.stdout + proc.stderr)
    return None


def combine(
    repo_dir: Path, candidates: list[dict], gates, gate_runner=run_gates
) -> dict:
    """Apply each candidate onto HEAD, oldest PR first, keeping only green ones.

    Each kept bump is one commit under Dependabot's author and message, so the
    ``chore(deps)`` prefix -- and with it the patch-only release bump -- survives.
    """
    base = git(repo_dir, "rev-parse", "HEAD").strip()
    git(repo_dir, "checkout", "-q", "-B", BUNDLE_REF.removeprefix("refs/heads/"))
    report: dict = {"base": base, "included": [], "skipped": []}
    target = repo_dir / TARGET_FILE
    for cand in sorted(candidates, key=lambda c: c["number"]):
        entry = {"pr": cand["number"], "title": cand["title"]}
        if cand["kind"] == "actions":
            report["skipped"].append({**entry, "reason": "actions"})
            continue
        try:
            pairs = parse_bump(cand["diff"])
            updated = apply_bump(target.read_text(encoding="utf-8"), pairs)
        except StaleBump as exc:
            report["skipped"].append({**entry, "reason": "stale", "detail": str(exc)})
            continue
        except BatchError as exc:
            report["skipped"].append(
                {**entry, "reason": "unparseable", "detail": str(exc)}
            )
            continue
        target.write_text(updated, encoding="utf-8")
        git(repo_dir, "add", TARGET_FILE)
        git(
            repo_dir,
            "-c",
            f"user.name={COMMITTER_NAME}",
            "-c",
            f"user.email={COMMITTER_EMAIL}",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-verify",
            "--author",
            DEPENDABOT_AUTHOR,
            "-F",
            "-",
            input=commit_message(cand["message"], cand["number"]),
        )
        failure = gate_runner(repo_dir, gates)
        if failure is None:
            report["included"].append({**entry, "changes": [list(p) for p in pairs]})
        else:
            git(repo_dir, "reset", "-q", "--hard", "HEAD~1")
            report["skipped"].append(
                {**entry, "reason": "gate", "gate": failure[0], "output": failure[1]}
            )
    return report


def write_bundle(repo_dir: Path, report: dict, path: Path) -> bool:
    """Bundle ``base..deps-batch``; return False (writing nothing) if empty."""
    if not report["included"]:
        return False
    git(repo_dir, "bundle", "create", str(path), f"{report['base']}..{BUNDLE_REF}")
    return True


def _gh(*args: str) -> str:
    return subprocess.run(
        ["gh", *args], check=True, capture_output=True, text=True
    ).stdout


def _gh_pages(path: str) -> list:
    pages = json.loads(_gh("api", "--paginate", "--slurp", path))
    return [item for page in pages for item in page]


def pr_diff(repo: str, number: int) -> str:
    return _gh(
        "api",
        "-H",
        "Accept: application/vnd.github.diff",
        f"repos/{repo}/pulls/{number}",
    )


def fetch_candidates(repo: str) -> list[dict]:
    """Open PRs against nightly-dev that ``classify_pr`` accepts."""
    out = []
    for pr in _gh_pages(
        f"repos/{repo}/pulls?state=open&base={BASE_BRANCH}&per_page=100"
    ):
        commits = _gh_pages(f"repos/{repo}/pulls/{pr['number']}/commits?per_page=100")
        authors = [(c.get("author") or {}).get("login") for c in commits]
        kind = classify_pr(pr, authors, repo)
        if kind == "ignore":
            continue
        out.append(
            {
                "number": pr["number"],
                "title": pr["title"],
                "kind": kind,
                "diff": pr_diff(repo, pr["number"]) if kind == "uv" else "",
                "message": commits[-1]["commit"]["message"],
            }
        )
    return out


_BUNDLE_SIGNATURES = (b"# v2 git bundle\n", b"# v3 git bundle\n")


def bundle_header(path: Path) -> tuple[list[str], dict[str, str]]:
    """Parse a bundle's header without trusting git to interpret it for us."""
    prereqs: list[str] = []
    heads: dict[str, str] = {}
    try:
        with path.open("rb") as handle:
            if handle.readline() not in _BUNDLE_SIGNATURES:
                raise BatchError("not a git bundle")
            for raw in handle:
                line = raw.decode("ascii").rstrip("\n")
                if line == "":
                    break
                if line.startswith("@"):  # v3 capability line
                    continue
                if line.startswith("-"):
                    prereqs.append(line[1:].split(" ", 1)[0])
                else:
                    sha, ref = line.split(" ", 1)
                    heads[ref] = sha
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise BatchError(f"unreadable bundle header: {exc}") from exc
    return prereqs, heads


def _diff_args(a: str, b: str) -> list[str]:
    return [
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        a,
        b,
    ]


def verify_bundle(
    repo_dir: Path,
    bundle: Path,
    report: dict,
    live_diff: Callable[[int], str],
    against: str = "HEAD",
) -> str:
    """Return the bundle's tip SHA only if every check passes; else raise.

    Run by ``publish``, which holds the write token, against output from
    ``combine``, which ran third-party code. So nothing from ``combine`` is
    trusted: each commit must be a Dependabot-authored, linear, pyproject-only
    change whose line replacements equal the *live* diff of the PR its trailer
    names. A compromised ``combine`` can at most re-propose what Dependabot
    already proposed.
    """
    base = report["base"]
    prereqs, heads = bundle_header(bundle)
    if prereqs != [base]:
        raise BatchError(f"bundle prerequisite {prereqs} is not the report base {base}")
    if set(heads) != {BUNDLE_REF}:
        raise BatchError(f"bundle must carry only {BUNDLE_REF}, got {sorted(heads)}")
    tip = heads[BUNDLE_REF]
    try:
        git(repo_dir, "bundle", "verify", "-q", str(bundle))
        git(
            repo_dir,
            "fetch",
            "-q",
            "--no-tags",
            str(bundle),
            f"{BUNDLE_REF}:refs/batch/tip",
        )
    except subprocess.CalledProcessError as exc:
        raise BatchError(f"bundle rejected by git: {exc.stderr.strip()}") from exc
    if git(repo_dir, "rev-parse", "refs/batch/tip").strip() != tip:
        raise BatchError("fetched tip does not match the bundle header")
    # The header's prerequisite line is attacker-controlled. Without this, a
    # chain rooted at an older ancestor, relabelled as base, would verify and
    # silently revert every pyproject line changed since that ancestor.
    descends = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, "refs/batch/tip"],
        cwd=repo_dir,
        capture_output=True,
    ).returncode
    if descends != 0:
        raise BatchError(f"bundle tip does not descend from base {base}")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, against], cwd=repo_dir
    ).returncode
    if ancestor != 0:
        raise BatchError(f"base {base} is not an ancestor of {against} ({BASE_BRANCH})")
    if git(repo_dir, "rev-list", "--min-parents=2", f"{base}..{tip}").strip():
        raise BatchError("the batch contains a merge commit")
    changed = git(repo_dir, *_diff_args(base, tip), "--name-only").split()
    if changed != [TARGET_FILE]:
        raise BatchError(f"the batch must change only {TARGET_FILE}, got {changed}")
    included = {entry["pr"] for entry in report["included"]}
    seen: set[int] = set()
    for sha in git(repo_dir, "rev-list", "--reverse", f"{base}..{tip}").split():
        author = git(repo_dir, "log", "-1", "--format=%an <%ae>", sha).strip()
        if author != DEPENDABOT_AUTHOR:
            raise BatchError(f"{sha[:12]}: author {author!r} is not Dependabot")
        found = TRAILER_RE.findall(git(repo_dir, "log", "-1", "--format=%B", sha))
        if len(found) != 1:
            raise BatchError(f"{sha[:12]}: needs exactly one Dependabot-PR trailer")
        number = int(found[0])
        if number not in included or number in seen:
            raise BatchError(
                f"{sha[:12]}: trailer #{number} is not an included, unique PR"
            )
        seen.add(number)
        got = parse_bump(git(repo_dir, *_diff_args(f"{sha}^", sha)))
        if got != parse_bump(live_diff(number)):
            raise BatchError(
                f"{sha[:12]}: change does not match PR #{number}'s live diff"
            )
    if seen != included:
        raise BatchError(
            f"report includes PRs with no commit: {sorted(included - seen)}"
        )
    return tip


def _cmd_verify(args) -> int:
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        tip = verify_bundle(
            Path.cwd(), Path(args.bundle), report, lambda n: pr_diff(args.repo, n)
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() if exc.stderr else exc
        print(f"error: git failed: {detail}", file=sys.stderr)
        return 1
    except (BatchError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(tip)
    return 0


def _cmd_fetch(args) -> int:
    Path(args.out).write_text(
        json.dumps(fetch_candidates(args.repo), indent=2), encoding="utf-8"
    )
    return 0


def _cmd_combine(args) -> int:
    repo_dir = Path.cwd()
    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    ci_text = (repo_dir / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    report = combine(repo_dir, candidates, gate_commands(ci_text))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    kept = write_bundle(repo_dir, report, out / "batch.bundle")
    print(
        f"kept {len(report['included'])}, skipped {len(report['skipped'])}, bundle={kept}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("fetch", help="list eligible Dependabot PRs (needs GH_TOKEN)")
    p.add_argument("--repo", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_fetch)
    p = sub.add_parser(
        "combine", help="apply and gate bumps in the cwd checkout (no token)"
    )
    p.add_argument("--candidates", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_combine)
    p = sub.add_parser("verify", help="fail-closed bundle check; prints the tip SHA")
    p.add_argument("--repo", required=True)
    p.add_argument("--report", required=True)
    p.add_argument("--bundle", required=True)
    p.set_defaults(func=_cmd_verify)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
