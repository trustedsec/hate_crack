# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

hate_crack is a menu-driven Python wrapper for hashcat that automates password cracking methodologies. It provides 16 attack modes, API integrations (Hashview, Weakpass, Hashmob), and utilities for wordlist/rule management.

## Commands

```bash
# Install (builds submodules, vendors assets, installs via uv)
make install

# Dev install (editable, with dev deps)
make dev-install

# Run tests (requires HATE_CRACK_SKIP_INIT=1 in worktrees without hashcat-utils)
HATE_CRACK_SKIP_INIT=1 uv run pytest -v

# Run a single test file
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_ui_menu_options.py -v

# Lint
uv run ruff check hate_crack
uv run ty check hate_crack

# Both lint checks
make lint

# Format
uv run ruff format hate_crack

# Coverage
make coverage
```

**Test environment variables**: `HATE_CRACK_SKIP_INIT=1` skips binary/config validation (essential for CI and worktrees). `HASHMOB_TEST_REAL=1`, `HASHVIEW_TEST_REAL=1`, `WEAKPASS_TEST_REAL=1` enable live API tests.

## Git Hooks

Git hooks are managed by [prek](https://github.com/j178/prek) (v0.3.3+). Install with:

```bash
prek install --hook-type pre-push --hook-type post-commit
```

Hooks are defined in `prek.toml` using the pre-commit local-repo schema (TOML, not YAML):

```toml
[[repos]]
repo = "local"

[[repos.hooks]]
id = "ruff"
entry = "uv run ruff check hate_crack"
language = "system"
stages = ["pre-push"]
pass_filenames = false
always_run = true
```

Active hooks:
- **pre-push**: ruff, ty, pytest, pytest-lima
- **post-commit**: audit-docs

**Note**: prek 0.3.3 expects `repos = [...]` at the top level. The old `[hooks.<stage>] commands = [...]` format is not supported and will fail with `missing field 'repos'`.

## Documentation Auditing

Automatic documentation audits run after each commit via prek hooks.

```bash
# Manually audit a commit
bash .claude/audit-docs.sh HEAD
bash .claude/audit-docs.sh <commit_sha>

# Check the last N commits for documentation gaps
bash .claude/check-docs.sh 5
```

See `.claude/DOCUMENTATION-AUDIT.md` for details on the audit system.

## Worktree Policy

**Every agent MUST work in a dedicated git worktree** - never edit files directly in the main repo checkout. This prevents conflicts when multiple agents run in parallel.

### Setup

```bash
# Create a worktree under /tmp (keeps the parent directory clean)
git worktree add /tmp/hate_crack-<task-name> -b <branch-name>
cd /tmp/hate_crack-<task-name>

# Install dev dependencies in the new worktree
uv sync --dev

# Run tests in the worktree
HATE_CRACK_SKIP_INIT=1 uv run pytest -v
```

### Rules

1. **Always create a worktree** before making any file changes: `git worktree add /tmp/hate_crack-<task> -b <branch>`
2. **All file edits** happen inside the worktree directory, not the main repo
3. **Run tests and lint** inside the worktree before merging
4. **Merge back** via PR or `git merge` from the main worktree
5. **Clean up** when done: `git worktree remove /tmp/hate_crack-<task>`

## Architecture

### Module Map

- **`hate_crack.py`** (root) - Entry point, menu registration, proxy to `hate_crack.main`
- **`hate_crack/main.py`** - Core logic (~3700 lines): hashcat subprocess wrappers, config loading, menu display, global state
- **`hate_crack/attacks.py`** - 16 attack handler functions that receive `ctx` (main module ref)
- **`hate_crack/api.py`** - Hashmob, Hashview, Weakpass API integrations
- **`hate_crack/cli.py`** - Argparse helpers, path resolution, logging setup
- **`hate_crack/formatting.py`** - Terminal UI helpers (multi-column list printing)

### Three-Layer Attack Pattern

Every attack spans three files with a specific wiring pattern:

1. **`hate_crack/main.py`** - Low-level hashcat function (e.g., `hcatBruteForce(hcatHashType, hcatHashFile)`)
   - Builds subprocess commands, manages `hcatProcess` global, handles KeyboardInterrupt
   - All hashcat invocations follow: build cmd list -> `cmd.extend(shlex.split(hcatTuning))` -> `_append_potfile_arg(cmd)` -> `subprocess.Popen(cmd)`

2. **`hate_crack/attacks.py`** - Menu handler wrapper (e.g., `def brute_force_crack(ctx: Any)`)
   - Receives `ctx` (the main module itself) via `_attack_ctx()`, which returns `sys.modules['hate_crack.main']`
   - Handles user prompts, then calls `ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile)`

3. **`hate_crack.py`** (root) - Menu registration + dispatcher
   - Has its own `get_main_menu_options()` that maps keys to `_attacks.<handler>`
   - **Important**: `hate_crack.py` has a DUPLICATE menu mapping separate from `main.py`'s `get_main_menu_options()`. Both must be updated when adding attacks.

### Adding a New Attack - Checklist

1. Add the hashcat wrapper function in `main.py` (e.g., `hcatMyAttack(...)`)
2. Add the handler in `attacks.py` (e.g., `def my_attack(ctx: Any)`)
3. Add a dispatcher in `main.py`: `def my_attack(): return _attacks.my_attack(_attack_ctx())`
4. Add the print line in `main.py`'s menu display loop (~line 3807+)
5. Add the menu entry in `main.py`'s `get_main_menu_options()`
6. Add the menu entry in `hate_crack.py`'s `get_main_menu_options()` (the duplicate)

### hate_crack.py <-> main.py Proxy

`hate_crack.py` uses `__getattr__` to proxy attribute access to `hate_crack.main`. It syncs mutable globals via `_sync_globals_to_main()` and `_sync_callables_to_main()`. Tests load `hate_crack.py` as `CLI_MODULE` and exercise both the proxy and direct module paths.

### Config System

`config.json` is resolved from multiple candidate directories (repo root, cwd, `~/.hate_crack`, `/opt/hate_crack`, etc.) and auto-created from `config.json.example` if missing. Each config key is loaded via try/except with `default_config` fallback. New config vars need: entry in `config.json.example`, try/except loading block in `main.py` (~line 454 area), and path normalization via `_normalize_wordlist_setting()` if it's a wordlist path.

### Path Distinction

- **`hate_path`** - hate_crack assets directory (hashcat-utils, princeprocessor, masks, PACK). All bundled binaries use this.
- **`hcatPath`** - hashcat installation directory. Only used for the hashcat binary itself.

### External Binary Pattern

Binaries are verified at startup via `ensure_binary(path, build_dir, name)`. Non-critical binaries (princeprocessor, hcstat2gen) use try/except around `ensure_binary` with a warning message. The `SKIP_INIT` flag bypasses all binary checks.

## Testing Patterns

- Menu option tests in `test_ui_menu_options.py` use monkeypatching against `CLI_MODULE` (loaded from `hate_crack.py`)
- API tests mock `requests` responses; most are offline-first
- conftest.py provides `hc_module` fixture via `load_hate_crack_module()` which dynamically imports root `hate_crack.py` with SKIP_INIT enabled
- Python 3.9-3.14 supported in CI (requires-python >=3.13 in pyproject.toml but CI tests older versions)
- E2E tests (`test_e2e_local_install.py`, `test_docker_script_install.py`) are opt-in via `HATE_CRACK_RUN_E2E=1` and `HATE_CRACK_RUN_DOCKER_TESTS=1`
