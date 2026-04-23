# Notifications Submenu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate Pushover notification menu entries under a new main-menu submenu at option `82 — Notifications`, and promote `notify_per_crack_enabled` to a first-class runtime toggle with a UI-level guard that refuses to enable it while the global notification switch is OFF.

**Architecture:** Persist the per-crack flag through the existing atomic-rewrite primitive in `hate_crack/notify/settings.py`; expose a `toggle_per_crack_enabled()` function in the notify module mirroring the existing `toggle_enabled()`; add a new main-menu handler `toggle_per_crack_notifications()` and a submenu dispatcher `notifications_submenu()` to `hate_crack/main.py` following the existing `wordlist_tools_submenu` pattern; update the duplicate menu wiring in `hate_crack.py` per the CLAUDE.md "Adding a New Attack" checklist.

**Tech Stack:** Python 3, existing `hate_crack/menu.py:interactive_menu`, `pytest` + `monkeypatch`, `uv run ruff`, `uv run ty`, `prek` pre-push hooks.

**Worktree:** `/tmp/hate_crack-notifications-submenu` on branch `feat/notifications-submenu` (already created, spec committed as `e165e3d`).

**Spec:** `.claude/specs/2026-04-22-notifications-submenu-design.md`

**Plan location note:** This repo's local `.git/info/exclude` ignores `docs/*`. The project's convention for specs and plans on the `feat/pushover-notifications` branch is `.claude/specs/` and `.claude/plans/`, so this plan lives there alongside `2026-04-22-test-pushover-menu.md`.

**Preflight for every task:**
- All edits happen in `/tmp/hate_crack-notifications-submenu`, never in `/Users/justinbollinger/projects/hate_crack`.
- Prefix every test command with `HATE_CRACK_SKIP_INIT=1` — the worktree has no `hashcat-utils` build and `config.json` loading would otherwise abort.
- Run all commands with `uv run …` so the worktree's own `.venv` is used.

---

## Task 1: Persist `notify_per_crack_enabled` atomically

**Files:**
- Modify: `hate_crack/notify/settings.py` (add a new top-level function after `save_enabled`, around line 148)
- Test: `tests/test_notify_settings.py` (add a new `TestSavePerCrackEnabled` class at the end of the file, after `TestAddToAllowlist`)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_notify_settings.py`:

```python
class TestSavePerCrackEnabled:
    def test_writes_new_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        save_per_crack_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data["notify_per_crack_enabled"] is True

    def test_preserves_existing_keys(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        initial = {
            "hcatBin": "hashcat",
            "notify_enabled": True,
            "notify_per_crack_enabled": False,
        }
        config_path.write_text(json.dumps(initial))
        save_per_crack_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data["hcatBin"] == "hashcat"
        assert data["notify_enabled"] is True
        assert data["notify_per_crack_enabled"] is True

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        save_per_crack_enabled(str(config_path), True)
        save_per_crack_enabled(str(config_path), False)
        data = json.loads(config_path.read_text())
        assert data["notify_per_crack_enabled"] is False
```

Update the top-level import at the top of `tests/test_notify_settings.py` to include the new function:

```python
from hate_crack.notify.settings import (
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
    save_per_crack_enabled,
)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /tmp/hate_crack-notifications-submenu
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notify_settings.py::TestSavePerCrackEnabled -v
```

Expected: `ImportError` on collection (symbol does not exist yet).

- [ ] **Step 3: Implement `save_per_crack_enabled`**

Insert in `hate_crack/notify/settings.py` immediately after `save_enabled` (around line 148, before `add_to_allowlist`):

```python
def save_per_crack_enabled(config_path: str, enabled: bool) -> None:
    """Persist ``notify_per_crack_enabled`` without disturbing other config keys."""

    def _apply(data: dict) -> None:
        data["notify_per_crack_enabled"] = bool(enabled)

    _atomic_rewrite(config_path, _apply)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notify_settings.py -v
```

Expected: all existing tests still pass, the three new tests in `TestSavePerCrackEnabled` pass.

- [ ] **Step 5: Commit**

```bash
git add hate_crack/notify/settings.py tests/test_notify_settings.py
git commit -m "feat(notify): persist notify_per_crack_enabled atomically"
```

---

## Task 2: Runtime toggle `toggle_per_crack_enabled`

**Files:**
- Modify: `hate_crack/notify/__init__.py` (add to imports, `__all__`, and append a new function after `toggle_enabled` around line 146)
- Create: `tests/test_notify_per_crack_toggle.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_notify_per_crack_toggle.py`:

```python
"""Unit tests for the toggle_per_crack_enabled runtime toggle."""
import json
from pathlib import Path

from hate_crack import notify as _notify


def _init_with(tmp_path: Path, **overrides) -> Path:
    """Seed a config file with defaults + overrides and init the notify module."""
    config_path = tmp_path / "config.json"
    cfg = {
        "notify_enabled": False,
        "notify_per_crack_enabled": False,
        "notify_pushover_token": "",
        "notify_pushover_user": "",
    }
    cfg.update(overrides)
    config_path.write_text(json.dumps(cfg))
    _notify.init(str(config_path), cfg)
    return config_path


class TestTogglePerCrackEnabled:
    def test_off_to_on_flips_and_persists(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path)
        try:
            new_state = _notify.toggle_per_crack_enabled()
            assert new_state is True
            assert _notify.get_settings().per_crack_enabled is True
            data = json.loads(config_path.read_text())
            assert data["notify_per_crack_enabled"] is True
        finally:
            _notify.clear_state_for_tests()

    def test_on_to_off_flips_and_persists(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_per_crack_enabled=True)
        try:
            new_state = _notify.toggle_per_crack_enabled()
            assert new_state is False
            assert _notify.get_settings().per_crack_enabled is False
            data = json.loads(config_path.read_text())
            assert data["notify_per_crack_enabled"] is False
        finally:
            _notify.clear_state_for_tests()

    def test_toggle_without_init_uses_defaults(self) -> None:
        # Mirrors the behavior of toggle_enabled: must not crash when init
        # was never called. The toggle flips an in-memory default; nothing
        # is persisted because _config_path is None.
        try:
            _notify.clear_state_for_tests()
            new_state = _notify.toggle_per_crack_enabled()
            assert new_state is True
            assert _notify.get_settings().per_crack_enabled is True
        finally:
            _notify.clear_state_for_tests()

    def test_does_not_touch_global_enabled(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_enabled=False)
        try:
            _notify.toggle_per_crack_enabled()
            data = json.loads(config_path.read_text())
            # notify_enabled stays False; only per-crack flipped.
            assert data["notify_enabled"] is False
            assert data["notify_per_crack_enabled"] is True
        finally:
            _notify.clear_state_for_tests()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /tmp/hate_crack-notifications-submenu
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notify_per_crack_toggle.py -v
```

Expected: `AttributeError: module 'hate_crack.notify' has no attribute 'toggle_per_crack_enabled'`.

- [ ] **Step 3: Implement `toggle_per_crack_enabled`**

Update the import at the top of `hate_crack/notify/__init__.py` (around line 47) from:

```python
from hate_crack.notify.settings import (
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
)
```

to:

```python
from hate_crack.notify.settings import (
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
    save_per_crack_enabled,
)
```

Add `"toggle_per_crack_enabled"` to `__all__` (around line 77, insert alphabetically — after `"toggle_enabled"`):

```python
__all__ = [
    "CrackTailer",
    "NotifySettings",
    "add_to_allowlist",
    "clear_state_for_tests",
    "extract_username_from_out_line",
    "get_settings",
    "init",
    "is_suppressed",
    "notify_crack",
    "notify_job_done",
    "prompt_notify_for_attack",
    "set_input_func",
    "start_tailer",
    "stop_tailer",
    "suppressed_notifications",
    "toggle_enabled",
    "toggle_per_crack_enabled",
    "_send_pushover",
]
```

Append the new function immediately after `toggle_enabled` (around line 145):

```python
def toggle_per_crack_enabled() -> bool:
    """Flip ``notify_per_crack_enabled``, persist to ``config.json``, return new state.

    If ``init`` was never called we still toggle an in-memory default — the
    UI update must not crash even if the config file is unreachable.
    """
    global _settings
    if _settings is None:
        _settings = NotifySettings()
    _settings.per_crack_enabled = not _settings.per_crack_enabled
    if _config_path:
        try:
            save_per_crack_enabled(_config_path, _settings.per_crack_enabled)
        except OSError as exc:
            logger.warning("Could not persist notify_per_crack_enabled: %s", exc)
    return _settings.per_crack_enabled
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notify_per_crack_toggle.py tests/test_notify_settings.py tests/test_notify_integration.py -v
```

Expected: all green, including the existing notify integration/settings tests (we have not regressed `toggle_enabled`).

- [ ] **Step 5: Commit**

```bash
git add hate_crack/notify/__init__.py tests/test_notify_per_crack_toggle.py
git commit -m "feat(notify): add toggle_per_crack_enabled runtime toggle"
```

---

## Task 3: UI handler `toggle_per_crack_notifications` with global-OFF guard

**Files:**
- Modify: `hate_crack/main.py` (add a new function immediately after `toggle_notifications`, around line 4109)
- Test: `tests/test_notify_per_crack_toggle.py` (add a new `TestTogglePerCrackNotificationsUI` class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_notify_per_crack_toggle.py`:

```python
import importlib.util

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_CLI_SPEC = importlib.util.spec_from_file_location(
    "hate_crack_cli_percrack", PROJECT_ROOT / "hate_crack.py"
)
CLI_MODULE = importlib.util.module_from_spec(_CLI_SPEC)
_CLI_SPEC.loader.exec_module(CLI_MODULE)


class TestTogglePerCrackNotificationsUI:
    def _seed_settings(self, monkeypatch, *, enabled: bool, per_crack: bool):
        from hate_crack.notify.settings import NotifySettings

        settings = NotifySettings(enabled=enabled, per_crack_enabled=per_crack)
        monkeypatch.setattr(
            CLI_MODULE._notify, "get_settings", lambda: settings
        )
        return settings

    def test_guard_refuses_on_when_global_off(self, monkeypatch, capsys):
        self._seed_settings(monkeypatch, enabled=False, per_crack=False)
        called = {"n": 0}

        def _fake_toggle() -> bool:
            called["n"] += 1
            return True

        monkeypatch.setattr(
            CLI_MODULE._notify, "toggle_per_crack_enabled", _fake_toggle
        )
        CLI_MODULE.toggle_per_crack_notifications()
        captured = capsys.readouterr().out
        assert "Global Pushover notifications are OFF" in captured
        assert called["n"] == 0

    def test_flips_on_when_global_on(self, monkeypatch, capsys):
        self._seed_settings(monkeypatch, enabled=True, per_crack=False)
        called = {"n": 0}

        def _fake_toggle() -> bool:
            called["n"] += 1
            return True

        monkeypatch.setattr(
            CLI_MODULE._notify, "toggle_per_crack_enabled", _fake_toggle
        )
        CLI_MODULE.toggle_per_crack_notifications()
        captured = capsys.readouterr().out
        assert "Per-crack notifications are now ON" in captured
        assert called["n"] == 1

    def test_off_to_off_is_allowed_even_if_global_off(self, monkeypatch, capsys):
        # Turning OFF must always succeed, even with global OFF, so a user
        # can clean up an inconsistent (per_crack=True, enabled=False) config.
        self._seed_settings(monkeypatch, enabled=False, per_crack=True)
        called = {"n": 0}

        def _fake_toggle() -> bool:
            called["n"] += 1
            return False

        monkeypatch.setattr(
            CLI_MODULE._notify, "toggle_per_crack_enabled", _fake_toggle
        )
        CLI_MODULE.toggle_per_crack_notifications()
        captured = capsys.readouterr().out
        assert "Per-crack notifications are now OFF" in captured
        assert called["n"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notify_per_crack_toggle.py::TestTogglePerCrackNotificationsUI -v
```

Expected: `AttributeError: module ... has no attribute 'toggle_per_crack_notifications'`.

- [ ] **Step 3: Implement the handler**

Insert in `hate_crack/main.py` immediately after `toggle_notifications` (currently ends around line 4108, just before `def test_pushover_notification():`):

```python
def toggle_per_crack_notifications():
    """Runtime toggle for ``notify_per_crack_enabled`` with a UI-level guard.

    Per-crack notifications require global notifications to be ON in order
    to fire (see ``notify.start_tailer``).  Turning per-crack ON while the
    global switch is OFF is silently ineffective, which surprises users —
    so we refuse the transition and point them at the global toggle.

    Turning per-crack OFF is always allowed, regardless of the global
    state, so users can clean up an inconsistent config without friction.
    """
    settings = _notify.get_settings()
    if not settings.per_crack_enabled and not settings.enabled:
        print(
            "\n[!] Global Pushover notifications are OFF. Enable option 1 "
            "(Toggle Pushover Notifications) first."
        )
        return
    new_state = _notify.toggle_per_crack_enabled()
    label = "ON" if new_state else "OFF"
    print(f"\nPer-crack notifications are now {label}.")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notify_per_crack_toggle.py -v
```

Expected: all `TestTogglePerCrackEnabled` and `TestTogglePerCrackNotificationsUI` tests pass.

- [ ] **Step 5: Commit**

```bash
git add hate_crack/main.py tests/test_notify_per_crack_toggle.py
git commit -m "feat(notify): add per-crack UI toggle with global-OFF guard"
```

---

## Task 4: Submenu dispatcher `notifications_submenu`

**Files:**
- Modify: `hate_crack/main.py` (add a new submenu dispatcher near the other submenu dispatchers, after `rule_tools_submenu` at line 3880)
- Create: `tests/test_notifications_submenu.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_notifications_submenu.py`:

```python
"""Unit tests for the Notifications submenu dispatcher (main-menu option 82).

Patching note: ``notifications_submenu`` is defined in ``hate_crack/main.py``
and resolves ``toggle_notifications`` / ``toggle_per_crack_notifications`` /
``test_pushover_notification`` against ``hate_crack.main``'s own globals.
We therefore patch that module directly — patching the ``hate_crack.py``
proxy would have no effect on the submenu's internal dispatch.
"""
import hate_crack.main as _main_mod
import hate_crack.menu as _menu_mod
from hate_crack.notify.settings import NotifySettings


def _stub_action_handlers(monkeypatch, calls):
    monkeypatch.setattr(
        _main_mod, "toggle_notifications", lambda: calls.append("toggle")
    )
    monkeypatch.setattr(
        _main_mod,
        "toggle_per_crack_notifications",
        lambda: calls.append("toggle_pc"),
    )
    monkeypatch.setattr(
        _main_mod,
        "test_pushover_notification",
        lambda: calls.append("test"),
    )


def _queue_menu_choices(monkeypatch, choices):
    """Queue ``choices`` as sequential return values from ``interactive_menu``.

    Always appends a final ``"99"`` so the loop exits even if the caller
    forgot — this mirrors how the real user ends a submenu.
    """
    iterator = iter(list(choices) + ["99"])

    def _fake_menu(items, title=""):
        return next(iterator)

    monkeypatch.setattr(_menu_mod, "interactive_menu", _fake_menu)


class TestNotificationsSubmenu:
    def test_choice_1_dispatches_toggle_notifications(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)
        _queue_menu_choices(monkeypatch, ["1"])
        _main_mod.notifications_submenu()
        assert calls == ["toggle"]

    def test_choice_2_dispatches_toggle_per_crack(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)
        _queue_menu_choices(monkeypatch, ["2"])
        _main_mod.notifications_submenu()
        assert calls == ["toggle_pc"]

    def test_choice_3_dispatches_test_pushover(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)
        _queue_menu_choices(monkeypatch, ["3"])
        _main_mod.notifications_submenu()
        assert calls == ["test"]

    def test_choice_99_exits_without_dispatch(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)

        def _only_99(items, title=""):
            return "99"

        monkeypatch.setattr(_menu_mod, "interactive_menu", _only_99)
        _main_mod.notifications_submenu()
        assert calls == []

    def test_none_choice_exits_without_dispatch(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)

        def _returns_none(items, title=""):
            return None

        monkeypatch.setattr(_menu_mod, "interactive_menu", _returns_none)
        _main_mod.notifications_submenu()
        assert calls == []

    def test_submenu_labels_reflect_live_settings(self, monkeypatch):
        captured_items = {}

        def _capture(items, title=""):
            captured_items["items"] = items
            captured_items["title"] = title
            return "99"

        monkeypatch.setattr(_menu_mod, "interactive_menu", _capture)
        monkeypatch.setattr(
            _main_mod._notify,
            "get_settings",
            lambda: NotifySettings(enabled=True, per_crack_enabled=False),
        )
        _main_mod.notifications_submenu()
        labels = {k: v for k, v in captured_items["items"]}
        assert "ON" in labels["1"]
        assert "OFF" in labels["2"]
        assert labels["3"] == "Send Test Pushover Notification"
        assert labels["99"] == "Back to Main Menu"
        assert "Notifications" in captured_items["title"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notifications_submenu.py -v
```

Expected: `AttributeError: module ... has no attribute 'notifications_submenu'`.

- [ ] **Step 3: Implement the submenu**

Insert in `hate_crack/main.py` immediately after `rule_tools_submenu` (currently ends at line 3881):

```python
def notifications_submenu():
    """Submenu for all Pushover notification controls (main-menu option 82)."""
    from hate_crack.menu import interactive_menu

    while True:
        settings = _notify.get_settings()
        global_label = "ON" if settings.enabled else "OFF"
        per_crack_label = "ON" if settings.per_crack_enabled else "OFF"
        items = [
            ("1", f"Toggle Pushover Notifications [{global_label}]"),
            ("2", f"Toggle Per-Crack Notifications [{per_crack_label}]"),
            ("3", "Send Test Pushover Notification"),
            ("99", "Back to Main Menu"),
        ]
        choice = interactive_menu(items, title="\nNotifications:")
        if choice is None or choice == "99":
            break
        if choice == "1":
            toggle_notifications()
        elif choice == "2":
            toggle_per_crack_notifications()
        elif choice == "3":
            test_pushover_notification()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_notifications_submenu.py tests/test_notify_per_crack_toggle.py -v
```

Expected: all six tests in `TestNotificationsSubmenu` pass; no regressions in Task 3 tests.

- [ ] **Step 5: Commit**

```bash
git add hate_crack/main.py tests/test_notifications_submenu.py
git commit -m "feat(notify): add Notifications submenu dispatcher"
```

---

## Task 5: Rewire main menu in `main.py` and `hate_crack.py`

**Files:**
- Modify: `hate_crack/main.py` (`get_main_menu_items` around line 4144, `get_main_menu_options` around line 4192)
- Modify: `hate_crack.py` (`get_main_menu_options` around line 74)
- Modify: `tests/test_ui_menu_options.py` (`MENU_OPTION_TEST_CASES` list around line 13)

- [ ] **Step 1: Update the parametrized menu test cases**

Edit `tests/test_ui_menu_options.py`. Replace the two rows for options `83` and `84` (lines 35–36 as of now) with a single row for option `82`:

Find:
```python
    ("83", CLI_MODULE, "toggle_notifications", "toggle-notifications"),
    ("84", CLI_MODULE, "test_pushover_notification", "test-pushover"),
```

Replace with:
```python
    ("82", CLI_MODULE, "notifications_submenu", "notifications-submenu"),
```

Then add the following regression test to the same file, immediately after `test_main_menu_option_94_hashview_visible_with_hashview_api_key`:

```python
def test_main_menu_no_longer_exposes_options_83_84():
    """Options 83 and 84 moved into the Notifications submenu (option 82)."""
    options = CLI_MODULE.get_main_menu_options()
    assert "83" not in options
    assert "84" not in options
    assert "82" in options


def test_main_menu_items_include_notifications_entry():
    items = dict(CLI_MODULE.get_main_menu_items())
    assert "82" in items
    assert "Notifications" in items["82"]
    assert "83" not in items
    assert "84" not in items
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_ui_menu_options.py -v
```

Expected: the parametrized `("82", …)` case fails with "Menu option 82 must exist", and the two new regression tests fail.

- [ ] **Step 3: Update `hate_crack/main.py`**

Edit `get_main_menu_items` (current definition starts at line 4144). Replace the block:

```python
        ("80", "Wordlist Tools"),
        ("81", "Rule File Tools"),
        (
            "83",
            f"Toggle Pushover Notifications [{'ON' if _notify.get_settings().enabled else 'OFF'}]",
        ),
        ("84", "Send Test Pushover Notification"),
```

with:

```python
        ("80", "Wordlist Tools"),
        ("81", "Rule File Tools"),
        ("82", "Notifications"),
```

Edit `get_main_menu_options` (current definition starts at line 4192). Replace the block:

```python
        "80": wordlist_tools_submenu,
        "81": rule_tools_submenu,
        "83": toggle_notifications,
        "84": test_pushover_notification,
```

with:

```python
        "80": wordlist_tools_submenu,
        "81": rule_tools_submenu,
        "82": notifications_submenu,
```

- [ ] **Step 4: Update `hate_crack.py`**

Edit `get_main_menu_options` (starts around line 74). Replace the block:

```python
        "80": _attacks.wordlist_tools_submenu,
        "81": _attacks.rule_tools_submenu,
        "83": toggle_notifications,
        "84": test_pushover_notification,
```

with:

```python
        "80": _attacks.wordlist_tools_submenu,
        "81": _attacks.rule_tools_submenu,
        "82": notifications_submenu,
```

The `notifications_submenu` name resolves automatically through the existing `__getattr__` proxy at `hate_crack.py:20-21`, so no explicit import is required.

- [ ] **Step 5: Run full UI and notify test suites**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest \
  tests/test_ui_menu_options.py \
  tests/test_notifications_submenu.py \
  tests/test_notify_per_crack_toggle.py \
  tests/test_notify_settings.py \
  tests/test_notify_integration.py \
  -v
```

Expected: every test passes, including the parametrized `82` case and the two regression tests.

- [ ] **Step 6: Commit**

```bash
git add hate_crack/main.py hate_crack.py tests/test_ui_menu_options.py
git commit -m "feat(notify): move options 83/84 under new Notifications submenu (82)"
```

---

## Task 6: Documentation updates

**Files:**
- Modify: `README.md` (add a new "Notifications (menu option 82)" section, modeled on the existing "Wordlist Tools (menu option 80)" section at line 475)
- Modify: `.claude/specs/2026-04-22-test-pushover-menu-design.md` (add a supersede note at the top)

- [ ] **Step 1: Add a README section**

Open `README.md`. The existing sections under `## Usage` include `### Wordlist Tools (menu option 80)` (around line 475). Insert a new section **immediately before** the Wordlist Tools section so the numbered menu options read top-to-bottom:

```markdown
### Notifications (menu option 82)

hate_crack can send Pushover push notifications when attacks complete and,
optionally, when individual hashes are cracked. All controls live under
main-menu option `82 — Notifications`:

1. **Toggle Pushover Notifications [ON/OFF]** — master switch. Persists to `config.json` as `notify_enabled`.
2. **Toggle Per-Crack Notifications [ON/OFF]** — when ON, a background tailer watches the `.out` file and pushes a notification per crack (with per-tick burst aggregation). Persists to `config.json` as `notify_per_crack_enabled`. Cannot be enabled while the master switch is OFF — enable option 1 first.
3. **Send Test Pushover Notification** — fires a canned push so you can confirm your Pushover token/user pair works. Works even when the master switch is OFF.

Credentials and tuning knobs remain config-file-only in `config.json`:

- `notify_pushover_token`, `notify_pushover_user` — required for any push to fire.
- `notify_attack_allowlist` — attack names that auto-consent without the `[y/N/always]` prompt. Populated automatically when you answer `always`.
- `notify_suppress_in_orchestrators` (default `true`) — silences nested attacks launched by Quick/Extensive/Brute-Force wrappers; the wrapper fires a single summary instead.
- `notify_max_cracks_per_burst` (default `5`), `notify_poll_interval_seconds` (default `5.0`) — per-crack tailer tuning. See `hate_crack/notify/tailer.py` for the burst aggregation logic.
```

- [ ] **Step 2: Add a supersede note to the old spec**

Open `.claude/specs/2026-04-22-test-pushover-menu-design.md`. Insert at the very top, before the first line:

```markdown
> **Superseded by** `.claude/specs/2026-04-22-notifications-submenu-design.md`.
> The top-level option 83/84 layout described here was replaced by a single
> main-menu entry at option 82 that opens a Notifications submenu.
```

- [ ] **Step 3: Verify markdown renders cleanly**

No test framework for markdown; a visual sanity check is enough. Run:

```bash
grep -n "menu option 82\|menu option 80" README.md
```

Expected: both sections appear, 82 before 80 in line order (so the final rendered doc reads 80 → 81 → 82 once we include 81… but 81 has no section in the current README, so the expected visible order is `82`-section, then `80`-section — which is fine; the README's submenu sections are not strictly ordered by option number today).

- [ ] **Step 4: Commit**

```bash
git add README.md .claude/specs/2026-04-22-test-pushover-menu-design.md
git commit -m "docs: document Notifications submenu (option 82) in README"
```

---

## Task 7: Final verification (lint, full test suite)

**Files:** none (verification only)

- [ ] **Step 1: Run ruff and ty**

```bash
cd /tmp/hate_crack-notifications-submenu
uv run ruff check hate_crack
uv run ty check hate_crack
```

Expected: zero errors from each. If `ruff` reports issues in the new code, auto-fix with `uv run ruff check --fix hate_crack` and re-run.

- [ ] **Step 2: Run ruff format (non-destructive check)**

```bash
uv run ruff format --check hate_crack
```

Expected: zero reformatting diffs. If diffs exist, apply with `uv run ruff format hate_crack` and commit as a separate `style:` commit.

- [ ] **Step 3: Run the full test suite**

```bash
HATE_CRACK_SKIP_INIT=1 uv run pytest -v
```

Expected: all tests pass. Pay attention to any pre-existing `xfail`/`skip` markers — they should remain unchanged.

- [ ] **Step 4: Manual smoke check of menu wiring (optional but recommended)**

```bash
HATE_CRACK_SKIP_INIT=1 uv run python - <<'PY'
import hate_crack as hc
items = hc.get_main_menu_items()
options = hc.get_main_menu_options()
print("items:")
for k, v in items:
    if k in ("80", "81", "82", "83", "84"):
        print(f"  {k}: {v}")
print("options keys for 80-84:", [k for k in options if k in ("80", "81", "82", "83", "84")])
PY
```

Expected output:
```
items:
  80: Wordlist Tools
  81: Rule File Tools
  82: Notifications
options keys for 80-84: ['80', '81', '82']
```

- [ ] **Step 5: Commit any lint/format fixes if there were any**

If Steps 1 or 2 produced a diff:

```bash
git add -u
git commit -m "style: ruff format pass for Notifications submenu"
```

Otherwise skip.

- [ ] **Step 6: Summarize the branch state**

```bash
git log --oneline feat/pushover-notifications..HEAD
```

Expected: six to seven commits, one per task (plus an optional style commit).

---

## Out of Scope

- Interactive editors for `notify_max_cracks_per_burst`, `notify_poll_interval_seconds`, or `notify_attack_allowlist` — these remain config-file-only.
- A "Show current notification settings" read-only submenu item.
- Any change to `start_tailer`, the Pushover HTTP backend, or the orchestrator suppression logic.
- Renaming or reorganizing existing tests beyond the parametrized `MENU_OPTION_TEST_CASES` list.
