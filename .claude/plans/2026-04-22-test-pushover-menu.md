# Test Pushover Menu Entry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add main-menu entry `84. Send Test Pushover Notification` that sends a canned Pushover message to verify the user's credentials and network path.

**Architecture:** One new function `test_pushover_notification()` in `hate_crack/main.py` that reads settings from the `notify` subsystem, calls the existing `notify._send_pushover(...)` once, and prints a one-line status to stdout. Two menu tables are updated (the main map in `main.py` and the duplicate in `hate_crack.py`). Per the spec, the test ignores the `notify_enabled` global toggle — if the toggle is OFF, we still send, but prepend an informational line so the user is not confused later.

**Tech Stack:** Python 3, pytest, `unittest.mock.patch`, existing `hate_crack.notify` package.

**Spec:** `.claude/specs/2026-04-22-test-pushover-menu-design.md`

**Worktree:** `/tmp/hate_crack-test-pushover` on branch `feat/test-pushover-menu`.

---

## File Map

**New files:**
- `tests/test_ui_test_pushover.py` — unit tests for `test_pushover_notification()`

**Modified files:**
- `hate_crack/main.py`
  - Add function `test_pushover_notification()` near the existing `toggle_notifications()` (around line 4091)
  - Add `("84", "Send Test Pushover Notification")` row to `get_main_menu_items()`
  - Add `"84": test_pushover_notification` entry to `get_main_menu_options()`
- `hate_crack.py`
  - Add `"84": test_pushover_notification` to the duplicate `get_main_menu_options()` (resolved via `__getattr__` proxy)
- `tests/test_ui_menu_options.py`
  - Add `("84", CLI_MODULE, "test_pushover_notification", "test-pushover")` to `MENU_OPTION_TEST_CASES`

---

## Task 1: Add `test_pushover_notification()` function (TDD)

**Files:**
- Create: `tests/test_ui_test_pushover.py`
- Modify: `hate_crack/main.py` (new function near line 4091, after `toggle_notifications`)

### Step 1: Write the failing test file

- [ ] Create `tests/test_ui_test_pushover.py` with the full test module below.

```python
"""Unit tests for main.test_pushover_notification()."""
from unittest.mock import patch

import pytest

from hate_crack import main as hc_main
from hate_crack import notify
from hate_crack.notify.settings import NotifySettings


@pytest.fixture(autouse=True)
def _reset_notify_state():
    notify.clear_state_for_tests()
    yield
    notify.clear_state_for_tests()


def _install_settings(
    *,
    enabled: bool = True,
    token: str = "tok",
    user: str = "usr",
) -> None:
    """Swap fresh settings into the notify module for this test."""
    settings = NotifySettings()
    settings.enabled = enabled
    settings.pushover_token = token
    settings.pushover_user = user
    notify._settings = settings


class TestTestPushoverNotification:
    def test_success_prints_confirmation_and_sends(self, capsys):
        _install_settings(enabled=True, token="tok", user="usr")
        with patch("hate_crack.notify._send_pushover", return_value=True) as send:
            hc_main.test_pushover_notification()
        assert send.called
        args = send.call_args.args
        assert args[0] == "tok"
        assert args[1] == "usr"
        assert args[2] == "hate_crack: test notification"
        assert "test notification from hate_crack" in args[3]
        out = capsys.readouterr().out
        assert "[+] Test Pushover notification sent" in out

    def test_failure_prints_failure_line(self, capsys):
        _install_settings(enabled=True, token="tok", user="usr")
        with patch("hate_crack.notify._send_pushover", return_value=False):
            hc_main.test_pushover_notification()
        out = capsys.readouterr().out
        assert "[!] Test Pushover notification failed" in out

    def test_missing_token_skips_send_and_warns(self, capsys):
        _install_settings(enabled=True, token="", user="usr")
        with patch("hate_crack.notify._send_pushover") as send:
            hc_main.test_pushover_notification()
        send.assert_not_called()
        out = capsys.readouterr().out
        assert "[!] Pushover credentials missing" in out
        assert "notify_pushover_token" in out

    def test_missing_user_skips_send_and_warns(self, capsys):
        _install_settings(enabled=True, token="tok", user="")
        with patch("hate_crack.notify._send_pushover") as send:
            hc_main.test_pushover_notification()
        send.assert_not_called()
        out = capsys.readouterr().out
        assert "[!] Pushover credentials missing" in out

    def test_globally_off_still_sends_with_note(self, capsys):
        _install_settings(enabled=False, token="tok", user="usr")
        with patch("hate_crack.notify._send_pushover", return_value=True) as send:
            hc_main.test_pushover_notification()
        send.assert_called_once()
        out = capsys.readouterr().out
        assert "notifications are globally OFF" in out
        assert "[+] Test Pushover notification sent" in out
```

### Step 2: Run tests to confirm they fail

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_ui_test_pushover.py -v`
- [ ] Expected: all five tests fail with `AttributeError: module 'hate_crack.main' has no attribute 'test_pushover_notification'`.

### Step 3: Implement `test_pushover_notification()` in `main.py`

- [ ] Open `hate_crack/main.py` and locate the `toggle_notifications()` function (around line 4091).
- [ ] Insert the following function directly below `toggle_notifications()` (i.e., between `toggle_notifications` and `get_main_menu_items`):

```python
def test_pushover_notification():
    """Send a canned test notification so the user can verify Pushover works.

    Ignores the global ``notify_enabled`` toggle on purpose: the point of the
    test is to confirm the wire is live, independent of whether attacks are
    currently wired to notify.  When the global toggle is OFF we still send
    but print a note so the user is not surprised later.
    """
    settings = _notify.get_settings()
    token = settings.pushover_token
    user = settings.pushover_user
    if not token or not user:
        print(
            "\n[!] Pushover credentials missing. Set notify_pushover_token "
            "and notify_pushover_user in config.json."
        )
        return

    if not settings.enabled:
        print("\n(notifications are globally OFF, but sending test anyway)")

    title = "hate_crack: test notification"
    message = (
        "This is a test notification from hate_crack. "
        "If you see this, Pushover is wired up correctly."
    )
    ok = _notify._send_pushover(token, user, title, message)
    if ok:
        print("[+] Test Pushover notification sent. Check your device.")
    else:
        print("[!] Test Pushover notification failed. See log output for details.")
```

### Step 4: Run the new tests to confirm they pass

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_ui_test_pushover.py -v`
- [ ] Expected: all five tests pass.

### Step 5: Commit

- [ ] Run:

```bash
git add tests/test_ui_test_pushover.py hate_crack/main.py
git commit -m "$(cat <<'EOF'
feat(notify): add test_pushover_notification helper

Canned send path so a user can verify Pushover credentials without
running an attack. Ignores the global notify_enabled toggle — the test's
purpose is to confirm the pipe is live, not that attack notifications
are enabled. Prints a note when the global toggle is OFF so the user is
not confused later.
EOF
)"
```

---

## Task 2: Wire the entry into `main.py`'s menu tables

**Files:**
- Modify: `hate_crack/main.py` — two edits inside `get_main_menu_items()` and `get_main_menu_options()`

### Step 1: Add the menu item row

- [ ] Open `hate_crack/main.py` and find the `("83", f"Toggle Pushover Notifications [...]")` entry inside `get_main_menu_items()` (around line 4135).
- [ ] Directly below the closing `)` of that 83 tuple, insert:

```python
        ("84", "Send Test Pushover Notification"),
```

Context (before):

```python
        (
            "83",
            f"Toggle Pushover Notifications [{'ON' if _notify.get_settings().enabled else 'OFF'}]",
        ),
        ("90", "Download rules from Hashmob.net"),
```

Context (after):

```python
        (
            "83",
            f"Toggle Pushover Notifications [{'ON' if _notify.get_settings().enabled else 'OFF'}]",
        ),
        ("84", "Send Test Pushover Notification"),
        ("90", "Download rules from Hashmob.net"),
```

### Step 2: Add the options map entry

- [ ] In the same file find `"83": toggle_notifications,` inside `get_main_menu_options()` (around line 4182).
- [ ] Insert on the next line:

```python
        "84": test_pushover_notification,
```

Context (after):

```python
        "83": toggle_notifications,
        "84": test_pushover_notification,
        "90": lambda: download_hashmob_rules(rules_dir=rulesDirectory),
```

### Step 3: Sanity-check main.py loads

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run python -c "from hate_crack import main; print(main.get_main_menu_options()['84'].__name__)"`
- [ ] Expected output ends with: `test_pushover_notification`

### Step 4: Commit

- [ ] Run:

```bash
git add hate_crack/main.py
git commit -m "feat(notify): wire option 84 into main.py menu"
```

---

## Task 3: Wire the entry into `hate_crack.py`'s duplicate menu

**Files:**
- Modify: `hate_crack.py` — one edit inside `get_main_menu_options()`

### Step 1: Add the options map entry

- [ ] Open `hate_crack.py` (repo root) and find `"83": toggle_notifications,` inside `get_main_menu_options()` (line 97).
- [ ] Insert on the next line:

```python
        "84": test_pushover_notification,
```

Note: `test_pushover_notification` is not explicitly imported in `hate_crack.py`; it resolves via the module's `__getattr__` proxy to `_main`. No import changes are needed.

Context (after):

```python
        "81": _attacks.rule_tools_submenu,
        "83": toggle_notifications,
        "84": test_pushover_notification,
        "90": download_hashmob_rules,
```

### Step 2: Sanity-check both menus agree on option 84

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run python -c "import importlib.util, pathlib; spec = importlib.util.spec_from_file_location('cli', pathlib.Path('hate_crack.py')); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print(m.get_main_menu_options()['84'].__name__)"`
- [ ] Expected output ends with: `test_pushover_notification`

### Step 3: Commit

- [ ] Run:

```bash
git add hate_crack.py
git commit -m "feat(notify): wire option 84 into hate_crack.py proxy menu"
```

---

## Task 4: Add parametrized menu-wiring test

**Files:**
- Modify: `tests/test_ui_menu_options.py` — one row added to `MENU_OPTION_TEST_CASES`

### Step 1: Add the test case row

- [ ] Open `tests/test_ui_menu_options.py` and find the line:

```python
    ("83", CLI_MODULE, "toggle_notifications", "toggle-notifications"),
```

- [ ] Insert directly below it:

```python
    ("84", CLI_MODULE, "test_pushover_notification", "test-pushover"),
```

### Step 2: Run the menu test suite

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_ui_menu_options.py -v`
- [ ] Expected: the new parametrized case `test_main_menu_option_returns_expected[84-...-test-pushover]` passes, and no existing cases regress.

### Step 3: Commit

- [ ] Run:

```bash
git add tests/test_ui_menu_options.py
git commit -m "test(notify): cover option 84 in menu wiring parametrize"
```

---

## Task 5: Full verification

**Files:** None. This task verifies the whole feature.

### Step 1: Run the full test suite

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest -v`
- [ ] Expected: all tests pass. No new failures compared to the baseline on `feat/pushover-notifications`.

### Step 2: Run lint

- [ ] Run: `uv run ruff check hate_crack`
- [ ] Expected: no errors. If `ty` is available, also run `uv run ty check hate_crack`.

### Step 3: Manual menu display spot-check (optional)

- [ ] Run: `HATE_CRACK_SKIP_INIT=1 uv run python -c "from hate_crack import main; [print(f'{k}: {v}') for k, v in main.get_main_menu_items()]" | grep -E "^(83|84)"`
- [ ] Expected output (token/user state may flip ON/OFF):

```
83: Toggle Pushover Notifications [OFF]
84: Send Test Pushover Notification
```

### Step 4: No-op if prior tasks already committed cleanly

- [ ] Run: `git status`
- [ ] Expected: `nothing to commit, working tree clean`. Branch has four commits ahead of `feat/pushover-notifications` (the four task commits).

---

## Self-Review Results

- **Spec coverage:** all four spec sections are covered — key `84` and label (Task 2+3), missing-creds/success/failure branches (Task 1), globally-OFF behavior (Task 1), menu wiring tests (Task 4). The unit test for the function is in a dedicated new file rather than extended into `test_notify.py` (the spec allowed either).
- **Placeholder scan:** no TBD/TODO tokens; every code step has literal code; every run step has a literal command and expected output.
- **Type consistency:** the function name `test_pushover_notification` is used identically across Tasks 1, 2, 3, and 4. The constants `"hate_crack: test notification"` and `"test notification from hate_crack"` appear verbatim in both the test assertions (Task 1 Step 1) and the implementation (Task 1 Step 3).
