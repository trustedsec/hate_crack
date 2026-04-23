# Notifications Submenu Design

**Date:** 2026-04-22
**Branch:** `feat/notifications-submenu` (forked from `feat/pushover-notifications`)
**Status:** Approved — ready for implementation planning
**Supersedes (in part):** `.claude/specs/2026-04-22-test-pushover-menu-design.md` (the top-level option 83/84 layout described there is replaced by this submenu)

## Motivation

The Pushover notification feature currently surfaces two top-level options in the main menu — `83) Toggle Pushover Notifications [ON/OFF]` and `84) Send Test Pushover Notification`. The `notify_per_crack_enabled` setting, which controls whether hashcat's `.out` file is tailed for live per-crack pings, is only reachable by editing `config.json` by hand.

Two goals:

1. Promote the per-crack setting to a first-class runtime toggle so users can flip it without leaving the program.
2. Consolidate notification controls under a single main-menu entry (option `82`), matching the existing `Wordlist Tools` / `Rule File Tools` submenu pattern, so the main menu stays short as more notification features are added.

## Scope

**In scope:**
- New main-menu option `82) Notifications` that opens a submenu.
- Submenu items:
  1. `Toggle Pushover Notifications [ON/OFF]` — existing behavior, relocated.
  2. `Toggle Per-Crack Notifications [ON/OFF]` — NEW.
  3. `Send Test Pushover Notification` — existing behavior, relocated.
  4. `99) Back to Main Menu`.
- Remove standalone options `83` and `84` from the main menu.
- New `toggle_per_crack_enabled()` in the notify module with atomic config persistence.
- Guard: refuse to turn per-crack ON while global notifications are OFF.
- Test coverage for the new toggle, guard behavior, and menu wiring.
- Update README and any in-tree docs that reference option 83/84.

**Out of scope:**
- Interactive editors for `notify_max_cracks_per_burst`, `notify_poll_interval_seconds`, `notify_attack_allowlist`, or Pushover credentials — these remain config-file-only for now.
- A "Show current notification settings" read-only view.
- Any change to how the per-crack tailer actually runs.

## Design

### Menu layout

`hate_crack/main.py:get_main_menu_items` and the duplicate in `hate_crack.py:get_main_menu_options`:

- **Add** `("82", "Notifications")` between `("81", "Rule File Tools")` and the `90+` range.
- **Remove** the two live-labeled entries for `83` and `84` and their corresponding entries in `get_main_menu_options`.

New submenu rendered by `notifications_submenu()` in `hate_crack/main.py`, using the existing `interactive_menu` helper and the same item-list pattern as `wordlist_tools_submenu` (`main.py:3860` dispatcher, `attacks.py:1171` implementation):

```
Notifications:
  1) Toggle Pushover Notifications [ON/OFF]
  2) Toggle Per-Crack Notifications [ON/OFF]
  3) Send Test Pushover Notification
 99) Back to Main Menu
```

Both `[ON/OFF]` labels are recomputed from `_notify.get_settings()` on each render, matching the live-label pattern already used for option 83 (`main.py:4170`).

### Toggle behavior

**`hate_crack/notify/settings.py`** — add `save_per_crack_enabled(config_path: str, enabled: bool) -> None`:

Mirrors `save_enabled` at `settings.py:141`. Uses the existing `_atomic_rewrite` primitive to write `notify_per_crack_enabled` without disturbing other keys. Single-line mutator.

**`hate_crack/notify/__init__.py`** — add `toggle_per_crack_enabled() -> bool`:

Mirrors `toggle_enabled` at `__init__.py:130`:

- Flips `_settings.per_crack_enabled`.
- Persists via `save_per_crack_enabled(_config_path, …)`.
- Returns the new bool.
- Logs `OSError` at `warning` level on persistence failure (same pattern as `toggle_enabled`).
- Exported via `__all__`.

The notify module does *not* enforce the "global must be ON" rule — the runtime logic at `start_tailer` (`__init__.py:264-272`) already correctly handles any combination of flags (per-crack only fires when both are true). The "global must be ON" rule is a *UI affordance*, not a data invariant, so it belongs in the menu handler.

**`hate_crack/main.py`** — add `toggle_per_crack_notifications()`:

```
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

Turning OFF is always allowed (the guard only fires when currently OFF and being asked to turn ON while the global is OFF). This lets users clean up inconsistent `notify_per_crack_enabled: true, notify_enabled: false` configs without surprise.

**`hate_crack/main.py`** — add `notifications_submenu()`:

Follows the `wordlist_tools_submenu` dispatcher pattern at `main.py:3860`. Holds an ordered item list, loops on `interactive_menu`, breaks on `None` or `"99"`, dispatches to `toggle_notifications`, `toggle_per_crack_notifications`, `test_pushover_notification`.

Labels for items 1 and 2 are recomputed inside the loop so they refresh after each toggle.

### Proxy shim

`hate_crack.py` auto-proxies attribute access to `hate_crack.main` via `__getattr__` (`hate_crack.py:20-21`), so `notifications_submenu` and `toggle_per_crack_notifications` will be reachable through the proxy without explicit re-export. The duplicate `get_main_menu_options` in `hate_crack.py` still needs the same `"82"` → `notifications_submenu` entry and removal of `"83"` / `"84"`, per the CLAUDE.md "Adding a New Attack" checklist (which also applies to menu changes).

## Testing

**New file `tests/test_notify_per_crack_toggle.py`:**

- `save_per_crack_enabled` round-trips True/False through a temp config, preserving other keys.
- `toggle_per_crack_enabled` flips in-memory state and persists to the config path passed to `_notify.init`.
- State survives a second `load_settings` call (verifies persistence is real, not just in-memory).

**Additions to `tests/test_notify_settings.py`:**

- A row asserting that `save_per_crack_enabled` writes the expected key, similar to the existing `save_enabled` coverage.

**Additions to `tests/test_ui_menu_options.py`:**

- `"82"` dispatches to the notifications submenu.
- `"83"` and `"84"` no longer appear in `get_main_menu_options()` / `get_main_menu_items()` — both for `main.py` directly and for `CLI_MODULE` (the `hate_crack.py` proxy).
- Submenu: choosing `"1"` calls `toggle_notifications`; `"2"` calls `toggle_per_crack_notifications`; `"3"` calls `test_pushover_notification`; `"99"` exits.
- Guard: when global is OFF and per-crack is OFF, selecting submenu `"2"` prints the refusal message and does NOT call `_notify.toggle_per_crack_enabled`.
- Guard: when global is OFF but per-crack is currently ON, selecting submenu `"2"` DOES flip (turning off is unrestricted).

All tests use monkeypatching against `CLI_MODULE` where the existing menu tests do, and against `_notify` directly where the underlying module behavior is under test.

## Documentation

- `README.md`: if it currently references option `83`/`84` or describes Pushover setup, update those references to point at submenu `82` and document the new per-crack toggle. If the README is silent on Pushover, do not invent a new section — keep this change minimal.
- `hate_crack/notify/__init__.py` module docstring: if it references menu wiring, update it; otherwise leave.
- `.claude/specs/2026-04-22-test-pushover-menu-design.md`: add a short "Superseded by …" header pointing at this spec; do not rewrite — it's history.
- Any in-tree comment that mentions option `83`/`84` by number.

## Execution

- Worktree: `/tmp/hate_crack-notifications-submenu`, branch `feat/notifications-submenu`, forked from `feat/pushover-notifications` tip (`7842f63`).
- Implementation uses subagent-driven development per user's global CLAUDE.md.
- All edits, tests, and lint runs happen inside the worktree.
- Merge back to `feat/pushover-notifications` via PR or `git merge` once all tests and lint pass.
