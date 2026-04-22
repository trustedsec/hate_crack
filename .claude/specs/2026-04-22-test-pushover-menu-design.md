# Test Pushover Notification — Menu Entry

**Date:** 2026-04-22
**Branch:** `feat/test-pushover-menu`

## Goal

Give the user a one-click way to verify that their Pushover credentials and
network path actually work, independent of running an attack.

## User-facing behavior

Main menu gains one new entry:

```
 84. Send Test Pushover Notification
```

Placed directly below the existing `83. Toggle Pushover Notifications`
entry so related controls sit together.

Selecting it calls `_send_pushover(...)` once with a canned title/message:

- **Title:** `hate_crack: test notification`
- **Message:** `This is a test notification from hate_crack. If you see this, Pushover is wired up correctly.`

It then prints one of three lines to the terminal:

1. **Credentials missing** — `notify_pushover_token` or `notify_pushover_user`
   is empty in `config.json`:
   > `[!] Pushover credentials missing. Set notify_pushover_token and notify_pushover_user in config.json.`
2. **Send succeeded** — `_send_pushover` returned `True`:
   > `[+] Test Pushover notification sent. Check your device.`
3. **Send failed** — `_send_pushover` returned `False` (HTTP non-200, network
   error, missing `requests`, etc.):
   > `[!] Test Pushover notification failed. See log output for details.`

### Global toggle behavior (option A)

The test **ignores** the `notify_enabled` global toggle. The entire purpose
of the test is to verify the pipe works, and forcing the user to flip the
toggle first would be friction for no benefit.

When the global toggle is OFF, we still send, but prepend an informational
line so the user is not confused later when no attack notifications arrive:

> `(notifications are globally OFF, but sending test anyway)`

## Implementation outline

Follows the existing three-layer pattern for non-attack menu items (same
shape as `toggle_notifications`):

1. **`hate_crack/main.py`** — new function `test_pushover_notification()`:
   - Read `_notify.get_settings()` for token/user.
   - Empty-creds branch -> print the missing-creds warning, return.
   - If `settings.enabled is False`, print the "globally OFF" note.
   - Call `_notify._send_pushover(token, user, title, message)`.
   - Print success or failure line based on the returned bool.
2. **`hate_crack/main.py`** — menu wiring in `get_main_menu_items()` and
   `get_main_menu_options()`:
   - Add `("84", "Send Test Pushover Notification")` right after the `83`
     entry.
   - Add `"84": test_pushover_notification` to the options map.
3. **`hate_crack.py`** — menu wiring in its duplicate
   `get_main_menu_options()`:
   - Add `"84": test_pushover_notification`. Per the proxy pattern,
     `test_pushover_notification` resolves through `__getattr__`.

No new module, no new dependency, no new config key.

## Testing

Add one test in `tests/test_notify.py` (or a new `tests/test_menu_test_pushover.py`
if the existing file is already dense):

- Monkeypatch `hate_crack.notify._send_pushover` to a stub returning `True`,
  call `main.test_pushover_notification()`, assert stdout contains the
  success line and the stub saw the canned title/message.
- Stub returning `False` -> assert failure line.
- Empty creds (`NotifySettings()` with blank token/user) -> assert
  missing-creds line and stub **not called**.
- `enabled = False` with good creds -> assert the "globally OFF" note
  appears and the stub **is** called.

Menu-wiring test: extend `test_ui_menu_options.py` to assert `"84"` is in
both the `main.get_main_menu_options()` dict and the `hate_crack.py`
duplicate, and that both resolve to a callable.

## Non-goals

- No new backend (Slack, webhooks) — a sibling test for those can be added
  when those backends exist.
- No interactive "enter token" prompt; the test assumes `config.json` is
  already populated, matching how `toggle_notifications` behaves.
- No persistent state changes from running the test.
