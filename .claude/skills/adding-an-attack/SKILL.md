---
name: adding-an-attack
description: Use when adding a new attack mode to hate_crack — the wiring across main.py, attacks.py, menu_registry.py, the menu test, and an optional non-interactive subcommand.
---

# Adding a New Attack

An attack spans `main.py`, `attacks.py` and `hate_crack/menu_registry.py` (see
"Three-Layer Attack Pattern" in `CLAUDE.md`). The menu is described once, in
the registry; `hate_crack.py` has no mapping of its own.

1. Add the hashcat wrapper function in `main.py` (e.g. `hcatMyAttack(...)`)
2. Add the handler in `attacks.py` (e.g. `def my_attack(ctx: Any)`)
3. Add a dispatcher in `main.py`: `def my_attack(): return _attacks.my_attack(_attack_ctx())`
4. Add ONE `MenuAction("<key>", "<label>", _late("my_attack"))` row to `MAIN_MENU`
   in `hate_crack/menu_registry.py`. The handler is looked up by name at call
   time, so the name must match the dispatcher in step 3
5. Add a row to the table in `tests/test_ui_menu_options.py`
6. Optional: for a scripted subcommand, add one `AttackSpec` row to
   `ATTACK_SPECS` in `hate_crack/noninteractive.py`. Do not edit
   `ATTACK_COMMANDS` or the subparser wiring separately; both derive from it
