---
name: adding-an-attack
description: Use when adding a new attack mode to hate_crack — the exact six wiring steps across main.py, attacks.py, and hate_crack.py, including the duplicate menu mapping that is easy to miss.
---

# Adding a New Attack

An attack spans three files (see "Three-Layer Attack Pattern" in `CLAUDE.md`).
Do all six steps — skipping step 6 leaves the attack invisible from the root
entry point even though it works via `main.py`.

1. Add the hashcat wrapper function in `main.py` (e.g. `hcatMyAttack(...)`)
2. Add the handler in `attacks.py` (e.g. `def my_attack(ctx: Any)`)
3. Add a dispatcher in `main.py`: `def my_attack(): return _attacks.my_attack(_attack_ctx())`
4. Add the print line in `main.py`'s menu display loop (~line 3807+)
5. Add the menu entry in `main.py`'s `get_main_menu_options()`
6. Add the menu entry in `hate_crack.py`'s `get_main_menu_options()` (the duplicate)
