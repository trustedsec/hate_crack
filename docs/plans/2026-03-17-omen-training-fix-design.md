# OMEN Training Fix + Wordlist Picker

## Problem

OMEN attack (menu option 16) fails silently - hashcat exits immediately without candidates. Root causes:

1. Model validation only checks `createConfig` exists, not the 4 `.level` files
2. No way to retrain once a model exists (training permanently skipped)
3. `enumNG` stderr/exit code not captured - failures are invisible
4. Training uses raw path input instead of the wordlist picker menu

## Design

### Bug fixes (main.py)

**Model validation** - Add `_omen_model_is_valid(model_dir)` that checks all 5 required files exist and are non-empty: `createConfig`, `CP.level`, `IP.level`, `EP.level`, `LN.level`.

**enumNG error handling** - Capture stderr from `enumNG` subprocess. If it exits non-zero or stderr has content, print the error and return early instead of letting hashcat sit on empty stdin.

**Training return value** - `hcatOmenTrain` returns `bool` (True on success) so callers can abort if training fails.

**Model metadata** - Write `model_info.json` alongside model files with `{"training_file": "...", "trained_at": "..."}`. Add `_omen_model_info(model_dir)` to read it.

### Menu flow (attacks.py: omen_attack)

1. Check OMEN binaries exist (unchanged)
2. Call `_omen_model_is_valid()` to check model
3. If valid, show status and prompt: Use existing / Train new / Cancel
4. If invalid/missing, go straight to training
5. Training wordlist picker: numbered list from `list_wordlist_files()` + custom path option
6. If training returns False, abort
7. Prompt for max candidates, run `hcatOmen`

### Files modified

- `hate_crack/main.py` - `_omen_model_is_valid`, `_omen_model_info`, `hcatOmenTrain` return bool + write metadata, `hcatOmen` capture enumNG stderr
- `hate_crack/attacks.py` - Rewrite `omen_attack()` with train/use/cancel + wordlist picker
- `tests/test_main_utils.py` - Model validation, training return value, enumNG error tests
- `tests/test_attacks_behavior.py` - omen_attack menu flow tests
