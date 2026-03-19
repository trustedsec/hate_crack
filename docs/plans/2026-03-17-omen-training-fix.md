# OMEN Training Fix + Wordlist Picker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix OMEN attack failing silently (hashcat gets no candidates) and add wordlist picker for training.

**Architecture:** Add model validation helper that checks all 5 required files. Capture enumNG stderr to surface errors. Rewrite omen_attack menu flow with train/use/cancel prompt and wordlist picker reusing list_wordlist_files(). Write model_info.json metadata during training.

**Tech Stack:** Python stdlib (json, subprocess, os), existing hate_crack helpers (list_wordlist_files, print_multicolumn_list)

---

### Task 1: Add _omen_model_is_valid() helper

**Files:**
- Modify: `hate_crack/main.py:2096-2099` (near `_omen_model_dir`)
- Test: `tests/test_omen_attack.py`

**Step 1: Write the failing tests**

Add to `tests/test_omen_attack.py`:

```python
class TestOmenModelValidation:
    @pytest.fixture
    def model_dir(self, tmp_path):
        d = tmp_path / "model"
        d.mkdir()
        return d

    def _create_valid_model(self, model_dir):
        for name in ["createConfig", "CP.level", "IP.level", "EP.level", "LN.level"]:
            (model_dir / name).write_text("data")

    def test_valid_model_returns_true(self, main_module, model_dir):
        self._create_valid_model(model_dir)
        assert main_module._omen_model_is_valid(str(model_dir)) is True

    def test_missing_level_file_returns_false(self, main_module, model_dir):
        self._create_valid_model(model_dir)
        (model_dir / "CP.level").unlink()
        assert main_module._omen_model_is_valid(str(model_dir)) is False

    def test_empty_file_returns_false(self, main_module, model_dir):
        self._create_valid_model(model_dir)
        (model_dir / "EP.level").write_text("")
        assert main_module._omen_model_is_valid(str(model_dir)) is False

    def test_missing_dir_returns_false(self, main_module, tmp_path):
        assert main_module._omen_model_is_valid(str(tmp_path / "nonexistent")) is False

    def test_config_only_returns_false(self, main_module, model_dir):
        (model_dir / "createConfig").write_text("data")
        assert main_module._omen_model_is_valid(str(model_dir)) is False
```

**Step 2: Run tests to verify they fail**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py::TestOmenModelValidation -v`
Expected: FAIL - `_omen_model_is_valid` not defined

**Step 3: Write implementation**

Add to `hate_crack/main.py` after `_omen_model_dir()`:

```python
_OMEN_REQUIRED_FILES = ["createConfig", "CP.level", "IP.level", "EP.level", "LN.level"]


def _omen_model_is_valid(model_dir):
    """Return True if all required OMEN model files exist and are non-empty."""
    if not os.path.isdir(model_dir):
        return False
    for name in _OMEN_REQUIRED_FILES:
        path = os.path.join(model_dir, name)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            return False
    return True
```

**Step 4: Run tests to verify they pass**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py::TestOmenModelValidation -v`
Expected: PASS

**Step 5: Commit**

```bash
git add hate_crack/main.py tests/test_omen_attack.py
git commit -m "feat: add _omen_model_is_valid helper checking all 5 required files"
```

---

### Task 2: Add _omen_model_info() and write model_info.json during training

**Files:**
- Modify: `hate_crack/main.py:2096-2142` (`_omen_model_dir` area and `hcatOmenTrain`)
- Test: `tests/test_omen_attack.py`

**Step 1: Write the failing tests**

Add to `tests/test_omen_attack.py`:

```python
import json

class TestOmenModelInfo:
    def test_returns_info_when_metadata_exists(self, main_module, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        info = {"training_file": "/path/to/rockyou.txt", "trained_at": "2026-03-17T12:00:00"}
        (model_dir / "model_info.json").write_text(json.dumps(info))
        result = main_module._omen_model_info(str(model_dir))
        assert result["training_file"] == "/path/to/rockyou.txt"

    def test_returns_none_when_no_metadata(self, main_module, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        assert main_module._omen_model_info(str(model_dir)) is None

    def test_returns_none_on_corrupt_json(self, main_module, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "model_info.json").write_text("not json")
        assert main_module._omen_model_info(str(model_dir)) is None
```

Update `TestHcatOmenTrain.test_builds_correct_command` to also assert return value and metadata:

```python
    def test_returns_true_on_success(self, main_module, tmp_path):
        training_file = tmp_path / "passwords.txt"
        training_file.write_text("password123\nletmein\n")
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()
        create_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.wait.return_value = None
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            result = main_module.hcatOmenTrain(str(training_file))

        assert result is True
        info_path = model_dir / "model_info.json"
        assert info_path.exists()
        info = json.loads(info_path.read_text())
        assert info["training_file"] == str(training_file)

    def test_returns_false_on_failure(self, main_module, tmp_path):
        training_file = tmp_path / "passwords.txt"
        training_file.write_text("test\n")
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()
        create_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.wait.return_value = None
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc

            result = main_module.hcatOmenTrain(str(training_file))

        assert result is False

    def test_returns_false_on_missing_binary(self, main_module, tmp_path):
        with patch.object(main_module, "_omen_dir", str(tmp_path / "omen")), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"):
            result = main_module.hcatOmenTrain("/nonexistent/file.txt")
        assert result is False
```

**Step 2: Run tests to verify they fail**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py::TestOmenModelInfo tests/test_omen_attack.py::TestHcatOmenTrain::test_returns_true_on_success tests/test_omen_attack.py::TestHcatOmenTrain::test_returns_false_on_failure tests/test_omen_attack.py::TestHcatOmenTrain::test_returns_false_on_missing_binary -v`
Expected: FAIL

**Step 3: Write implementation**

Add `_omen_model_info` to `hate_crack/main.py` after `_omen_model_is_valid`:

```python
def _omen_model_info(model_dir):
    """Read model_info.json from model_dir. Returns dict or None."""
    info_path = os.path.join(model_dir, "model_info.json")
    if not os.path.isfile(info_path):
        return None
    try:
        with open(info_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
```

Modify `hcatOmenTrain` to return bool and write metadata:

```python
def hcatOmenTrain(training_file):
    omen_dir = _omen_dir
    create_bin = os.path.join(omen_dir, hcatOmenCreateBin)
    if not os.path.isfile(create_bin):
        print(f"Error: OMEN createNG binary not found: {create_bin}")
        return False
    training_file = os.path.abspath(training_file)
    if not os.path.isfile(training_file):
        print(f"Error: Training file not found: {training_file}")
        return False
    model_dir = _omen_model_dir()
    print(f"Training OMEN model with: {training_file}")
    print(f"Model output directory: {model_dir}")
    cmd = [
        create_bin,
        "--iPwdList",
        training_file,
        "-C",
        os.path.join(model_dir, "createConfig"),
        "-c",
        os.path.join(model_dir, "CP"),
        "-i",
        os.path.join(model_dir, "IP"),
        "-e",
        os.path.join(model_dir, "EP"),
        "-l",
        os.path.join(model_dir, "LN"),
    ]
    print(f"[*] Running: {_format_cmd(cmd)}")
    proc = subprocess.Popen(cmd)
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(proc.pid)))
        proc.kill()
        return False
    if proc.returncode != 0:
        print(f"OMEN training failed with exit code {proc.returncode}")
        return False
    print("OMEN model training complete.")
    import datetime
    info = {
        "training_file": training_file,
        "trained_at": datetime.datetime.now().isoformat(),
    }
    try:
        with open(os.path.join(model_dir, "model_info.json"), "w") as f:
            json.dump(info, f)
    except OSError:
        pass
    return True
```

**Step 4: Run tests to verify they pass**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py -v`
Expected: PASS (existing tests may need minor adjustments since hcatOmenTrain now returns a value - the old test that doesn't check the return is fine)

**Step 5: Commit**

```bash
git add hate_crack/main.py tests/test_omen_attack.py
git commit -m "feat: hcatOmenTrain returns bool and writes model_info.json metadata"
```

---

### Task 3: Capture enumNG stderr in hcatOmen

**Files:**
- Modify: `hate_crack/main.py:2145-2183` (`hcatOmen`)
- Test: `tests/test_omen_attack.py`

**Step 1: Write the failing test**

Add to `tests/test_omen_attack.py`:

```python
class TestHcatOmenErrorHandling:
    def test_prints_enumng_stderr_on_failure(self, main_module, tmp_path, capsys):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenEnumBin", "enumNG"), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
            mock_enum_proc.stderr = MagicMock()
            mock_enum_proc.stderr.read.return_value = b"ERROR: Could not open CP.level"
            mock_enum_proc.wait.return_value = None
            mock_enum_proc.returncode = 1
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_hashcat_proc.returncode = 0
            mock_enum_proc.wait.return_value = None
            mock_popen.side_effect = [mock_enum_proc, mock_hashcat_proc]

            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)

        captured = capsys.readouterr()
        assert "enumNG failed" in captured.out or "Could not open" in captured.out
```

**Step 2: Run test to verify it fails**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py::TestHcatOmenErrorHandling -v`
Expected: FAIL

**Step 3: Write implementation**

Modify `hcatOmen` in `hate_crack/main.py`. Key changes:
- Add `stderr=subprocess.PIPE` to the enumNG Popen call
- After both processes complete, check `enum_proc.returncode` and read stderr
- Print any stderr content

```python
def hcatOmen(hcatHashType, hcatHashFile, max_candidates):
    global hcatProcess
    omen_dir = _omen_dir
    enum_bin = os.path.join(omen_dir, hcatOmenEnumBin)
    if not os.path.isfile(enum_bin):
        print(f"Error: OMEN enumNG binary not found: {enum_bin}")
        return
    model_dir = _omen_model_dir()
    config_path = os.path.join(model_dir, "createConfig")
    if not os.path.isfile(config_path):
        print(f"Error: OMEN model not found at {config_path}")
        print("Run training first (option 16).")
        return
    enum_cmd = [enum_bin, "-p", "-m", str(max_candidates), "-C", config_path]
    hashcat_cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
    ]
    hashcat_cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(hashcat_cmd)
    print(f"[*] Running: {_format_cmd(enum_cmd)} | {_format_cmd(hashcat_cmd)}")
    _debug_cmd(hashcat_cmd)
    enum_proc = subprocess.Popen(
        enum_cmd, cwd=model_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    hcatProcess = subprocess.Popen(hashcat_cmd, stdin=enum_proc.stdout)
    enum_proc.stdout.close()
    try:
        hcatProcess.wait()
        enum_proc.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()
        enum_proc.kill()
        return
    if enum_proc.returncode != 0:
        stderr_output = enum_proc.stderr.read().decode("utf-8", errors="replace").strip()
        print(f"[!] enumNG failed with exit code {enum_proc.returncode}")
        if stderr_output:
            print(f"[!] enumNG error: {stderr_output}")
    if enum_proc.stderr:
        enum_proc.stderr.close()
```

**Step 4: Run tests to verify they pass**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py -v`
Expected: PASS (check existing TestHcatOmen tests still pass - they may need `stderr` added to the mock)

**Step 5: Commit**

```bash
git add hate_crack/main.py tests/test_omen_attack.py
git commit -m "fix: capture enumNG stderr and report errors instead of silent failure"
```

---

### Task 4: Rewrite omen_attack menu flow with wordlist picker

**Files:**
- Modify: `hate_crack/attacks.py:512-536` (`omen_attack`)
- Test: `tests/test_omen_attack.py`

**Step 1: Write the failing tests**

Replace the existing `TestOmenAttackHandler` in `tests/test_omen_attack.py` with:

```python
class TestOmenAttackHandler:
    def _make_ctx(self, tmp_path, model_valid=True):
        ctx = MagicMock()
        ctx.hate_path = str(tmp_path)
        ctx._omen_dir = str(tmp_path / "omen")
        ctx.hcatOmenCreateBin = "createNG"
        ctx.hcatOmenEnumBin = "enumNG"
        ctx.omenTrainingList = "/default/rockyou.txt"
        ctx.omenMaxCandidates = 1000000
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx._omen_model_is_valid.return_value = model_valid
        ctx._omen_model_info.return_value = {"training_file": "/old/rockyou.txt"} if model_valid else None
        ctx._omen_model_dir.return_value = str(tmp_path / "model")
        ctx.hcatOmenTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["rockyou.txt", "custom.txt"]
        return ctx

    def test_use_existing_model(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.input", side_effect=["1", ""]):
            from hate_crack.attacks import omen_attack
            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_not_called()
        ctx.hcatOmen.assert_called_once()

    def test_train_new_model_with_wordlist_pick(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        # User picks "2" (train new), then "1" (first wordlist), then default candidates
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.input", side_effect=["2", "1", ""]):
            from hate_crack.attacks import omen_attack
            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_called_once()
        training_arg = ctx.hcatOmenTrain.call_args[0][0]
        assert "rockyou.txt" in training_arg
        ctx.hcatOmen.assert_called_once()

    def test_cancel_aborts(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.input", side_effect=["3"]):
            from hate_crack.attacks import omen_attack
            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_not_called()
        ctx.hcatOmen.assert_not_called()

    def test_no_model_goes_straight_to_training(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=False)
        # No model -> wordlist pick "1" -> default candidates
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.input", side_effect=["1", ""]):
            from hate_crack.attacks import omen_attack
            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_called_once()
        ctx.hcatOmen.assert_called_once()

    def test_training_failure_aborts_enumeration(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=False)
        ctx.hcatOmenTrain.return_value = False
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.input", side_effect=["1"]):
            from hate_crack.attacks import omen_attack
            omen_attack(ctx)
        ctx.hcatOmen.assert_not_called()

    def test_custom_path_for_training(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=False)
        # User types "p" for custom path, then the path
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.input", side_effect=["p", "/custom/wordlist.txt", ""]):
            from hate_crack.attacks import omen_attack
            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_called_once_with("/custom/wordlist.txt")
```

**Step 2: Run tests to verify they fail**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py::TestOmenAttackHandler -v`
Expected: FAIL (old omen_attack doesn't match new flow)

**Step 3: Write implementation**

Rewrite `omen_attack` in `hate_crack/attacks.py`:

```python
def omen_attack(ctx: Any) -> None:
    print("\n\tOMEN Attack (Ordered Markov ENumerator)")
    omen_dir = os.path.join(ctx.hate_path, "omen")
    create_bin = os.path.join(omen_dir, ctx.hcatOmenCreateBin)
    enum_bin = os.path.join(omen_dir, ctx.hcatOmenEnumBin)
    if not os.path.isfile(create_bin) or not os.path.isfile(enum_bin):
        print("\n\tOMEN binaries not found. Build them with:")
        print(f"\t  cd {omen_dir} && make")
        return

    model_dir = ctx._omen_model_dir()
    model_valid = ctx._omen_model_is_valid(model_dir)
    need_training = True

    if model_valid:
        info = ctx._omen_model_info(model_dir)
        trained_with = info.get("training_file", "unknown") if info else "unknown"
        print(f"\n\tOMEN model found (trained with: {trained_with})")
        print("\t1. Use existing model")
        print("\t2. Train new model (overwrites existing)")
        print("\t3. Cancel")
        choice = input("\n\tChoice: ").strip()
        if choice == "1":
            need_training = False
        elif choice == "3":
            return
        elif choice != "2":
            return
    else:
        print("\n\tNo valid OMEN model found. Training is required.")

    if need_training:
        training_file = _omen_pick_training_wordlist(ctx)
        if not training_file:
            return
        if not ctx.hcatOmenTrain(training_file):
            print("\n\t[!] Training failed. Aborting OMEN attack.")
            return

    max_candidates = input(
        f"\n\tMax candidates to generate ({ctx.omenMaxCandidates}): "
    ).strip()
    if not max_candidates:
        max_candidates = str(ctx.omenMaxCandidates)
    ctx.hcatOmen(ctx.hcatHashType, ctx.hcatHashFile, int(max_candidates))


def _omen_pick_training_wordlist(ctx: Any):
    """Show wordlist picker for OMEN training. Returns path or None."""
    wordlist_files = ctx.list_wordlist_files(ctx.hcatWordlists)
    if wordlist_files:
        entries = [f"{i}. {f}" for i, f in enumerate(wordlist_files, start=1)]
        max_len = max((len(e) for e in entries), default=24)
        print_multicolumn_list(
            "Training Wordlists",
            entries,
            min_col_width=max_len,
            max_col_width=max_len,
        )
    print("\tp. Enter a custom path")
    sel = input("\n\tSelect wordlist for training: ").strip()
    if sel.lower() == "p":
        path = input("\n\tPath to training wordlist: ").strip()
        return path if path else None
    try:
        idx = int(sel)
        if 1 <= idx <= len(wordlist_files):
            return os.path.join(ctx.hcatWordlists, wordlist_files[idx - 1])
    except (ValueError, IndexError):
        pass
    print("\t[!] Invalid selection.")
    return None
```

**Step 4: Run tests to verify they pass**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_omen_attack.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add hate_crack/attacks.py tests/test_omen_attack.py
git commit -m "feat: omen_attack wordlist picker with train/use/cancel menu"
```

---

### Task 5: Final verification

**Step 1: Run full test suite**

Run: `HATE_CRACK_SKIP_INIT=1 uv run pytest -v`
Expected: All pass

**Step 2: Run linter**

Run: `uv run ruff check hate_crack`
Expected: All checks passed

**Step 3: Run formatter check**

Run: `uv run ruff format --check hate_crack`
Expected: Clean (fix any issues with `uv run ruff format hate_crack`)

**Step 4: Commit any format fixes**

```bash
git add -u
git commit -m "chore: format fixes"
```
