import builtins
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


def _make_mock_proc():
    proc = MagicMock()
    proc.wait.return_value = None
    proc.pid = 12345
    return proc


def _make_masks_dir(tmp_path, lengths):
    """Create a Corporate_Masks dir holding corp_<n>.hcmask for each length."""
    masks_dir = tmp_path / "Corporate_Masks"
    masks_dir.mkdir(exist_ok=True)
    for length in lengths:
        (masks_dir / f"corp_{length}.hcmask").touch()
    return masks_dir


@contextmanager
def _patched(main_module, masks_dir, popen, tuning="", potfile=""):
    """Patch the module globals hcatCorporateMasks reads, plus Popen.

    ``patch.object`` rather than raw assignment: ``hate_crack.main`` is shared
    across the session, so anything set here has to be restored afterwards.
    """
    with (
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", tuning),
        patch.object(main_module, "hcatPotfilePath", potfile),
        patch.object(main_module, "_corporate_masks_dir", str(masks_dir)),
        patch.object(main_module, "generate_session_id", return_value="test_session"),
        patch("hate_crack.main.subprocess.Popen", **popen) as mock_popen,
    ):
        yield mock_popen


def _mask_lengths_invoked(mock_popen):
    """The corp_<n> lengths passed to hashcat, in invocation order."""
    lengths = []
    for call in mock_popen.call_args_list:
        cmd = call[0][0]
        mask = cmd[cmd.index("-a") + 2]
        lengths.append(int(mask.rsplit("corp_", 1)[1].split(".hcmask")[0]))
    return lengths


class TestHcatCorporateMasks:
    def test_default_range_runs_each_length_in_ascending_order(
        self, main_module, tmp_path
    ):
        """8-10 runs corp_8, corp_9, corp_10 -- in that order, one call each."""
        masks_dir = _make_masks_dir(tmp_path, range(8, 11))

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=8, maxLen=10
            )

        assert mock_popen.call_count == 3
        assert _mask_lengths_invoked(mock_popen) == [8, 9, 10]

    def test_signature_defaults_match_the_documented_constants(
        self, main_module, tmp_path
    ):
        """Calling with no range uses MIN_LEN..DEFAULT_MAX_LEN, not stray literals."""
        masks_dir = _make_masks_dir(tmp_path, range(8, 15))

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks("1000", str(tmp_path / "hashes.txt"))

        assert _mask_lengths_invoked(mock_popen) == list(
            range(
                main_module.CORPORATE_MASK_MIN_LEN,
                main_module.CORPORATE_MASK_DEFAULT_MAX_LEN + 1,
            )
        )

    def test_every_command_is_a_mask_attack_against_its_own_mask_file(
        self, main_module, tmp_path
    ):
        """-a is followed by 3, and 3 by the mask file: position, not membership."""
        masks_dir = _make_masks_dir(tmp_path, range(8, 11))

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=8, maxLen=10
            )

        for call in mock_popen.call_args_list:
            cmd = call[0][0]
            assert cmd[cmd.index("-a") + 1] == "3"
            assert cmd[cmd.index("-a") + 2].startswith(str(masks_dir))

    def test_missing_mask_file_in_range_is_skipped(self, main_module, tmp_path):
        """A gap in the shipped set skips only that length, not the whole run."""
        masks_dir = _make_masks_dir(tmp_path, [8, 10])  # corp_9 deliberately absent

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=8, maxLen=10
            )

        assert _mask_lengths_invoked(mock_popen) == [8, 10]

    @pytest.mark.parametrize("dirname", ["Corporate_Masks", "Corporate_Masks_absent"])
    def test_no_mask_files_warns_and_runs_nothing(
        self, main_module, tmp_path, capsys, dirname
    ):
        """Both an empty dir and an absent one warn and invoke hashcat zero times."""
        masks_dir = tmp_path / dirname
        if dirname == "Corporate_Masks":
            masks_dir.mkdir()

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=8, maxLen=10
            )

        assert mock_popen.call_count == 0
        captured = capsys.readouterr()
        assert "No corporate mask files found" in captured.out
        assert str(masks_dir) in captured.out
        assert "make submodules" in captured.out

    def test_out_of_range_bounds_are_clamped_to_the_shipped_set(
        self, main_module, tmp_path
    ):
        """minLen=1/maxLen=99 clamps to 8..14 rather than reaching outside it.

        The mask dir holds corp_1..corp_20 so an unclamped range would visit
        lengths outside the shipped set -- without those files present, the
        os.path.isfile filter alone would mask a missing clamp.
        """
        masks_dir = _make_masks_dir(tmp_path, range(1, 21))

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=1, maxLen=99
            )

        assert _mask_lengths_invoked(mock_popen) == list(
            range(
                main_module.CORPORATE_MASK_MIN_LEN,
                main_module.CORPORATE_MASK_MAX_LEN + 1,
            )
        )

    def test_reversed_bounds_are_swapped(self, main_module, tmp_path):
        """minLen=10/maxLen=8 runs 8..10 rather than an empty range."""
        masks_dir = _make_masks_dir(tmp_path, range(8, 11))

        with _patched(
            main_module, masks_dir, {"return_value": _make_mock_proc()}
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=10, maxLen=8
            )

        assert _mask_lengths_invoked(mock_popen) == [8, 9, 10]

    def test_tuning_tokens_and_potfile_arg_are_appended(self, main_module, tmp_path):
        """hcatTuning is shlex-split onto the command and the potfile arg follows."""
        masks_dir = _make_masks_dir(tmp_path, [8])
        potfile = str(tmp_path / "hate.pot")

        with _patched(
            main_module,
            masks_dir,
            {"return_value": _make_mock_proc()},
            tuning="-w 4 --workload-profile 4",
            potfile=potfile,
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=8, maxLen=8
            )

        cmd = mock_popen.call_args[0][0]
        assert cmd[cmd.index("-w") + 1] == "4"
        assert cmd[cmd.index("--workload-profile") + 1] == "4"
        assert f"--potfile-path={potfile}" in cmd

    def test_keyboard_interrupt_aborts_remaining_lengths(self, main_module, tmp_path):
        """Ctrl-C during one length stops the run instead of rolling on."""
        masks_dir = _make_masks_dir(tmp_path, range(8, 14))

        interrupted = MagicMock()
        interrupted.pid = 12346
        interrupted.wait.side_effect = KeyboardInterrupt()

        with _patched(
            main_module,
            masks_dir,
            {"side_effect": [_make_mock_proc(), interrupted]},
        ) as mock_popen:
            main_module.hcatCorporateMasks(
                "1000", str(tmp_path / "hashes.txt"), minLen=8, maxLen=13
            )

        # Six lengths exist; the run stops at the second rather than reaching 13.
        assert mock_popen.call_count == 2
        interrupted.kill.assert_called()


class TestCorporateMasksHandler:
    """The menu handler in attacks.py -- prompt handling, not hashcat."""

    @staticmethod
    def _ctx(seen):
        from hate_crack import main as hc_main

        return SimpleNamespace(
            hcatHashType="1000",
            hcatHashFile="dummy.hash",
            CORPORATE_MASK_MIN_LEN=hc_main.CORPORATE_MASK_MIN_LEN,
            CORPORATE_MASK_MAX_LEN=hc_main.CORPORATE_MASK_MAX_LEN,
            CORPORATE_MASK_DEFAULT_MAX_LEN=hc_main.CORPORATE_MASK_DEFAULT_MAX_LEN,
            hcatCorporateMasks=lambda hash_type, hash_file, min_len, max_len: (
                seen.update(min_len=min_len, max_len=max_len)
            ),
        )

    def _run(self, monkeypatch, answers):
        from hate_crack import attacks

        seen = {}
        replies = iter(answers)
        monkeypatch.setattr(builtins, "input", lambda _prompt="": next(replies))
        attacks.corporate_masks_crack(self._ctx(seen))
        return seen

    def test_pressing_enter_twice_takes_the_documented_defaults(self, monkeypatch):
        assert self._run(monkeypatch, ["", ""]) == {"min_len": 8, "max_len": 10}

    def test_explicit_range_is_passed_through(self, monkeypatch):
        assert self._run(monkeypatch, ["9", "12"]) == {"min_len": 9, "max_len": 12}

    def test_non_integer_and_out_of_range_input_reprompts(self, monkeypatch):
        """Neither a typo nor an out-of-bounds number escapes the prompt loop."""
        answers = ["abc", "99", "9", "", ""]
        assert self._run(monkeypatch, answers)["min_len"] == 9

    def test_offered_max_default_is_never_below_the_chosen_min(self, monkeypatch):
        """min=12 then Enter must not yield max=10, which the prompt would reject.

        The default ceiling is 10, so a fixed default would hand back an
        inverted range for any minimum above it.
        """
        seen = self._run(monkeypatch, ["12", ""])
        assert seen == {"min_len": 12, "max_len": 12}

    def test_max_below_min_is_rejected_and_reprompted(self, monkeypatch):
        """The max prompt's floor is the min just chosen, so 8 after 10 reprompts."""
        seen = self._run(monkeypatch, ["10", "8", "11"])
        assert seen == {"min_len": 10, "max_len": 11}
