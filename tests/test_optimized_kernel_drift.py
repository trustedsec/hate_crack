"""Coverage for the optimizedKernelAttacks drift warning (#270).

An attack added after a user's config.json was written is absent from that
file's whole-list opt-in forever, so it never gets -O and nothing says so.
"""

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


class TestOptimizedKernelDrift:
    def test_a_complete_list_reports_no_drift(self, main_module):
        configured = set(main_module.DEFAULT_OPTIMIZED_ATTACKS)
        assert main_module._optimized_kernel_drift(configured) == []

    def test_an_attack_added_later_is_reported(self, main_module):
        """The real failure: a config written before hcatCorporateMasks existed."""
        configured = set(main_module.DEFAULT_OPTIMIZED_ATTACKS) - {
            "hcatCorporateMasks",
            "hcatRosettaMask",
        }
        assert main_module._optimized_kernel_drift(configured) == [
            "hcatCorporateMasks",
            "hcatRosettaMask",
        ]

    def test_names_outside_the_defaults_are_not_reported(self, main_module):
        """Opt-in extras like hcatOmen are not defaults, so absence isn't drift."""
        configured = set(main_module.DEFAULT_OPTIMIZED_ATTACKS) | {"hcatOmen"}
        assert main_module._optimized_kernel_drift(configured) == []

    def test_an_empty_list_reports_every_default(self, main_module):
        assert main_module._optimized_kernel_drift(set()) == sorted(
            main_module.DEFAULT_OPTIMIZED_ATTACKS
        )


class TestOptimizedKernelDriftWarning:
    def test_each_missing_attack_is_named(self, main_module, monkeypatch, capsys):
        """A count alone wouldn't tell the user which attacks to add."""
        monkeypatch.setattr(main_module, "SKIP_INIT", False)

        main_module._warn_optimized_kernel_drift(
            ["hcatCorporateMasks", "hcatRosettaMask"], "/tmp/config.json"
        )

        out = capsys.readouterr().out
        assert "hcatCorporateMasks" in out
        assert "hcatRosettaMask" in out
        assert "/tmp/config.json" in out
        assert "2 attack(s)" in out
        assert "optimizedKernelAttacks" in out

    def test_no_drift_prints_nothing(self, main_module, monkeypatch, capsys):
        monkeypatch.setattr(main_module, "SKIP_INIT", False)

        main_module._warn_optimized_kernel_drift([], "/tmp/config.json")

        assert capsys.readouterr().out == ""

    def test_skip_init_silences_the_warning(self, main_module, monkeypatch, capsys):
        """The suite imports main constantly; startup output would drown it."""
        monkeypatch.setattr(main_module, "SKIP_INIT", True)

        main_module._warn_optimized_kernel_drift(["hcatCorporateMasks"], "/c.json")

        assert capsys.readouterr().out == ""

    def test_config_path_is_optional(self, main_module, monkeypatch, capsys):
        """Under SKIP_INIT with no config on disk the path can legitimately be None."""
        monkeypatch.setattr(main_module, "SKIP_INIT", False)

        main_module._warn_optimized_kernel_drift(["hcatCorporateMasks"], None)

        out = capsys.readouterr().out
        assert "hcatCorporateMasks" in out
        assert " in None" not in out
