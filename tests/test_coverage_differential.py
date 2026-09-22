"""Old and new coverage paths must agree on every membership decision."""

import pytest

from hate_crack import attack_coverage as ac
from tools import coverage_differential as cd


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def _rules(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return str(p)


def test_paths_agree_when_nothing_is_recorded(store, tmp_path):
    path = _rules(tmp_path, "a.rule", ["$1", "c", "sa@"])
    out = cd.compare(store, "a" * 64, [(path, "rule")], "", "")
    assert out.only_legacy == []
    assert out.only_interned == []
    assert out.agreed == 3


def test_paths_agree_after_recording_a_subset(store, tmp_path):
    path = _rules(tmp_path, "a.rule", ["$1", "c", "sa@"])
    cd.record_via_both(store, "a" * 64, [(path, "rule")], "", "", subset=["$1"])
    out = cd.compare(store, "a" * 64, [(path, "rule")], "", "")
    assert out.only_legacy == []
    assert out.only_interned == []


def test_paths_agree_on_masks_with_equivalent_charset_spellings(store, tmp_path):
    # canonical_mask_entry collapses these; both paths must collapse identically.
    path = _rules(tmp_path, "m.hcmask", ["abc,?1?1", "cba,?1?1", "?d?d?l"])
    cd.record_via_both(store, "b" * 64, [(path, "mask")], "", "", subset=["abc,?1?1"])
    out = cd.compare(store, "b" * 64, [(path, "mask")], "", "")
    assert out.only_legacy == []
    assert out.only_interned == []


def test_paths_agree_on_undecodable_rule_bytes(store, tmp_path):
    # rulegen.py writes latin-1. Two rules differing only in non-UTF-8 bytes
    # must stay distinct in BOTH paths. errors="replace" once collapsed 154
    # distinct rules here.
    p = tmp_path / "latin1.rule"
    p.write_bytes(b"$\xc3\n$\xa9\n$\xc3$\xa1\n")
    cd.record_via_both(store, "c" * 64, [(str(p), "rule")], "", "", subset_index=[0])
    out = cd.compare(store, "c" * 64, [(str(p), "rule")], "", "")
    assert out.only_legacy == []
    assert out.only_interned == []


def test_variant_is_not_conflated_in_either_path(store, tmp_path):
    path = _rules(tmp_path, "m.hcmask", ["?d?d?l"])
    cd.record_via_both(
        store, "d" * 64, [(path, "mask")], "", "--increment 1-8", subset=["?d?d?l"]
    )
    plain = cd.compare(store, "d" * 64, [(path, "mask")], "", "")
    assert plain.agreed == 1
    assert plain.only_legacy == []
    assert plain.only_interned == []
