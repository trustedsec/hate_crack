import importlib

import pytest


def test_tokenize_runs_splits_letters_digits_symbols():
    from hate_crack import main as hc_main

    assert hc_main._tokenize_runs("CrawlingHorse432") == [
        ("L", "CrawlingHorse"),
        ("D", "432"),
    ]


def test_tokenize_runs_handles_middle_digit_run():
    from hate_crack import main as hc_main

    assert hc_main._tokenize_runs("ChangeMe2day1624$!") == [
        ("L", "ChangeMe"),
        ("D", "2"),
        ("L", "day"),
        ("D", "1624"),
        ("S", "$!"),
    ]


def test_tokenize_runs_empty_string_returns_empty_list():
    from hate_crack import main as hc_main

    assert hc_main._tokenize_runs("") == []


def test_tokenize_runs_merges_non_ascii_letters_into_the_letter_run():
    from hate_crack import main as hc_main

    # "ö".isalpha() is True in Python, so it joins the surrounding letters
    # into one "L" run rather than breaking it.
    assert hc_main._tokenize_runs("Sömmer") == [("L", "Sömmer")]


def test_tokenize_runs_classifies_non_ascii_punctuation_as_symbol():
    from hate_crack import main as hc_main

    # "§" (section sign) is not alphabetic or a digit, so it falls into the
    # "S" catch-all like any ASCII symbol would.
    assert hc_main._tokenize_runs("Pass§word1") == [
        ("L", "Pass"),
        ("S", "§"),
        ("L", "word"),
        ("D", "1"),
    ]


def test_shape_signature_is_run_types_only():
    from hate_crack import main as hc_main

    runs = hc_main._tokenize_runs("ChangeMe2day1624$!")
    assert hc_main._shape_signature(runs) == ("L", "D", "L", "D", "S")


def test_seed_key_is_letter_run_contents_only():
    from hate_crack import main as hc_main

    runs = hc_main._tokenize_runs("ChangeMe2day1624$!")
    assert hc_main._seed_key(runs) == ("ChangeMe", "day")


def test_seed_key_empty_when_no_letters():
    from hate_crack import main as hc_main

    runs = hc_main._tokenize_runs("12345!!!")
    assert hc_main._seed_key(runs) == ()


def test_infer_charset_expands_partial_shift_row_symbols():
    from hate_crack import main as hc_main

    observed = set("$!#&*^(@%")  # 9 of the 10 US shift-row symbols
    assert hc_main._infer_charset(observed) == "!@#$%^&*()"


def test_infer_charset_expands_partial_digits():
    from hate_crack import main as hc_main

    observed = set("432559134795")  # digits from the CrawlingHorse cluster
    assert hc_main._infer_charset(observed) == "0123456789"


def test_infer_charset_keeps_exact_set_below_coverage_threshold():
    from hate_crack import main as hc_main

    observed = {"1", "2"}  # 2 of 10 digits, below the 50% coverage threshold
    assert hc_main._infer_charset(observed) == "12"


def test_infer_charset_returns_sorted_observed_when_no_alphabet_matches():
    from hate_crack import main as hc_main

    observed = {"z", "9", "!"}  # mixed classes -- not a subset of any one alphabet
    assert hc_main._infer_charset(observed) == "".join(sorted(observed))


def test_build_template_identifies_fixed_and_variable_runs():
    from hate_crack import main as hc_main

    plaintexts = [
        "CrawlingHorse432",
        "CrawlingHorse559",
        "CrawlingHorse134",
        "CrawlingHorse795",
    ]
    templates, skipped = hc_main._cluster_smart_mask_templates(
        plaintexts, min_cluster_size=3
    )

    assert skipped == 0
    assert len(templates) == 1
    template = templates[0]
    assert template.fixed_runs == ((0, "L", "CrawlingHorse"),)
    assert template.variable_positions == (1,)
    assert template.variable_charsets == ("0123456789",)
    assert template.length_combinations == ((3,),)
    assert template.member_count == 4
    assert template.total_positions == 2


def test_build_template_folds_constant_middle_run_into_fixed_skeleton():
    from hate_crack import main as hc_main

    plaintexts = [
        "ChangeMe2day1624$!",
        "ChangeMe2day1625#&*",
        "ChangeMe2day1924!**",
    ]
    templates, skipped = hc_main._cluster_smart_mask_templates(
        plaintexts, min_cluster_size=3
    )

    assert skipped == 0
    assert len(templates) == 1
    template = templates[0]
    # Position 1 ("2") and position 2 ("day") are constant across all three
    # members despite "2" being a digit run -- constancy, not run type,
    # decides fixed vs. variable.
    assert template.fixed_runs == (
        (0, "L", "ChangeMe"),
        (1, "D", "2"),
        (2, "L", "day"),
    )
    assert template.variable_positions == (3, 4)
    assert set(template.length_combinations) == {(4, 2), (4, 3)}


def test_cluster_below_minimum_size_is_dropped():
    from hate_crack import main as hc_main

    plaintexts = ["Foo111", "Foo222"]  # only 2 members, min is 3
    templates, skipped = hc_main._cluster_smart_mask_templates(
        plaintexts, min_cluster_size=3
    )
    assert templates == []
    assert skipped == 0


def test_all_digit_stem_is_skipped_and_counted():
    from hate_crack import main as hc_main

    plaintexts = ["111222", "333444", "555666"]  # no alphabetic run at all
    templates, skipped = hc_main._cluster_smart_mask_templates(
        plaintexts, min_cluster_size=3
    )
    assert templates == []
    assert skipped == 3


def test_exact_password_reuse_produces_no_template():
    from hate_crack import main as hc_main

    plaintexts = ["Summer2025!", "Summer2025!", "Summer2025!"]  # nothing varies
    templates, skipped = hc_main._cluster_smart_mask_templates(
        plaintexts, min_cluster_size=3
    )
    assert templates == []
    assert skipped == 0


def test_different_shapes_do_not_cluster_together():
    from hate_crack import main as hc_main

    plaintexts = ["Foo111", "Foo222", "Foo333!!"]  # last one has an extra symbol run
    templates, skipped = hc_main._cluster_smart_mask_templates(
        plaintexts, min_cluster_size=3
    )
    assert templates == []  # each shape bucket only has 1-2 members


def test_escape_mask_literal_doubles_question_marks():
    from hate_crack import main as hc_main

    assert hc_main._escape_mask_literal("CrawlingHorse") == "CrawlingHorse"
    assert hc_main._escape_mask_literal("Pass?word") == "Pass??word"


def test_build_hcmask_lines_single_length_combination():
    from hate_crack import main as hc_main

    template = hc_main._SmartMaskTemplate(
        fixed_runs=((0, "L", "CrawlingHorse"),),
        variable_positions=(1,),
        variable_charsets=("0123456789",),
        length_combinations=((3,),),
        member_count=4,
        total_positions=2,
    )
    assert hc_main._build_hcmask_lines(template) == ["0123456789,CrawlingHorse?1?1?1"]


def test_build_hcmask_lines_multiple_length_combinations_produce_multiple_lines():
    from hate_crack import main as hc_main

    template = hc_main._SmartMaskTemplate(
        fixed_runs=(
            (0, "L", "ChangeMe"),
            (1, "D", "2"),
            (2, "L", "day"),
        ),
        variable_positions=(3, 4),
        variable_charsets=("0123456789", "!@#$%^&*()"),
        length_combinations=((4, 2), (4, 3)),
        member_count=11,
        total_positions=5,
    )
    assert hc_main._build_hcmask_lines(template) == [
        "0123456789,!@#$%^&*(),ChangeMe2day?1?1?1?1?2?2",
        "0123456789,!@#$%^&*(),ChangeMe2day?1?1?1?1?2?2?2",
    ]


def test_build_hcmask_lines_escapes_literal_question_mark_in_fixed_run():
    from hate_crack import main as hc_main

    template = hc_main._SmartMaskTemplate(
        fixed_runs=((0, "S", "Pass?word"),),
        variable_positions=(1,),
        variable_charsets=("0123456789",),
        length_combinations=((2,),),
        member_count=3,
        total_positions=2,
    )
    assert hc_main._build_hcmask_lines(template) == ["0123456789,Pass??word?1?1"]


def test_identical_charsets_share_one_slot():
    """Nine varying digit runs need one ?1, not nine slots.

    ``?1`` repeated at several positions enumerates exactly what several
    identically-defined slots would, so sharing is free -- and it is what stops
    hashcat's eight-slot ceiling from acting as a ceiling on varying runs.
    """
    from hate_crack import main as hc_main

    template = hc_main._SmartMaskTemplate(
        fixed_runs=tuple((i, "L", "x") for i in range(0, 18, 2)),
        variable_positions=tuple(range(1, 18, 2)),
        variable_charsets=("0123456789",) * 9,
        length_combinations=((1,) * 9,),
        member_count=3,
        total_positions=18,
    )
    lines = hc_main._build_hcmask_lines(template)
    assert lines == ["0123456789," + "x?1" * 9]


def test_slot_sharing_preserves_per_position_charsets():
    """Sharing must key on the charset, not collapse distinct ones together."""
    from hate_crack import main as hc_main

    template = hc_main._SmartMaskTemplate(
        fixed_runs=((0, "L", "a"), (2, "L", "b"), (4, "L", "c")),
        variable_positions=(1, 3, 5),
        variable_charsets=("0123456789", "abc", "0123456789"),
        length_combinations=((1, 1, 1),),
        member_count=3,
        total_positions=6,
    )
    assert hc_main._build_hcmask_lines(template) == ["0123456789,abc,a?1b?2c?1"]


def test_nine_distinct_charsets_raise_the_slot_limit():
    from hate_crack import main as hc_main

    template = hc_main._SmartMaskTemplate(
        fixed_runs=tuple((i, "L", "x") for i in range(0, 18, 2)),
        variable_positions=tuple(range(1, 18, 2)),
        variable_charsets=tuple("abcdefghi"[i] * 3 for i in range(9)),
        length_combinations=((1,) * 9,),
        member_count=3,
        total_positions=18,
    )
    with pytest.raises(hc_main.SmartMaskSlotLimit) as excinfo:
        hc_main._build_hcmask_lines(template)
    assert excinfo.value.needed == 9


def test_eight_distinct_charsets_still_build():
    """Eight is allowed, so the guard must not be off by one."""
    from hate_crack import main as hc_main
    from hashcat_rosetta.mask import parse_hcmask_line

    template = hc_main._SmartMaskTemplate(
        fixed_runs=tuple((i, "L", "x") for i in range(0, 16, 2)),
        variable_positions=tuple(range(1, 16, 2)),
        variable_charsets=tuple("abcdefgh"[i] * 3 for i in range(8)),
        length_combinations=((1,) * 8,),
        member_count=3,
        total_positions=16,
    )
    (line,) = hc_main._build_hcmask_lines(template)
    parsed = parse_hcmask_line(line)
    assert len(parsed.custom) == 8
    assert parsed.mask == "".join(f"x?{n}" for n in range(1, 9))


def test_build_hcmask_lines_output_parses_as_valid_hcmask():
    """Every generated line must round-trip through HashcatRosetta's own
    parser -- this is the same grammar hashcat's -a3 mode expects."""
    from hate_crack import main as hc_main
    from hashcat_rosetta.mask import parse_hcmask_line

    template = hc_main._SmartMaskTemplate(
        fixed_runs=((0, "L", "CrawlingHorse"),),
        variable_positions=(1,),
        variable_charsets=("0123456789",),
        length_combinations=((3,),),
        member_count=4,
        total_positions=2,
    )
    for line in hc_main._build_hcmask_lines(template):
        parsed = parse_hcmask_line(line)
        assert parsed.mask == "CrawlingHorse?1?1?1"


def _install_smart_mask_test_env(monkeypatch, hc_main, hashfile):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    monkeypatch.setattr(hc_main, "hcatHashCracked", 0)
    monkeypatch.setattr(hc_main, "hcatHashFile", str(hashfile))
    monkeypatch.setattr(hc_main, "generate_session_id", lambda: "test_session")
    monkeypatch.setattr(hc_main, "hcatBin", "hashcat")
    monkeypatch.setattr(hc_main, "hcatTuning", "")
    monkeypatch.setattr(hc_main, "hcatPotfilePath", "")


class _NoopPopen:
    """Popen stand-in for hashcat invocations: records the command, never
    actually runs anything.

    ``hcmask_snapshots``, when given a list, gets the raw bytes of any
    ``.hcmask`` file argument at invocation time -- hcatSmartMask deletes
    that file once its attack finishes, so a test asserting on its content
    must capture it here rather than reading the path after the call.
    """

    def __init__(self, seen, hcmask_snapshots=None):
        self.seen = seen
        self.hcmask_snapshots = hcmask_snapshots

    def __call__(self, args, **_kwargs):
        import os

        self.seen.append(list(args))
        if self.hcmask_snapshots is not None:
            for arg in args:
                if (
                    isinstance(arg, str)
                    and arg.endswith(".hcmask")
                    and os.path.isfile(arg)
                ):
                    with open(arg, "rb") as f:
                        self.hcmask_snapshots.append(f.read())
        return self._Proc()

    class _Proc:
        pid = 4321

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None


def test_hcatSmartMask_runs_a_single_attack_for_one_qualifying_template(
    monkeypatch, tmp_path
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "a:CrawlingHorse432\nb:CrawlingHorse559\nc:CrawlingHorse134\nd:CrawlingHorse795\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 4)

    popen_calls = []
    hcmask_snapshots = []
    monkeypatch.setattr(
        hc_main.subprocess, "Popen", _NoopPopen(popen_calls, hcmask_snapshots)
    )

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert len(popen_calls) == 1
    cmd = popen_calls[0]
    assert cmd[cmd.index("-a") + 1] == "3"
    assert hcmask_snapshots == [b"0123456789,CrawlingHorse?1?1?1\n"]
    assert hc_main.hcatSmartMaskCount == 4  # lineCount(...) - hcatHashCracked(0)


def test_hcatSmartMask_combines_multiple_templates_into_one_hcmask_file(
    monkeypatch, tmp_path
):
    """Two unrelated clusters (different literal stems) must produce exactly
    one hashcat invocation over one .hcmask file containing both mask
    lines, not one invocation per template."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "a:CrawlingHorse432\nb:CrawlingHorse559\nc:CrawlingHorse134\n"
        "d:ChangeMe24\ne:ChangeMe37\nf:ChangeMe81\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 6)

    popen_calls = []
    hcmask_snapshots = []
    monkeypatch.setattr(
        hc_main.subprocess, "Popen", _NoopPopen(popen_calls, hcmask_snapshots)
    )

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert len(popen_calls) == 1
    assert len(hcmask_snapshots) == 1
    lines = hcmask_snapshots[0].decode("latin-1").splitlines()
    assert lines == [
        "0123456789,CrawlingHorse?1?1?1",
        "0123456789,ChangeMe?1?1",
    ]


def test_hcatSmartMask_removes_the_hcmask_file_after_the_attack(monkeypatch, tmp_path):
    import os

    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "a:CrawlingHorse432\nb:CrawlingHorse559\nc:CrawlingHorse134\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert len(popen_calls) == 1  # the attack did run
    assert not os.path.exists(tmp_path / "hashes.txt.smartmask.hcmask")


def test_smartmask_hcmask_file_removed_by_cleanup(tmp_path, monkeypatch):
    """Mirrors test_main_spoonman.test_cleanup_removes_derived_output: a
    belt-and-braces backstop for the case where hcatSmartMask's own cleanup
    never ran (e.g. the process was killed mid-attack)."""
    import os

    import hate_crack.main as hc_main

    hash_file = str(tmp_path / "hashes.txt")
    hcmask_path = hash_file + ".smartmask.hcmask"
    with open(hcmask_path, "w") as f:
        f.write("0123456789,CrawlingHorse?1?1?1\n")

    monkeypatch.setattr(hc_main, "hcatHashFile", hash_file)
    monkeypatch.setattr(hc_main, "hcatHashFileOrig", hash_file)
    monkeypatch.setattr(hc_main, "hcatHashType", "1000")
    monkeypatch.setattr(hc_main, "pwdump_format", False)
    hc_main.cleanup()

    assert not os.path.exists(hcmask_path)


def test_hcatSmartMask_keyspace_guard_only_excludes_the_oversized_template(
    monkeypatch, tmp_path, capsys
):
    """One oversized template among several must be dropped from the
    combined .hcmask file, while the rest still run in a single attack."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "a:CrawlingHorse432\nb:CrawlingHorse559\nc:CrawlingHorse134\n"
        "d:ChangeMe24\ne:ChangeMe37\nf:ChangeMe81\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 6)

    popen_calls = []
    hcmask_snapshots = []
    monkeypatch.setattr(
        hc_main.subprocess, "Popen", _NoopPopen(popen_calls, hcmask_snapshots)
    )

    # CrawlingHorse's ?1?1?1 is 10**3 = 1000 candidates; a limit of 500
    # excludes it while admitting ChangeMe's ?1?1 (10**2 = 100 candidates).
    hc_main.hcatSmartMask("1000", str(hashfile), keyspace_limit=500)

    assert "exceeds the 500-candidate guardrail" in capsys.readouterr().out
    assert len(popen_calls) == 1
    lines = hcmask_snapshots[0].decode("latin-1").splitlines()
    assert lines == ["0123456789,ChangeMe?1?1"]


def test_hcatSmartMask_no_qualifying_cluster_skips_hashcat(
    monkeypatch, tmp_path, capsys
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("a:onlyone123\n")
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert popen_calls == []
    assert "no qualifying clusters found" in capsys.readouterr().out


def test_hcatSmartMask_uses_configured_min_cluster_size(monkeypatch, tmp_path):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("a:CrawlingHorse432\nb:CrawlingHorse559\n")
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 2)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    # The built-in default (_SMART_MASK_MIN_CLUSTER_SIZE == 3) would reject
    # this 2-member cluster; the configured override lets it through.
    monkeypatch.setattr(hc_main, "hcatSmartMaskMinClusterSize", 2)

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert len(popen_calls) == 1


def test_hcatSmartMask_decodes_hex_wrapped_plaintext(monkeypatch, tmp_path):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    hex_plain = "CrawlingHorse432".encode("iso-8859-9").hex()
    (tmp_path / "hashes.txt.out").write_text(
        f"h0:$HEX[{hex_plain}]\nh1:CrawlingHorse559\nh2:CrawlingHorse134\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert len(popen_calls) == 1  # the $HEX[...] entry still joined the cluster


def test_hcatSmartMask_hcmask_file_preserves_high_bytes_from_hex_wrapper(
    monkeypatch, tmp_path
):
    """A cracked plaintext containing a byte >= 0x80 (why hashcat had to
    $HEX[...]-wrap it in the first place) must reach the .hcmask file as
    that exact byte. Writing the file as UTF-8 would re-encode it into a
    different, multi-byte sequence that hashcat would never match."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    plain_stem = "Sömmer"  # "ö" (U+00F6) -> single byte 0xF6 in latin-1
    hex_lines = "\n".join(
        f"h{i}:$HEX[{(plain_stem + digits).encode('latin-1').hex()}]"
        for i, digits in enumerate(["432", "559", "134"])
    )
    (tmp_path / "hashes.txt.out").write_text(hex_lines + "\n")
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)

    popen_calls = []
    hcmask_snapshots = []
    monkeypatch.setattr(
        hc_main.subprocess, "Popen", _NoopPopen(popen_calls, hcmask_snapshots)
    )

    hc_main.hcatSmartMask("1000", str(hashfile))

    raw_bytes = hcmask_snapshots[0]
    assert b"S\xf6mmer" in raw_bytes  # the original single byte, not UTF-8's \xc3\xb6
    assert b"\xc3\xb6" not in raw_bytes


def test_hcatSmartMask_keyspace_guard_skips_oversized_template(
    monkeypatch, tmp_path, capsys
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "a:CrawlingHorse432\nb:CrawlingHorse559\nc:CrawlingHorse134\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile), keyspace_limit=1)

    assert popen_calls == []
    assert "exceeds the 1-candidate guardrail" in capsys.readouterr().out


def test_hcatSmartMask_prints_warning_when_rosetta_unavailable(
    monkeypatch, tmp_path, capsys
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "a:CrawlingHorse432\nb:CrawlingHorse559\nc:CrawlingHorse134\n"
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)
    monkeypatch.setattr(hc_main, "rosetta_parse_hcmask_line", None)
    monkeypatch.setattr(hc_main, "rosetta_format_hcmask_line", None)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert popen_calls == []
    assert "HashcatRosetta is unavailable" in capsys.readouterr().out


def test_hcatSmartMask_reports_skipped_all_digit_stems(monkeypatch, tmp_path, capsys):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("a:111222\nb:333444\nc:555666\n")
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile))

    assert popen_calls == []
    out = capsys.readouterr().out
    assert "skipping 3 plaintext(s) with no alphabetic stem" in out


def test_smart_mask_crack_default_keyspace_limit_passes_none(monkeypatch):
    import builtins
    from types import SimpleNamespace
    from hate_crack import attacks

    seen = {}

    def fake_hcatSmartMask(hash_type, hash_file, **kwargs):
        seen["hash_type"] = hash_type
        seen["hash_file"] = hash_file
        seen["keyspace_limit"] = kwargs.get("keyspace_limit")

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatSmartMask=fake_hcatSmartMask,
    )

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "")
    attacks.smart_mask_crack(ctx)

    assert seen["hash_type"] == "1000"
    assert seen["hash_file"] == "dummy.hash"
    assert seen["keyspace_limit"] is None


def test_smart_mask_crack_custom_keyspace_limit(monkeypatch):
    import builtins
    from types import SimpleNamespace
    from hate_crack import attacks

    seen = {}

    def fake_hcatSmartMask(hash_type, hash_file, **kwargs):
        seen["keyspace_limit"] = kwargs.get("keyspace_limit")

    ctx = SimpleNamespace(
        hcatHashType="1000", hcatHashFile="dummy.hash", hcatSmartMask=fake_hcatSmartMask
    )

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "12345")
    attacks.smart_mask_crack(ctx)

    assert seen["keyspace_limit"] == 12345


def test_smart_mask_crack_zero_keyspace_limit_warns_no_limit(monkeypatch, capsys):
    import builtins
    from types import SimpleNamespace
    from hate_crack import attacks

    seen = {}

    def fake_hcatSmartMask(hash_type, hash_file, **kwargs):
        seen["keyspace_limit"] = kwargs.get("keyspace_limit")

    ctx = SimpleNamespace(
        hcatHashType="1000", hcatHashFile="dummy.hash", hcatSmartMask=fake_hcatSmartMask
    )

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "0")
    attacks.smart_mask_crack(ctx)

    assert seen["keyspace_limit"] == 0
    assert "No limit" in capsys.readouterr().out


def test_smart_mask_crack_rejects_negative_then_accepts_blank(monkeypatch):
    import builtins
    from types import SimpleNamespace
    from hate_crack import attacks

    seen = {}

    def fake_hcatSmartMask(hash_type, hash_file, **kwargs):
        seen["keyspace_limit"] = kwargs.get("keyspace_limit")

    ctx = SimpleNamespace(
        hcatHashType="1000", hcatHashFile="dummy.hash", hcatSmartMask=fake_hcatSmartMask
    )

    responses = iter(["-5", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.smart_mask_crack(ctx)

    assert seen["keyspace_limit"] is None


def test_hcatSmartMask_reports_a_slot_exhausted_template_instead_of_dropping_it_quietly(
    monkeypatch, tmp_path, capsys
):
    """Nine runs of nine *different* charsets cannot be expressed at all.

    Before the guard this surfaced as an opaque "unbuildable template" from the
    mask parser, with nothing naming the cause; the whole cluster went missing
    for a reason the operator could not act on.
    """
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    # Nine varying runs, each drawing on a different alphabet, separated by
    # fixed letter runs so the shape signature stays stable across members.
    alphabets = ["01", "23", "45", "67", "89", "!@", "#$", "%^", "&*"]
    members = []
    for pick in range(2):
        parts = []
        for index, alphabet in enumerate(alphabets):
            parts.append(chr(ord("a") + index))
            parts.append(alphabet[pick])
        members.append("".join(parts))
    members.append(members[0][:-1] + alphabets[-1][0])

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text(
        "".join(f"{i}:{m}\n" for i, m in enumerate(members))
    )
    _install_smart_mask_test_env(monkeypatch, hc_main, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 3)

    popen_calls = []
    monkeypatch.setattr(hc_main.subprocess, "Popen", _NoopPopen(popen_calls))

    hc_main.hcatSmartMask("1000", str(hashfile))

    out = capsys.readouterr().out
    assert "charset slots" in out, out
    assert "9 distinct charsets" in out, out
    assert popen_calls == [], "an inexpressible template must not launch hashcat"
