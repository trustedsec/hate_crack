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
