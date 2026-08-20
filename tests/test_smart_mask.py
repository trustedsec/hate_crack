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
