"""Unit tests for hate_crack.main._valid_hcmask."""

import os

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import main as hc_main  # noqa: E402


def test_literal_only_mask_is_valid():
    assert hc_main._valid_hcmask("password123") is True


def test_all_placeholder_classes_are_valid():
    assert hc_main._valid_hcmask("?u?l?d?s?a?b") is True


def test_mixed_literal_and_placeholder_is_valid():
    assert hc_main._valid_hcmask("?u?l?l?l-2026") is True


def test_escaped_literal_question_mark_is_valid():
    assert hc_main._valid_hcmask("?u?l?l??") is True


def test_trailing_unescaped_question_mark_is_invalid():
    assert hc_main._valid_hcmask("?u?l?l?") is False


def test_unknown_placeholder_letter_is_invalid():
    assert hc_main._valid_hcmask("?u?x?d") is False


def test_empty_mask_is_invalid():
    assert hc_main._valid_hcmask("") is False


def test_well_over_old_32_char_cap_is_now_valid():
    # The old hand-rolled checker capped masks at 32 characters as a guard
    # against runaway model output -- hashcat_rosetta.mask.parse_hcmask_line
    # (delegated to since the rosetta mask integration) enforces hashcat's
    # own real 256-position limit instead, so this 80-position mask is valid.
    assert hc_main._valid_hcmask("?a" * 40) is True


def test_non_string_input_is_invalid():
    assert hc_main._valid_hcmask(None) is False


def test_mask_with_custom_charset_comma_is_valid():
    # A comma is the legitimate custom-charset/mask separator in real hcmask
    # syntax -- "aeiou" here is custom charset 1, referenced as ?1.
    assert hc_main._valid_hcmask("aeiou,?1?1?d?d?d") is True


def test_mask_with_literal_backslash_is_valid():
    # A backslash that isn't part of an escaped comma (\,) is just an
    # ordinary literal character in real hcmask syntax.
    assert hc_main._valid_hcmask("?u?l?l\\?d?d?d") is True


def test_mask_with_embedded_newline_is_invalid():
    assert hc_main._valid_hcmask("?u?l?l\n?d?d?d") is False


def test_mask_with_literal_space_is_valid():
    assert hc_main._valid_hcmask("?u?l?l ?d?d?d") is True


def test_exactly_max_length_mask_is_valid():
    assert hc_main._valid_hcmask("?a" * 16) is True  # 32 characters


def test_at_hashcat_256_position_limit_is_valid():
    assert hc_main._valid_hcmask("a" * 256) is True


def test_one_over_hashcat_256_position_limit_is_invalid():
    assert hc_main._valid_hcmask("a" * 257) is False


def test_single_question_mark_is_invalid():
    assert hc_main._valid_hcmask("?") is False


def test_triple_question_mark_is_invalid():
    assert hc_main._valid_hcmask("???") is False


def test_quadruple_question_mark_is_valid():
    assert hc_main._valid_hcmask("????") is True


def test_mask_with_leading_hash_is_invalid():
    assert hc_main._valid_hcmask("#comment") is False


def test_custom_charset_reference_is_valid():
    assert hc_main._valid_hcmask("aeiou,?1?1?1?1?d?d") is True


def test_custom_charset_reference_beyond_defined_count_is_invalid():
    # Only one custom charset is defined here; ?2 is not.
    assert hc_main._valid_hcmask("aeiou,?1?2") is False


def test_up_to_eight_custom_charsets_is_valid():
    assert hc_main._valid_hcmask("a,b,c,d,e,f,g,h,?1?2?3?4?5?6?7?8") is True


def test_more_than_eight_custom_charsets_is_invalid():
    assert hc_main._valid_hcmask("a,b,c,d,e,f,g,h,i,?1") is False


def test_custom_charset_back_reference_is_valid():
    # ?2 is defined as charset 1 (digits) plus the letter 'a'.
    assert hc_main._valid_hcmask("0123456789,?1a,?1?2") is True
