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


def test_overlength_mask_is_invalid():
    assert hc_main._valid_hcmask("?a" * 40) is False


def test_non_string_input_is_invalid():
    assert hc_main._valid_hcmask(None) is False


def test_mask_with_comma_is_invalid():
    assert hc_main._valid_hcmask("?u?l?l,?d?d?d") is False


def test_mask_with_backslash_is_invalid():
    assert hc_main._valid_hcmask("?u?l?l\\?d?d?d") is False


def test_mask_with_embedded_newline_is_invalid():
    assert hc_main._valid_hcmask("?u?l?l\n?d?d?d") is False


def test_mask_with_literal_space_is_valid():
    assert hc_main._valid_hcmask("?u?l?l ?d?d?d") is True


def test_exactly_max_length_mask_is_valid():
    assert hc_main._valid_hcmask("?a" * 16) is True  # 32 characters


def test_one_over_max_length_mask_is_invalid():
    assert hc_main._valid_hcmask("a" + "?a" * 16) is False  # 33 characters


def test_single_question_mark_is_invalid():
    assert hc_main._valid_hcmask("?") is False


def test_triple_question_mark_is_invalid():
    assert hc_main._valid_hcmask("???") is False


def test_quadruple_question_mark_is_valid():
    assert hc_main._valid_hcmask("????") is True


def test_mask_with_leading_hash_is_invalid():
    assert hc_main._valid_hcmask("#comment") is False
