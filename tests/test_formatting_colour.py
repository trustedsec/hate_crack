"""Colour in the multi-column grid, without breaking its alignment.

print_multicolumn_list pads with ljust() and truncates on len(), so a
pre-coloured entry string would be padded and truncated by its *byte* length
including escape sequences: the grid goes ragged and a long name can be cut
mid-escape, leaving the terminal coloured for everything after it.
"""

from __future__ import annotations

import re

from hate_crack.formatting import print_multicolumn_list

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def test_styles_do_not_change_the_visible_layout(capsys):
    entries = [f"{i}) item{i}" for i in range(1, 7)]
    print_multicolumn_list("T", entries, min_col_width=12, max_col_width=12)
    plain = capsys.readouterr().out

    print_multicolumn_list(
        "T",
        entries,
        min_col_width=12,
        max_col_width=12,
        styles=["\x1b[36m", None, "\x1b[36m", None, "\x1b[36m", None],
    )
    coloured = capsys.readouterr().out

    assert ANSI.sub("", coloured) == plain, (
        "colour changed the visible layout; padding is not visible-width aware"
    )


def test_every_style_is_reset(capsys):
    print_multicolumn_list("T", ["1) a"], styles=["\x1b[36m"])
    out = capsys.readouterr().out
    assert "\x1b[36m" in out
    assert "\x1b[0m" in out, "an unreset colour leaks into the rest of the session"


def test_no_styles_argument_emits_no_escapes(capsys):
    print_multicolumn_list("T", ["1) a", "2) b"])
    assert not ANSI.search(capsys.readouterr().out)


def test_truncation_counts_visible_characters(capsys):
    print_multicolumn_list(
        "T",
        ["1) a-very-long-entry-name"],
        min_col_width=10,
        max_col_width=10,
        styles=["\x1b[36m"],
    )
    out = capsys.readouterr().out
    visible = ANSI.sub("", out).splitlines()
    row = next(line for line in visible if line.strip().startswith("1)"))
    assert len(row.rstrip()) <= 10, f"truncated on byte length, not visible: {row!r}"
    assert out.rstrip().endswith("\x1b[0m") or "\x1b[0m" in out


def test_styled_last_column_does_not_strand_padding_before_reset(capsys):
    # A styled entry that is the last populated column in its row needs
    # padding to reach col_width; that padding must not survive as trailing
    # whitespace in front of the reset code, or the visible-width comparison
    # with an unstyled render would fail.
    entries = ["1) short"]
    print_multicolumn_list("T", entries, min_col_width=20, max_col_width=20)
    plain = capsys.readouterr().out

    print_multicolumn_list(
        "T", entries, min_col_width=20, max_col_width=20, styles=["\x1b[36m"]
    )
    coloured = capsys.readouterr().out

    assert ANSI.sub("", coloured) == plain
