import os


def _terminal_width(default: int = 120) -> int:
    try:
        width = os.get_terminal_size().columns
        if width:
            return width
    except Exception:
        pass
    try:
        width = int(os.environ.get("COLUMNS", ""))
        if width > 0:
            return width
    except Exception:
        pass
    return default


def print_multicolumn_list(
    title, entries, min_col_width=20, max_col_width=None, styles=None
):
    if not entries:
        if title:
            print(f"\n{title}:\n  (none)")
        return

    terminal_width = _terminal_width()
    max_len = max(len(entry) for entry in entries)
    if max_col_width is None:
        max_col_width = max_len + 2
    col_width = max(min_col_width, min(max_col_width, terminal_width))
    num_cols = max(1, terminal_width // col_width)
    rows = (len(entries) + num_cols - 1) // num_cols

    if title:
        print("\n" + "=" * terminal_width)
        print(title)
        print("=" * terminal_width)

    for row in range(rows):
        line_parts = []
        for col in range(num_cols):
            idx = row + col * rows
            if idx < len(entries):
                entry = entries[idx]
                max_entry_len = max(1, col_width)
                if len(entry) > max_entry_len:
                    if max_entry_len > 3:
                        entry = entry[: max_entry_len - 3] + "..."
                    else:
                        entry = entry[:max_entry_len]
                padded = entry.ljust(col_width)
                style = styles[idx] if styles and idx < len(styles) else None
                # Style is applied to the already-padded, already-truncated
                # text: ljust() and the truncation above both count characters,
                # so an escape sequence inside `entry` would be measured as
                # visible width and the grid would go ragged.
                line_parts.append(f"{style}{padded}\033[0m" if style else padded)
        line = "".join(line_parts)
        # rstrip() alone would leave trailing padding spaces stranded in front
        # of a reset code when the last populated column is styled (its last
        # character is the "m" of "\033[0m", not whitespace, so a plain
        # rstrip() no-ops there). Strip a trailing reset first, rstrip the
        # remainder, then reattach it so the visible width still matches the
        # unstyled render exactly.
        reset_suffix = "\033[0m" if line.endswith("\033[0m") else ""
        if reset_suffix:
            line = line[: -len(reset_suffix)].rstrip() + reset_suffix
        else:
            line = line.rstrip()
        print(line)

    if title:
        print("=" * terminal_width)
