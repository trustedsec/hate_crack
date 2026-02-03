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


def print_multicolumn_list(title, entries, min_col_width=20, max_col_width=None):
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
                max_entry_len = max(1, col_width - 2)
                if len(entry) > max_entry_len:
                    if max_entry_len > 3:
                        entry = entry[: max_entry_len - 3] + "..."
                    else:
                        entry = entry[:max_entry_len]
                line_parts.append(entry.ljust(col_width))
        print("".join(line_parts).rstrip())

    if title:
        print("=" * terminal_width)
