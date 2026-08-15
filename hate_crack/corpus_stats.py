"""Whole-corpus statistics for LLM prompts.

The LLM modes used to describe a corpus by pasting an evenly-spaced sample of
its lines into the prompt. That caps what the model can see at
``ollamaMaxSampleLines`` (500 by default) and, worse, hides the one thing that
matters for pattern inference: *frequency*. Five hundred lines drawn from a
120,000-password dump say nothing about which basewords dominate it.

This module summarizes the entire file instead — one pass, bounded output — so
the prompt carries full-corpus facts at roughly the token cost of the sample it
replaces. The heavy lifting is deliberately reused rather than reinvented:
baseword extraction is :func:`hate_crack.rulegen.derive`, the same function the
Spoonman attack derives its baseword list with.

Nothing here contacts the model or the network; it is pure aggregation, which
keeps it cheap to test.
"""

import os
from collections import Counter

from hate_crack import rulegen
from hate_crack.plaintext import (
    decode_hex_wrapper,
    is_gzipped,
    looks_like_hash_line,
    usable_plaintext,
)

__all__ = [
    "decode_hex_wrapper",
    "format_summary",
    "looks_like_hash_line",
    "summarize",
    "usable_plaintext",
]

# Bounds on what reaches the prompt. Each list is truncated to its top N by
# frequency, so summary size is independent of corpus size.
TOP_BASEWORDS = 150
TOP_MASKS = 15
TOP_SUFFIXES = 15
TOP_YEARS = 10
TOP_SPECIALS = 10

# Basewords appearing once in a large corpus are usually typos or one-offs and
# crowd out the families worth extrapolating from.
MIN_BASEWORD_HITS = 2

# Anchor points for the capped sample: the file is divided into this many
# equal byte ranges and a contiguous run of lines is read at the start of each.
# Contiguous runs rather than one seek per line because the cap is measured in
# millions — that many individual seeks thrashes any disk, and on a network
# share it is slower than reading the file outright. A couple of thousand
# anchors spread the sample finely enough that the local ordering inside each
# run cannot dominate the statistics.
SAMPLE_ANCHORS = 2000

# Bytes read to estimate the corpus line count. Only the average line length is
# wanted, and passwords are short and uniform enough that a few megabytes
# settle it; reading further to refine an estimate would cost more than the
# estimate saves.
_ESTIMATE_BYTES = 4 * 1024 * 1024

# How often summarize() reports progress, in lines read. The per-line work here
# is roughly ten passes over the password (mask, casing, baseword derivation,
# two trailing-run scans, a year window), so a multi-million-line corpus takes
# tens of seconds; without periodic reporting the caller can only show elapsed
# time, which is indistinguishable from a hang. Reporting every 100k lines
# repaints often enough to look alive and rarely enough to stay off the hot
# path.
PROGRESS_INTERVAL = 100_000


def _is_ascii_digit(c):
    """Return True iff *c* is an ASCII decimal digit, ``0``-``9``.

    ``str.isdigit()`` is True for Unicode digits that ``int()`` rejects (e.g.
    the superscript ``²``), which crashes anything downstream that assumes
    ``isdigit()`` implies ``int()`` will succeed. ``str.isdecimal()`` fixes
    that crash but is still too broad for our purposes: it is also True for
    non-ASCII decimal digits such as Arabic-Indic ``١٢٣`` (``int('١٢٣')``
    returns 123 without raising), and hashcat's ``?d`` mask charset and its
    digit-suffix candidates are ASCII ``0-9`` only. So neither built-in alone
    is the right predicate everywhere in this module; both the year-parsing
    guard and the mask/suffix classification actually want ASCII-only
    digits, hence one shared predicate rather than three different
    spellings of "digit".
    """
    return "0" <= c <= "9"


def _mask_eligible(pw):
    """Return True iff a hashcat mask can describe *pw* at all.

    hashcat masks are ASCII-only in two independent ways (#230): every built-in
    charset is ASCII (``?a`` is exactly the 95 printable ASCII characters), and
    masks are *byte*-oriented while :func:`_mask` is *character*-oriented, so a
    4-character/5-byte string such as ``ab\xb2x`` cannot be described by any
    4-position mask regardless of which charset symbols are chosen. Rather than
    report a mask an operator cannot paste into a hashcat command, non-ASCII
    passwords are left out of the mask counters entirely and the exclusion is
    reported alongside them.
    """
    return pw.isascii()


def _mask(pw):
    """Return the hashcat-style character-class mask for *pw*.

    Only meaningful for ASCII input; see :func:`_mask_eligible`. It is left
    total rather than made to raise so that the ASCII contract its callers and
    tests rely on is untouched by #230 — :func:`summarize` simply stops calling
    it for non-ASCII passwords.
    """
    out = []
    for c in pw:
        if _is_ascii_digit(c):
            out.append("?d")
        elif "a" <= c <= "z":
            out.append("?l")
        elif "A" <= c <= "Z":
            out.append("?u")
        else:
            out.append("?s")
    return "".join(out)


def _case_shape(pw):
    """Classify the letter casing of *pw*."""
    letters = [c for c in pw if c.isalpha()]
    if not letters:
        return "no letters"
    uppers = [c.isupper() for c in letters]
    if not any(uppers):
        return "all lowercase"
    if all(uppers):
        return "ALL UPPERCASE"
    if uppers[0] and not any(uppers[1:]):
        return "Capitalized"
    return "mIxEd case"


def _trailing_run(pw, predicate):
    """Return the maximal trailing run of characters satisfying *predicate*."""
    i = len(pw)
    while i > 0 and predicate(pw[i - 1]):
        i -= 1
    return pw[i:]


def _years(pw):
    """Yield plausible 4-digit years appearing anywhere in *pw*."""
    for i in range(len(pw) - 3):
        chunk = pw[i : i + 4]
        if all(_is_ascii_digit(c) for c in chunk) and (1900 <= int(chunk) <= 2099):
            yield chunk


def _estimate_line_count(path, size):
    """Estimate the number of lines in *path* from its first few megabytes.

    An exact count would mean a full read, which is the cost the cap exists to
    avoid — on a 29 GB corpus even a bare line count runs for minutes. The
    figure is only used to decide whether to sample and to report coverage, so
    an estimate within a few percent is ample. Returns the exact count when the
    whole file fits inside the estimation window.
    """
    if size == 0:
        return 0
    with open(path, "rb") as fh:
        chunk = fh.read(min(size, _ESTIMATE_BYTES))
    newlines = chunk.count(b"\n")
    if len(chunk) >= size:
        # Whole file read: exact, plus one for a final line with no newline.
        return newlines + (0 if chunk.endswith(b"\n") or not chunk else 1)
    if newlines == 0:
        # A single line longer than the window; nothing to extrapolate from.
        return 1
    return max(1, round(size / (len(chunk) / newlines)))


def _iter_lines(path):
    """Yield every line of *path*, decoded latin-1."""
    with open(path, encoding="latin-1") as fh:
        yield from fh


def _iter_sampled_lines(path, size, cap):
    """Yield at most *cap* lines drawn evenly from across *path*.

    Opened in binary mode and decoded per line: seeking to an arbitrary byte
    offset is well defined on a binary file and not on a TextIOWrapper, whose
    seek() contract accepts only cookies returned by its own tell(). latin-1
    round-trips every byte, so the decoded text matches what the full-read path
    produces, and usable_plaintext() strips the trailing newline either way.
    """
    anchors = max(1, min(SAMPLE_ANCHORS, cap))
    per_anchor = max(1, cap // anchors)
    yielded = 0
    with open(path, "rb") as fh:
        for i in range(anchors):
            if yielded >= cap:
                return
            fh.seek((size * i) // anchors)
            if i:
                # The offset lands mid-line; that fragment is not a password.
                fh.readline()
            for _ in range(per_anchor):
                raw = fh.readline()
                if not raw:
                    break
                yield raw.decode("latin-1")
                yielded += 1
                if yielded >= cap:
                    return


def summarize(path, progress=None, max_lines=None):
    """Aggregate every password in *path* into a bounded stats dict.

    Reads the file once. Raises OSError if it cannot be read and ValueError if
    it holds no usable passwords, matching how rulegen.generate reports an
    empty corpus.

    *progress*, when given, is called with the number of lines read so far —
    every :data:`PROGRESS_INTERVAL` lines and once more at the end with the
    true total, so the last figure a caller paints matches the file. Lines
    read, not passwords kept: the time goes into reading, and a corpus that is
    mostly unusable lines would otherwise appear stalled.

    *max_lines*, when given and positive, bounds the pass: a corpus estimated
    to hold more than that many lines is sampled evenly across its whole byte
    range rather than read end to end, and the returned dict carries
    ``sampled=True`` with an ``estimated_total``. This is not a refinement —
    the loop below runs at roughly 135k lines/s, so an uncapped pass over a
    multi-billion-line corpus takes hours and grows ``unique`` without bound
    until it exhausts memory. Sampling evenly rather than truncating keeps the
    statistics representative: large wordlists are ordered, so a head slice
    describes the ordering instead of the corpus.
    """
    if is_gzipped(path):
        raise ValueError(
            f"{path} is gzip-compressed; decompress it before calling summarize()"
        )

    basewords = Counter()
    masks = Counter()
    lengths = Counter()
    shapes = Counter()
    digit_suffixes = Counter()
    special_suffixes = Counter()
    specials = Counter()
    years = Counter()
    total = 0
    mask_total = 0
    mask_excluded_non_ascii = 0
    hash_shaped = 0
    unique = set()

    lines_read = 0

    cap = max_lines if max_lines and max_lines > 0 else None
    size = os.path.getsize(path)
    estimated_total = _estimate_line_count(path, size) if cap else None
    sampled = cap is not None and estimated_total > cap
    lines = _iter_sampled_lines(path, size, cap) if sampled else _iter_lines(path)

    for raw in lines:
        lines_read += 1
        if progress is not None and lines_read % PROGRESS_INTERVAL == 0:
            progress(lines_read)
        pw = usable_plaintext(raw)
        if not pw:
            continue
        total += 1
        if looks_like_hash_line(raw.strip()):
            hash_shaped += 1
        unique.add(pw)
        lengths[len(pw)] += 1
        if _mask_eligible(pw):
            mask_total += 1
            masks[_mask(pw)] += 1
        else:
            mask_excluded_non_ascii += 1
        shapes[_case_shape(pw)] += 1

        base, _rule = rulegen.derive(pw)
        # rulegen.derive falls back to the password itself when it holds no
        # letters, so a PIN-heavy corpus would otherwise fill the baseword
        # list with digit strings and crowd out the word families it exists
        # to surface. The digit-only share is not lost: it shows up as the
        # "no letters" casing entry and in the masks.
        if base and any(c.isalpha() for c in base):
            basewords[base] += 1

        digits = _trailing_run(pw, _is_ascii_digit)
        if digits:
            digit_suffixes[digits] += 1
        trailing_specials = _trailing_run(
            pw, lambda c: not c.isalnum() and not c.isspace()
        )
        if trailing_specials:
            special_suffixes[trailing_specials] += 1

        for c in pw:
            if not c.isalnum():
                specials[c] += 1
        for year in _years(pw):
            years[year] += 1

    # Final count before the empty-corpus check: a file that turned out to hold
    # no passwords was still read, and the caller's last painted figure should
    # say how much.
    if progress is not None and lines_read % PROGRESS_INTERVAL != 0:
        progress(lines_read)

    if total == 0:
        raise ValueError(f"no passwords read from {path}")

    # A baseword floor only makes sense once there is enough corpus for "seen
    # twice" to mean anything; on a small corpus it would empty the list.
    floor = MIN_BASEWORD_HITS if total >= 500 else 1
    ranked_basewords = [
        (word, hits) for word, hits in basewords.most_common() if hits >= floor
    ][:TOP_BASEWORDS]

    return {
        "path": path,
        "total": total,
        "sampled": sampled,
        "lines_scanned": lines_read,
        # None when uncapped: no estimate was taken, and reporting the scanned
        # count as an "estimate" would misrepresent an exact figure.
        "estimated_total": estimated_total if sampled else None,
        "hash_shaped": hash_shaped,
        "unique": len(unique),
        "basewords": ranked_basewords,
        "baseword_total": len(basewords),
        "masks": masks.most_common(TOP_MASKS),
        # Mask shares are computed over the passwords a mask could describe,
        # not over the whole corpus: dividing by "total" would understate every
        # mask by the non-ASCII fraction.
        "mask_total": mask_total,
        "mask_excluded_non_ascii": mask_excluded_non_ascii,
        "lengths": sorted(lengths.items()),
        "shapes": shapes.most_common(),
        "digit_suffixes": digit_suffixes.most_common(TOP_SUFFIXES),
        "special_suffixes": special_suffixes.most_common(TOP_SPECIALS),
        "specials": specials.most_common(TOP_SPECIALS),
        "years": years.most_common(TOP_YEARS),
    }


def _share(count, total):
    """Render *count* as "312x, 0.7%".

    Both figures, and the percentage at adaptive precision, because a diverse
    corpus has no single dominant baseword: at whole-percent precision every
    entry in a 30,000-baseword corpus renders as "0%", which tells the model
    the opposite of the truth — that the ranking carries no information.
    """
    if not total:
        return f"{count:,}x"
    pct = 100.0 * count / total
    if pct >= 10:
        rendered = f"{pct:.0f}%"
    elif pct >= 0.1:
        rendered = f"{pct:.1f}%"
    else:
        rendered = f"{pct:.2f}%"
    return f"{count:,}x, {rendered}"


def _line(label, pairs, total, limit=None):
    """Render one "label: a (12x, 4%), b (9x, 3%)" line, or "" when empty."""
    if not pairs:
        return ""
    if limit is not None:
        pairs = pairs[:limit]
    rendered = ", ".join(f"{value} ({_share(count, total)})" for value, count in pairs)
    return f"{label}: {rendered}\n"


def format_summary(stats):
    """Render *stats* as the compact text block that goes into the prompt.

    Percentages rather than raw counts throughout: the model needs to know that
    a baseword dominates the corpus, and a share communicates that without
    inviting it to echo numbers back as password candidates.
    """
    total = stats["total"]
    if stats.get("sampled"):
        # The uncapped header's "ENTIRE corpus" claim would be false here, and
        # the model has no way to detect that from the numbers. Coverage is
        # stated so it can weigh a 0.1% sample differently from a 90% one; the
        # shares themselves stay trustworthy because the sample is drawn evenly
        # across the file rather than off the front.
        estimated = stats.get("estimated_total") or total
        coverage = 100.0 * total / estimated if estimated else 100.0
        out = [
            f"Corpus: {total} passwords ({stats['unique']} distinct, "
            f"{stats['baseword_total']} distinct basewords), sampled evenly "
            f"from across a corpus of roughly {estimated:,} lines "
            f"({coverage:.2f}% coverage). The shares below are representative "
            "of the whole file, not exhaustive counts.\n"
        ]
    else:
        out = [
            f"Corpus: {stats['total']} passwords "
            f"({stats['unique']} distinct, {stats['baseword_total']} distinct "
            "basewords). These figures cover the ENTIRE corpus, not a sample.\n"
        ]

    lengths = stats["lengths"]
    if lengths:
        common = sorted(lengths, key=lambda kv: kv[1], reverse=True)[:8]
        out.append(
            "Lengths: "
            + ", ".join(f"{n} chars ({_share(c, total)})" for n, c in sorted(common))
            + "\n"
        )

    out.append(_line("Casing", stats["shapes"], total))
    # Non-ASCII passwords carry no mask (#230), so masks are shares of the
    # mask-eligible population. A stats dict without the key falls back to the
    # whole corpus, which is also the correct denominator whenever nothing was
    # excluded. When nothing is excluded the label and the shares are
    # byte-identical to what this rendered before #230.
    mask_total = stats.get("mask_total", total)
    mask_excluded = stats.get("mask_excluded_non_ascii", 0)
    if mask_excluded:
        mask_label = (
            f"Masks (over {mask_total:,} of {total:,}; "
            f"{mask_excluded:,} excluded as non-ASCII)"
        )
    else:
        mask_label = "Masks"
    if stats["masks"]:
        out.append(_line(mask_label, stats["masks"], mask_total))
    elif mask_excluded:
        # An all-non-ASCII corpus has no masks at all; _line would render
        # nothing and the omission would look like an absent statistic rather
        # than a deliberate exclusion.
        out.append(f"{mask_label}: none\n")
    out.append(_line("Trailing digits", stats["digit_suffixes"], total))
    out.append(_line("Trailing symbols", stats["special_suffixes"], total))
    out.append(_line("Symbols used", stats["specials"], total))
    out.append(_line("Years", stats["years"], total))

    if stats["basewords"]:
        out.append(
            f"\nTop basewords by share of corpus (of {stats['baseword_total']} "
            "distinct):\n"
        )
        for word, hits in stats["basewords"]:
            out.append(f"  {word} ({_share(hits, total)})\n")

    return "".join(part for part in out if part)
