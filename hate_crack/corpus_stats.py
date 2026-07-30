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


def summarize(path):
    """Aggregate every password in *path* into a bounded stats dict.

    Reads the file once. Raises OSError if it cannot be read and ValueError if
    it holds no usable passwords, matching how rulegen.generate reports an
    empty corpus.
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

    with open(path, encoding="latin-1") as fh:
        for raw in fh:
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
    out = [
        f"Corpus: {stats['total']} passwords "
        f"({stats['unique']} distinct, {stats['baseword_total']} distinct basewords). "
        "These figures cover the ENTIRE corpus, not a sample.\n"
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
