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

import binascii
from collections import Counter

from hate_crack import rulegen

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


def decode_hex_wrapper(plaintext):
    """Expand hashcat's ``$HEX[...]`` wrapper to the bytes it encodes.

    hashcat wraps any plaintext it cannot write literally — non-ASCII bytes, or
    anything holding the output separator — as ``$HEX[68656c6c6f]``. Left alone,
    the wrapper is read as if it were the password itself, which pollutes
    baseword and mask statistics with the letters of ``$HEX[`` and the corpus's
    hex digits.

    Decoded to latin-1 so one byte maps to one character, matching how the rest
    of this module and rulegen read a corpus: hashcat rules address bytes, not
    codepoints. Returns *plaintext* unchanged if it is not a well-formed
    wrapper, so malformed input degrades to today's behaviour rather than
    vanishing.
    """
    if not (plaintext.startswith("$HEX[") and plaintext.endswith("]")):
        return plaintext
    body = plaintext[5:-1]
    try:
        return binascii.unhexlify(body).decode("latin-1")
    except (binascii.Error, ValueError):
        return plaintext


def usable_plaintext(raw):
    """Return the usable plaintext from a raw corpus line, or "".

    Blank/whitespace-only lines are discarded. Lines in ``hash:password``
    format (as hashcat ``--show`` emits) are split on the first colon so only
    the plaintext is returned; lines with no colon are returned as-is. A
    ``hash:`` line whose plaintext is empty after stripping returns "".
    ``$HEX[...]`` plaintexts are decoded — see :func:`decode_hex_wrapper`.
    """
    stripped = raw.strip()
    if not stripped:
        return ""
    if ":" in stripped:
        stripped = stripped.split(":", 1)[1]
    if not stripped:
        return ""
    return decode_hex_wrapper(stripped)


def looks_like_hash(value):
    """True if *value* looks like an uncracked hash rather than a plaintext.

    Operators keep raw NTDS dumps (``user:rid:lm:nt:::``) alongside cracked
    output, and both end in ``.out`` or ``.ntds`` in a working directory. A
    dump's first colon splits into the *rest of the hash line*, not a password,
    so the statistics silently describe hex strings. This flags the shape so
    :func:`summarize` can warn instead of reporting nonsense confidently.
    """
    if value.endswith(":::") or "aad3b435b51404eeaad3b435b51404ee" in value:
        return True
    head = value.split(":", 1)[0]
    return len(head) >= 32 and all(c in "0123456789abcdefABCDEF" for c in head)


def _mask(pw):
    """Return the hashcat-style character-class mask for *pw*."""
    out = []
    for c in pw:
        if c.isdigit():
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
        if chunk.isdigit() and (1900 <= int(chunk) <= 2099):
            yield chunk


def summarize(path):
    """Aggregate every password in *path* into a bounded stats dict.

    Reads the file once. Raises OSError if it cannot be read and ValueError if
    it holds no usable passwords, matching how rulegen.generate reports an
    empty corpus.
    """
    basewords = Counter()
    masks = Counter()
    lengths = Counter()
    shapes = Counter()
    digit_suffixes = Counter()
    special_suffixes = Counter()
    specials = Counter()
    years = Counter()
    total = 0
    hash_shaped = 0
    unique = set()

    with open(path, encoding="latin-1") as fh:
        for raw in fh:
            pw = usable_plaintext(raw)
            if not pw:
                continue
            total += 1
            if looks_like_hash(pw):
                hash_shaped += 1
            unique.add(pw)
            lengths[len(pw)] += 1
            masks[_mask(pw)] += 1
            shapes[_case_shape(pw)] += 1

            base, _rule = rulegen.derive(pw)
            # rulegen.derive falls back to the password itself when it holds no
            # letters, so a PIN-heavy corpus would otherwise fill the baseword
            # list with digit strings and crowd out the word families it exists
            # to surface. The digit-only share is not lost: it shows up as the
            # "no letters" casing entry and in the masks.
            if base and any(c.isalpha() for c in base):
                basewords[base] += 1

            digits = _trailing_run(pw, str.isdigit)
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
    out.append(_line("Masks", stats["masks"], total))
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
