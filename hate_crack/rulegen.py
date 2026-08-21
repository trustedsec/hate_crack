"""Derive basewords + hashcat rules that reconstruct every password in a corpus.

Contributed by @Spoonman1091 in trustedsec/hate_crack#169.

Baseword model: the letters-only core of each password, lowercased. Each
password is paired with a rule that rebuilds it exactly, using ops hashcat
supports natively:

    :            no-op
    l u c        lowercase all / uppercase all / capitalize
    T{p}         toggle case at position p        (p in 0-9A-Z = 0..35)
    ${x}         append char x
    ^{x}         prepend char x
    i{p}{x}      insert char x at position p
    o{p}{x}      overwrite char at position p with x

An argument that is a CR or an LF is spelled ``\\xNN``, which hashcat decodes to
the single byte. A rule file is read a line at a time, so the raw byte cannot
survive it: an LF ends the rule where it falls and a raw CR makes hashcat reject
the line. No other byte is escaped, because no other byte needs it.

The baseword list and the rule list together reconstruct 100% of the corpus,
so the rule file is truncatable: it is sorted by how many passwords each rule
rebuilds, most productive first.

Leet restoration, and why :func:`generate` reads the corpus twice
----------------------------------------------------------------

A letters-only core throws away every leet-substituted letter: a synthetic
``Sw1ftK1ng`` becomes the baseword ``swftkng`` plus two ``i`` inserts, which
rebuilds exactly that one password and combines productively with nothing.
Keeping a letter in the slot and overwriting it with ``o{p}{x}`` costs the same
one function per slot and leaves a pronounceable word in the list.

Reversing a leet substitution is ambiguous, though — ``1`` is ``i`` or ``l``,
``$`` is ``s``, ``0`` is ``o`` — and a wrong guess splits one baseword into two.
Measured on a 360,000-password sample, a *static* reverse-leet map produced
4.2% *more* unique basewords than deleting the letter did, so restoration is
gated on attestation instead: a slot is only restored when the resulting
baseword was already derived from some other password in the same corpus.

Knowing that requires having read the corpus once already, which is why
``leet_restore=True`` makes :func:`generate` read it **twice**:

* Pass 1 is exactly the letters-only derivation, and its baseword counter is
  kept as the attestation dictionary. Its own statistics are discarded.
* Pass 2 re-derives every password through :func:`derive_leet_aware` against
  that dictionary. Every counter written out, and every statistic reported,
  comes from pass 2.

The cost is a doubled read, plus pass 1's dictionary held live alongside pass
2's two counters. The dictionary is filtered down to the keys that meet the
attestation threshold before pass 2 starts — 93.4% of them fail it on a
360,000-password sample, because a corpus's baseword tail is overwhelmingly
singletons — so what is actually carried is a small fraction of a counter
rather than a third full one. The ``max_unique`` bound below applies to both
passes. ``leet_restore=False`` reads the corpus once and reproduces the
letters-only output exactly.

That 100% guarantee holds only while :func:`generate` keeps every key it sees.
A corpus large enough to threaten the machine's RAM makes that impossible: the
per-key cost of the two counters is roughly 80 bytes, so a corpus with billions
of distinct basewords would need tens of gigabytes before a single line of
output is written, and an OOM kill mid-pass throws away the whole run. To
degrade gracefully instead, :func:`generate` bounds each counter at
``max_unique`` keys (see :data:`MAX_UNIQUE_KEYS`) and periodically discards the
lowest-frequency ones. When that pruning fires the output no longer
reconstructs 100% of the corpus — it reconstructs the retained keys, coverage
percentages are relative to those, and both ``coverage.txt`` and the run's
console output say so. Passing ``max_unique=None`` restores the exact,
unbounded behaviour for anyone who has the memory to spare.

The literal fallback, and what it does and does not mean
-------------------------------------------------------

When a password cannot be expressed as baseword-plus-rule, :func:`derive`
falls back to :func:`_literal_pair`, which emits it verbatim as its own
baseword with a ``:`` no-op rule -- except when the password holds a CR or
LF, in which case the break is lifted out of the baseword into an escaped
``i{p}{x}`` insert op instead (:func:`_literal_with_line_breaks`; #295), since
a wordlist line has no escape syntax to hold the raw byte. Two very
different things end up in this fallback, and :func:`generate` counts them
separately because only one of them is a loss:

* ``no_letter_literals`` — the password holds no ASCII letter at all, so there
  is no letters-only core to derive from. A digit- or symbol-only password is
  its own baseword, which is the right answer rather than a defect. On a
  360,000-password sample this was **100%** of the fallbacks.
* ``unrepresentable`` — the password does hold letters and still could not be
  encoded, because it hit one of the two hashcat limits below. This one is a
  real loss of expressiveness. On the same sample it was **zero**: the limits
  are real, but on the realistic 6-12 character passwords a corpus is actually
  made of they essentially never fire.

``literal_fallbacks`` is retained in the returned dict as the sum of the two,
for compatibility with callers written before the split.

The limits themselves, for completeness:

* Positions are encoded in a 36-character alphabet, so ``T``/``i``/``o`` cannot
  address past index 35.
* hashcat rejects any rule with more than ``MAX_RULE_FUNCTIONS`` functions.
  It does so *silently* when other valid rules are present in the same file,
  which is why the op count is enforced here rather than discovered later as
  missing coverage.
"""

import itertools
import os
from collections import Counter
from typing import NamedTuple

from hate_crack.plaintext import is_gzipped, looks_like_hash_line, usable_plaintext

POS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# hashcat's rule engine accepts at most this many functions in a single rule.
# Verified against hashcat v7: 31 functions run, 32 yields "No valid rules
# left" when the rule stands alone and is dropped without warning when it
# shares a file with valid rules.
MAX_RULE_FUNCTIONS = 31

# Ceiling on how many distinct keys either of :func:`generate`'s counters may
# hold before the lowest-frequency ones are discarded.
#
# Measured with tracemalloc against a Counter of 1,000,000 unique 8-character
# string keys: 80 bytes per key, covering the dict entry, the index table, and
# the key object itself. 20,000,000 keys is therefore ~1.6 GB per counter, or
# ~3.2 GB for the baseword and rule counters together — an amount a cracking
# host can spare alongside hashcat.
#
# The figure is not arbitrary caution. An unbounded pass over a 31 GB /
# ~3.6-billion-password corpus reached 14.1 GB RSS at ~11% of the file with the
# growth rate still climbing, and was projected to need 70-130 GB against 64 GB
# of RAM. Nothing is written until the read loop ends, so the OOM kill would
# have destroyed a multi-hour pass with no output at all.
MAX_UNIQUE_KEYS = 20_000_000

# How many corpus lines to read between counter-size checks. Checking every
# line would cost two len() calls per password for no benefit; a million lines
# can add at most a million keys to a counter, which is 5% of the default bound.
_PRUNE_CHECK_INTERVAL = 1_000_000


def _prune_counter(counter, max_unique):
    """Discard the lowest-frequency keys of *counter* until it fits *max_unique*.

    Removes whole frequency tiers from the bottom up — every key seen exactly
    once first, then every key seen twice, and so on — stopping as soon as the
    counter is at or below *max_unique*. Whole tiers rather than a partial cut
    at the boundary: the tail of a password corpus is overwhelmingly keys seen
    once, so clearing the tier outright drops the counter well below the bound
    and buys many millions of lines before the next prune, whereas trimming to
    exactly *max_unique* would re-trip on the very next check.

    The bound is unconditional. When only one tier is left and it is still over
    *max_unique* — every surviving key tied at the same frequency, which is
    exactly what a corpus of all-distinct keys looks like — the tier is cut
    partway instead, keeping *max_unique* of its keys and discarding the rest.
    The choice among tied keys is arbitrary (dict order), because by definition
    frequency gives no reason to prefer any of them. Stopping short here would
    return a counter still over the bound and let it grow unchecked for the
    rest of the read, which is the OOM this function exists to prevent.

    Returns ``(keys_discarded, observations_discarded)``.

    Deletes in place rather than rebuilding. A rebuild via a filtered
    comprehension is the obvious implementation but transiently holds two
    counters at once, roughly doubling the peak footprint this function exists
    to lower. The only transient here is a list of the doomed keys: 8 bytes per
    entry for the pointer (the key objects are already alive), so a worst-case
    peak of ~10% of the counter's own size rather than ~100%. CPython frees
    each key string as it is deleted and compacts the dict's table on the next
    resize.
    """
    if max_unique is None or len(counter) <= max_unique:
        return (0, 0)

    # Histogram of frequencies. Bounded by the number of *distinct* counts, not
    # by the number of keys, so it is negligible next to the counter itself.
    histogram = Counter(counter.values())
    remaining = len(counter)
    threshold = 0
    for freq in sorted(histogram):
        if remaining <= max_unique:
            break
        if remaining - histogram[freq] <= 0:
            # This is the last tier and clearing it would empty the counter, so
            # it is cut partway below instead of removed outright.
            break
        threshold = freq
        remaining -= histogram[freq]

    doomed = [key for key, hits in counter.items() if hits <= threshold]
    if remaining > max_unique:
        # Only the tied top tier is left and it still overflows. Cut it down
        # arbitrarily so the bound actually holds: keep the first `max_unique`
        # keys encountered and append the rest to `doomed` as they are found,
        # rather than materialising a second list of every survivor, so the
        # transient stays proportional to what is discarded, not to what is
        # kept.
        kept = 0
        for key, hits in counter.items():
            if hits > threshold:
                kept += 1
                if kept > max_unique:
                    doomed.append(key)

    observations = 0
    for key in doomed:
        observations += counter[key]
        del counter[key]
    return (len(doomed), observations)


def _pos(n):
    """Return the rule-alphabet character for index *n*, or None if unaddressable."""
    return POS[n] if 0 <= n < len(POS) else None


def _isalpha(c):
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


# The two bytes that cannot appear raw in an op argument. A rule file is read a
# line at a time, so an LF ends the rule wherever it falls -- the rest of it,
# and the argument it belonged to, become a blank line. A raw CR is worse than
# useless: hashcat rejects the line outright ("No valid rules left"). Every
# other byte survives verbatim, NUL and 0x80-0xFF included, all three verified
# against 7.1.2.
#
# hashcat decodes \xNN in an argument to a single byte before applying the rule,
# which is what makes these two expressible at all rather than a reason to drop
# the password. Deliberately not applied to any other byte: a raw high byte
# already works, and one real corpus produced 728 rules holding one.
_ARG_ESCAPES = {"\n": "\\x0a", "\r": "\\x0d"}


def _escape_arg(c):
    """Return *c* spelled so it survives a line-based rule file."""
    return _ARG_ESCAPES.get(c, c)


def _read_arg(rule, i):
    """Return ``(character, width)`` for the literal argument at index *i*.

    hashcat decodes escapes across the whole line before parsing ops, which is
    not quite the same thing as decoding each argument in place. For everything
    :func:`derive` emits the two agree, because every argument is preceded by
    its own op character: a raw backslash argument is always followed by the
    next op (``$\\`` then ``$x`` reads as ``\\$x``), so it can never combine
    with what follows into an escape that was not written as one.
    """
    if rule[i] == "\\" and rule[i + 1 : i + 2] == "x" and len(rule) >= i + 4:
        try:
            return chr(int(rule[i + 2 : i + 4], 16)), 4
        except ValueError:
            pass
    return rule[i], 1


def count_ops(rule):
    """Return the number of hashcat functions in *rule*.

    Raises ValueError on an op this module does not emit.
    """
    count = 0
    i = 0
    while i < len(rule):
        op = rule[i]
        if op in ":luc":
            i += 1
        elif op == "T":
            i += 2
        elif op in "$^":
            # The argument may be an escape, which is one argument spelled in
            # four characters -- not four ops.
            i += 1 + _read_arg(rule, i + 1)[1]
        elif op in "io":
            i += 2 + _read_arg(rule, i + 2)[1]
        else:
            raise ValueError(f"unknown op {op!r} in rule {rule!r}")
        count += 1
    return count


# What each hashcat rule op takes after the op character itself: "p" for a
# position/count token, which must come from the 36-character POS alphabet, and
# "c" for a literal character, which may be anything printable. Counting
# arguments is not enough — hashcat rejects 'Ta' as surely as it rejects an
# unknown op, and just as silently.
#
# Wider than the subset :func:`derive` emits, because :func:`validate_rule`
# screens rules written by something else (see hate_crack.llm.generate_rules).
#
# Established empirically against hashcat v7 rather than from the rule
# documentation, which lists ops this hashcat will not run. Verified rejected
# both by --stdout and by a real -m 0 run, and therefore deliberately absent:
#
#   4 6 M X   memory ops (append/prepend memory, memorize, extract)
#   < > _ ! / ( ) %   reject-plain ops
#
# hashcat answers "No valid rules left" for each of those on its own and drops
# it silently from a file that also holds valid rules, which is the whole reason
# this function exists — so treating them as valid here would defeat it.
#
# Also deliberately absent, in the opposite direction: 'h' and 'H' (hex-encode),
# 'S', and 'v'/'B' (two arguments each). hashcat v7 runs them, but hate_crack
# supports v6 installs too, and a rule this table blesses that the operator's
# hashcat does not know is dropped silently — the exact failure this screen is
# for. Rejecting a valid rule only costs one rule; accepting an invalid one
# costs coverage nobody sees go missing.
RULE_OP_ARGS = {
    **{op: "" for op in ":lucCtrdfkKqE{}[]"},
    **{op: "p" for op in "TpDzZ'-+.,yYLR"},
    **{op: "c" for op in "$^e@"},
    **{op: "pp" for op in "xO*"},
    **{op: "pc" for op in "io3"},
    "s": "cc",
}

# hashcat rejects a rule line longer than this outright.
MAX_RULE_LENGTH = 255


def validate_rule(rule):
    """Return True if *rule* is a rule line hashcat will accept.

    Stricter than :func:`count_ops`, which only knows the ops this module
    emits and raises on anything else. This screens arbitrary rule text — a
    model's output, a hand-written file — so one bad line cannot poison a whole
    rule file. hashcat drops an invalid rule *silently* when valid rules share
    the file, which turns a malformed line into missing coverage rather than an
    error, so the filtering has to happen before hashcat sees it.

    Rejects: unknown ops, an op whose arguments run off the end of the line, a
    position argument outside the :data:`POS` alphabet, non-printable or
    non-ASCII characters, an over-long line, and more than
    ``MAX_RULE_FUNCTIONS`` functions. Comments and blank lines are not rules
    and are rejected too; callers strip those first if they want to keep them.
    """
    if not isinstance(rule, str) or not rule:
        return False
    if len(rule) > MAX_RULE_LENGTH:
        return False
    if any(not (" " <= c <= "~") for c in rule):
        return False

    count = 0
    i = 0
    while i < len(rule):
        # hashcat allows functions to be separated by spaces for readability.
        # A space is only a separator *between* functions — as an argument it is
        # consumed by the op below, exactly as hashcat's parser does it.
        if rule[i] == " ":
            i += 1
            continue
        kinds = RULE_OP_ARGS.get(rule[i])
        if kinds is None:
            return False
        # Arguments are measured rather than counted, because hashcat decodes
        # \xNN to a single byte: an escape is one argument four characters wide.
        at = i + 1
        for kind in kinds:
            # The op and all of its arguments must fit inside the line.
            if at >= len(rule):
                return False
            decoded, width = _read_arg(rule, at)
            if kind == "p" and decoded not in POS:
                return False
            at += width
        if at > len(rule):
            return False
        i = at
        count += 1
        if count > MAX_RULE_FUNCTIONS:
            return False
    return count > 0


# Tie-break order among equally-cheap case encodings, per :func:`_case_ops`.
_CASE_STRATEGY_ORDER = {"none": 0, "c": 1, "u": 2, "direct": 3}


def _case_ops(flags):
    """Return the cheapest case-op list for the case mask *flags*, or None.

    *flags* has one entry per baseword position: True where the position must
    end up uppercase, False where it must end up lowercase, and None where the
    caller does not care — which is what :func:`derive_leet_aware` passes for a
    restored leet slot, since an ``o`` op overwrites that position afterwards
    and whatever case it held is discarded.

    Four encodings are costed in rule functions and the cheapest wins:

    ``none``    no ops at all; available only when nothing must be uppercase.
    ``c``       capitalize, then toggle every other required uppercase, plus
                position 0 back down if it must be lowercase.
    ``u``       uppercase everything, then toggle every required lowercase.
    ``direct``  toggle each required uppercase individually.

    An encoding is disqualified when it would need a ``T`` at a position past
    the 36-character :data:`POS` alphabet. Ties break in the order ``none, c,
    u, direct``. Returns None only when every encoding is disqualified, which
    the caller answers with the literal fallback.
    """
    candidates = []

    # Strategy: none (no case ops) - valid only when no uppercase
    if not any(flags):
        candidates.append((0, [], "none"))

    # Strategy: c + fix - uppercase index 0, then toggle uppercase letters at >0
    # and toggle index 0 if it should be lowercase.
    c_ops = ["c"]
    c_valid = True
    for i, is_upper in enumerate(flags):
        if i > 0 and is_upper:
            p = _pos(i)
            if p is None:
                c_valid = False
                break
            c_ops.append("T" + p)
    if c_valid and flags[0] is False:
        c_ops.append("T0")
    if c_valid:
        candidates.append((len(c_ops), c_ops, "c"))

    # Strategy: u + invert - uppercase all, then toggle lowercase letters
    u_ops = ["u"]
    u_valid = True
    for i, is_upper in enumerate(flags):
        if is_upper is False:
            p = _pos(i)
            if p is None:
                u_valid = False
                break
            u_ops.append("T" + p)
    if u_valid:
        candidates.append((len(u_ops), u_ops, "u"))

    # Strategy: direct - toggle each uppercase letter
    direct_ops = []
    direct_valid = True
    for i, is_upper in enumerate(flags):
        if is_upper:
            p = _pos(i)
            if p is None:
                direct_valid = False
                break
            direct_ops.append("T" + p)
    if direct_valid:
        candidates.append((len(direct_ops), direct_ops, "direct"))

    if not candidates:
        return None
    return min(candidates, key=lambda x: (x[0], _CASE_STRATEGY_ORDER[x[2]]))[1]


def _literal_with_line_breaks(pw):
    """Derive a literal-fallback password whose bytes include a CR or LF.

    The baseword is the password with those bytes removed and the rule inserts
    them back, in increasing index order so each insert accounts for the shift
    from the ones before it -- the same accounting :func:`derive` does for
    interior non-letters. Falls back to the literal pair when a break sits past
    the last addressable position, which leaves a baseword the caller cannot
    write; :func:`generate` counts those rather than emitting them.
    """
    base = "".join(c for c in pw if c not in _ARG_ESCAPES)
    ops = []
    for idx, c in enumerate(pw):
        if c not in _ARG_ESCAPES:
            continue
        p = _pos(idx)
        if p is None:
            return (pw, ":")
        ops.append("i" + p + _escape_arg(c))
    if len(ops) > MAX_RULE_FUNCTIONS:
        return (pw, ":")
    return (base, "".join(ops))


def _literal_pair(pw):
    """The literal fallback for *pw*: the password as its own baseword.

    A ``:`` no-op rule, except when *pw* holds a CR or LF -- a wordlist
    line has no escape syntax, so a baseword still holding one cannot be
    written at all. Lifting the break into an escaped insert op keeps the
    password covered instead of counted as a loss (#295 residual gap).
    """
    if any(c in _ARG_ESCAPES for c in pw):
        return _literal_with_line_breaks(pw)
    return (pw, ":")


def derive(pw):
    """Return ``(baseword, rule)`` such that applying *rule* to *baseword* yields *pw*.

    Falls back to :func:`_literal_pair` — the password as its own literal
    baseword, with any CR/LF lifted into an escaped insert op — whenever the
    transformation cannot be expressed within hashcat's limits.
    """
    if pw == "":
        return ("", ":")
    letters = [c for c in pw if _isalpha(c)]
    if not letters:
        # A letterless password is its own baseword -- but a wordlist line
        # cannot hold a CR or LF, and unlike a rule argument there is no escape
        # on that side to spell it with. Lift the line breaks out into insert
        # ops, which can be escaped, and let the rest be the baseword.
        return _literal_pair(pw)
    base = "".join(c.lower() for c in letters)
    idxs = [i for i, c in enumerate(pw) if _isalpha(c)]
    first, last = idxs[0], idxs[-1]
    prefix, core, suffix = pw[:first], pw[first : last + 1], pw[last + 1 :]

    # Case ops apply to the pure-lowercase base, so positions are 0..len(base)-1.
    case_ops = _case_ops([c.isupper() for c in letters])
    if case_ops is None:
        # Every case encoding needed an unaddressable position; fall back.
        return _literal_pair(pw)
    ops = list(case_ops)
    # Interior non-letters, inserted at core-relative indices in increasing
    # order so each insert accounts for the shift from the ones before it.
    for idx, c in enumerate(core):
        if not _isalpha(c):
            p = _pos(idx)
            if p is None:
                return _literal_pair(pw)
            ops.append("i" + p + _escape_arg(c))
    # Trailing non-letters append; position-independent, so these merge well
    # across passwords.
    for c in suffix:
        ops.append("$" + _escape_arg(c))
    # Leading non-letters prepend, reversed so the final order comes out right.
    for c in reversed(prefix):
        ops.append("^" + _escape_arg(c))

    if len(ops) > MAX_RULE_FUNCTIONS:
        return _literal_pair(pw)

    return (base, "".join(ops) if ops else ":")


# Candidate letters each leet character may stand in for, most-to-least
# conventional within an entry. Every value is a list because the mapping is
# one-to-many in general: '1' is as often 'l' as 'i', and treating the
# single-candidate entries as a different shape would only invite a caller to
# forget which is which.
#
# This map alone is NOT enough to restore a letter — applied unconditionally it
# makes the baseword list worse (see the module docstring). It only proposes
# candidates; :func:`derive_leet_aware` picks among them by corpus attestation.
REVERSE_LEET = {
    "@": ["a"],
    "0": ["o"],
    "3": ["e"],
    "$": ["s"],
    "4": ["a"],
    "7": ["t"],
    "5": ["s"],
    "9": ["g"],
    "8": ["b"],
    "+": ["t"],
    "!": ["i"],
    "1": ["i", "l"],
}

# Most leet slots one password may have before restoration is skipped for it.
# Each slot multiplies the candidate search by 1 + len(REVERSE_LEET[char]), so
# four slots of the worst case ('1', three candidates each counting "leave it")
# is 81 dictionary lookups — bounded. Passwords with five or more leet
# characters are rare and are the ones least likely to attest anyway.
#
# This is a performance guard, not just a scope limit: the growth is
# exponential in the number of slots, and removing the cap makes the test
# suite time out on inputs that are merely long rather than pathological.
MAX_LEET_SLOTS = 4


def derive_leet_aware(pw, dictionary, min_hits=2):
    """Like :func:`derive`, but restores leet-substituted letters into the baseword.

    *dictionary* maps letters-only baseword to how many corpus passwords
    produced it — :func:`generate`'s pass-1 counter. A candidate restoration is
    only accepted when *dictionary* attests its baseword at least *min_hits*
    times, so an ambiguous or wrong reversal never enters the output; see the
    module docstring for why that gate exists.

    Falls back to exactly ``derive(pw)`` whenever there is nothing to restore,
    nothing attested, or the restored form cannot be expressed within hashcat's
    limits. With an empty *dictionary* it is therefore ``derive`` outright.
    """
    base, rule, _ = _derive_leet_aware(pw, dictionary, min_hits)
    return (base, rule)


def _derive_leet_aware(pw, dictionary, min_hits=2):
    """:func:`derive_leet_aware` plus a flag for whether anything was restored.

    The flag is what :func:`generate` counts as ``leet_restored``. Returning it
    from here rather than comparing against a second ``derive(pw)`` call in the
    caller keeps pass 2 at one derivation per password.
    """
    letters = [c for c in pw if _isalpha(c)]
    if not letters:
        return (*derive(pw), False)
    idxs = [i for i, c in enumerate(pw) if _isalpha(c)]
    first, last = idxs[0], idxs[-1]
    prefix, core, suffix = pw[:first], pw[first : last + 1], pw[last + 1 :]

    # Only interior non-letters can be restored: a leading or trailing one is
    # already a position-independent ^ or $ op, which combines across passwords
    # better than anything inside the word could.
    slots = [i for i, c in enumerate(core) if not _isalpha(c) and c in REVERSE_LEET]
    if not slots or len(slots) > MAX_LEET_SLOTS:
        return (*derive(pw), False)

    # Each slot may be left alone (None) or restored to one of its candidates.
    # The all-None combination is deliberately included: it is today's
    # letters-only baseword, and when the corpus attests that more strongly
    # than any restoration, leaving the letter out is the right answer.
    options = [[None, *REVERSE_LEET[core[i]]] for i in slots]
    best = None
    for combo in itertools.product(*options):
        chosen = {
            slot: letter for slot, letter in zip(slots, combo) if letter is not None
        }
        candidate = "".join(
            c.lower() if _isalpha(c) else chosen.get(idx, "")
            for idx, c in enumerate(core)
        )
        hits = dictionary.get(candidate, 0)
        if hits < min_hits:
            continue
        # Most-attested wins; then the more letters restored, since that is the
        # more word-like baseword; then lexicographic, purely so the result
        # cannot depend on iteration order (Constraint 4).
        key = (-hits, -len(chosen), candidate)
        if best is None or key < best[0]:
            best = (key, candidate, chosen)
    if best is None:
        return (*derive(pw), False)
    _, base, chosen = best
    if not chosen:
        # The letters-only baseword won on attestation. Nothing was restored,
        # so this is derive()'s answer; take it rather than rebuilding it.
        return (*derive(pw), False)

    # Case ops index into the restored baseword, which interleaves the restored
    # letters with the real ones. A restored slot's case is a don't-care: the o
    # op below overwrites it with the leet character regardless.
    flags = [
        c.isupper() if _isalpha(c) else None
        for idx, c in enumerate(core)
        if _isalpha(c) or idx in chosen
    ]
    case_ops = _case_ops(flags)
    if case_ops is None:
        return (*derive(pw), False)
    ops = list(case_ops)

    # Both ops address the core-relative index directly. For an insert that is
    # the same accounting derive() does. For an overwrite it holds because the
    # restored letter sits at baseword index (letters + restorations to its
    # left) and the inserts already emitted have shifted it right by exactly
    # the number of un-restored slots to its left; the two sum to the core
    # index. Position 0 is always a letter, since a core begins with one.
    for idx, c in enumerate(core):
        if _isalpha(c):
            continue
        p = _pos(idx)
        if p is None:
            return (*derive(pw), False)
        ops.append(("o" if idx in chosen else "i") + p + _escape_arg(c))
    for c in suffix:
        ops.append("$" + _escape_arg(c))
    for c in reversed(prefix):
        ops.append("^" + _escape_arg(c))

    if len(ops) > MAX_RULE_FUNCTIONS:
        return (*derive(pw), False)

    return (base, "".join(ops) if ops else ":", True)


def apply_rule(word, rule):
    """Reference implementation of the op subset :func:`derive` emits.

    Mirrors hashcat's semantics for these ops so callers can verify a derived
    pair without shelling out. It deliberately does not model
    :data:`MAX_RULE_FUNCTIONS`; :func:`derive` enforces that instead.
    """
    s = word
    i = 0
    while i < len(rule):
        op = rule[i]
        if op == ":":
            i += 1
        elif op == "l":
            s = s.lower()
            i += 1
        elif op == "u":
            s = s.upper()
            i += 1
        elif op == "c":
            s = (s[:1].upper() + s[1:].lower()) if s else s
            i += 1
        elif op == "T":
            p = POS.index(rule[i + 1])
            if p < len(s):
                ch = s[p]
                s = s[:p] + (ch.lower() if ch.isupper() else ch.upper()) + s[p + 1 :]
            i += 2
        elif op == "$":
            ch, width = _read_arg(rule, i + 1)
            s = s + ch
            i += 1 + width
        elif op == "^":
            ch, width = _read_arg(rule, i + 1)
            s = ch + s
            i += 1 + width
        elif op == "i":
            p = POS.index(rule[i + 1])
            ch, width = _read_arg(rule, i + 2)
            p = min(p, len(s))
            s = s[:p] + ch + s[p:]
            i += 2 + width
        elif op == "o":
            p = POS.index(rule[i + 1])
            ch, width = _read_arg(rule, i + 2)
            if p < len(s):
                s = s[:p] + ch + s[p + 1 :]
            i += 2 + width
        else:
            raise ValueError(f"unknown op {op!r} in rule {rule!r}")
    return s


def _is_printable_ascii(pw):
    return all(0x20 <= ord(c) <= 0x7E for c in pw)


def _derives_to_itself(pw):
    """True when ``(pw, ":")`` is a real derivation rather than a literal fallback.

    Both outcomes look identical from outside :func:`derive` — the password as
    its own baseword under a no-op rule — so telling them apart is what decides
    whether a fallback gets counted. An all-lowercase-ASCII password is the only
    input that legitimately lands there: it has no case ops, no interior, no
    prefix and no suffix, so it can never hit either hashcat limit. Everything
    else that comes back as ``(pw, ":")`` got there by bailing out. Empty input
    is the degenerate member of the same set (``all()`` of nothing is True).

    Testing for lowercase specifically, not for a letter: an uppercase letter
    past position 35 disqualifies every case encoding, and that password is a
    genuine fallback even though it is nothing but letters. Screening on "holds
    a non-letter" instead, as this check first did, silently missed exactly that
    case.

    A CR or LF is ignored here rather than disqualifying: an all-lowercase
    password with an addressable break derives successfully via an ``i``
    insert op, and for such a password :func:`derive`'s real answer can come
    out byte-for-byte identical to :func:`_literal_pair`'s fallback answer
    (both lift the same break to the same insert). Without this widening that
    coincidence would be miscounted as a fallback even though it derived.
    """
    return all("a" <= c <= "z" for c in pw if c not in _ARG_ESCAPES)


class _Scan(NamedTuple):
    """One pass over a corpus: the counters it built and the stats it observed."""

    base_counts: Counter
    rule_counts: Counter
    total: int
    skipped: int
    no_letter_literals: int
    unrepresentable: int
    hash_shaped: int
    unwritable_basewords: int
    selfcheck_failures: list
    leet_restored: int
    pruned_basewords: int
    pruned_baseword_hits: int
    pruned_rules: int
    pruned_rule_hits: int


def _scan_corpus(
    corpus_path,
    ascii_only,
    verify,
    max_unique,
    dictionary=None,
    min_hits=2,
    count_rules=True,
):
    """Read *corpus_path* once, deriving a baseword and rule for each password.

    With *dictionary* set, derivation goes through :func:`_derive_leet_aware`
    against it; otherwise it is plain :func:`derive`. *count_rules* False skips
    the rule counter entirely, which is what pass 1 of a ``leet_restore`` run
    wants: it needs only the baseword counter, and building a rule counter it
    will throw away would hold a second counter's worth of memory for nothing.
    """
    base_counts = Counter()
    rule_counts = Counter()
    total = 0
    skipped = 0
    no_letter_literals = 0
    unrepresentable = 0
    hash_shaped = 0
    unwritable_basewords = 0
    leet_restored = 0
    selfcheck_failures = []
    lines_read = 0
    pruned_basewords = 0
    pruned_baseword_hits = 0
    pruned_rules = 0
    pruned_rule_hits = 0

    with open(corpus_path, encoding="latin-1") as fh:
        for line in fh:
            lines_read += 1
            if max_unique is not None and lines_read % _PRUNE_CHECK_INTERVAL == 0:
                # Each counter is checked independently: a corpus can blow the
                # baseword bound long before the rule bound, or the reverse.
                keys, hits = _prune_counter(base_counts, max_unique)
                pruned_basewords += keys
                pruned_baseword_hits += hits
                keys, hits = _prune_counter(rule_counts, max_unique)
                pruned_rules += keys
                pruned_rule_hits += hits
            stripped = line.rstrip("\r\n")
            if looks_like_hash_line(stripped.strip()):
                hash_shaped += 1
            # The corpus this attack is built for is a previous engagement's
            # cracked output, whose lines are "hash:password". Deriving from the
            # whole line prepends the digest's hex digits to the baseword and
            # spends 20-30 rule functions rebuilding them, which both poisons
            # the baseword list and pushes real transformations over
            # MAX_RULE_FUNCTIONS into the literal fallback.
            #
            # keep_whitespace: a leading or trailing space can be part of the
            # password, and this is the one caller that must rebuild it byte for
            # byte. Letting usable_plaintext() strip it derives the stripped
            # form instead, and does so silently — the self-check below compares
            # against the same stripped password, so it passes. The line's own
            # terminator is already gone (rstrip above), which is why opting in
            # here is safe.
            pw = usable_plaintext(stripped, keep_whitespace=True)
            if pw == "":
                continue
            if ascii_only and not _is_printable_ascii(pw):
                skipped += 1
                continue
            if dictionary is None:
                base, rule = derive(pw)
                restored = False
            else:
                base, rule, restored = _derive_leet_aware(pw, dictionary, min_hits)
            # A password can hold a literal CR or LF -- hashcat hands those over
            # hex-wrapped, as $HEX[...0a], and the line's own terminator was
            # rstripped above, so anything left here came out of the decode and
            # is part of the password. derive() spells such a byte \xNN in a rule
            # argument, which hashcat decodes and which a line-based rule file
            # can therefore hold. The baseword side has no equivalent: a
            # wordlist line is the word, with no escape syntax to spell a break
            # with, so a baseword still holding one cannot be written at all.
            # Only a derivation that could not even lift the break into an
            # insert op -- a break past addressable position 35, or one that
            # would push the rule over MAX_RULE_FUNCTIONS -- lands here; see
            # _literal_pair()/_literal_with_line_breaks().
            #
            # Written anyway it would split its own record across two lines and
            # hashcat would read two wrong words, silently -- the reconstruction
            # self-check below cannot see it, because apply_rule() rebuilds the
            # password faithfully from a pair the writer then corrupts. So skip
            # it, and count it, rather than shrink the output quietly.
            if any(c in _ARG_ESCAPES for c in base):
                unwritable_basewords += 1
                continue
            total += 1
            leet_restored += restored
            # A literal fallback: the pair came back as _literal_pair(pw) would
            # produce it, without that being a real derivation. Comparing the
            # full pair (rather than just base == pw and rule == ":") catches
            # the CR/LF fallback pairs too, since those no longer leave base
            # equal to pw. _derives_to_itself excludes the genuine derivations
            # that can coincide with that same pair byte-for-byte. Whether the
            # password holds any letter is what separates the two kinds of
            # fallback — see the module docstring.
            if (base, rule) == _literal_pair(pw) and not _derives_to_itself(pw):
                if any(_isalpha(c) for c in pw):
                    unrepresentable += 1
                else:
                    no_letter_literals += 1
            # The self-check runs against the password in hand, before either
            # counter is touched, so pruning can never make it fail spuriously.
            if verify and apply_rule(base, rule) != pw:
                selfcheck_failures.append(pw)
            base_counts[base] += 1
            if count_rules:
                rule_counts[rule] += 1

    return _Scan(
        base_counts=base_counts,
        rule_counts=rule_counts,
        total=total,
        skipped=skipped,
        no_letter_literals=no_letter_literals,
        unrepresentable=unrepresentable,
        hash_shaped=hash_shaped,
        unwritable_basewords=unwritable_basewords,
        selfcheck_failures=selfcheck_failures,
        leet_restored=leet_restored,
        pruned_basewords=pruned_basewords,
        pruned_baseword_hits=pruned_baseword_hits,
        pruned_rules=pruned_rules,
        pruned_rule_hits=pruned_rule_hits,
    )


def generate(
    corpus_path,
    outdir,
    cover=(50, 75, 95, 99),
    ascii_only=False,
    verify=True,
    print_fn=print,
    max_unique=MAX_UNIQUE_KEYS,
    leet_restore=True,
    leet_min_hits=2,
    baseword_caps=(),
):
    """Derive basewords and rules from *corpus_path*, writing them under *outdir*.

    Returns a dict with the output paths and corpus statistics. ``verify``
    reconstructs every password through :func:`apply_rule` as a self-check;
    it is cheap relative to reading the corpus but can be skipped.

    Literal fallbacks are reported split in two — ``no_letter_literals``
    (expected, and not a defect) and ``unrepresentable`` (a genuine loss) —
    because they mean opposite things; see the module docstring.
    ``literal_fallbacks`` remains as their sum for compatibility.

    ``baseword_caps`` mirrors ``cover`` on the baseword side: for each N it
    writes ``basewords.top{N}.txt`` holding the N most-frequent basewords, and
    the paths come back keyed by N in ``capped_basewords``. The uncapped
    ``basewords.txt`` is always written regardless. Unlike ``cover``, N is a
    count of basewords rather than a coverage percentage — a baseword list is
    overwhelmingly singletons (94% of one 360,000-password sample), so a
    percentage-of-observations cut would keep almost the whole list.

    ``leet_restore`` reads the corpus **twice** so leet-substituted letters can
    be kept in the baseword instead of deleted from it — see the module
    docstring for the mechanism and for why one pass cannot do it. Pass 1's
    baseword counter becomes the attestation dictionary; a restoration needs
    ``leet_min_hits`` attestations to be accepted. Every counter written and
    every statistic returned comes from pass 2. ``leet_restore=False`` reads the
    corpus once and derives exactly as :func:`derive` does.

    ``max_unique`` bounds how many distinct keys the baseword and rule counters
    may each hold; once either exceeds it, its lowest-frequency keys are
    discarded (see :func:`_prune_counter`). ``None`` disables the bound and
    restores the exact but unbounded behaviour. When pruning fires the results
    describe only the retained keys: the reported coverage percentages are
    relative to the observations those keys account for, not to the whole
    corpus, and ``pruned`` is True in the returned dict. The bound applies to
    both passes, so a pruned attestation dictionary attests less and restores
    less — it never restores wrongly, because pruning deletes keys outright and
    so can only understate a count, never overstate one. The dictionary is also
    filtered to keys meeting ``leet_min_hits`` before pass 2, which is
    output-neutral for the same reason read in reverse.
    """
    if is_gzipped(corpus_path):
        raise ValueError(
            f"{corpus_path} is gzip-compressed; decompress it before calling generate()"
        )

    os.makedirs(outdir, exist_ok=True)

    if leet_restore:
        # Pass 1 exists only for its baseword counter, so it skips both the
        # rule counter and the self-check; every statistic below comes from
        # pass 2. `dictionary` is dropped before the output is written so the
        # three-counter peak does not outlive the read.
        dictionary = _scan_corpus(
            corpus_path,
            ascii_only,
            verify=False,
            max_unique=max_unique,
            count_rules=False,
        ).base_counts
        # Drop every key that cannot satisfy _derive_leet_aware's
        # `hits >= min_hits` gate. Provably output-neutral: a count is read only
        # by that gate and by the -hits sort key, and a key below the threshold
        # fails the gate before the sort ever sees it. It is pure ballast
        # otherwise, and there is a lot of it — 93.4% of the keys on a
        # 360,000-password sample, since a corpus's baseword tail is
        # overwhelmingly singletons. Dropping them takes the peak back to
        # roughly the two-counter budget the max_unique bound is sized for,
        # instead of holding a third full-sized counter live across all of
        # pass 2. Rebinding the name is what actually reclaims it: the
        # unfiltered Counter has to become unreachable *before* pass 2 starts
        # allocating, or the filter has bought nothing.
        dictionary = {k: v for k, v in dictionary.items() if v >= leet_min_hits}
        scan = _scan_corpus(
            corpus_path,
            ascii_only,
            verify,
            max_unique,
            dictionary=dictionary,
            min_hits=leet_min_hits,
        )
        del dictionary
    else:
        scan = _scan_corpus(corpus_path, ascii_only, verify, max_unique)

    base_counts = scan.base_counts
    rule_counts = scan.rule_counts
    total = scan.total
    skipped = scan.skipped
    no_letter_literals = scan.no_letter_literals
    unrepresentable = scan.unrepresentable
    # Kept for callers written before the two were split apart; computed as the
    # sum here rather than counted separately so the identity cannot drift.
    literal_fallbacks = no_letter_literals + unrepresentable
    hash_shaped = scan.hash_shaped
    unwritable_basewords = scan.unwritable_basewords
    selfcheck_failures = scan.selfcheck_failures
    leet_restored = scan.leet_restored
    pruned_basewords = scan.pruned_basewords
    pruned_baseword_hits = scan.pruned_baseword_hits
    pruned_rules = scan.pruned_rules
    pruned_rule_hits = scan.pruned_rule_hits

    if total == 0:
        raise ValueError(f"no passwords read from {corpus_path}")

    def _path(name):
        return os.path.join(outdir, name)

    # One ranking, used for the full list and every cap, so a capped file is
    # always a prefix of basewords.txt rather than a separately-ordered list.
    ranked_bases = base_counts.most_common()
    basewords_path = _path("basewords.txt")
    with open(basewords_path, "w", encoding="latin-1") as f:
        for base, _ in ranked_bases:
            f.write(base + "\n")

    # The baseword side is the limiting one: measured against unseen
    # passwords, most misses are a missing baseword rather than a missing
    # rule. A cap therefore trades reach for keyspace and is not an accuracy
    # win -- it exists so a run can be made to fit the time available.
    capped_basewords = {}
    for target in baseword_caps:
        capped_base = _path(f"basewords.top{target}.txt")
        with open(capped_base, "w", encoding="latin-1") as f:
            for base, _ in ranked_bases[:target]:
                f.write(base + "\n")
        capped_basewords[target] = capped_base

    ranked = rule_counts.most_common()
    rules_path = _path("rules.full.rule")
    with open(rules_path, "w", encoding="latin-1") as f:
        for rule, _ in ranked:
            f.write(rule + "\n")

    pruned = bool(pruned_basewords or pruned_rules)
    # The rule ranking is a ranking of rules, so its denominator is the
    # observations the retained *rules* account for. Without pruning that is
    # every password, so the numbers are unchanged; with it, using `total`
    # would silently understate every percentage.
    retained_hits = total - pruned_rule_hits
    # Reconstruction needs BOTH a surviving baseword and a surviving rule, and
    # the two counters are pruned independently, so the rule denominator alone
    # overstates how much of the corpus can still be rebuilt. Which passwords
    # lost which half is not tracked — that would mean a third structure of the
    # size this task exists to bound — so report the bracket instead of a
    # number the code cannot actually know. The upper bound assumes the two
    # sets of losses overlap completely, the lower bound that they are
    # disjoint.
    reconstructable_max = total - max(pruned_baseword_hits, pruned_rule_hits)
    reconstructable_min = max(total - pruned_baseword_hits - pruned_rule_hits, 0)

    capped_paths = {}
    for target in cover:
        needed = float(target) / 100.0 * retained_hits
        cumulative = 0
        count = 0
        for _, hits in ranked:
            cumulative += hits
            count += 1
            if cumulative >= needed:
                break
        capped = _path(f"rules.top{target}.rule")
        with open(capped, "w", encoding="latin-1") as f:
            for rule, _ in ranked[:count]:
                f.write(rule + "\n")
        capped_paths[target] = capped

    # Rules needed to reach each coverage milestone.
    milestones = {}
    cumulative = 0
    for i, (_, hits) in enumerate(ranked, start=1):
        cumulative += hits
        pct = 100.0 * cumulative / retained_hits
        for mark in (50, 75, 80, 90, 95, 99, 100):
            if mark not in milestones and pct >= mark:
                milestones[mark] = i

    coverage_path = _path("coverage.txt")
    with open(coverage_path, "w", encoding="latin-1") as f:
        f.write(f"corpus:              {corpus_path}\n")
        f.write(f"passwords:           {total}\n")
        f.write(f"skipped (non-ascii): {skipped}\n")
        f.write(f"unique basewords:    {len(base_counts)}\n")
        f.write(f"unique rules:        {len(rule_counts)}\n")
        f.write(f"literal fallbacks:   {literal_fallbacks}\n")
        f.write(f"no_letter_literals:  {no_letter_literals}\n")
        f.write(
            "  (no ASCII letter anywhere, so the password is its own baseword --\n"
            "   with a ':' rule, unless it holds a CR or LF, in which case the\n"
            "   break is lifted into an escaped insert op instead (#295) and\n"
            "   kept out of the baseword. Either way this is NOT a defect: a\n"
            "   digit- or symbol-only password has no letters-only core to\n"
            "   derive, and it is a perfectly good dictionary entry as it\n"
            "   stands. These two sum to the literal fallbacks above.)\n"
        )
        f.write(f"unrepresentable:     {unrepresentable}\n")
        f.write(
            "  (has letters, but could not be encoded: a T/i/o position past\n"
            f"   index 35, or more than {MAX_RULE_FUNCTIONS} rule functions. This one IS\n"
            "   a loss of expressiveness. Measured at zero on a 360,000-password\n"
            "   sample, so anything above zero here is unusual.)\n"
        )
        f.write(f"hash-shaped lines:   {hash_shaped}\n")
        f.write(f"unwritable basewords:{unwritable_basewords}\n")
        f.write(
            "  (the baseword held a literal CR or LF, which arrives via a\n"
            "   $HEX[...] plaintext. A rule argument can spell such a byte \\xNN\n"
            "   and hashcat decodes it, so a break is normally lifted into an\n"
            "   insert op and kept out of the baseword entirely (#295). This\n"
            "   remains only for the break itself hitting one of the two\n"
            "   hashcat limits: a position past index 35, or more than\n"
            f"   {MAX_RULE_FUNCTIONS} rule functions needed to insert every break. A\n"
            "   wordlist line has no escape syntax, so such a baseword is\n"
            "   skipped rather than written truncated. Normally zero.)\n"
        )
        if leet_restore:
            f.write(f"leet restored:       {leet_restored}\n")
            f.write(
                "  (the corpus was read TWICE: pass 1 built the attestation\n"
                "   dictionary of letters-only basewords, pass 2 re-derived every\n"
                "   password against it, keeping a leet-substituted letter in the\n"
                f"   baseword when at least {leet_min_hits} other passwords attested\n"
                "   the restored form. All figures here come from pass 2.)\n"
            )
        if verify:
            f.write(f"self-check failures: {len(selfcheck_failures)} (must be 0)\n")
        if pruned:
            f.write(f"\npruned (max_unique={max_unique}):\n")
            f.write(
                f"  basewords discarded: {pruned_basewords} "
                f"({pruned_baseword_hits} passwords)\n"
            )
            f.write(
                f"  rules discarded:     {pruned_rules} "
                f"({pruned_rule_hits} passwords)\n"
            )
            f.write(
                "  These were the lowest-frequency keys, dropped while reading to\n"
                "  keep memory bounded. The output no longer reconstructs 100% of\n"
                "  the corpus.\n"
            )
            # A password needs both halves to survive, and which passwords lost
            # which half is not tracked, so this is a range rather than a count.
            if reconstructable_min == reconstructable_max:
                f.write(
                    f"  still reconstructable: {reconstructable_max} of {total} "
                    "passwords\n"
                )
            else:
                f.write(
                    f"  still reconstructable: between {reconstructable_min} and "
                    f"{reconstructable_max} of {total} passwords\n"
                    "  (a password needs both its baseword and its rule to survive;\n"
                    "   the two counters are pruned independently)\n"
                )
        f.write("\nrules needed for coverage:\n")
        if pruned_rule_hits:
            # Only meaningful when the rule counter itself lost observations —
            # otherwise the denominator is still the whole corpus and saying
            # "not of all N read" against the same N is self-contradictory.
            f.write(
                f"  (percentages are of the {retained_hits} passwords the retained\n"
                f"   rules cover, not of all {total} read)\n"
            )
        elif pruned:
            f.write(
                "  (percentages are of rule coverage only; basewords were pruned,\n"
                "   so fewer passwords are reconstructable than these imply)\n"
            )
        for mark in sorted(milestones):
            f.write(f"  {mark:3d}%: {milestones[mark]} rules\n")

    print_fn(
        f"[*] {total} passwords -> {len(base_counts)} basewords, "
        f"{len(rule_counts)} rules ({literal_fallbacks} literal fallbacks: "
        f"{no_letter_literals} with no letters at all, "
        f"{unrepresentable} unrepresentable)"
    )
    if leet_restore:
        print_fn(
            f"[*] {leet_restored} basewords kept a leet-substituted letter "
            "(corpus read twice: attestation pass, then derivation pass)"
        )
    if pruned:
        print_fn(
            f"[!] Memory bound reached: {pruned_basewords} basewords and "
            f"{pruned_rules} rules were discarded to keep each counter under "
            f"max_unique={max_unique} distinct keys. They were the "
            "lowest-frequency keys, covering "
            f"{pruned_baseword_hits} of {total} passwords on the baseword side "
            f"and {pruned_rule_hits} on the rule side. A password needs both "
            "halves, so between "
            f"{reconstructable_min} and {reconstructable_max} of {total} "
            "passwords are still reconstructable — this run does NOT cover "
            "100% of the corpus, and the coverage percentages are rule "
            "coverage over the retained keys. If you need exact figures, run "
            "against a random sample of the corpus small enough to fit, or "
            "raise max_unique if you have the RAM."
        )
    if hash_shaped > total * 0.25:
        print_fn(
            f"[!] Warning: {hash_shaped} lines look like hashes rather than "
            "plaintexts. This corpus may be an uncracked dump instead of cracked "
            "output, in which case the basewords and rules below are meaningless."
        )
    if unwritable_basewords:
        print_fn(
            f"[!] {unwritable_basewords} passwords could not be written: the "
            "baseword itself held a literal CR or LF (a $HEX[...] plaintext) "
            "that could not be lifted into an insert op -- the break sat past "
            "addressable position 35, or needed more inserts than the "
            f"{MAX_RULE_FUNCTIONS}-function rule cap allows -- and a wordlist "
            "line has no escape syntax to spell one with. Coverage excludes "
            "them."
        )
    if selfcheck_failures:
        print_fn(
            f"[!] {len(selfcheck_failures)} passwords failed the reconstruction "
            "self-check; coverage is below 100%."
        )

    return {
        "basewords": basewords_path,
        "capped_basewords": capped_basewords,
        "rules": rules_path,
        "capped_rules": capped_paths,
        "coverage": coverage_path,
        "total": total,
        "skipped": skipped,
        "basewords_count": len(base_counts),
        "rules_count": len(rule_counts),
        # literal_fallbacks == no_letter_literals + unrepresentable, always.
        "literal_fallbacks": literal_fallbacks,
        "no_letter_literals": no_letter_literals,
        "unrepresentable": unrepresentable,
        "hash_shaped": hash_shaped,
        "unwritable_basewords": unwritable_basewords,
        "leet_restored": leet_restored,
        "selfcheck_failures": selfcheck_failures,
        "milestones": milestones,
        "pruned": pruned,
        "pruned_basewords": pruned_basewords,
        "pruned_rules": pruned_rules,
        "pruned_baseword_hits": pruned_baseword_hits,
        "pruned_rule_hits": pruned_rule_hits,
        "reconstructable_min": reconstructable_min,
        "reconstructable_max": reconstructable_max,
    }
