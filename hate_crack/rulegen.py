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

The baseword list and the rule list together reconstruct 100% of the corpus,
so the rule file is truncatable: it is sorted by how many passwords each rule
rebuilds, most productive first.

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

Two hashcat limits bound what a rule can express, and both fall back to
emitting the password verbatim as its own baseword with a ``:`` no-op rule:

* Positions are encoded in a 36-character alphabet, so ``T``/``i``/``o`` cannot
  address past index 35.
* hashcat rejects any rule with more than ``MAX_RULE_FUNCTIONS`` functions.
  It does so *silently* when other valid rules are present in the same file,
  which is why the op count is enforced here rather than discovered later as
  missing coverage.
"""

import os
from collections import Counter

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
        elif op in "T$^":
            i += 2
        elif op in "io":
            i += 3
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
        # The op and all of its arguments must fit inside the line.
        if i + 1 + len(kinds) > len(rule):
            return False
        for offset, kind in enumerate(kinds, start=1):
            if kind == "p" and rule[i + offset] not in POS:
                return False
        i += 1 + len(kinds)
        count += 1
        if count > MAX_RULE_FUNCTIONS:
            return False
    return count > 0


def derive(pw):
    """Return ``(baseword, rule)`` such that applying *rule* to *baseword* yields *pw*.

    Falls back to ``(pw, ":")`` — the password as its own literal baseword —
    whenever the transformation cannot be expressed within hashcat's limits.
    """
    if pw == "":
        return ("", ":")
    letters = [c for c in pw if _isalpha(c)]
    if not letters:
        return (pw, ":")
    base = "".join(c.lower() for c in letters)
    idxs = [i for i, c in enumerate(pw) if _isalpha(c)]
    first, last = idxs[0], idxs[-1]
    prefix, core, suffix = pw[:first], pw[first : last + 1], pw[last + 1 :]

    ops = []
    # Case ops apply to the pure-lowercase base, so positions are 0..len(base)-1.
    up = [c.isupper() for c in letters]

    # Compute the cheapest case encoding from four candidate strategies.
    # Each strategy is valid only if all required positions are addressable (< 36).
    # Pick the minimum cost; break ties in order: none, c, u, direct.
    candidates = []

    # Strategy: none (no case ops) - valid only when no uppercase
    if not any(up):
        candidates.append((0, [], "none"))

    # Strategy: c + fix - uppercase index 0, then toggle uppercase letters at >0
    # and toggle index 0 if it should be lowercase.
    c_ops = ["c"]
    c_valid = True
    for i, is_upper in enumerate(up):
        if i > 0 and is_upper:
            p = _pos(i)
            if p is None:
                c_valid = False
                break
            c_ops.append("T" + p)
    if c_valid and not up[0]:
        c_ops.append("T0")
    if c_valid:
        candidates.append((len(c_ops), c_ops, "c"))

    # Strategy: u + invert - uppercase all, then toggle lowercase letters
    u_ops = ["u"]
    u_valid = True
    for i, is_upper in enumerate(up):
        if not is_upper:
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
    for i, is_upper in enumerate(up):
        if is_upper:
            p = _pos(i)
            if p is None:
                direct_valid = False
                break
            direct_ops.append("T" + p)
    if direct_valid:
        candidates.append((len(direct_ops), direct_ops, "direct"))

    if candidates:
        # Sort by cost, then by tie-break order: none, c, u, direct
        order_map = {"none": 0, "c": 1, "u": 2, "direct": 3}
        best_ops = min(candidates, key=lambda x: (x[0], order_map[x[2]]))[1]
        ops.extend(best_ops)
    else:
        # All strategies disqualified; fall back to literal
        return (pw, ":")
    # Interior non-letters, inserted at core-relative indices in increasing
    # order so each insert accounts for the shift from the ones before it.
    for idx, c in enumerate(core):
        if not _isalpha(c):
            p = _pos(idx)
            if p is None:
                return (pw, ":")
            ops.append("i" + p + c)
    # Trailing non-letters append; position-independent, so these merge well
    # across passwords.
    for c in suffix:
        ops.append("$" + c)
    # Leading non-letters prepend, reversed so the final order comes out right.
    for c in reversed(prefix):
        ops.append("^" + c)

    if len(ops) > MAX_RULE_FUNCTIONS:
        return (pw, ":")

    return (base, "".join(ops) if ops else ":")


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
            s = s + rule[i + 1]
            i += 2
        elif op == "^":
            s = rule[i + 1] + s
            i += 2
        elif op == "i":
            p = POS.index(rule[i + 1])
            ch = rule[i + 2]
            p = min(p, len(s))
            s = s[:p] + ch + s[p:]
            i += 3
        elif op == "o":
            p = POS.index(rule[i + 1])
            ch = rule[i + 2]
            if p < len(s):
                s = s[:p] + ch + s[p + 1 :]
            i += 3
        else:
            raise ValueError(f"unknown op {op!r} in rule {rule!r}")
    return s


def _is_printable_ascii(pw):
    return all(0x20 <= ord(c) <= 0x7E for c in pw)


def generate(
    corpus_path,
    outdir,
    cover=(50, 75, 95, 99),
    ascii_only=False,
    verify=True,
    print_fn=print,
    max_unique=MAX_UNIQUE_KEYS,
):
    """Derive basewords and rules from *corpus_path*, writing them under *outdir*.

    Returns a dict with the output paths and corpus statistics. ``verify``
    reconstructs every password through :func:`apply_rule` as a self-check;
    it is cheap relative to reading the corpus but can be skipped.

    ``max_unique`` bounds how many distinct keys the baseword and rule counters
    may each hold; once either exceeds it, its lowest-frequency keys are
    discarded (see :func:`_prune_counter`). ``None`` disables the bound and
    restores the exact but unbounded behaviour. When pruning fires the results
    describe only the retained keys: the reported coverage percentages are
    relative to the observations those keys account for, not to the whole
    corpus, and ``pruned`` is True in the returned dict.
    """
    if is_gzipped(corpus_path):
        raise ValueError(
            f"{corpus_path} is gzip-compressed; decompress it before calling generate()"
        )

    os.makedirs(outdir, exist_ok=True)
    base_counts = Counter()
    rule_counts = Counter()
    total = 0
    skipped = 0
    literal_fallbacks = 0
    hash_shaped = 0
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
            pw = usable_plaintext(stripped)
            if pw == "":
                continue
            if ascii_only and not _is_printable_ascii(pw):
                skipped += 1
                continue
            total += 1
            base, rule = derive(pw)
            if base == pw and rule == ":" and any(not _isalpha(c) for c in pw):
                literal_fallbacks += 1
            # The self-check runs against the password in hand, before either
            # counter is touched, so pruning can never make it fail spuriously.
            if verify and apply_rule(base, rule) != pw:
                selfcheck_failures.append(pw)
            base_counts[base] += 1
            rule_counts[rule] += 1

    if total == 0:
        raise ValueError(f"no passwords read from {corpus_path}")

    def _path(name):
        return os.path.join(outdir, name)

    basewords_path = _path("basewords.txt")
    with open(basewords_path, "w", encoding="latin-1") as f:
        for base, _ in base_counts.most_common():
            f.write(base + "\n")

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
        f.write(f"hash-shaped lines:   {hash_shaped}\n")
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
        f"{len(rule_counts)} rules ({literal_fallbacks} literal fallbacks)"
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
    if selfcheck_failures:
        print_fn(
            f"[!] {len(selfcheck_failures)} passwords failed the reconstruction "
            "self-check; coverage is below 100%."
        )

    return {
        "basewords": basewords_path,
        "rules": rules_path,
        "capped_rules": capped_paths,
        "coverage": coverage_path,
        "total": total,
        "skipped": skipped,
        "basewords_count": len(base_counts),
        "rules_count": len(rule_counts),
        "literal_fallbacks": literal_fallbacks,
        "hash_shaped": hash_shaped,
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
