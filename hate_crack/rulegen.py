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

The baseword list and the rule list together reconstruct 100% of the corpus,
so the rule file is truncatable: it is sorted by how many passwords each rule
rebuilds, most productive first.

Two hashcat limits bound what a rule can express, and both fall back to
emitting the password verbatim as its own baseword with a ``:`` no-op rule:

* Positions are encoded in a 36-character alphabet, so ``T``/``i`` cannot
  address past index 35.
* hashcat rejects any rule with more than ``MAX_RULE_FUNCTIONS`` functions.
  It does so *silently* when other valid rules are present in the same file,
  which is why the op count is enforced here rather than discovered later as
  missing coverage.
"""

import os
from collections import Counter

from hate_crack.plaintext import looks_like_hash_line, usable_plaintext

POS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# hashcat's rule engine accepts at most this many functions in a single rule.
# Verified against hashcat v7: 31 functions run, 32 yields "No valid rules
# left" when the rule stands alone and is dropped without warning when it
# shares a file with valid rules.
MAX_RULE_FUNCTIONS = 31


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
        elif op == "i":
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
    if not any(up):
        pass
    elif up[0] and not any(up[1:]):
        ops.append("c")
    elif all(up):
        ops.append("u")
    else:
        for i, is_upper in enumerate(up):
            if is_upper:
                p = _pos(i)
                if p is None:
                    return (pw, ":")
                ops.append("T" + p)
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
):
    """Derive basewords and rules from *corpus_path*, writing them under *outdir*.

    Returns a dict with the output paths and corpus statistics. ``verify``
    reconstructs every password through :func:`apply_rule` as a self-check;
    it is cheap relative to reading the corpus but can be skipped.
    """
    os.makedirs(outdir, exist_ok=True)
    base_counts = Counter()
    rule_counts = Counter()
    total = 0
    skipped = 0
    literal_fallbacks = 0
    hash_shaped = 0
    selfcheck_failures = []

    with open(corpus_path, encoding="latin-1") as fh:
        for line in fh:
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

    capped_paths = {}
    for target in cover:
        needed = float(target) / 100.0 * total
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
        pct = 100.0 * cumulative / total
        for mark in (50, 80, 90, 95, 99, 100):
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
        f.write("\nrules needed for coverage:\n")
        for mark in sorted(milestones):
            f.write(f"  {mark:3d}%: {milestones[mark]} rules\n")

    print_fn(
        f"[*] {total} passwords -> {len(base_counts)} basewords, "
        f"{len(rule_counts)} rules ({literal_fallbacks} literal fallbacks)"
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
    }
