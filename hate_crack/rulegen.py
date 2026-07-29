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
    cover=(95, 99),
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
    selfcheck_failures = []

    with open(corpus_path, encoding="latin-1") as fh:
        for line in fh:
            pw = line.rstrip("\r\n")
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
        if verify:
            f.write(f"self-check failures: {len(selfcheck_failures)} (must be 0)\n")
        f.write("\nrules needed for coverage:\n")
        for mark in sorted(milestones):
            f.write(f"  {mark:3d}%: {milestones[mark]} rules\n")

    print_fn(
        f"[*] {total} passwords -> {len(base_counts)} basewords, "
        f"{len(rule_counts)} rules ({literal_fallbacks} literal fallbacks)"
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
        "selfcheck_failures": selfcheck_failures,
        "milestones": milestones,
    }
