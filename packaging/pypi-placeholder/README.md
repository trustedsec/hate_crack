# hate_crack (PyPI name placeholder — not the tool)

**This is not an installable copy of hate_crack.** `pip install hate-crack` will
fail on purpose. The name is held here only so nobody else can publish under it,
because a package claiming to be an offensive security tool would be installed
with an expectation of trust, often on a host holding client hash material and
API credentials.

hate_crack is installed from source:

```bash
git clone https://github.com/trustedsec/hate_crack
cd hate_crack
make install
```

Full instructions: <https://github.com/trustedsec/hate_crack#installation>

## Why there is no real distribution

hate_crack is not self-contained in the way a wheel requires:

- It builds compiled helpers (hashcat-utils, princeprocessor, OMEN) from git
  submodules, which would need a per-platform build matrix or a C toolchain on
  every target.
- `HashcatRosetta` is reached through a `sys.path` insertion relative to the
  repository, not as a declared dependency.
- Self-update is git-native (`git checkout` plus `make install`), so a
  site-packages copy could not update itself.
- hashcat, wordlists, and rules still have to be installed separately, so a
  single-command install would not actually be single-command.
