# Publishing the PyPI name placeholder

This directory is not part of the hate_crack distribution. It exists to hold the
`hate-crack` / `hate_crack` name on PyPI (both spellings normalize to the same
project) with an artifact that cannot be mistaken for a working install.

hate_crack itself is not publishable as a wheel: it builds compiled helpers from
git submodules, reaches `HashcatRosetta` through a `sys.path` insertion relative
to the repository, and self-updates with `git checkout` plus `make install`. See
issue #218 for the full reasoning. **Do not turn this into a real release
pipeline.**

## How it fails loudly

`placeholder_backend.py` is an in-tree PEP 517 backend that delegates sdist
building to setuptools but raises from `build_wheel`,
`prepare_metadata_for_build_wheel`, and the editable equivalents. pip and uv both
reach one of those hooks on every install, so the install aborts with the source
install instructions instead of succeeding. Only an sdist is uploaded; there is
no wheel to fall back to.

There is also no `requires-python`, deliberately — pinning it would make pip
report "no matching distribution" on older interpreters, which reads like a
version problem rather than "this package does not exist".

## One-time PyPI setup

Trusted Publishing has to be configured before the first upload, because there is
no project on the index yet to attach a publisher to:

1. On PyPI, go to *Your account → Publishing → Add a new pending publisher*.
2. Fill in: project `hate_crack`, owner `trustedsec`, repository `hate_crack`,
   workflow `pypi-placeholder.yml`, environment `pypi`.
3. In this repository's settings, create an environment named `pypi` and restrict
   it to the users allowed to publish.

No PyPI API token is created or stored in repository secrets.

## Publishing

`.github/workflows/pypi-placeholder.yml` is `workflow_dispatch`-only and is not
referenced by `auto-tag.yml`, `nightly-tag.yml`, or `release.yml`
(`tests/test_pypi_placeholder.py` asserts this). Because the workflow must exist
on the default branch to appear in the Actions UI, dispatch it from `main` after
the batch integration merge.

```
Actions → Publish PyPI name placeholder → Run workflow
```

It builds the sdist, runs `verify_placeholder.py` against the artifact (exactly
one sdist, version `0.0.0`, `Inactive` classifier, no entry points, nothing
importable), then uploads via OIDC.

To check the build locally without publishing:

```bash
uv build --sdist --out-dir dist .
uv run --no-project python verify_placeholder.py dist
```

`pip install dist/hate_crack-0.0.0.tar.gz` should fail with the placeholder
message; that is the behaviour being shipped.
