"""PEP 517 backend that can build an sdist but refuses to build a wheel.

The point of the placeholder is that `pip install hate-crack` must fail loudly
rather than succeed and leave an operator believing they have the tool. pip
reaches a wheel build (or the metadata hook that precedes it) for every install,
so raising there is what makes the install impossible. Sdist building still has
to work, because the sdist is the artifact uploaded to PyPI.
"""

MESSAGE = (
    "hate_crack is not installable from PyPI. The name on the index is a "
    "placeholder held to keep it from being squatted; there is no package "
    "behind it.\n\n"
    "Install from source instead:\n\n"
    "    git clone https://github.com/trustedsec/hate_crack\n"
    "    cd hate_crack\n"
    "    make install\n\n"
    "See https://github.com/trustedsec/hate_crack#installation"
)


def _setuptools():
    # Imported lazily so the refusal hooks below work even where setuptools is
    # absent, and so this module stays importable for testing.
    from setuptools import build_meta

    return build_meta


def build_sdist(*args, **kwargs):
    return _setuptools().build_sdist(*args, **kwargs)


def get_requires_for_build_sdist(*args, **kwargs):
    return _setuptools().get_requires_for_build_sdist(*args, **kwargs)


def get_requires_for_build_wheel(*args, **kwargs):
    return _setuptools().get_requires_for_build_wheel(*args, **kwargs)


def build_wheel(*_args, **_kwargs):
    raise RuntimeError(MESSAGE)


def prepare_metadata_for_build_wheel(*_args, **_kwargs):
    # pip calls this first to resolve dependencies. Failing here keeps it from
    # ever reaching build_wheel, and surfaces the same message.
    raise RuntimeError(MESSAGE)


def build_editable(*_args, **_kwargs):
    raise RuntimeError(MESSAGE)


def prepare_metadata_for_build_editable(*_args, **_kwargs):
    raise RuntimeError(MESSAGE)
