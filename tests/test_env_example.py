"""Drift guard for the tracked `.env.example`.

The template is generated from ``CONFIG_SCHEMA``'s ``home="env"`` rows by
``hate_crack/config_writer.py``, never hand-edited, so the only thing worth
asserting is that the committed bytes still match what the generator produces
-- plus the one rule the generator cannot enforce for us, namely that the four
credential keys ship empty in a file that lives in a public repo.
"""

import os

from hate_crack.config_schema import ENV_KEYS, SECRET_ENV_KEYS
from hate_crack.config_writer import (
    REGENERATE_COMMAND,
    env_example_path,
    render_env_example,
)

EXAMPLE_PATH = env_example_path()


def _committed_text() -> str:
    with open(EXAMPLE_PATH) as fh:
        return fh.read()


def test_env_example_is_tracked_and_present():
    assert os.path.isfile(EXAMPLE_PATH), (
        f"{EXAMPLE_PATH} is missing; regenerate with `{REGENERATE_COMMAND}`"
    )


def test_env_example_matches_the_generator():
    assert _committed_text() == render_env_example(), (
        "the committed .env.example no longer matches config_writer's output; "
        f"regenerate with `{REGENERATE_COMMAND}`"
    )


def test_env_example_covers_every_env_homed_key():
    text = _committed_text()
    for entry in ENV_KEYS:
        assert f"\n{entry.env}=" in text, (
            f"{entry.env} is missing from .env.example; "
            f"regenerate with `{REGENERATE_COMMAND}`"
        )


def test_env_example_holds_no_json_homed_keys():
    """A json-homed key here would be ignored-with-a-warning on first run."""
    from hate_crack.config_schema import JSON_KEYS

    text = _committed_text()
    for entry in JSON_KEYS:
        assert f"\n{entry.env}=" not in text, (
            f"{entry.env} belongs in config.json.example, not .env.example"
        )


def test_secret_keys_ship_empty():
    """Never a placeholder that looks like a real credential: this file is
    committed to a public repository."""
    text = _committed_text()
    for key in SECRET_ENV_KEYS:
        assert f"\n{key}=\n" in text, (
            f"{key} must ship with an empty value in .env.example"
        )


def test_header_names_the_regeneration_command():
    assert REGENERATE_COMMAND in _committed_text()
