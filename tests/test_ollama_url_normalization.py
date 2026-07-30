"""Tests for OLLAMA_HOST -> ollamaUrl normalization (issue #119).

``ollamaUrl`` used to be built as ``"http://" + OLLAMA_HOST``, which mangled any
value that already carried a scheme -- the form Ollama's own tooling accepts.
"""

import importlib
import os
from unittest import mock

import pytest

from hate_crack import config_loader
from hate_crack import main as hc_main


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        # Bare host:port -- the historical default, must keep working.
        ("localhost:11434", "http://localhost:11434"),
        ("box:11434", "http://box:11434"),
        ("127.0.0.1:11434", "http://127.0.0.1:11434"),
        # Scheme already present -- previously produced http://http://...
        ("http://box:11434", "http://box:11434"),
        ("https://ollama.example.com", "https://ollama.example.com"),
        ("https://ollama.example.com:443", "https://ollama.example.com:443"),
        # Trailing slashes stripped: callers append f"{ollamaUrl}/v1".
        ("http://box:11434/", "http://box:11434"),
        ("https://ollama.example.com///", "https://ollama.example.com"),
        ("box:11434/", "http://box:11434"),
        # Whitespace and empty values fall back to the default.
        ("  box:11434  ", "http://box:11434"),
        ("", "http://localhost:11434"),
        ("   ", "http://localhost:11434"),
    ],
)
def test_normalize_ollama_url(host, expected):
    assert hc_main._normalize_ollama_url(host) == expected


def test_scheme_is_never_doubled():
    """The exact regression from issue #119."""
    for host in ("http://box:11434", "https://ollama.example.com"):
        assert "http://http" not in hc_main._normalize_ollama_url(host)
        assert "http://https" not in hc_main._normalize_ollama_url(host)


def test_result_builds_a_valid_v1_endpoint():
    """llm.py derives its client base URL as f"{ollamaUrl}/v1"."""
    for host in ("box:11434", "http://box:11434/", "https://x.example.com//"):
        url = hc_main._normalize_ollama_url(host)
        assert f"{url}/v1".count("//") == 1


def test_module_level_ollamaUrl_honours_a_scheme_in_the_env():
    """Guard the wiring, not just the helper: ollamaUrl is built at import."""
    with mock.patch.dict(
        os.environ, {"OLLAMA_HOST": "https://ollama.example.com"}, clear=False
    ):
        reloaded = importlib.reload(hc_main)
        try:
            assert reloaded.ollamaUrl == "https://ollama.example.com"
        finally:
            # Restore the module to the ambient environment for other tests.
            importlib.reload(reloaded)


def test_ollama_host_in_a_dotenv_resolves(tmp_path):
    """OLLAMA_HOST is a schema key, so a .env value reaches ollamaUrl.

    It used to be read straight off ``os.environ``, but the loader parses
    `.env` with ``dotenv_values()`` -- which returns a mapping and never
    exports into the process environment -- so ``OLLAMA_HOST`` written in a
    `.env` was reported as an unrecognized key and silently ignored, and the
    run talked to localhost instead.
    """
    env_path = tmp_path / ".env"
    env_path.write_text("OLLAMA_HOST=theplague.example.local:11434\n")

    result = config_loader.load_config(
        env_path=str(env_path), legacy_json_path=None, environ={}
    )

    assert result.warnings == []
    assert result.config["ollamaHost"] == "theplague.example.local:11434"
    assert (
        hc_main._normalize_ollama_url(result.config["ollamaHost"])
        == "http://theplague.example.local:11434"
    )


def test_a_real_ollama_host_env_var_still_overrides_the_dotenv():
    """The variable Ollama's own CLI reads keeps winning, so exporting it for a
    one-off run does not require editing `.env`."""
    env_path = None
    result = config_loader.load_config(
        env_path=env_path,
        legacy_json_path=None,
        environ={"OLLAMA_HOST": "https://ollama.example.com"},
    )

    assert result.config["ollamaHost"] == "https://ollama.example.com"


def test_module_level_ollamaUrl_defaults_to_localhost():
    env = {k: v for k, v in os.environ.items() if k != "OLLAMA_HOST"}
    with mock.patch.dict(os.environ, env, clear=True):
        reloaded = importlib.reload(hc_main)
        try:
            assert reloaded.ollamaUrl == "http://localhost:11434"
        finally:
            importlib.reload(reloaded)
