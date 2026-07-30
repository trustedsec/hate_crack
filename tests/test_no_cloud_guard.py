"""Tests for OLLAMA_NO_CLOUD: refusing Ollama's cloud-hosted models.

Ollama proxies a ``-cloud``-tagged model to ollama.com through the same local
``/v1`` endpoint a local model uses, so nothing about the request shape says
the prompt is about to leave the host. hate_crack's LLM prompts carry recovered
plaintexts, corpus statistics and client target details, so the model name is
the only thing that can be checked before the data is already gone.
"""

from __future__ import annotations

import inspect

import pytest

from hate_crack import llm
from hate_crack.config_loader import load_config

CLOUD_NAMES = [
    "gpt-oss:120b-cloud",
    "deepseek-v3.1:671b-cloud",
    "qwen3-coder:480b-cloud",
    "kimi-k2:1t-cloud",
    # Untagged: the suffix is on the name itself.
    "something-cloud",
    # Surrounding whitespace is a config-file artifact, not a different model.
    "  gpt-oss:120b-cloud  ",
]

LOCAL_NAMES = [
    "qwen2.5:32b",
    "qwen3.6:35b-a3b-q4_K_M",
    "llama3.3:70b",
    "mistral",
    # A local model that merely *mentions* cloud is not cloud-hosted: the
    # marker is a suffix on the tag, not a substring anywhere in the name.
    "cloudy-llama:8b",
    "cloud-atlas:7b",
    "llama3:cloud-ish",
]


@pytest.mark.parametrize("model", CLOUD_NAMES)
def test_cloud_models_are_recognized(model):
    assert llm.is_cloud_model(model) is True


@pytest.mark.parametrize("model", LOCAL_NAMES)
def test_local_models_are_not_flagged(model):
    assert llm.is_cloud_model(model) is False


@pytest.mark.parametrize("model", CLOUD_NAMES)
def test_guard_refuses_a_cloud_model_when_enabled(model):
    with pytest.raises(llm.CloudModelRefused) as exc:
        llm.ensure_model_allowed(model, no_cloud=True)
    assert exc.value.model == model


@pytest.mark.parametrize("model", LOCAL_NAMES)
def test_guard_allows_a_local_model_when_enabled(model):
    llm.ensure_model_allowed(model, no_cloud=True)


@pytest.mark.parametrize("model", CLOUD_NAMES)
def test_guard_is_opt_in(model):
    """Default-off: a user who deliberately configured a cloud model keeps it."""
    llm.ensure_model_allowed(model, no_cloud=False)


def test_refusal_message_names_the_model_and_the_setting():
    with pytest.raises(llm.CloudModelRefused) as exc:
        llm.ensure_model_allowed("gpt-oss:120b-cloud", no_cloud=True)
    message = str(exc.value)
    assert "gpt-oss:120b-cloud" in message
    assert "OLLAMA_NO_CLOUD" in message


# ---------------------------------------------------------------------------
# The guard lives at the choke point, not at the call sites
# ---------------------------------------------------------------------------

ENTRY_POINTS = ["research_target", "generate_candidates", "generate_rules"]


@pytest.mark.parametrize("name", ENTRY_POINTS)
def test_every_entry_point_requires_an_explicit_policy(name):
    """``no_cloud`` is keyword-only with no default on purpose.

    A default would let a new call site inherit a permissive policy by
    forgetting to pass anything, which is precisely how a data-egress guard
    stops guarding.
    """
    parameter = inspect.signature(getattr(llm, name)).parameters["no_cloud"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


@pytest.mark.parametrize("name", ENTRY_POINTS)
def test_every_entry_point_refuses_before_building_a_client(name, monkeypatch):
    """The refusal must happen before any network object is constructed.

    Asserting "it raised" is not enough: a guard that runs after the client is
    built, or after the request is assembled, is one refactor away from running
    after the request is sent.
    """

    def _fail(*args, **kwargs):
        raise AssertionError("_build_client must not be reached for a cloud model")

    monkeypatch.setattr(llm, "_build_client", _fail)

    kwargs = {
        "research_target": {"company": "Synthetic Corp"},
        "generate_candidates": {"mode": "target", "context_data": {}},
        "generate_rules": {"context_data": {}},
    }[name]

    with pytest.raises(llm.CloudModelRefused):
        getattr(llm, name)(
            "http://localhost:11434",
            "gpt-oss:120b-cloud",
            8192,
            no_cloud=True,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------


def test_ollama_no_cloud_resolves_from_a_dotenv(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("OLLAMA_NO_CLOUD=1\n")

    result = load_config(env_path=str(env_path), legacy_json_path=None, environ={})

    assert result.warnings == []
    assert result.config["ollamaNoCloud"] is True


def test_ollama_no_cloud_defaults_to_off():
    result = load_config(env_path=None, legacy_json_path=None, environ={})
    assert result.config["ollamaNoCloud"] is False
