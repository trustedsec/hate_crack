"""Tests for OLLAMA_NO_CLOUD's destination check (#274).

Complements tests/test_no_cloud_guard.py, which covers the pre-existing
model-*name* heuristic (``is_cloud_model`` / ``ensure_model_allowed`` /
``CloudModelRefused``). That check is a no-op on the vLLM/OpenAI backends
because it only inspects the model name, so this file covers the destination
check added alongside it: ``is_offsite_url`` / ``ensure_destination_allowed`` /
``CloudDestinationRefused`` / ``offsite_destination_warning``.

DNS is never touched. Tests that exercise resolution pass their own
``resolve`` stub (or patch ``socket.getaddrinfo`` directly); everything else
uses an IP literal, which ``is_offsite_url`` classifies without resolving
anything. Genuinely global addresses use well-known public resolvers
(``8.8.8.8``, ``1.1.1.1``) rather than an RFC 5737 documentation range
(``192.0.2.0/24`` etc.) -- Python's ``ipaddress`` marks those ranges
``is_private``, so they cannot stand in for a global address here.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import llm  # noqa: E402

# An IP literal that resolves to nothing, needs no DNS, and is unambiguously
# offsite -- used everywhere an offsite destination is needed without an
# injected resolver.
OFFSITE_URL = "http://8.8.8.8:8000"


@pytest.fixture(autouse=True)
def _block_real_dns(monkeypatch):
    """Make a real DNS lookup fail the test instead of silently succeeding.

    Every hostname case above either injects its own ``resolve`` stub or
    patches ``socket.getaddrinfo`` directly, so this should never actually
    fire -- it exists to catch a *future* regression in the
    ``localhost``/local-suffix short-circuit (or a test that forgets to
    inject a resolver) with a clear failure instead of a live lookup.
    """

    def _poisoned_getaddrinfo(host, *args, **kwargs):
        raise AssertionError(
            f"real DNS resolution attempted for {host!r} -- inject a resolve "
            "stub (or patch socket.getaddrinfo) instead"
        )

    monkeypatch.setattr(llm.socket, "getaddrinfo", _poisoned_getaddrinfo)


# ---------------------------------------------------------------------------
# is_offsite_url
# ---------------------------------------------------------------------------


def _resolve_to(*addresses):
    return lambda host: list(addresses)


def _unresolvable(host):
    return []


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434",
        "http://[::1]:11434",
        "http://[0:0:0:0:0:0:0:1]:11434",
    ],
)
def test_loopback_ip_literal_is_not_offsite(url):
    assert llm.is_offsite_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:11434",
        "http://172.16.5.5:11434",
        "http://192.168.1.5:11434",
    ],
)
def test_rfc1918_ip_literal_is_not_offsite(url):
    assert llm.is_offsite_url(url) is False


def test_link_local_ip_literal_is_not_offsite():
    assert llm.is_offsite_url("http://169.254.1.1:11434") is False


def test_global_ip_literal_is_offsite():
    assert llm.is_offsite_url(OFFSITE_URL) is True


def test_localhost_hostname_is_not_offsite():
    assert llm.is_offsite_url("http://localhost:11434") is False


@pytest.mark.parametrize(
    "host",
    [
        "vllm-host.local",
        "vllm-host.internal",
        "vllm-host.lan",
        "vllm-host.localdomain",
    ],
)
def test_local_suffix_hostname_is_not_offsite(host):
    assert llm.is_offsite_url(f"http://{host}:8000") is False


def test_hostname_resolving_only_privately_is_not_offsite():
    resolve = _resolve_to("10.0.0.5")
    assert llm.is_offsite_url("http://vllm-box:8000", resolve=resolve) is False


def test_hostname_resolving_globally_is_offsite():
    resolve = _resolve_to("8.8.8.8")
    assert llm.is_offsite_url("http://vllm-host.example:8000", resolve=resolve) is True


def test_hostname_resolving_to_a_mix_is_offsite():
    resolve = _resolve_to("10.0.0.5", "8.8.8.8")
    assert llm.is_offsite_url("http://mixed-host.example:8000", resolve=resolve) is True


def test_unresolvable_hostname_is_offsite_fail_closed():
    """The one deliberately fail-closed case: an operator who set
    OLLAMA_NO_CLOUD=true asked for "nothing leaves this host", and an
    unverifiable destination should be refused, not silently allowed."""
    assert (
        llm.is_offsite_url("http://vllm-host.example:8000", resolve=_unresolvable)
        is True
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not a url at all",
        "://///",
    ],
)
def test_empty_or_garbage_url_is_not_offsite(url):
    assert llm.is_offsite_url(url) is False


def test_malformed_bracketed_ipv6_host_is_not_offsite():
    """urlsplit() raises ValueError on a malformed bracketed-IPv6 host (e.g. a
    typo'd OLLAMA_HOST missing its closing bracket) rather than returning an
    odd hostname. Same rule as any other unparseable host: not offsite,
    since it cannot be reached at all -- and this must not be an uncaught
    traceback on the menu 12 / menu 23 warning call, which runs before any
    try block in main.py."""
    assert llm.is_offsite_url("http://[::1") is False


@pytest.mark.parametrize(
    "url",
    [
        "http://100.64.0.1:11434",
        "http://100.100.100.100:11434",
        "http://100.127.255.254:11434",
    ],
)
def test_cgnat_tailscale_range_is_not_offsite(url):
    """100.64.0.0/10 (RFC 6598 CGNAT) is what Tailscale assigns to every
    tailnet node, so reaching a GPU box over Tailscale is an ordinary
    "remote but private" setup, not cloud egress. Python's ipaddress reports
    this range as neither is_private nor is_link_local, so it must be
    special-cased rather than left to fall through to the general rule."""
    assert llm.is_offsite_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        # 2002:0808:0808::/... encodes 8.8.8.8 (a genuinely global address).
        "http://[2002:0808:0808::1]:11434",
        # 2002:6300:6301::/... encodes 99.0.99.1 as a second example.
        "http://[2002:6300:6301::1]:11434",
    ],
)
def test_six_to_four_range_is_offsite(url):
    """2002::/16 (RFC 3056 6to4) encodes a global IPv4 address by definition.
    Python's ipaddress.is_private reports True for it on this interpreter, so
    it must be special-cased explicitly -- getting this one wrong leaks:
    an offsite destination would be treated as local and the request sent
    with no warning at all."""
    assert llm.is_offsite_url(url) is True


def test_default_resolver_is_used_when_none_injected(monkeypatch):
    """The module-level default wraps socket.getaddrinfo -- verified by
    patching it directly rather than touching real DNS."""

    def fake_getaddrinfo(host, port):
        assert host == "vllm-host.example"
        return [(None, None, None, None, ("8.8.8.8", 0))]

    monkeypatch.setattr(llm.socket, "getaddrinfo", fake_getaddrinfo)
    assert llm.is_offsite_url("http://vllm-host.example:8000") is True


def test_default_resolver_failure_is_offsite(monkeypatch):
    def fake_getaddrinfo(host, port):
        raise OSError("name or service not known")

    monkeypatch.setattr(llm.socket, "getaddrinfo", fake_getaddrinfo)
    assert llm.is_offsite_url("http://vllm-host.example:8000") is True


# ---------------------------------------------------------------------------
# ensure_destination_allowed
# ---------------------------------------------------------------------------


def test_ensure_destination_allowed_raises_when_no_cloud_and_offsite():
    with pytest.raises(llm.CloudDestinationRefused) as exc:
        llm.ensure_destination_allowed(OFFSITE_URL, no_cloud=True)
    assert "8.8.8.8" in str(exc.value)
    assert "OLLAMA_NO_CLOUD" in str(exc.value)
    assert exc.value.url == OFFSITE_URL


def test_ensure_destination_allowed_silent_when_no_cloud_false_and_offsite():
    llm.ensure_destination_allowed(OFFSITE_URL, no_cloud=False)


def test_ensure_destination_allowed_silent_when_no_cloud_true_and_local():
    llm.ensure_destination_allowed("http://localhost:11434", no_cloud=True)


def test_ensure_destination_allowed_silent_when_no_cloud_false_and_local():
    llm.ensure_destination_allowed("http://localhost:11434", no_cloud=False)


# ---------------------------------------------------------------------------
# offsite_destination_warning
# ---------------------------------------------------------------------------


def test_warning_is_none_for_a_local_destination():
    assert (
        llm.offsite_destination_warning(
            "http://localhost:11434", "ollama", no_cloud=False
        )
        is None
    )


def test_warning_names_the_host_and_the_setting_for_an_offsite_destination():
    text = llm.offsite_destination_warning(OFFSITE_URL, "vllm", no_cloud=False)
    assert text is not None
    assert "8.8.8.8" in text
    assert "OLLAMA_NO_CLOUD" in text


def test_warning_is_none_when_no_cloud_is_true_even_for_an_offsite_destination():
    """The refusal is the message that must be believed: with
    OLLAMA_NO_CLOUD=true, ensure_destination_allowed is about to raise for
    this exact URL, so the warning must not also claim the data 'will be
    sent there' right before that happens."""
    assert llm.offsite_destination_warning(OFFSITE_URL, "vllm", no_cloud=True) is None


def test_warning_no_cloud_is_keyword_only_with_no_default():
    import inspect

    parameter = inspect.signature(llm.offsite_destination_warning).parameters[
        "no_cloud"
    ]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


# ---------------------------------------------------------------------------
# Each of the four llm.py entry points is guarded
# ---------------------------------------------------------------------------

ENTRY_POINTS = ["research_target", "generate_candidates", "generate_rules"]


@pytest.mark.parametrize("name", ENTRY_POINTS)
def test_entry_point_refuses_an_offsite_destination_before_building_a_client(
    name, monkeypatch
):
    def _fail(*args, **kwargs):
        raise AssertionError("_build_client must not be reached for an offsite host")

    monkeypatch.setattr(llm, "_build_client", _fail)

    kwargs = {
        "research_target": {"company": "Synthetic Corp"},
        "generate_candidates": {"mode": "target", "context_data": {}},
        "generate_rules": {"context_data": {}},
    }[name]

    with pytest.raises(llm.CloudDestinationRefused):
        getattr(llm, name)(
            OFFSITE_URL,
            "some-model",
            8192,
            no_cloud=True,
            backend="vllm",
            api_key="sk-x",
            **kwargs,
        )


def test_generate_masks_refuses_an_offsite_destination_before_the_rosetta_call():
    with (
        mock.patch("hate_crack.llm._rosetta_generate_masks") as rosetta_call,
        pytest.raises(llm.CloudDestinationRefused),
    ):
        llm.generate_masks(
            OFFSITE_URL,
            "some-model",
            8192,
            "8 char passwords",
            no_cloud=True,
            backend="ollama",
            api_key="ollama",
        )
    rosetta_call.assert_not_called()


def test_model_guard_takes_precedence_over_destination_guard():
    """Both would fire here (a cloud model AND an offsite URL) -- the
    pre-existing model check must still win, matching how generate_masks
    already puts ensure_model_allowed ahead of its own backend refusal."""
    with pytest.raises(llm.CloudModelRefused):
        llm.research_target(
            OFFSITE_URL,
            "gpt-oss:120b-cloud",
            8192,
            "Synthetic Corp",
            no_cloud=True,
            backend="ollama",
            api_key="ollama",
        )
