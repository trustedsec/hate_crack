"""
Tests for Hashview integration - Mocked API calls for CI/CD
"""

import gzip
import pytest
import requests
import sys
import os
import json
import tempfile
import uuid
from unittest.mock import Mock, patch, MagicMock


# Add the parent directory to the path to import hate_crack
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from hate_crack.api import HashviewAPI, _digest_for_type, _md4

# Test configuration - these are mock values, not real credentials
HASHVIEW_URL = "https://hashview.example.com"
HASHVIEW_API_KEY = "test-api-key-123"

# Obviously-synthetic example plaintexts. This is a public repository and real
# passwords (or basewords/partials of them) must never appear as example values,
# including in fixtures. Every hash constant below is derived from these strings
# so hash:plaintext pairs stay internally consistent under client-side
# validation instead of relying on memorised digests of real passwords.
SYNTH_PLAIN_A = "Synthetic-Example-Aaa"
SYNTH_PLAIN_B = "Synthetic-Example-Bbb"
SYNTH_PLAIN_C = "Synthetic-Example-Ccc"


def _synth_digest(hash_type, plaintext):
    """Digest of a synthetic plaintext under ``hash_type`` (hashcat mode)."""
    digest = _digest_for_type(str(hash_type), plaintext.encode("utf-8"))
    if digest is None:
        raise ValueError(f"no client-side digest available for mode {hash_type}")
    return digest


# NTLM (mode 1000) and MD5 (mode 0) digests of the synthetic plaintexts.
NTLM_A = _synth_digest(1000, SYNTH_PLAIN_A)
NTLM_B = _synth_digest(1000, SYNTH_PLAIN_B)
NTLM_C = _synth_digest(1000, SYNTH_PLAIN_C)
MD5_A = _synth_digest(0, SYNTH_PLAIN_A)
# The all-zero NTLM of the empty password; a marker Hashview must never import.
NTLM_EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"

# A synthetic plaintext holding a genuine multi-byte UTF-8 character (£, not
# ASCII/Latin-1-as-a-single-byte). Its NTLM digest is computed by encoding the
# actual Unicode string as UTF-16LE directly -- the correct hashcat behaviour
# for real text -- rather than through ``_synth_digest``/``_digest_for_type``,
# which is exactly the code path under test (issue: potfile lines with
# non-ASCII plaintexts were wrongly rejected as "would be rejected by
# Hashview").
SYNTH_PLAIN_UNICODE = "Synthetic-Example-£-Ddd"
NTLM_UNICODE = _md4(SYNTH_PLAIN_UNICODE.encode("utf-16le"))


class TestHashviewAPI:
    """Test suite for HashviewAPI class with mocked API calls"""

    def _live_api(self):
        """Return a genuinely live HashviewAPI, or skip.

        Live tests must NOT request the ``api`` fixture: that fixture holds
        ``patch("requests.Session")`` open for the whole test body, so a client
        built inside such a test gets a ``MagicMock`` session and never reaches
        the server (issue #223). Credentials come from the environment only —
        ``HASHVIEW_TEST_REAL=1`` plus ``HASHVIEW_URL``/``HASHVIEW_API_KEY``,
        which is what the local docker stack exports — so a plain run can never
        silently hit somebody's real Hashview via config.json.
        """
        if os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"):
            pytest.skip("Set HASHVIEW_TEST_REAL=1 to run live Hashview tests.")
        url = os.environ.get("HASHVIEW_URL")
        key = os.environ.get("HASHVIEW_API_KEY")
        if not url or not key:
            pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY env vars.")
        real_api = HashviewAPI(url, key)
        # Regression detector for the mock leak: if a future fixture change
        # re-mocks requests.Session for a live test, fail here instead of
        # asserting against a MagicMock and reporting it as a skip.
        #
        # The Mock check goes FIRST deliberately. `patch("requests.Session")`
        # replaces the class as well as the instance, so the isinstance() check
        # below raises `TypeError: isinstance() arg 2 must be a type` in exactly
        # the case this guard exists to diagnose -- failing loudly, but with a
        # message that says nothing about a mock leak. Checking against Mock,
        # whose class is never patched, reports the real cause.
        assert not isinstance(real_api.session, (Mock, MagicMock)), (
            "live client session is a mock: requests.Session is patched, most "
            "likely because this live test was given the `api` fixture. See #223."
        )
        assert isinstance(real_api.session, requests.Session), (
            f"live client session must be a real requests.Session, "
            f"got {type(real_api.session)!r}"
        )
        return real_api

    @staticmethod
    def _live_hash_type():
        """The hashcat mode the live stack has data seeded for."""
        return os.environ.get("HASHVIEW_HASH_TYPE", "1000")

    @staticmethod
    def _live_env_int(name):
        """Return ``name`` from the environment as an int, or skip."""
        raw = os.environ.get(name)
        if not raw:
            pytest.skip(f"Set {name} to run this live Hashview test.")
        return int(raw)

    @staticmethod
    def _raw_hashfiles_by_type(real_api, hash_type):
        """GET the type-scoped listing straight off the wire.

        ``get_hashfiles_by_type`` swallows every exception and returns ``[]``, so
        ``isinstance(result, list)`` alone cannot tell a real answer from a
        failure (issue #228). Reading the raw response gives the live tests a
        server-derived expectation to compare the client's parse against.
        """
        url = f"{real_api.base_url}/v1/hashfiles/hash_type/{hash_type}"
        resp = real_api.session.get(url, headers=real_api._auth_headers())
        assert resp.status_code == 200, (
            f"{url} answered {resp.status_code}: {resp.text[:200]!r}"
        )
        payload = resp.json()
        assert isinstance(payload, dict), f"expected a JSON object, got {payload!r}"
        hashfiles = payload.get("hashfiles")
        assert isinstance(hashfiles, list), f"no hashfiles list in {payload!r}"
        return hashfiles

    @pytest.fixture
    def api(self):
        """Create a HashviewAPI instance with mocked session"""
        with patch("requests.Session"):
            api = HashviewAPI(base_url=HASHVIEW_URL, api_key=HASHVIEW_API_KEY)
            # Replace the session with a mock
            api.session = MagicMock()
            yield api

    @pytest.fixture
    def test_hashfile(self):
        """Create a temporary test hashfile with NTLM hashes of synthetic values"""
        test_hashes = [NTLM_A, NTLM_B, NTLM_C]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            hashfile_path = f.name
            for hash_val in test_hashes:
                f.write(hash_val + "\n")

        yield hashfile_path

        # Cleanup

    @pytest.fixture
    def test_hashfile_for_live(self, tmp_path):
        """Factory: a hash-only file whose digests match the given hashcat mode.

        The live stack seeds mode 0 (MD5) as well as 1000 (NTLM), so the file
        has to be built for whichever mode ``HASHVIEW_HASH_TYPE`` selects.
        """

        def _make(hash_type):
            try:
                digests = [
                    _synth_digest(hash_type, plain)
                    for plain in (SYNTH_PLAIN_A, SYNTH_PLAIN_B, SYNTH_PLAIN_C)
                ]
            except ValueError as exc:
                pytest.skip(str(exc))
            path = tmp_path / "live_hashes.txt"
            path.write_text("".join(d + "\n" for d in digests))
            return str(path)

        return _make

    def test_get_hashfiles_by_type_success(self, api):
        """The /v1/hashfiles/hash_type/<type> endpoint returns a list (mocked transport)."""
        mock_response = Mock()
        mock_response.json.return_value = [
            {"id": 1, "customer_id": 1, "name": "hashfile1.txt", "hash_type": 1000},
            {"id": 2, "customer_id": 2, "name": "hashfile2.txt", "hash_type": 1000},
        ]
        mock_response.raise_for_status = Mock()
        api.session.get.return_value = mock_response
        result = api.get_hashfiles_by_type("1000")
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "hashfile1.txt"

    def test_get_hashfiles_by_type_success_live(self):
        """Live Hashview lists hashfiles of a hash_type, parsed as the server sent them.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        hash_type = self._live_hash_type()
        try:
            expected = self._raw_hashfiles_by_type(real_api, hash_type)
            result = real_api.get_hashfiles_by_type(hash_type)
        except requests.RequestException as exc:
            pytest.skip(f"Hashview hashfile listing request failed: {exc}")

        assert isinstance(result, list), f"expected a list, got {result!r}"
        # The client must surface exactly the server's hashfiles — not the []
        # that its own ``except Exception`` produces when the call really failed.
        assert [hf.get("id") for hf in result] == [hf.get("id") for hf in expected]
        for hashfile in result:
            assert "name" in hashfile, f"no name in hashfile: {hashfile!r}"
            assert str(hashfile.get("hash_type")) == str(hash_type), hashfile

    def test_get_customer_hashfiles_requires_hash_type(self, api):
        """Without a hash_type there is no Hashview list route, so we return []."""
        result = api.get_customer_hashfiles(1)
        assert result == []

    def test_get_all_customer_hashfiles_sweeps_and_dedupes(self, api):
        """Aggregate sweeps per-type listings, filters by customer, dedupes by id."""
        per_type = {
            1000: [
                {"id": 1, "customer_id": 1, "name": "ntlm.txt", "hash_type": 1000},
                {"id": 2, "customer_id": 2, "name": "other.txt", "hash_type": 1000},
            ],
            5600: [
                {"id": 3, "customer_id": 1, "name": "ntlmv2.txt", "hash_type": 5600},
                # id 1 appears again under another type; must dedupe (first wins)
                {"id": 1, "customer_id": 1, "name": "ntlm.txt", "hash_type": 5600},
            ],
        }
        api.get_hashfiles_by_type = Mock(
            side_effect=lambda ht: per_type.get(int(ht), [])
        )

        result = api.get_all_customer_hashfiles(1, hash_types=[1000, 5600])

        ids = sorted(hf["id"] for hf in result)
        assert ids == [1, 3]  # customer 2 excluded, id 1 not duplicated
        by_id = {hf["id"]: hf for hf in result}
        assert str(by_id[1]["hash_type"]) == "1000"  # first type seen wins
        assert str(by_id[3]["hash_type"]) == "5600"

    def test_get_all_customer_hashfiles_aborts_on_404(self, api):
        """A 404 means the listing endpoint is absent (e.g. Hashview main);
        the sweep stops after the first request instead of probing every type."""
        import requests

        def _raise_404(ht):
            resp = Mock()
            resp.status_code = 404
            raise requests.exceptions.HTTPError("404 Not Found", response=resp)

        api.get_hashfiles_by_type = Mock(side_effect=_raise_404)
        result = api.get_all_customer_hashfiles(1, hash_types=[1000, 5600, 3000])
        assert result == []
        # Stopped after the first 404, did not sweep all three types.
        assert api.get_hashfiles_by_type.call_count == 1

    def test_get_all_customer_hashfiles_skips_failing_types(self, api):
        """A per-type query that errors is skipped, not fatal."""

        def _by_type(ht):
            if int(ht) == 1000:
                raise RuntimeError("boom")
            return [{"id": 9, "customer_id": 1, "name": "x", "hash_type": int(ht)}]

        api.get_hashfiles_by_type = Mock(side_effect=_by_type)
        result = api.get_all_customer_hashfiles(1, hash_types=[1000, 5600])
        assert [hf["id"] for hf in result] == [9]

    def test_get_all_customer_hashfiles_prefers_customer_scoped_route(self, api):
        """The one-request route answers it; the 26-type sweep never runs."""
        files = [
            {"id": 1, "customer_id": 1, "name": "ntlm.txt", "hash_type": 1000},
            {"id": 4, "customer_id": 1, "name": "exotic.txt", "hash_type": 99999},
        ]
        api.list_customer_hashfiles = Mock(return_value=files)
        api.get_hashfiles_by_type = Mock()

        result = api.get_all_customer_hashfiles(1)

        assert result == files
        api.list_customer_hashfiles.assert_called_once_with(1)
        api.get_hashfiles_by_type.assert_not_called()
        # A type outside COMMON_HASH_TYPES survives; the sweep would have missed it.
        assert 99999 not in api.COMMON_HASH_TYPES
        assert 4 in [hf["id"] for hf in result]

    def test_get_all_customer_hashfiles_falls_back_when_route_absent(self, api):
        """Servers predating the customer-scoped route 404; the sweep covers them."""
        import requests

        resp = Mock()
        resp.status_code = 404
        api.list_customer_hashfiles = Mock(
            side_effect=requests.exceptions.HTTPError("404 Not Found", response=resp)
        )
        api.get_hashfiles_by_type = Mock(
            side_effect=lambda ht: (
                [{"id": 7, "customer_id": 1, "name": "ntlm.txt", "hash_type": 1000}]
                if int(ht) == 1000
                else []
            )
        )

        result = api.get_all_customer_hashfiles(1)

        assert [hf["id"] for hf in result] == [7]
        assert api.get_hashfiles_by_type.call_count == len(api.COMMON_HASH_TYPES)

    def test_get_all_customer_hashfiles_does_not_sweep_on_non_404(self, api):
        """A 500 is a real failure, not a missing route.

        Falling back would spend 26 requests against an already-unhealthy server
        to produce a list that silently omits whatever the errors hid.
        """
        import requests

        resp = Mock()
        resp.status_code = 500
        api.list_customer_hashfiles = Mock(
            side_effect=requests.exceptions.HTTPError("500 Server Error", response=resp)
        )
        api.get_hashfiles_by_type = Mock()

        with pytest.raises(requests.exceptions.HTTPError):
            api.get_all_customer_hashfiles(1)
        api.get_hashfiles_by_type.assert_not_called()

    def test_list_customer_hashfiles_unwraps_response(self, api):
        """The route returns {"hashfiles": [...]}; bare lists are tolerated too."""
        resp = Mock()
        resp.raise_for_status = Mock()
        resp.json = Mock(return_value={"status": 200, "hashfiles": [{"id": 3}]})
        api.session.get = Mock(return_value=resp)

        assert api.list_customer_hashfiles(5) == [{"id": 3}]
        url = api.session.get.call_args[0][0]
        assert url.endswith("/v1/customers/5/hashfiles")

        resp.json = Mock(return_value=[{"id": 8}])
        assert api.list_customer_hashfiles(5) == [{"id": 8}]

        resp.json = Mock(side_effect=ValueError("not json"))
        assert api.list_customer_hashfiles(5) == []

    def test_get_customer_hashfiles(self, api):
        """Filter the type-scoped hashfile list by customer_id (mocked transport)."""
        api.get_hashfiles_by_type = Mock(
            return_value=[
                {"id": 1, "customer_id": 1, "name": "hashfile1.txt"},
                {"id": 2, "customer_id": 2, "name": "hashfile2.txt"},
                {"id": 3, "customer_id": 1, "name": "hashfile3.txt"},
            ]
        )
        result = api.get_customer_hashfiles(1, hash_type="1000")
        assert len(result) == 2
        assert all(hf["customer_id"] == 1 for hf in result)
        api.get_hashfiles_by_type.assert_called_once_with("1000")

    def test_get_customer_hashfiles_live(self):
        """Live Hashview: the customer filter keeps exactly that customer's files.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        customer_id = self._live_env_int("HASHVIEW_CUSTOMER_ID")
        hash_type = self._live_hash_type()
        try:
            all_hashfiles = self._raw_hashfiles_by_type(real_api, hash_type)
            result = real_api.get_customer_hashfiles(customer_id, hash_type=hash_type)
        except requests.RequestException as exc:
            pytest.skip(f"Hashview hashfile listing request failed: {exc}")

        expected_ids = [
            hf.get("id")
            for hf in all_hashfiles
            if int(hf.get("customer_id", 0)) == customer_id
        ]
        assert [hf.get("id") for hf in result] == expected_ids
        assert all(int(hf["customer_id"]) == customer_id for hf in result)
        # The seeded customer owns at least one hashfile of the seeded type, so
        # an empty result here means the filter (or the listing) is broken.
        assert result, (
            f"customer {customer_id} has no hash_type {hash_type} hashfiles in "
            f"the server's listing of {len(all_hashfiles)} file(s)"
        )

    def test_display_customers_multicolumn_empty(self, api, capsys):
        """Test display_customers_multicolumn with no customers (mock only, as real API not needed)."""
        api.display_customers_multicolumn([])
        captured = capsys.readouterr()
        assert "No customers found" in captured.out

    def test_list_customers_native_json_array(self, api):
        """Server returns `users` as a native JSON array (issue #229, no double-decode)."""
        mock_resp = Mock()
        mock_resp.json.return_value = {"users": [{"id": 1, "name": "Acme"}]}
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        result = api.list_customers()
        assert result["customers"] == [{"id": 1, "name": "Acme"}]

    def test_list_customers_legacy_json_string(self, api):
        """Older servers double-encode `users` as a JSON string; still supported."""
        mock_resp = Mock()
        mock_resp.json.return_value = {"users": json.dumps([{"id": 2, "name": "Beta"}])}
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        result = api.list_customers()
        assert result["customers"] == [{"id": 2, "name": "Beta"}]

    def test_get_hashfile_details_md5_zero(self, api):
        """hash_type 0 (MD5) is falsy; must not fall through to the envelope `type`."""
        mock_resp = Mock()
        mock_resp.json.return_value = {
            "hash_type": 0,
            "msg": "OK",
            "status": 200,
            "type": "message",
        }
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        details = api.get_hashfile_details(42)
        assert details["hashtype"] == 0

    def test_get_hashfile_details_ntlm(self, api):
        """Sanity: NTLM (1000) still parses from `hash_type`."""
        mock_resp = Mock()
        mock_resp.json.return_value = {
            "hash_type": 1000,
            "msg": "OK",
            "status": 200,
            "type": "message",
        }
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        assert api.get_hashfile_details(7)["hashtype"] == 1000

    def test_get_hashfile_hash_type_reads_hashfiles_key(self, api):
        """Endpoint returns {hashfiles: [...]} objects; return their ids."""
        mock_resp = Mock()
        mock_resp.json.return_value = {
            "status": 200,
            "type": "message",
            "msg": "OK",
            "hashfiles": [{"id": 3, "name": "a"}, {"id": 9, "name": "b"}],
        }
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        assert api.get_hashfile_hash_type(1000) == [3, 9]

    def test_list_rules_native_array(self, api):
        """/v1/rules returns {rules: [...]} as a native JSON array."""
        mock_resp = Mock()
        mock_resp.json.return_value = {
            "status": 200,
            "rules": [{"id": 4, "name": "best64.rule", "size": 77}],
        }
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        rules = api.list_rules()
        assert rules == [{"id": 4, "name": "best64.rule", "size": 77}]

    def test_download_rules_gunzips_to_plaintext(self, api, tmp_path):
        """Rule download arrives gzip-compressed; saved file must be plaintext."""
        import gzip

        plaintext = b":\nc\nu\nsa\n"
        mock_resp = Mock()
        mock_resp.content = gzip.compress(plaintext)
        mock_resp.headers = {}
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        out = os.path.join(str(tmp_path), "best64.rule")
        result = api.download_rules(4, out)
        assert result["output_file"] == out
        with open(out, "rb") as f:
            assert f.read() == plaintext

    def test_download_rules_passes_plaintext_through(self, api, tmp_path):
        """If the body is already plaintext (not gzip), save it unchanged."""
        mock_resp = Mock()
        mock_resp.content = b":\nc\nu\n"
        mock_resp.headers = {}
        mock_resp.raise_for_status = Mock()
        api.session.get.return_value = mock_resp

        out = os.path.join(str(tmp_path), "plain.rule")
        api.download_rules(7, out)
        with open(out, "rb") as f:
            assert f.read() == b":\nc\nu\n"

    def test_download_rules_raises_on_404(self, api, tmp_path):
        """Unknown rule id is a real HTTP 404 -> raise_for_status propagates."""
        from requests.exceptions import HTTPError

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock(side_effect=HTTPError("404"))
        api.session.get.return_value = mock_resp

        with pytest.raises(HTTPError):
            api.download_rules(99999999, os.path.join(str(tmp_path), "x.rule"))

    def test_upload_cracked_hashes_success(self, api, tmp_path):
        """Uploading cracked hashes with valid lines (mocked transport)."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(
            f"{NTLM_A}:{SYNTH_PLAIN_A}\n"
            f"{NTLM_B}:{SYNTH_PLAIN_B}\n"
            f"{NTLM_EMPTY}:{SYNTH_PLAIN_C}\n"
            "invalidline\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 2}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response
        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert "imported" in result
        assert result["imported"] == 2

    def test_upload_cracked_hashes_success_live(self, tmp_path):
        """Live Hashview accepts an import of valid hash:plaintext pairs.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        hash_type = os.environ.get("HASHVIEW_HASH_TYPE", "1000")
        try:
            pairs = [
                (_synth_digest(hash_type, plain), plain)
                for plain in (SYNTH_PLAIN_A, SYNTH_PLAIN_B)
            ]
        except ValueError as exc:
            # Data condition, not a failure: we cannot construct a pair that
            # passes client-side validation for this mode.
            pytest.skip(str(exc))
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text("".join(f"{h}:{p}\n" for h, p in pairs))

        try:
            result = real_api.upload_cracked_hashes(
                str(cracked_file), hash_type=hash_type
            )
        except requests.RequestException as exc:
            pytest.skip(f"Hashview import request failed: {exc}")

        assert isinstance(result, dict), f"expected a JSON object, got {result!r}"
        assert result.get("uploaded") == 2, result
        assert result.get("skipped") == 0, result

    def test_upload_cracked_hashes_api_error(self, api, tmp_path):
        """Test uploading cracked hashes with API error response (mock only)."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(f"{NTLM_A}:{SYNTH_PLAIN_A}\n")
        mock_response = Mock()
        mock_response.json.return_value = {"type": "Error", "msg": "Some error"}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response
        with pytest.raises(Exception) as excinfo:
            api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert "Hashview API Error" in str(excinfo.value)

    def test_upload_cracked_hashes_invalid_json(self, api, tmp_path):
        """Test uploading cracked hashes with invalid JSON response (mock only)."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(f"{NTLM_A}:{SYNTH_PLAIN_A}\n")
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_response.text = "not a json"
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response
        with pytest.raises(Exception) as excinfo:
            api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert "Invalid API response" in str(excinfo.value)

    def test_upload_cracked_hashes_unicode_plaintext_ntlm(self, api, tmp_path):
        """A genuine multi-byte UTF-8 plaintext validates correctly for NTLM.

        Regression test: ``_validate_cracked_pair`` used to zero-extend each
        *UTF-8 byte* of a non-$HEX plaintext before UTF-16LE encoding, instead
        of encoding the actual Unicode codepoints. That doubled up any
        non-ASCII character (e.g. ``£`` became two UTF-16 code units instead
        of one), producing the wrong NTLM digest and skipping an otherwise
        valid cracked hash with "plaintext does not match hash under mode
        1000".
        """
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(
            f"{NTLM_UNICODE}:{SYNTH_PLAIN_UNICODE}\n", encoding="utf-8"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["uploaded"] == 1
        assert result["skipped"] == 0

    def test_upload_skips_wrong_type_line(self, api, tmp_path, capsys):
        """An MD5 line mixed into an NTLM upload is filtered client-side."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(
            # MD5 of the synthetic plaintext — invalid as NTLM, must be dropped
            f"{MD5_A}:{SYNTH_PLAIN_A}\n"
            # genuine NTLM of the same plaintext — must be kept
            f"{NTLM_A}:{SYNTH_PLAIN_A}\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["imported"] == 1
        # Only the valid NTLM line should have been sent (body is bytes)
        sent = api.session.post.call_args.kwargs.get("data")
        if sent is None:
            sent = api.session.post.call_args.args[1]
        assert isinstance(sent, bytes)
        assert f"{NTLM_A}:{SYNTH_PLAIN_A}".encode() in sent
        assert MD5_A.encode() not in sent
        out = capsys.readouterr().out
        assert "Skipped 1 line" in out

    def test_upload_preserves_non_utf8_plaintext(self, api, tmp_path):
        """A plaintext byte that is not valid UTF-8 reaches Hashview intact.

        The file is read as bytes and the plaintext hex-wrapped, so validation
        still recognizes it as the true NTLM pre-image instead of seeing the
        lossy decode (which would be skipped as a mode mismatch).
        """
        plain_bytes = b"abc\xffdef"
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_bytes(
            b"fec45000e0d53e0e103cb66c1fa7fc45:" + plain_bytes + b"\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        api.upload_cracked_hashes(str(cracked_file), hash_type="1000")

        sent = api.session.post.call_args.kwargs.get("data")
        if sent is None:
            sent = api.session.post.call_args.args[1]
        # mode 1000: $HEX[...] is inlined as the latin-1 code points re-encoded
        # as UTF-8, which is what the server re-hashes.
        assert sent == b"fec45000e0d53e0e103cb66c1fa7fc45:" + plain_bytes.decode(
            "latin-1"
        ).encode("utf-8")

    def test_upload_surfaces_client_counts(self, api, tmp_path):
        """upload_cracked_hashes reports uploaded/skipped even when the server
        returns a bare OK with no counts of its own."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(
            f"{MD5_A}:{SYNTH_PLAIN_A}\n"  # MD5 -> skipped
            f"{NTLM_A}:{SYNTH_PLAIN_A}\n"  # NTLM -> uploaded
        )
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": 200,
            "type": "message",
            "msg": "OK",
        }
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["uploaded"] == 1
        assert result["skipped"] == 1

    def test_upload_preserves_server_counts(self, api, tmp_path):
        """A Hashview that reports counts keeps them; client counts are added
        without clobbering the server's."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(f"{NTLM_A}:{SYNTH_PLAIN_A}\n")
        mock_response = Mock()
        mock_response.json.return_value = {
            "msg": "OK",
            "count": 1,
            "verified": 1,
            "updated": 1,
            "unmatched": 0,
        }
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["updated"] == 1
        assert result["verified"] == 1
        assert result["uploaded"] == 1  # client count added alongside

    def _sent_body(self, api):
        sent = api.session.post.call_args.kwargs.get("data")
        if sent is None:
            sent = api.session.post.call_args.args[1]
        return sent

    def test_upload_decodes_hex_ntlm_ascii(self, api, tmp_path):
        """$HEX[...] with trailing space is decoded to real bytes on the wire."""
        cracked_file = tmp_path / "cracked.txt"
        # NTLM of "%032023RC$ " (trailing space) emitted by hashcat as $HEX[...]
        cracked_file.write_text(
            "c153ace1d5b148820dab48a8aa5aa02e:$HEX[2530333230323352432420]\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["imported"] == 1
        body = self._sent_body(api)
        # The $HEX wrapper must be gone; the decoded plaintext (with its
        # trailing space) is sent so a non-$HEX-aware Hashview verifies it.
        assert b"$HEX[" not in body
        assert b"c153ace1d5b148820dab48a8aa5aa02e:%032023RC$ " in body

    def test_upload_decodes_hex_ntlm_highbyte(self, api, tmp_path):
        """High-byte $HEX (0xA8) becomes UTF-8 so the server rebuilds U+00A8."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(
            "af70d9ee21294a74f6337b121e6c9624:$HEX[a833333531343136335777]\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        body = self._sent_body(api)
        # 0xA8 -> latin-1 U+00A8 -> UTF-8 bytes C2 A8
        assert b"af70d9ee21294a74f6337b121e6c9624:\xc2\xa833514163Ww" in body

    def test_upload_keeps_hex_with_embedded_newline(self, api, tmp_path):
        """$HEX encoding a newline can't be inlined; the wrapper is kept."""
        cracked_file = tmp_path / "cracked.txt"
        # NTLM("a\nb") — plaintext contains a literal newline
        import hashlib as _h  # noqa

        cracked_file.write_text("9c6d9b0dc5e5f4d8a4c8e0a1e0b1c2d3:$HEX[610a62]\n")
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        # validate=False so the (bogus) hash isn't dropped before we inspect wire
        api.upload_cracked_hashes(str(cracked_file), hash_type="1000", validate=False)
        body = self._sent_body(api)
        assert b"$HEX[610a62]" in body  # kept verbatim, no raw newline injected
        assert b"a\nb" not in body

    def test_upload_all_invalid_raises(self, api, tmp_path):
        """If validation drops every line, we raise instead of posting empty."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(f"{MD5_A}:{SYNTH_PLAIN_A}\n")
        api.session.post.side_effect = AssertionError("should not POST")
        with pytest.raises(Exception) as excinfo:
            api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert "No valid hashes" in str(excinfo.value)

    def test_upload_validation_can_be_disabled(self, api, tmp_path):
        """validate=False restores the old permissive behaviour."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(f"{MD5_A}:{SYNTH_PLAIN_A}\n")
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(
            str(cracked_file), hash_type="1000", validate=False
        )
        assert result["imported"] == 1

    def test_create_customer_success(self, api):
        """create_customer returns the server's JSON body (mocked transport)."""
        mock_response = Mock()
        mock_response.json.return_value = {"customer_id": 10, "msg": "Customer added"}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response
        result = api.create_customer("New Customer")
        assert result["customer_id"] == 10
        assert result["msg"] == "Customer added"

    def test_create_customer_success_live(self):
        """Live Hashview creates a customer and returns its new id.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        customer_name = f"Example Customer {uuid.uuid4().hex[:8]}"
        try:
            result = real_api.create_customer(customer_name)
        except requests.RequestException as exc:
            pytest.skip(f"Hashview create_customer request failed: {exc}")

        assert isinstance(result, dict), f"expected a JSON object, got {result!r}"
        # Hashview answers {"customer_id": N, "msg": "Customer added", ...}.
        customer_id = result.get("customer_id") or result.get("id")
        assert customer_id, f"no customer id in response: {result!r}"
        assert int(customer_id) > 0

    def test_download_left_hashes_live(self, tmp_path):
        """Live Hashview: GET /v1/hashfiles/<id> streams the uncracked hashes to disk.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        customer_id = self._live_env_int("HASHVIEW_CUSTOMER_ID")
        hashfile_id = self._live_env_int("HASHVIEW_HASHFILE_ID")
        output_file = tmp_path / f"left_{customer_id}_{hashfile_id}.txt"
        potfile = tmp_path / "hashcat.potfile"

        url = f"{real_api.base_url}/v1/hashfiles/{hashfile_id}"
        try:
            probe = real_api.session.get(url, headers=real_api._auth_headers())
            assert probe.status_code == 200, (
                f"{url} answered {probe.status_code}: {probe.text[:200]!r}"
            )
            expected_body = probe.content
            result = real_api.download_left_hashes(
                customer_id,
                hashfile_id,
                output_file=str(output_file),
                potfile_path=str(potfile),
            )
        except requests.RequestException as exc:
            pytest.skip(f"Hashview left-hash download request failed: {exc}")

        assert result["output_file"] == str(output_file)
        assert os.path.exists(result["output_file"])
        with open(result["output_file"], "rb") as f:
            content = f.read()
        # The downloaded file must be exactly what the endpoint served (the
        # found-merge is a no-op on stock Hashview, which has no found route).
        assert content == expected_body
        assert result["size"] == len(content)
        # Left hashes are ciphertext only; a plaintext must never land here.
        for line in content.decode("utf-8", "replace").splitlines():
            assert line.strip(), "blank line in the left-hash download"

    def test_download_left_hashes(self, api, tmp_path):
        """Test downloading left hashes (mocked transport)."""
        mock_response = Mock()
        mock_response.content = b"hash1\nhash2\n"
        mock_response.raise_for_status = Mock()
        mock_response.headers = {"content-length": "0"}
        mock_response.status_code = 404  # For the found file lookup

        def iter_content(chunk_size=8192):
            yield mock_response.content

        mock_response.iter_content = iter_content
        api.session.get.return_value = mock_response

        output_file = tmp_path / "left_1_2.txt"
        result = api.download_left_hashes(1, 2, output_file=str(output_file))
        assert os.path.exists(result["output_file"])
        with open(result["output_file"], "rb") as f:
            content = f.read()
        assert content == b"hash1\nhash2\n"
        assert result["size"] == len(content)

        # Verify auth headers were passed in the left hashes download call.
        # The uncracked ("left") hashes come from GET /v1/hashfiles/<id>
        # (the trailing /found call is a separate lookup).
        call_args_list = api.session.get.call_args_list
        left_call = [
            c
            for c in call_args_list
            if "/v1/hashfiles/2" in str(c) and "found" not in str(c)
        ][0]
        assert left_call.kwargs.get("headers") is not None
        auth_headers = left_call.kwargs.get("headers")
        assert "Cookie" in auth_headers or "uuid" in str(auth_headers)
        assert HASHVIEW_API_KEY in str(auth_headers)

    def test_download_wordlist(self, api, tmp_path):
        """Test downloading a wordlist (mocked transport)."""
        mock_response = Mock()
        mock_response.content = b"gzipdata"
        mock_response.raise_for_status = Mock()
        mock_response.headers = {"content-length": "0"}

        def iter_content(chunk_size=8192):
            yield mock_response.content

        mock_response.iter_content = iter_content
        api.session.get.return_value = mock_response

        output_file = tmp_path / "wordlist_1.gz"
        result = api.download_wordlist(1, output_file=str(output_file))
        assert os.path.exists(result["output_file"])
        with open(result["output_file"], "rb") as f:
            content = f.read()
        assert content == b"gzipdata"
        assert result["size"] == len(content)

        # Verify auth headers were passed in the download call
        # session.get should be called with headers containing the auth cookie
        call_args_list = api.session.get.call_args_list
        # Last call should be the download (not the update call for id 1)
        download_call = [c for c in call_args_list if "wordlists/1" in str(c)][0]
        assert download_call.kwargs.get("headers") is not None
        auth_headers = download_call.kwargs.get("headers")
        assert "Cookie" in auth_headers or "uuid" in str(auth_headers)
        assert HASHVIEW_API_KEY in str(auth_headers)

    def test_download_wordlist_live(self, tmp_path):
        """Live Hashview: a wordlist uploaded by this test downloads back intact.

        The local seeder creates no wordlist, so rather than skip for lack of
        seeded data the test uploads its own synthetic fixture and asserts the
        round trip. Hashview serves wordlists gzip-compressed, so the download
        is gunzipped before comparison.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        words = [SYNTH_PLAIN_A, SYNTH_PLAIN_B, SYNTH_PLAIN_C]
        payload = "".join(w + "\n" for w in words).encode("utf-8")
        source = tmp_path / "hate_crack_live_wordlist.txt"
        source.write_bytes(payload)
        name = f"hate-crack-test-{uuid.uuid4().hex[:8]}.txt"

        try:
            upload_result = real_api.upload_wordlist_file(str(source), name)
            assert isinstance(upload_result, dict), (
                f"expected a JSON object, got {upload_result!r}"
            )
            wordlist_id = upload_result.get("wordlist_id") or upload_result.get("id")
            assert wordlist_id, f"no wordlist id in response: {upload_result!r}"

            output_file = tmp_path / f"wordlist_{wordlist_id}.gz"
            result = real_api.download_wordlist(
                int(wordlist_id), output_file=str(output_file)
            )
        except requests.RequestException as exc:
            pytest.skip(f"Hashview wordlist round-trip request failed: {exc}")

        assert result["output_file"] == str(output_file)
        assert os.path.exists(result["output_file"])
        with open(result["output_file"], "rb") as f:
            downloaded = f.read()
        assert result["size"] == len(downloaded)
        assert downloaded, "downloaded wordlist is empty"
        try:
            body = gzip.decompress(downloaded)
        except (OSError, EOFError):
            # A fork may serve the wordlist uncompressed; compare as-is.
            body = downloaded
        assert body.splitlines() == [w.encode("utf-8") for w in words]

    def test_download_wordlist_saves_to_wordlists_dir(self, api, tmp_path):
        """When output_file is relative, it should resolve to get_hcat_wordlists_dir()."""
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()

        mock_response = Mock()
        mock_response.content = b"gzipdata"
        mock_response.raise_for_status = Mock()
        mock_response.headers = {
            "content-length": "8",
            "content-disposition": 'attachment; filename="mylist.txt.gz"',
        }
        mock_response.iter_content = lambda chunk_size=8192: iter(
            [mock_response.content]
        )
        api.session.get.return_value = mock_response

        with patch(
            "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
        ):
            result = api.download_wordlist(99)

        expected_path = str(wordlists_dir / "mylist.txt.gz")
        assert result["output_file"] == expected_path
        assert os.path.exists(expected_path)
        with open(expected_path, "rb") as f:
            assert f.read() == b"gzipdata"

    def test_download_wordlist_absolute_path_unchanged(self, api, tmp_path):
        """When output_file is absolute, it should not be redirected."""
        abs_output = str(tmp_path / "direct_output.gz")

        mock_response = Mock()
        mock_response.content = b"data"
        mock_response.raise_for_status = Mock()
        mock_response.headers = {"content-length": "4"}
        mock_response.iter_content = lambda chunk_size=8192: iter(
            [mock_response.content]
        )
        api.session.get.return_value = mock_response

        result = api.download_wordlist(99, output_file=abs_output)

        assert result["output_file"] == abs_output
        assert os.path.exists(abs_output)

    def test_list_wordlists_live(self):
        """Live test for Hashview wordlist listing with auth headers."""
        # Only run this test if explicitly enabled
        if os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"):
            pytest.skip(
                "Set HASHVIEW_TEST_REAL=1 to run live Hashview list_wordlists test."
            )

        # For live tests, prefer explicit env vars so developers don't accidentally
        # hit a config.json default/localhost target.
        hashview_url = os.environ.get("HASHVIEW_URL")
        hashview_api_key = os.environ.get("HASHVIEW_API_KEY")
        if not hashview_url or not hashview_api_key:
            pytest.skip("Missing HASHVIEW_URL/HASHVIEW_API_KEY env vars.")

        # Only proceed if the server is actually reachable
        try:
            import socket
            from urllib.parse import urlparse

            parsed = urlparse(hashview_url)
            host = parsed.hostname
            port = parsed.port
            if not host:
                pytest.skip(
                    f"Could not parse hostname from hashview_url: {hashview_url!r}"
                )
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result != 0:
                pytest.skip(f"Hashview server not reachable at {host}:{port}")
        except Exception as e:
            pytest.skip(f"Could not check Hashview server availability: {e}")

        real_api = HashviewAPI(hashview_url, hashview_api_key)
        wordlists = real_api.list_wordlists()
        assert isinstance(wordlists, list)

    def test_create_job_workflow(self, api, test_hashfile):
        """Test creating a job in Hashview (option 2 complete workflow)"""
        print("\n" + "=" * 60)
        print("Testing Option 2: Create Job Workflow")
        print("=" * 60)

        # Mock responses for different endpoints - API returns 'users' as a JSON string
        mock_customers_response = Mock()
        mock_customers_response.json.return_value = {
            "users": json.dumps([{"id": 1, "name": "Test Customer"}])
        }
        mock_customers_response.raise_for_status = Mock()

        mock_upload_response = Mock()
        mock_upload_response.json.return_value = {
            "hashfile_id": 4567,
            "msg": "Hashfile added",
        }
        mock_upload_response.raise_for_status = Mock()

        mock_job_response = Mock()
        mock_job_response.json.return_value = {"job_id": 789, "msg": "Job added"}
        mock_job_response.raise_for_status = Mock()

        # Configure session mock
        api.session.get.return_value = mock_customers_response
        api.session.post.side_effect = [mock_upload_response, mock_job_response]

        # Step 1: Get test customer
        print("\n[Step 1] Getting test customer...")
        customers_result = api.list_customers()
        test_customer = customers_result["customers"][0]
        customer_id = test_customer["id"]
        print(f"  ✓ Using customer ID: {customer_id} ({test_customer['name']})")

        # Step 2: Upload hashfile
        print("\n[Step 2] Uploading hashfile...")
        hash_type = 1000  # NTLM
        file_format = 5  # hash_only
        hashfile_name = "test_hashfile_automated"

        upload_result = api.upload_hashfile(
            test_hashfile, customer_id, hash_type, file_format, hashfile_name
        )

        hashfile_id = upload_result["hashfile_id"]
        print(f"  ✓ Hashfile ID: {hashfile_id}")

        # Step 3: Create job
        print("\n[Step 3] Creating job...")
        job_name = "test_job_automated"

        job_result = api.create_job(
            name=job_name, hashfile_id=hashfile_id, customer_id=customer_id
        )

        assert job_result is not None, "No job result returned"
        print("  ✓ Job created successfully")

        if "job_id" in job_result:
            print(f"  ✓ Job ID: {job_result['job_id']}")

        print("\n" + "=" * 60)
        print("✓ Option 2 (Create Job) is READY and WORKING!")
        print("=" * 60)

    def test_start_job_uses_post(self, api):
        """start_job must POST to /v1/jobs/start/<id> (the route is POST-only)."""
        mock_response = Mock()
        mock_response.json.return_value = {"status": 200, "msg": "Job started"}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.start_job(42)

        assert result["msg"] == "Job started"
        api.session.post.assert_called_once_with(f"{HASHVIEW_URL}/v1/jobs/start/42")
        api.session.get.assert_not_called()

    def test_delete_job_uses_delete_verb(self, api):
        """delete_job must use DELETE /v1/jobs/<id> (there is no /jobs/delete/)."""
        mock_response = Mock()
        mock_response.json.return_value = {"status": 200, "msg": "Job deleted"}
        mock_response.raise_for_status = Mock()
        api.session.delete.return_value = mock_response

        result = api.delete_job(7)

        assert result["msg"] == "Job deleted"
        api.session.delete.assert_called_once_with(f"{HASHVIEW_URL}/v1/jobs/7")

    def test_stop_job_not_supported(self, api):
        """Hashview has no stop-job route, so stop_job raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            api.stop_job(7)

    def test_create_job_with_new_customer_live(self, test_hashfile_for_live):
        """Live Hashview: new customer -> hashfile upload -> job -> start -> delete.

        Deliberately does not take the ``api`` fixture — see ``_live_api``.
        """
        real_api = self._live_api()
        hash_type = os.environ.get("HASHVIEW_HASH_TYPE", "1000")
        hashfile = test_hashfile_for_live(hash_type)
        customer_name = f"Example Customer {uuid.uuid4().hex[:8]}"

        try:
            customer_result = real_api.create_customer(customer_name)
            customer_id = customer_result.get("customer_id") or customer_result.get(
                "id"
            )
            assert customer_id, f"no customer id in response: {customer_result!r}"

            upload_result = real_api.upload_hashfile(
                hashfile,
                int(customer_id),
                int(hash_type),
                5,
                "test_hashfile_new_customer",
            )
            hashfile_id = upload_result.get("hashfile_id")
            assert hashfile_id, f"no hashfile_id in response: {upload_result!r}"

            job_result = real_api.create_job(
                name=f"test_job_new_customer_{uuid.uuid4().hex[:6]}",
                hashfile_id=hashfile_id,
                customer_id=int(customer_id),
            )
            assert isinstance(job_result, dict), (
                f"expected a JSON object, got {job_result!r}"
            )
            assert "job_id" in job_result, f"job creation failed: {job_result!r}"
            job_id = job_result["job_id"]

            assert real_api.start_job(job_id).get("job_id") == job_id
            # Hashview has no stop-job route; the client must say so.
            with pytest.raises(NotImplementedError):
                real_api.stop_job(job_id)
            assert real_api.delete_job(job_id).get("job_id") == job_id
        except requests.RequestException as exc:
            pytest.skip(f"Hashview job workflow request failed: {exc}")

    def test_create_job_with_new_customer(self, api, test_hashfile):
        """New customer -> hashfile upload -> job creation (mocked transport)."""
        mock_create_customer = Mock()
        mock_create_customer.json.return_value = {
            "customer_id": 101,
            "msg": "Customer added",
        }
        mock_create_customer.raise_for_status = Mock()

        mock_upload_hashfile = Mock()
        mock_upload_hashfile.json.return_value = {
            "hashfile_id": 202,
            "msg": "Hashfile added",
        }
        mock_upload_hashfile.raise_for_status = Mock()

        mock_create_job = Mock()
        mock_create_job.json.return_value = {"job_id": 303, "msg": "Job added"}
        mock_create_job.raise_for_status = Mock()

        api.session.post.side_effect = [
            mock_create_customer,
            mock_upload_hashfile,
            mock_create_job,
        ]

        customer_result = api.create_customer("Example Customer")
        assert customer_result.get("customer_id") == 101
        upload_result = api.upload_hashfile(
            test_hashfile, 101, 1000, 5, "test_hashfile_new_customer"
        )
        assert upload_result.get("hashfile_id") == 202
        job_result = api.create_job("test_job_new_customer", 202, 101)
        assert job_result.get("job_id") == 303

    def test_file_format_detection(self, tmp_path):
        """Test auto-detection of hashfile formats"""
        # Test pwdump format (4+ colons)
        pwdump_file = tmp_path / "pwdump.txt"
        pwdump_file.write_text(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )

        # Test user:hash format (2 parts, non-hex username)
        userhash_file = tmp_path / "userhash.txt"
        userhash_file.write_text(f"user123:{MD5_A}\n")

        # Test hash_only format (default)
        hashonly_file = tmp_path / "hashonly.txt"
        hashonly_file.write_text(f"{MD5_A}\n")

        # Test hex:hash format (should be hash_only since first part is all hex)
        hexhash_file = tmp_path / "hexhash.txt"
        hexhash_file.write_text(f"abcdef123456:{MD5_A}\n")

        # Detection logic (same as in main.py)
        def detect_format(filepath):
            file_format = 5  # Default to hash_only
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline().strip()
                    if first_line:
                        parts = first_line.split(":")
                        if len(parts) >= 4:
                            file_format = 0  # pwdump
                        elif len(parts) == 2 and not all(
                            c in "0123456789abcdefABCDEF" for c in parts[0]
                        ):
                            file_format = 4  # user:hash
            except Exception:
                file_format = 5
            return file_format

        # Verify detection
        assert detect_format(pwdump_file) == 0, "Should detect pwdump format"
        assert detect_format(userhash_file) == 4, "Should detect user:hash format"
        assert detect_format(hashonly_file) == 5, "Should detect hash_only format"
        assert detect_format(hexhash_file) == 5, "hex:hash should default to hash_only"

    def test_download_left_with_auto_merge(self, api, tmp_path, monkeypatch):
        """Test that download_left automatically downloads and splits found hashes for hashcat"""
        # Use a different CWD than the output directory to ensure merging uses
        # output_file's directory (not os.getcwd()).
        other_cwd = tmp_path / "other_cwd"
        other_cwd.mkdir()
        monkeypatch.chdir(other_cwd)

        # Mock left hashes download
        mock_left_response = Mock()
        mock_left_response.content = b"uncracked_hash1\nuncracked_hash2\n"
        mock_left_response.raise_for_status = Mock()
        mock_left_response.headers = {"content-length": "0"}

        def iter_content_left(chunk_size=8192):
            yield mock_left_response.content

        mock_left_response.iter_content = iter_content_left

        # Mock found hashes download
        mock_found_response = Mock()
        mock_found_response.content = (
            b"found_hash1:found_password1\nfound_hash2:found_password2\n"
        )
        mock_found_response.raise_for_status = Mock()
        mock_found_response.headers = {"content-length": "0"}

        def iter_content_found(chunk_size=8192):
            yield mock_found_response.content

        mock_found_response.iter_content = iter_content_found

        # Set up session.get to return different responses
        api.session.get.side_effect = [mock_left_response, mock_found_response]

        # Mock potfile path so cleanup isn't blocked by missing ~/.hashcat dir
        potfile = str(tmp_path / "hashcat.potfile")
        monkeypatch.setattr("hate_crack.api.get_hcat_potfile_path", lambda: potfile)

        # Download left hashes (should auto-download and split found for hashcat)
        left_file = tmp_path / "left_1_2.txt"
        result = api.download_left_hashes(1, 2, output_file=str(left_file))

        # Verify left file was created
        assert os.path.exists(result["output_file"])

        # Verify left file contains the full original hashlist (left + found)
        with open(result["output_file"], "r") as f:
            left_contents = f.read()
        assert "found_hash1\n" in left_contents, (
            "Found hashes must be appended as hash-only lines"
        )
        assert "found_password1" not in left_contents, (
            "Plaintext passwords must not appear in the left file"
        )
        assert "found_hash2\n" in left_contents, (
            "Found hashes must be appended as hash-only lines"
        )
        assert "found_password2" not in left_contents, (
            "Plaintext passwords must not appear in the left file"
        )
        assert "uncracked_hash1" in left_contents
        assert "uncracked_hash2" in left_contents

        # Verify found files are cleaned up after merge
        found_file = tmp_path / "found_1_2.txt"
        assert not os.path.exists(found_file), (
            "Found file should be deleted after merge"
        )

        found_hashes_file = tmp_path / "found_hashes_1_2.txt"
        found_clears_file = tmp_path / "found_clears_1_2.txt"
        assert not os.path.exists(str(found_hashes_file)), (
            "Split hashes file should be deleted after merge"
        )
        assert not os.path.exists(str(found_clears_file)), (
            "Split clears file should be deleted after merge"
        )

        # Verify potfile received the found hash:plaintext pairs
        with open(potfile, "r") as f:
            potfile_contents = f.read()
        assert "found_hash1:found_password1" in potfile_contents
        assert "found_hash2:found_password2" in potfile_contents

    def test_download_left_rsplit_ntlmv2(self, api, tmp_path, monkeypatch):
        """rsplit correctly extracts the full NTLMv2 hash (which contains colons) from a found line."""
        potfile = str(tmp_path / "hashcat.potfile")
        monkeypatch.setattr("hate_crack.api.get_hcat_potfile_path", lambda: potfile)

        ntlmv2_hash = "alice::DOMAIN:aabbccdd:ntproofstr:blob"
        ntlmv2_found_line = f"{ntlmv2_hash}:s3cr3t\n"

        mock_left = Mock()
        mock_left.content = b"some_other_hash\n"
        mock_left.raise_for_status = Mock()
        mock_left.headers = {"content-length": "0"}
        mock_left.iter_content = lambda chunk_size=8192: iter([mock_left.content])

        mock_found = Mock()
        mock_found.content = ntlmv2_found_line.encode()
        mock_found.raise_for_status = Mock()
        mock_found.headers = {"content-length": "0"}
        mock_found.iter_content = lambda chunk_size=8192: iter([mock_found.content])
        mock_found.status_code = 200

        api.session.get.side_effect = [mock_left, mock_found]

        left_file = tmp_path / "left_1_2.txt"
        api.download_left_hashes(1, 2, output_file=str(left_file))

        with open(str(left_file), "r") as f:
            contents = f.read()

        assert ntlmv2_hash + "\n" in contents, (
            "Full NTLMv2 hash (with colons) must be appended to the left file"
        )
        assert "s3cr3t" not in contents, (
            "Plaintext password must not appear in the left file"
        )

    def test_download_left_hex_wraps_non_utf8_plaintext(
        self, api, tmp_path, monkeypatch
    ):
        """A non-UTF-8 plaintext byte survives to the potfile as $HEX[...].

        A lossy decode would drop the byte and persist a plaintext that no
        longer hashes to the stored hash.
        """
        potfile = str(tmp_path / "hashcat.potfile")
        monkeypatch.setattr("hate_crack.api.get_hcat_potfile_path", lambda: potfile)

        plain_bytes = b"abc\xffdef"
        found_line = b"found_hash1:" + plain_bytes + b"\n"

        mock_left = Mock()
        mock_left.content = b"uncracked_hash1\n"
        mock_left.raise_for_status = Mock()
        mock_left.headers = {"content-length": "0"}
        mock_left.iter_content = lambda chunk_size=8192: iter([mock_left.content])

        mock_found = Mock()
        mock_found.content = found_line
        mock_found.raise_for_status = Mock()
        mock_found.headers = {"content-length": "0"}
        mock_found.iter_content = lambda chunk_size=8192: iter([mock_found.content])
        mock_found.status_code = 200

        api.session.get.side_effect = [mock_left, mock_found]

        left_file = tmp_path / "left_1_2.txt"
        api.download_left_hashes(1, 2, output_file=str(left_file))

        with open(potfile, "r", encoding="utf-8") as f:
            contents = f.read()

        expected = "found_hash1:$HEX[" + plain_bytes.hex() + "]"
        assert expected in contents, (
            "Non-UTF-8 plaintext must be hex-wrapped, not silently altered"
        )
        assert "abcdef" not in contents, (
            "The lossy decode of the plaintext must not reach the potfile"
        )

    def test_download_left_potfile_path_param_overrides_config(self, api, tmp_path):
        """Test that a passed-in potfile_path is used instead of re-reading config."""
        mock_left_response = Mock()
        mock_left_response.content = b"hash1\n"
        mock_left_response.raise_for_status = Mock()
        mock_left_response.headers = {"content-length": "0"}
        mock_left_response.iter_content = lambda chunk_size=8192: iter(
            [mock_left_response.content]
        )

        mock_found_response = Mock()
        mock_found_response.content = b"found_hash:plaintext\n"
        mock_found_response.raise_for_status = Mock()
        mock_found_response.headers = {"content-length": "0"}
        mock_found_response.iter_content = lambda chunk_size=8192: iter(
            [mock_found_response.content]
        )

        api.session.get.side_effect = [mock_left_response, mock_found_response]

        explicit_potfile = str(tmp_path / "explicit.potfile")
        other_potfile = str(tmp_path / "other.potfile")

        left_file = tmp_path / "left_1_2.txt"
        # Pass potfile_path explicitly - config-derived path should NOT be used
        with patch("hate_crack.api.get_hcat_potfile_path", return_value=other_potfile):
            api.download_left_hashes(
                1, 2, output_file=str(left_file), potfile_path=explicit_potfile
            )

        assert os.path.exists(explicit_potfile), "Explicit potfile should be written"
        assert not os.path.exists(other_potfile), (
            "Config-derived potfile should NOT be written"
        )
        with open(explicit_potfile, "r") as f:
            assert "found_hash:plaintext" in f.read()

    def test_download_left_id_matching(self, api, tmp_path):
        """Test that found hashes only merge when customer_id and hashfile_id match"""
        # Create .out file with specific IDs
        out_file = tmp_path / "left_1_2.txt.out"
        out_file.write_text("existing_hash:existing_plaintext\n")

        # Mock left hashes download for different IDs
        mock_response = Mock()
        mock_response.content = b"hash1\nhash2\n"
        mock_response.raise_for_status = Mock()
        mock_response.headers = {"content-length": "0"}

        def iter_content(chunk_size=8192):
            yield mock_response.content

        mock_response.iter_content = iter_content
        api.session.get.return_value = mock_response

        # Download left hashes with different IDs (3_4 instead of 1_2)
        left_file = tmp_path / "left_3_4.txt"
        api.download_left_hashes(3, 4, output_file=str(left_file))

        # Verify the different IDs' .out file wasn't affected
        with open(str(out_file), "r") as f:
            content = f.read()
        assert content == "existing_hash:existing_plaintext\n", (
            "Different ID's .out file should be unchanged"
        )

    def test_download_left_tolerates_missing_found(self, api, tmp_path):
        """Test that 404 on found hash download doesn't fail the workflow"""
        # Mock successful left download
        mock_left_response = Mock()
        mock_left_response.content = b"hash1\nhash2\n"
        mock_left_response.raise_for_status = Mock()
        mock_left_response.headers = {"content-length": "0"}

        def iter_content(chunk_size=8192):
            yield mock_left_response.content

        mock_left_response.iter_content = iter_content

        # Mock 404 response for found download
        from requests.exceptions import HTTPError

        mock_found_response = Mock()
        mock_found_response.status_code = 404

        def raise_404():
            response = Mock()
            response.status_code = 404
            raise HTTPError("404 Not Found", response=response)

        mock_found_response.raise_for_status = raise_404

        # Set up session.get to return different responses
        api.session.get.side_effect = [mock_left_response, mock_found_response]

        # Download left hashes (should complete despite 404 on found)
        left_file = tmp_path / "left_1_2.txt"
        result = api.download_left_hashes(1, 2, output_file=str(left_file))

        # Verify left file was created successfully
        assert os.path.exists(result["output_file"])
        with open(result["output_file"], "rb") as f:
            content = f.read()
        assert content == b"hash1\nhash2\n"

    def test_hashfile_orig_path_preservation(self, tmp_path, monkeypatch):
        """Test that _ensure_hashfile_in_cwd is a pass-through returning the input path."""
        from hate_crack.main import _ensure_hashfile_in_cwd

        # Create a test hashfile in a different directory
        test_dir = tmp_path / "subdir"
        test_dir.mkdir()
        test_file = test_dir / "test.txt"
        test_file.write_text("hash1\nhash2\n")

        original_path = str(test_file)

        # Set HATE_CRACK_ORIG_CWD so _ensure_hashfile_in_cwd targets tmp_path
        monkeypatch.setenv("HATE_CRACK_ORIG_CWD", str(tmp_path))

        # Call _ensure_hashfile_in_cwd
        result_path = _ensure_hashfile_in_cwd(original_path)

        assert result_path == original_path, "Pass-through should return the input path"
        assert os.path.exists(original_path), "Original file should still exist"


def test_download_left_hashes_has_no_hash_type_parameter():
    """hash_type was accepted from two call sites and never used (issue #204)."""
    import inspect

    sig = inspect.signature(HashviewAPI.download_left_hashes)
    assert "hash_type" not in sig.parameters


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
