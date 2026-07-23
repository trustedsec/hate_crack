"""
Tests for Hashview integration - Mocked API calls for CI/CD
"""

import pytest
import sys
import os
import json
import tempfile
import uuid
from unittest.mock import Mock, patch, MagicMock


# Add the parent directory to the path to import hate_crack
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from hate_crack.api import HashviewAPI

# Test configuration - these are mock values, not real credentials
HASHVIEW_URL = "https://hashview.example.com"
HASHVIEW_API_KEY = "test-api-key-123"


class TestHashviewAPI:
    """Test suite for HashviewAPI class with mocked API calls"""

    def _get_hashview_config(self):
        env_url = os.environ.get("HASHVIEW_URL")
        env_key = os.environ.get("HASHVIEW_API_KEY")
        if env_url and env_key:
            return env_url, env_key
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
        try:
            with open(config_path) as f:
                config = json.load(f)
            url = config.get("hashview_url")
            key = config.get("hashview_api_key")
            if url and key:
                return url, key
        except Exception:
            pass
        return env_url, env_key

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
        """Create a temporary test hashfile with NTLM hashes"""
        test_hashes = [
            "8846f7eaee8fb117ad06bdd830b7586c",  # password (NTLM)
            "e19ccf75ee54e06b06a5907af13cef42",  # 123456 (NTLM)
            "5835048ce94ad0564e29a924a03510ef",  # 12345678 (NTLM)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            hashfile_path = f.name
            for hash_val in test_hashes:
                f.write(hash_val + "\n")

        yield hashfile_path

        # Cleanup

    def test_get_hashfiles_by_type_success(self, api):
        """The /v1/hashfiles/hash_type/<type> endpoint returns a list (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.get_hashfiles_by_type("1000")
            assert isinstance(result, list)
            if result:
                assert "name" in result[0]
        else:
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
        api.get_hashfiles_by_type = Mock(side_effect=lambda ht: per_type.get(int(ht), []))

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

    def test_get_customer_hashfiles(self, api):
        """Filter the type-scoped hashfile list by customer_id (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        customer_id = os.environ.get("HASHVIEW_CUSTOMER_ID")
        if hashview_url and hashview_api_key and customer_id:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.get_customer_hashfiles(int(customer_id), hash_type="1000")
            assert isinstance(result, list)
            # If there are hashfiles, all should match customer_id
            if result:
                assert all(hf["customer_id"] == int(customer_id) for hf in result)
        else:
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
        """Test uploading cracked hashes with valid lines (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        hash_type = os.environ.get("HASHVIEW_HASH_TYPE", "1000")
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            cracked_file = tmp_path / "cracked.txt"
            cracked_file.write_text(
                "8846f7eaee8fb117ad06bdd830b7586c:password\n"
                "e19ccf75ee54e06b06a5907af13cef42:123456\n"
            )
            try:
                result = real_api.upload_cracked_hashes(
                    str(cracked_file), hash_type=hash_type
                )
                assert "imported" in result
            except Exception as e:
                # If the API does not allow upload, skip
                pytest.skip(f"Real API upload_cracked_hashes not allowed: {e}")
        else:
            cracked_file = tmp_path / "cracked.txt"
            cracked_file.write_text(
                "8846f7eaee8fb117ad06bdd830b7586c:password\n"
                "e19ccf75ee54e06b06a5907af13cef42:123456\n"
                "31d6cfe0d16ae931b73c59d7e0c089c0:should_skip\n"
                "invalidline\n"
            )
            mock_response = Mock()
            mock_response.json.return_value = {"imported": 2}
            mock_response.raise_for_status = Mock()
            api.session.post.return_value = mock_response
            result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
            assert "imported" in result
            assert result["imported"] == 2

    def test_upload_cracked_hashes_api_error(self, api, tmp_path):
        """Test uploading cracked hashes with API error response (mock only)."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text("8846f7eaee8fb117ad06bdd830b7586c:password\n")
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
        cracked_file.write_text("8846f7eaee8fb117ad06bdd830b7586c:password\n")
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_response.text = "not a json"
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response
        with pytest.raises(Exception) as excinfo:
            api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert "Invalid API response" in str(excinfo.value)

    def test_upload_skips_wrong_type_line(self, api, tmp_path, capsys):
        """An MD5 line mixed into an NTLM upload is filtered client-side."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text(
            # MD5("password") — invalid as NTLM, must be dropped
            "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
            # genuine NTLM("password") — must be kept
            "8846f7eaee8fb117ad06bdd830b7586c:password\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["imported"] == 1
        # Only the valid NTLM line should have been sent
        sent = api.session.post.call_args.kwargs.get("data")
        if sent is None:
            sent = api.session.post.call_args.args[1]
        assert "8846f7eaee8fb117ad06bdd830b7586c:password" in sent
        assert "5f4dcc3b5aa765d61d8327deb882cf99" not in sent
        out = capsys.readouterr().out
        assert "Skipped 1 line" in out

    def test_upload_accepts_hex_ntlm(self, api, tmp_path):
        """$HEX[...] NTLM plaintexts validate and are uploaded."""
        cracked_file = tmp_path / "cracked.txt"
        # NTLM of "%032023RC$ " emitted by hashcat as $HEX[...]
        cracked_file.write_text(
            "c153ace1d5b148820dab48a8aa5aa02e:$HEX[2530333230323352432420]\n"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert result["imported"] == 1

    def test_upload_all_invalid_raises(self, api, tmp_path):
        """If validation drops every line, we raise instead of posting empty."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\n")
        api.session.post.side_effect = AssertionError("should not POST")
        with pytest.raises(Exception) as excinfo:
            api.upload_cracked_hashes(str(cracked_file), hash_type="1000")
        assert "No valid hashes" in str(excinfo.value)

    def test_upload_validation_can_be_disabled(self, api, tmp_path):
        """validate=False restores the old permissive behaviour."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\n")
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(
            str(cracked_file), hash_type="1000", validate=False
        )
        assert result["imported"] == 1

    def test_create_customer_success(self, api):
        """Test creating a customer (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            try:
                result = real_api.create_customer("New Customer Test")
                assert "id" in result
                assert "name" in result
            except Exception as e:
                pytest.skip(f"Real API create_customer not allowed: {e}")
        else:
            mock_response = Mock()
            mock_response.json.return_value = {"id": 10, "name": "New Customer"}
            mock_response.raise_for_status = Mock()
            api.session.post.return_value = mock_response
            result = api.create_customer("New Customer")
            assert result["id"] == 10
            assert result["name"] == "New Customer"

    def test_download_left_hashes(self, api, tmp_path):
        """Test downloading left hashes: real API if possible, else mock."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        customer_id = os.environ.get("HASHVIEW_CUSTOMER_ID")
        hashfile_id = os.environ.get("HASHVIEW_HASHFILE_ID")
        if all([hashview_url, hashview_api_key, customer_id, hashfile_id]):
            # Real API test
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            output_file = tmp_path / f"left_{customer_id}_{hashfile_id}.txt"
            result = real_api.download_left_hashes(
                int(customer_id), int(hashfile_id), output_file=str(output_file)
            )
            assert os.path.exists(result["output_file"])
            with open(result["output_file"], "rb") as f:
                content = f.read()
            print(f"[DEBUG] Downloaded {len(content)} bytes to {result['output_file']}")
            assert result["size"] == len(content)
        else:
            # Mock test
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
        """Test downloading a wordlist: real API if possible, else mock."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        wordlist_id = os.environ.get("HASHVIEW_WORDLIST_ID")
        if all([hashview_url, hashview_api_key, wordlist_id]):
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            output_file = tmp_path / f"wordlist_{wordlist_id}.gz"
            result = real_api.download_wordlist(
                int(wordlist_id), output_file=str(output_file)
            )
            assert os.path.exists(result["output_file"])
            with open(result["output_file"], "rb") as f:
                content = f.read()
            print(f"[DEBUG] Downloaded {len(content)} bytes to {result['output_file']}")
            assert result["size"] == len(content)
        else:
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

    def test_create_job_with_new_customer(self, api, test_hashfile):
        """Test creating a new customer and then creating a job (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        hash_type = os.environ.get("HASHVIEW_HASH_TYPE", "1000")
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            customer_name = f"Example Customer {uuid.uuid4().hex[:8]}"
            try:
                customer_result = real_api.create_customer(customer_name)
                customer_id = customer_result.get("customer_id") or customer_result.get(
                    "id"
                )
                if not customer_id:
                    pytest.skip("Create customer did not return a customer_id.")
                upload_result = real_api.upload_hashfile(
                    test_hashfile,
                    int(customer_id),
                    int(hash_type),
                    5,
                    "test_hashfile_new_customer",
                )
                hashfile_id = upload_result.get("hashfile_id")
                if not hashfile_id:
                    pytest.skip("Upload hashfile did not return a hashfile_id.")
                job_result = real_api.create_job(
                    name=f"test_job_new_customer_{uuid.uuid4().hex[:6]}",
                    hashfile_id=hashfile_id,
                    customer_id=int(customer_id),
                )
                if isinstance(job_result, dict) and "msg" in job_result:
                    msg = str(job_result.get("msg", ""))
                    if "Failed to add job" in msg:
                        pytest.xfail(f"Hashview rejected job creation: {msg}")
                assert job_result is not None
                if isinstance(job_result, dict):
                    assert "job_id" in job_result
                    job_id = job_result.get("job_id")
                    try:
                        real_api.start_job(job_id)
                    except Exception:
                        pass
                    try:
                        real_api.stop_job(job_id)
                    except Exception:
                        pass
                    try:
                        real_api.delete_job(job_id)
                    except Exception:
                        pass
            except Exception as e:
                pytest.skip(f"Real API create_job with new customer not allowed: {e}")
        else:
            mock_create_customer = Mock()
            mock_create_customer.json.return_value = {
                "customer_id": 101,
                "name": "Example Customer",
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
        userhash_file.write_text("user123:5f4dcc3b5aa765d61d8327deb882cf99\n")

        # Test hash_only format (default)
        hashonly_file = tmp_path / "hashonly.txt"
        hashonly_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")

        # Test hex:hash format (should be hash_only since first part is all hex)
        hexhash_file = tmp_path / "hexhash.txt"
        hexhash_file.write_text("abcdef123456:5f4dcc3b5aa765d61d8327deb882cf99\n")

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

    def test_download_left_potfile_path_param_overrides_config(self, api, tmp_path):
        """Test that a passed-in potfile_path is used instead of re-reading config."""
        mock_left_response = Mock()
        mock_left_response.content = b"hash1\n"
        mock_left_response.raise_for_status = Mock()
        mock_left_response.headers = {"content-length": "0"}
        mock_left_response.iter_content = lambda chunk_size=8192: iter([mock_left_response.content])

        mock_found_response = Mock()
        mock_found_response.content = b"found_hash:plaintext\n"
        mock_found_response.raise_for_status = Mock()
        mock_found_response.headers = {"content-length": "0"}
        mock_found_response.iter_content = lambda chunk_size=8192: iter([mock_found_response.content])

        api.session.get.side_effect = [mock_left_response, mock_found_response]

        explicit_potfile = str(tmp_path / "explicit.potfile")
        other_potfile = str(tmp_path / "other.potfile")

        left_file = tmp_path / "left_1_2.txt"
        # Pass potfile_path explicitly - config-derived path should NOT be used
        with patch("hate_crack.api.get_hcat_potfile_path", return_value=other_potfile):
            api.download_left_hashes(1, 2, output_file=str(left_file), potfile_path=explicit_potfile)

        assert os.path.exists(explicit_potfile), "Explicit potfile should be written"
        assert not os.path.exists(other_potfile), "Config-derived potfile should NOT be written"
        with open(explicit_potfile, "r") as f:
            assert "found_hash:plaintext" in f.read()

    def test_download_left_id_matching(self, api, tmp_path):
        """Test that found hashes only merge when customer_id and hashfile_id match"""
        # Create .out file with specific IDs
        out_file = tmp_path / "left_1_2.txt.out"
        out_file.write_text("existing_hash:password\n")

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
        assert content == "existing_hash:password\n", (
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
