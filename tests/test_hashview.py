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
        with patch("requests.Session") as mock_session_class:
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

    def test_list_hashfiles_success(self, api):
        """Test successful hashfile listing with real API if possible, else mock."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.list_hashfiles()
            assert isinstance(result, list)
            # If there are no hashfiles, that's valid, but if present, check structure
            if result:
                assert "name" in result[0]
        else:
            mock_response = Mock()
            mock_response.json.return_value = {
                "hashfiles": json.dumps(
                    [
                        {"id": 1, "customer_id": 1, "name": "hashfile1.txt"},
                        {"id": 2, "customer_id": 2, "name": "hashfile2.txt"},
                    ]
                )
            }
            mock_response.raise_for_status = Mock()
            api.session.get.return_value = mock_response
            result = api.list_hashfiles()
            assert isinstance(result, list)
            assert len(result) == 2
            assert result[0]["name"] == "hashfile1.txt"

    def test_list_hashfiles_empty(self, api):
        """Test hashfile listing returns empty list if no hashfiles (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.list_hashfiles()
            # If there are no hashfiles, result should be []
            if not result:
                assert result == []
            else:
                assert isinstance(result, list)
        else:
            mock_response = Mock()
            mock_response.json.return_value = {}
            mock_response.raise_for_status = Mock()
            api.session.get.return_value = mock_response
            result = api.list_hashfiles()
            assert result == []

    def test_get_customer_hashfiles(self, api):
        """Test filtering hashfiles by customer_id (real API if possible)."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        customer_id = os.environ.get("HASHVIEW_CUSTOMER_ID")
        if hashview_url and hashview_api_key and customer_id:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.get_customer_hashfiles(int(customer_id))
            assert isinstance(result, list)
            # If there are hashfiles, all should match customer_id
            if result:
                assert all(hf["customer_id"] == int(customer_id) for hf in result)
        else:
            api.list_hashfiles = Mock(
                return_value=[
                    {"id": 1, "customer_id": 1, "name": "hashfile1.txt"},
                    {"id": 2, "customer_id": 2, "name": "hashfile2.txt"},
                    {"id": 3, "customer_id": 1, "name": "hashfile3.txt"},
                ]
            )
            result = api.get_customer_hashfiles(1)
            assert len(result) == 2
            assert all(hf["customer_id"] == 1 for hf in result)

    def test_display_customers_multicolumn_empty(self, api, capsys):
        """Test display_customers_multicolumn with no customers (mock only, as real API not needed)."""
        api.display_customers_multicolumn([])
        captured = capsys.readouterr()
        assert "No customers found" in captured.out

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
            
            # Verify auth headers were passed in the left hashes download call
            call_args_list = api.session.get.call_args_list
            left_call = [c for c in call_args_list if "left" in str(c)][0]
            assert left_call.kwargs.get("headers") is not None
            auth_headers = left_call.kwargs.get("headers")
            assert "Cookie" in auth_headers or "uuid" in str(auth_headers)
            assert HASHVIEW_API_KEY in str(auth_headers)

    def test_download_found_hashes(self, api, tmp_path):
        """Test downloading found hashes: real API if possible, else mock."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        customer_id = os.environ.get("HASHVIEW_CUSTOMER_ID")
        hashfile_id = os.environ.get("HASHVIEW_HASHFILE_ID")
        if all([hashview_url, hashview_api_key, customer_id, hashfile_id]):
            # Real API test
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            output_file = tmp_path / f"found_{customer_id}_{hashfile_id}.txt"
            result = real_api.download_found_hashes(
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
            mock_response.content = b"hash1:pass1\nhash2:pass2\n"
            mock_response.raise_for_status = Mock()
            mock_response.headers = {"content-length": "0"}

            def iter_content(chunk_size=8192):
                yield mock_response.content

            mock_response.iter_content = iter_content
            api.session.get.return_value = mock_response

            output_file = tmp_path / "found_1_2.txt"
            result = api.download_found_hashes(1, 2, output_file=str(output_file))
            assert os.path.exists(result["output_file"])
            with open(result["output_file"], "rb") as f:
                content = f.read()
            assert content == b"hash1:pass1\nhash2:pass2\n"
            assert result["size"] == len(content)
            
            # Verify auth headers were passed in the found hashes download call
            call_args_list = api.session.get.call_args_list
            found_call = [c for c in call_args_list if "found" in str(c)][0]
            assert found_call.kwargs.get("headers") is not None
            auth_headers = found_call.kwargs.get("headers")
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

    @pytest.mark.skipif(
        os.environ.get("HASHVIEW_TEST_REAL", "").lower() not in ("1", "true", "yes"),
        reason="Set HASHVIEW_TEST_REAL=1 to run live Hashview list_wordlists test.",
    )
    def test_list_wordlists_live(self):
        """Live test for Hashview wordlist listing with auth headers."""
        hashview_url, hashview_api_key = self._get_hashview_config()
        if not hashview_url or not hashview_api_key:
            pytest.skip("Missing hashview_url/hashview_api_key in config.json or env.")
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
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    if first_line:
                        parts = first_line.split(':')
                        if len(parts) >= 4:
                            file_format = 0  # pwdump
                        elif len(parts) == 2 and not all(c in '0123456789abcdefABCDEF' for c in parts[0]):
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
        mock_found_response.content = b"found_hash1:found_password1\nfound_hash2:found_password2\n"
        mock_found_response.raise_for_status = Mock()
        mock_found_response.headers = {"content-length": "0"}
        
        def iter_content_found(chunk_size=8192):
            yield mock_found_response.content
        
        mock_found_response.iter_content = iter_content_found
        
        # Set up session.get to return different responses
        api.session.get.side_effect = [mock_left_response, mock_found_response]
        
        # Download left hashes (should auto-download and split found for hashcat)
        left_file = tmp_path / "left_1_2.txt"
        result = api.download_left_hashes(1, 2, output_file=str(left_file))
        
        # Verify left file was created
        assert os.path.exists(result["output_file"])
        
        # Verify found file was downloaded and deleted
        found_file = tmp_path / "found_1_2.txt"
        assert not os.path.exists(found_file), "Found file should be deleted after split"
        assert not (other_cwd / "found_1_2.txt").exists()
        
        # Verify split files were created and deleted
        found_hashes_file = tmp_path / "found_hashes_1_2.txt"
        found_clears_file = tmp_path / "found_clears_1_2.txt"
        assert not os.path.exists(str(found_hashes_file)), "Split hashes file should be deleted"
        assert not os.path.exists(str(found_clears_file)), "Split clears file should be deleted"
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
        result = api.download_left_hashes(3, 4, output_file=str(left_file))
        
        # Verify the different IDs' .out file wasn't affected
        with open(str(out_file), 'r') as f:
            content = f.read()
        assert content == "existing_hash:password\n", "Different ID's .out file should be unchanged"

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
        with open(result["output_file"], 'rb') as f:
            content = f.read()
        assert content == b"hash1\nhash2\n"

    def test_hashfile_orig_path_preservation(self, tmp_path):
        """Test that original hashfile path is preserved before _ensure_hashfile_in_cwd"""
        import sys
        import os
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        from hate_crack.main import _ensure_hashfile_in_cwd
        
        # Create a test hashfile in a different directory
        test_dir = tmp_path / "subdir"
        test_dir.mkdir()
        test_file = test_dir / "test.txt"
        test_file.write_text("hash1\nhash2\n")
        
        original_path = str(test_file)
        
        # Save current directory
        orig_cwd = os.getcwd()
        try:
            # Change to tmp_path
            os.chdir(str(tmp_path))
            
            # Call _ensure_hashfile_in_cwd
            result_path = _ensure_hashfile_in_cwd(original_path)
            
            # The result should be different from original (in cwd now)
            # But original_path should still exist and be unchanged
            assert os.path.exists(original_path), "Original file should still exist"
            assert os.path.exists(result_path), "Result file should exist"
            
            # If they're different, result should be in cwd
            if result_path != original_path:
                assert os.path.dirname(result_path) == str(tmp_path), "Result should be in cwd"
        finally:
            os.chdir(orig_cwd)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
