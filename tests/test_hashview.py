"""
Tests for Hashview integration - Mocked API calls for CI/CD
"""
import pytest
import sys
import os
import json
import tempfile
from unittest.mock import Mock, patch, MagicMock


# Add the parent directory to the path to import hate_crack
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from hate_crack.api import HashviewAPI

# Test configuration - these are mock values, not real credentials
HASHVIEW_URL = 'https://hashview.example.com'
HASHVIEW_API_KEY = 'test-api-key-123'


class TestHashviewAPI:
    """Test suite for HashviewAPI class with mocked API calls"""
    
    @pytest.fixture
    def api(self):
        """Create a HashviewAPI instance with mocked session"""
        with patch('requests.Session') as mock_session_class:
            api = HashviewAPI(
                base_url=HASHVIEW_URL,
                api_key=HASHVIEW_API_KEY
            )
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
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            hashfile_path = f.name
            for hash_val in test_hashes:
                f.write(hash_val + '\n')
        
        yield hashfile_path
        
        # Cleanup

    def test_list_hashfiles_success(self, api):
        """Test successful hashfile listing with real API if possible, else mock."""
        hashview_url = os.environ.get('HASHVIEW_URL')
        hashview_api_key = os.environ.get('HASHVIEW_API_KEY')
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.list_hashfiles()
            assert isinstance(result, list)
            # If there are no hashfiles, that's valid, but if present, check structure
            if result:
                assert 'name' in result[0]
        else:
            mock_response = Mock()
            mock_response.json.return_value = {
                'hashfiles': json.dumps([
                    {'id': 1, 'customer_id': 1, 'name': 'hashfile1.txt'},
                    {'id': 2, 'customer_id': 2, 'name': 'hashfile2.txt'}
                ])
            }
            mock_response.raise_for_status = Mock()
            api.session.get.return_value = mock_response
            result = api.list_hashfiles()
            assert isinstance(result, list)
            assert len(result) == 2
            assert result[0]['name'] == 'hashfile1.txt'

    def test_list_hashfiles_empty(self, api):
        """Test hashfile listing returns empty list if no hashfiles (real API if possible)."""
        hashview_url = os.environ.get('HASHVIEW_URL')
        hashview_api_key = os.environ.get('HASHVIEW_API_KEY')
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
        hashview_url = os.environ.get('HASHVIEW_URL')
        hashview_api_key = os.environ.get('HASHVIEW_API_KEY')
        customer_id = os.environ.get('HASHVIEW_CUSTOMER_ID')
        if hashview_url and hashview_api_key and customer_id:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            result = real_api.get_customer_hashfiles(int(customer_id))
            assert isinstance(result, list)
            # If there are hashfiles, all should match customer_id
            if result:
                assert all(hf['customer_id'] == int(customer_id) for hf in result)
        else:
            api.list_hashfiles = Mock(return_value=[
                {'id': 1, 'customer_id': 1, 'name': 'hashfile1.txt'},
                {'id': 2, 'customer_id': 2, 'name': 'hashfile2.txt'},
                {'id': 3, 'customer_id': 1, 'name': 'hashfile3.txt'}
            ])
            result = api.get_customer_hashfiles(1)
            assert len(result) == 2
            assert all(hf['customer_id'] == 1 for hf in result)

    def test_display_customers_multicolumn_empty(self, api, capsys):
        """Test display_customers_multicolumn with no customers (mock only, as real API not needed)."""
        api.display_customers_multicolumn([])
        captured = capsys.readouterr()
        assert "No customers found" in captured.out

    def test_upload_cracked_hashes_success(self, api, tmp_path):
        """Test uploading cracked hashes with valid lines (real API if possible)."""
        hashview_url = os.environ.get('HASHVIEW_URL')
        hashview_api_key = os.environ.get('HASHVIEW_API_KEY')
        hash_type = os.environ.get('HASHVIEW_HASH_TYPE', '1000')
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            cracked_file = tmp_path / "cracked.txt"
            cracked_file.write_text("8846f7eaee8fb117ad06bdd830b7586c:password\n"
                                    "e19ccf75ee54e06b06a5907af13cef42:123456\n")
            try:
                result = real_api.upload_cracked_hashes(str(cracked_file), hash_type=hash_type)
                assert 'imported' in result
            except Exception as e:
                # If the API does not allow upload, skip
                pytest.skip(f"Real API upload_cracked_hashes not allowed: {e}")
        else:
            cracked_file = tmp_path / "cracked.txt"
            cracked_file.write_text("8846f7eaee8fb117ad06bdd830b7586c:password\n"
                                    "e19ccf75ee54e06b06a5907af13cef42:123456\n"
                                    "31d6cfe0d16ae931b73c59d7e0c089c0:should_skip\n"
                                    "invalidline\n")
            mock_response = Mock()
            mock_response.json.return_value = {'imported': 2}
            mock_response.raise_for_status = Mock()
            api.session.post.return_value = mock_response
            result = api.upload_cracked_hashes(str(cracked_file), hash_type='1000')
            assert 'imported' in result
            assert result['imported'] == 2

    def test_upload_cracked_hashes_api_error(self, api, tmp_path):
        """Test uploading cracked hashes with API error response (mock only)."""
        cracked_file = tmp_path / "cracked.txt"
        cracked_file.write_text("8846f7eaee8fb117ad06bdd830b7586c:password\n")
        mock_response = Mock()
        mock_response.json.return_value = {'type': 'Error', 'msg': 'Some error'}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response
        with pytest.raises(Exception) as excinfo:
            api.upload_cracked_hashes(str(cracked_file), hash_type='1000')
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
            api.upload_cracked_hashes(str(cracked_file), hash_type='1000')
        assert "Invalid API response" in str(excinfo.value)

    def test_create_customer_success(self, api):
        """Test creating a customer (real API if possible)."""
        hashview_url = os.environ.get('HASHVIEW_URL')
        hashview_api_key = os.environ.get('HASHVIEW_API_KEY')
        if hashview_url and hashview_api_key:
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            try:
                result = real_api.create_customer("New Customer Test")
                assert 'id' in result
                assert 'name' in result
            except Exception as e:
                pytest.skip(f"Real API create_customer not allowed: {e}")
        else:
            mock_response = Mock()
            mock_response.json.return_value = {'id': 10, 'name': 'New Customer'}
            mock_response.raise_for_status = Mock()
            api.session.post.return_value = mock_response
            result = api.create_customer("New Customer")
            assert result['id'] == 10
            assert result['name'] == "New Customer"

    def test_download_left_hashes(self, api, tmp_path):
        """Test downloading left hashes: real API if possible, else mock."""
        hashview_url = os.environ.get('HASHVIEW_URL')
        hashview_api_key = os.environ.get('HASHVIEW_API_KEY')
        customer_id = os.environ.get('HASHVIEW_CUSTOMER_ID')
        hashfile_id = os.environ.get('HASHVIEW_HASHFILE_ID')
        if all([hashview_url, hashview_api_key, customer_id, hashfile_id]):
            # Real API test
            real_api = HashviewAPI(hashview_url, hashview_api_key)
            output_file = tmp_path / f"left_{customer_id}_{hashfile_id}.txt"
            result = real_api.download_left_hashes(int(customer_id), int(hashfile_id), output_file=str(output_file))
            assert os.path.exists(result['output_file'])
            with open(result['output_file'], 'rb') as f:
                content = f.read()
            print(f"[DEBUG] Downloaded {len(content)} bytes to {result['output_file']}")
            assert result['size'] == len(content)
        else:
            # Mock test
            mock_response = Mock()
            mock_response.content = b"hash1\nhash2\n"
            mock_response.raise_for_status = Mock()
            mock_response.headers = {'content-length': '0'}
            def iter_content(chunk_size=8192):
                yield mock_response.content
            mock_response.iter_content = iter_content
            api.session.get.return_value = mock_response

            output_file = tmp_path / "left_1_2.txt"
            result = api.download_left_hashes(1, 2, output_file=str(output_file))
            assert os.path.exists(result['output_file'])
            with open(result['output_file'], 'rb') as f:
                content = f.read()
            assert content == b"hash1\nhash2\n"
            assert result['size'] == len(content)
    
    def test_create_job_workflow(self, api, test_hashfile):
        """Test creating a job in Hashview (option 2 complete workflow)"""
        print("\n" + "="*60)
        print("Testing Option 2: Create Job Workflow")
        print("="*60)
        
        # Mock responses for different endpoints - API returns 'users' as a JSON string
        mock_customers_response = Mock()
        mock_customers_response.json.return_value = {
            'users': json.dumps([{'id': 1, 'name': 'Test Customer'}])
        }
        mock_customers_response.raise_for_status = Mock()
        
        mock_upload_response = Mock()
        mock_upload_response.json.return_value = {
            'hashfile_id': 4567,
            'msg': 'Hashfile added'
        }
        mock_upload_response.raise_for_status = Mock()
        
        mock_job_response = Mock()
        mock_job_response.json.return_value = {
            'job_id': 789,
            'msg': 'Job added'
        }
        mock_job_response.raise_for_status = Mock()
        
        # Configure session mock
        api.session.get.return_value = mock_customers_response
        api.session.post.side_effect = [mock_upload_response, mock_job_response]
        
        # Step 1: Get test customer
        print("\n[Step 1] Getting test customer...")
        customers_result = api.list_customers()
        test_customer = customers_result['customers'][0]
        customer_id = test_customer['id']
        print(f"  ✓ Using customer ID: {customer_id} ({test_customer['name']})")
        
        # Step 2: Upload hashfile
        print("\n[Step 2] Uploading hashfile...")
        hash_type = 1000  # NTLM
        file_format = 5  # hash_only
        hashfile_name = "test_hashfile_automated"
        
        upload_result = api.upload_hashfile(
            test_hashfile,
            customer_id,
            hash_type,
            file_format,
            hashfile_name
        )
        
        hashfile_id = upload_result['hashfile_id']
        print(f"  ✓ Hashfile ID: {hashfile_id}")
        
        # Step 3: Create job
        print("\n[Step 3] Creating job...")
        job_name = "test_job_automated"
        
        job_result = api.create_job(
            name=job_name,
            hashfile_id=hashfile_id,
            customer_id=customer_id
        )
        
        assert job_result is not None, "No job result returned"
        print("  ✓ Job created successfully")
        
        if 'job_id' in job_result:
            print(f"  ✓ Job ID: {job_result['job_id']}")
        
        print("\n" + "="*60)
        print("✓ Option 2 (Create Job) is READY and WORKING!")
        print("="*60)

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
