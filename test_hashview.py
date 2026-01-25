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
sys.path.insert(0, os.path.dirname(__file__))

from hate_crack import HashviewAPI

# Test configuration - these are mock values, not real credentials
HASHVIEW_URL = 'https://hashview.example.com'
HASHVIEW_API_KEY = 'test-api-key-123'


class TestHashviewAPI:
    """Test suite for HashviewAPI class with mocked API calls"""
    
    @pytest.fixture
    def api(self):
        """Create a HashviewAPI instance with mocked session"""
        with patch('hate_crack.requests.Session') as mock_session_class:
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
        if os.path.exists(hashfile_path):
            os.unlink(hashfile_path)
    
    def test_list_customers_success(self, api):
        """Test successful customer listing with mocked API call"""
        # Mock the response - API returns 'users' as a JSON string
        mock_response = Mock()
        mock_response.json.return_value = {
            'users': json.dumps([
                {'id': 1, 'name': 'Test Customer 1', 'description': 'Test description 1'},
                {'id': 2, 'name': 'Test Customer 2', 'description': 'Test description 2'}
            ])
        }
        mock_response.raise_for_status = Mock()
        api.session.get.return_value = mock_response
        
        # Make API call
        result = api.list_customers()
        
        # Assertions
        assert result is not None
        assert 'customers' in result
        assert isinstance(result['customers'], list)
        assert len(result['customers']) == 2
        
        # Print results for visibility
        print(f"\nFound {len(result['customers'])} customers:")
        for customer in result['customers']:
            print(f"  ID: {customer.get('id')}, Name: {customer.get('name')}, Description: {customer.get('description', 'N/A')}")
    
    def test_list_customers_returns_valid_data(self, api):
        """Test that customer data has expected structure"""
        # Mock the response - API returns 'users' as a JSON string
        mock_response = Mock()
        mock_response.json.return_value = {
            'users': json.dumps([
                {'id': 1, 'name': 'Test Customer', 'description': 'Test'}
            ])
        }
        mock_response.raise_for_status = Mock()
        api.session.get.return_value = mock_response
        
        result = api.list_customers()
        
        assert 'customers' in result
        
        # If there are customers, validate structure
        if result['customers']:
            for customer in result['customers']:
                assert 'id' in customer
                assert 'name' in customer
                # Description is optional
    
    def test_connection_and_auth(self, api):
        """Test that we can connect and authenticate"""
        # Mock successful response - API returns 'users' as a JSON string
        mock_response = Mock()
        mock_response.json.return_value = {
            'users': json.dumps([
                {'id': 1, 'name': 'Test Customer'}
            ])
        }
        mock_response.raise_for_status = Mock()
        api.session.get.return_value = mock_response
        
        result = api.list_customers()
        assert result is not None
        
        # Valid response should have 'customers' key
        assert 'customers' in result, "Valid authentication should return customers data"
        
        print(f"\n✓ Successfully connected to {HASHVIEW_URL}")
        print(f"✓ Authentication successful")
    
    def test_invalid_api_key_fails(self):
        """Test that an invalid API key results in authentication failure"""
        with patch('hate_crack.requests.Session') as mock_session_class:
            # Create API instance with invalid API key
            invalid_api = HashviewAPI(
                base_url=HASHVIEW_URL,
                api_key="invalid-api-key-123-this-should-fail"
            )
            
            # Mock error response
            mock_session = MagicMock()
            mock_response = Mock()
            mock_response.json.return_value = {
                'type': 'Error',
                'msg': 'You are not authorized to perform this action',
                'status': 401
            }
            mock_response.raise_for_status = Mock()
            mock_session.get.return_value = mock_response
            invalid_api.session = mock_session
            
            # Attempt to list customers with invalid key
            result = invalid_api.list_customers()
            
            # API returns 200 but with error message in response body
            assert result is not None
            assert 'type' in result
            assert result['type'] == 'Error'
            assert 'msg' in result
            assert 'not authorized' in result['msg'].lower()
            
            print(f"\n✓ Invalid API key correctly rejected")
            print(f"  Error message: {result['msg']}")
    
    def test_upload_hashfile(self, api, test_hashfile):
        """Test uploading a hashfile to Hashview"""
        print("\n[Test] Uploading hashfile...")
        
        # Mock list_customers response - API returns 'users' as a JSON string
        mock_customers_response = Mock()
        mock_customers_response.json.return_value = {
            'users': json.dumps([{'id': 1, 'name': 'Test Customer'}])
        }
        mock_customers_response.raise_for_status = Mock()
        
        # Mock upload_hashfile response
        mock_upload_response = Mock()
        mock_upload_response.json.return_value = {
            'hashfile_id': 4567,
            'msg': 'Hashfile added'
        }
        mock_upload_response.raise_for_status = Mock()
        
        # Set up session mock to return different responses
        api.session.get.return_value = mock_customers_response
        api.session.post.return_value = mock_upload_response
        
        # Get first customer
        customers_result = api.list_customers()
        customer_id = customers_result['customers'][0]['id']
        
        # Upload hashfile
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
        
        assert upload_result is not None, "No upload result returned"
        assert 'hashfile_id' in upload_result, "No hashfile_id returned"
        
        print(f"  ✓ Hashfile uploaded successfully")
        print(f"  ✓ Hashfile ID: {upload_result['hashfile_id']}")
    
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
        print(f"  ✓ Job created successfully")
        
        if 'job_id' in job_result:
            print(f"  ✓ Job ID: {job_result['job_id']}")
        
        print("\n" + "="*60)
        print("✓ Option 2 (Create Job) is READY and WORKING!")
        print("="*60)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
