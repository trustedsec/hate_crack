"""
Tests for Hashview integration - Real API calls
"""
import pytest
import sys
import os
import json

# Add the parent directory to the path to import hate_crack
sys.path.insert(0, os.path.dirname(__file__))

# Import requests - required for real API calls
try:
    import requests
except ImportError:
    pytest.skip("requests module not available", allow_module_level=True)

from hate_crack import HashviewAPI

# Load config for Hashview credentials
config_path = os.path.join(os.path.dirname(__file__), 'config.json')
with open(config_path, 'r') as f:
    config = json.load(f)

HASHVIEW_URL = config.get('hashview_url', 'https://hashview.example.com')
HASHVIEW_API_KEY = config.get('hashview_api_key', 'test-api-key-123')


class TestHashviewAPI:
    """Test suite for HashviewAPI class with real API calls"""
    
    @pytest.fixture
    def api(self):
        """Create a real HashviewAPI instance"""
        api = HashviewAPI(
            base_url=HASHVIEW_URL,
            api_key=HASHVIEW_API_KEY
        )
        return api
    
    def test_list_customers_success(self, api):
        """Test successful customer listing with real API call"""
        # Make real API call
        result = api.list_customers()
        
        # Assertions
        assert result is not None
        assert 'customers' in result
        assert isinstance(result['customers'], list)
        
        # Print results for visibility
        print(f"\nFound {len(result['customers'])} customers:")
        for customer in result['customers']:
            print(f"  ID: {customer.get('id')}, Name: {customer.get('name')}, Description: {customer.get('description', 'N/A')}")
    
    def test_list_customers_returns_valid_data(self, api):
        """Test that customer data has expected structure"""
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
        # This will fail if credentials are wrong or server is down
        try:
            result = api.list_customers()
            assert result is not None
            
            # Check for API error response (invalid credentials)
            if 'type' in result and result['type'] == 'Error':
                pytest.fail(f"Authentication failed: {result.get('msg', 'Unknown error')}")
            
            # Valid response should have 'customers' key
            assert 'customers' in result, "Valid authentication should return customers data"
            
            print(f"\n✓ Successfully connected to {HASHVIEW_URL}")
            print(f"✓ Authentication successful")
        except requests.exceptions.ConnectionError:
            pytest.fail(f"Could not connect to {HASHVIEW_URL}")
    
    def test_invalid_api_key_fails(self):
        """Test that an invalid API key results in authentication failure"""
        # Create API instance with invalid API key
        invalid_api = HashviewAPI(
            base_url=HASHVIEW_URL,
            api_key="invalid-api-key-123-this-should-fail"
        )
        
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

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
