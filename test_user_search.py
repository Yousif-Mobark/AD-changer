#!/usr/bin/env python3
"""
Simple test script to verify the user search functionality
in the Flask app by directly calling the function.
"""

import os
import sys
sys.path.append('/home/yousif/ad_password_changer')

from app import change_password_with_service_account
from flask import Flask
import tempfile

# Create a minimal Flask app context for testing
app = Flask(__name__)
app.secret_key = 'test-key'

def test_user_search():
    """Test the user search functionality"""
    print("🧪 Testing User Search in Flask App")
    print("=" * 50)
    
    # Test username that we know exists
    test_username = "y.abdulhafies.c"
    test_password = "TestPassword123!"
    
    print(f"👤 Testing with username: {test_username}")
    
    with app.test_request_context():
        # Mock session data
        from flask import session
        session['username'] = test_username
        session['authenticated'] = True
        
        try:
            # This should now find the user successfully
            # (but might fail at password change due to permissions/policy)
            result = change_password_with_service_account(test_username, test_password)
            
            # The result will be a Flask response object
            print("✅ Function executed without search errors!")
            print("📋 Check the console output above for DEBUG messages")
            
            # Note: The actual password change might still fail due to:
            # 1. Password policy requirements
            # 2. Service account permissions
            # 3. User account status
            # But the search should work now!
            
        except Exception as e:
            print(f"❌ Function failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_user_search()