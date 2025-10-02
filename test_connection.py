#!/usr/bin/env python3

import os
import ssl
from ldap3 import Server, Connection, ALL, Tls
from dotenv import load_dotenv

load_dotenv()

# AD Config
AD_SERVER = os.getenv('AD_SERVER')
AD_DOMAIN = os.getenv('AD_DOMAIN')
AD_BASE_DN = os.getenv('AD_BASE_DN')
SKIP_TLS_VERIFY = os.getenv('LDAP_SKIP_TLS_VERIFY', 'False').lower() == 'true'

print(f"AD_SERVER: {AD_SERVER}")
print(f"AD_DOMAIN: {AD_DOMAIN}")
print(f"SKIP_TLS_VERIFY: {SKIP_TLS_VERIFY}")
print(f"AD_BASE_DN: {AD_BASE_DN}")

def test_ldap_connection():
    """Test LDAP connection with current settings"""
    try:
        print("\n🔍 Testing LDAP Connection...")
        
        tls_config = Tls(
            validate=ssl.CERT_NONE if SKIP_TLS_VERIFY else ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLS,
            ca_certs_file=None,
            local_private_key_file=None,
            local_certificate_file=None,
            ciphers=None
        )
        
        print(f"📡 Connecting to: {AD_SERVER}")
        print(f"🔐 TLS Validation: {'DISABLED' if SKIP_TLS_VERIFY else 'ENABLED'}")
        
        server = Server(
            AD_SERVER,
            port=636,
            use_ssl=True,
            tls=tls_config,
            get_info=ALL
        )
        
        print(f"✅ Server object created successfully")
        print(f"🏢 Server info: {server}")
        
        # Test with service account credentials
        svc_user = os.getenv('AD_SERVICE_USER')
        svc_pass = os.getenv('AD_SERVICE_PASS')
        
        if '@' not in svc_user:
            svc_user = f"{svc_user}@{AD_DOMAIN}"
            
        print(f"👤 Testing connection with: {svc_user}")
        
        conn = Connection(
            server,
            user=svc_user,
            password=svc_pass,
            auto_bind=False,
            raise_exceptions=True
        )
        
        print("🔗 Attempting to bind...")
        if conn.bind():
            print("✅ LDAP Connection successful!")
            print(f"📋 Connection details: {conn}")
            
            # Test a simple search to verify functionality
            print("\n🔍 Testing search functionality...")
            search_result = conn.search(
                search_base=AD_BASE_DN,
                search_filter="(objectClass=*)",
                attributes=['cn'],
                size_limit=1
            )
            
            if search_result:
                print("✅ Search test successful!")
                print(f"📊 Found {len(conn.entries)} entries")
            else:
                print("⚠️ Search test failed, but connection is working")
                
            conn.unbind()
            print("✅ Connection closed successfully")
            return True
        else:
            print(f"❌ LDAP Bind failed: {conn.result}")
            return False
            
    except Exception as e:
        print(f"💥 Connection error: {e}")
        print(f"📋 Error type: {type(e).__name__}")
        return False

if __name__ == "__main__":
    print("🚀 LDAP Connection Test")
    print("=" * 50)
    
    success = test_ldap_connection()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 Connection test PASSED! Your SSL configuration is working.")
    else:
        print("❌ Connection test FAILED. Check your configuration.")