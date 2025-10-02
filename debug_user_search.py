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

def get_ldap_connection(user_principal, password):
    """Create and return a bound LDAP connection"""
    try:
        tls_config = Tls(
            validate=ssl.CERT_NONE if SKIP_TLS_VERIFY else ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLS,
            ca_certs_file=None,
            local_private_key_file=None,
            local_certificate_file=None,
            ciphers=None
        )
        
        server = Server(
            AD_SERVER,
            port=636,
            use_ssl=True,
            tls=tls_config,
            get_info=ALL
        )
        
        conn = Connection(
            server,
            user=user_principal,
            password=password,
            auto_bind=False,
            raise_exceptions=True
        )
        return conn
    except Exception as e:
        print(f"LDAP connection setup error: {e}")
        raise

def search_for_user(username):
    """Search for a specific user in Active Directory"""
    print(f"\n🔍 Searching for user: {username}")
    print("=" * 50)
    
    # Connect with service account
    svc_user = os.getenv('AD_SERVICE_USER') or "sso1"
    svc_pass = os.getenv('AD_SERVICE_PASS') or "NELC@2030"
    
    if '@' not in svc_user:
        svc_user = f"{svc_user}@{AD_DOMAIN}"
    
    conn = get_ldap_connection(svc_user, svc_pass)
    
    if not conn.bind():
        print("❌ Service account authentication failed")
        return False
    
    print(f"✅ Connected as: {svc_user}")
    
    # Calculate domain root from AD_DOMAIN
    domain_root = "DC=" + ",DC=".join(AD_DOMAIN.split('.'))
    user_principal = f"{username}@{AD_DOMAIN}"
    
    print(f"🏢 Domain root: {domain_root}")
    print(f"👤 User principal: {user_principal}")
    print(f"📁 Configured base DN: {AD_BASE_DN}")
    
    # Try different search strategies
    search_attempts = [
        (domain_root, f"(userPrincipalName={user_principal})", "User Principal Name (with domain)"),
        (domain_root, f"(sAMAccountName={username})", "SAM Account Name (without domain)"),
        (domain_root, f"(|(userPrincipalName={user_principal})(sAMAccountName={username}))", "Either UPN or SAM"),
        (domain_root, f"(cn={username})", "Common Name"),
        (domain_root, f"(|(cn=*{username}*)(sAMAccountName=*{username}*)(userPrincipalName=*{username}*))", "Wildcard search"),
        (AD_BASE_DN, f"(userPrincipalName={user_principal})", "Original base DN with UPN"),
        (AD_BASE_DN, f"(sAMAccountName={username})", "Original base DN with SAM"),
    ]
    
    found_users = []
    
    for i, (search_base, search_filter, description) in enumerate(search_attempts, 1):
        print(f"\n🔎 Attempt {i}: {description}")
        print(f"   Base: {search_base}")
        print(f"   Filter: {search_filter}")
        
        try:
            result = conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName', 'cn', 'mail']
            )
            
            if result and conn.entries:
                print(f"   ✅ Found {len(conn.entries)} user(s)!")
                for entry in conn.entries:
                    user_info = {
                        'dn': str(entry.distinguishedName),
                        'sam': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else 'N/A',
                        'upn': str(entry.userPrincipalName) if hasattr(entry, 'userPrincipalName') else 'N/A',
                        'cn': str(entry.cn) if hasattr(entry, 'cn') else 'N/A',
                        'mail': str(entry.mail) if hasattr(entry, 'mail') else 'N/A'
                    }
                    found_users.append(user_info)
                    print(f"   📋 DN: {user_info['dn']}")
                    print(f"   👤 SAM: {user_info['sam']}")
                    print(f"   📧 UPN: {user_info['upn']}")
                    print(f"   🏷️ CN: {user_info['cn']}")
                    print(f"   📮 Mail: {user_info['mail']}")
                    
                if i == 1:  # If first attempt succeeded, we found the exact match
                    break
            else:
                print(f"   ❌ No users found")
                
        except Exception as e:
            print(f"   💥 Search failed: {e}")
    
    conn.unbind()
    
    print(f"\n📊 Summary:")
    print(f"   Total unique users found: {len(set(user['dn'] for user in found_users))}")
    
    if found_users:
        print(f"   ✅ User search successful!")
        # Return the most likely match (first one found)
        best_match = found_users[0]
        print(f"   🎯 Best match: {best_match['dn']}")
        return best_match
    else:
        print(f"   ❌ User '{username}' not found in Active Directory")
        return None

if __name__ == "__main__":
    print("🔍 Active Directory User Search Tool")
    print("=" * 50)
    
    # Test with the problematic username
    test_username = "y.abdulhafies.c"
    result = search_for_user(test_username)
    
    if result:
        print(f"\n🎉 SUCCESS: User found and can be used for password changes!")
    else:
        print(f"\n💡 SUGGESTIONS:")
        print(f"   1. Verify the username is correct: '{test_username}'")
        print(f"   2. Check if user exists in domain: '{AD_DOMAIN}'")
        print(f"   3. Verify service account has read permissions")
        print(f"   4. Try running a broader search to see what users exist")
        
    print(f"\n🔧 To test with a different username, run:")
    print(f"   python3 {__file__} <username>")