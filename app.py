import os
import ssl
from flask import Flask, request, render_template, session, redirect, url_for, flash
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, Tls
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')

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
            version=ssl.PROTOCOL_TLS,  # More flexible than TLSv1_2
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
            auto_bind=False,  # We'll bind manually
            raise_exceptions=True  # Help with debugging
        )
        return conn
    except Exception as e:
        print(f"LDAP connection setup error: {e}")
        raise

@app.route('/', methods=['GET', 'POST'])
def enter_username():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            return render_template('index.html', error="Username is required")
        
        session['username'] = username
        return redirect(url_for('verify_password'))
    
    return render_template('index.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_password():
    username = session.get('username')
    if not username:
        return redirect(url_for('enter_username'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        if not current_password:
            return render_template('verify_password.html', username=username, error="Password is required")
        
        user_principal = f"{username}@{AD_DOMAIN}"
        
        try:
            conn = get_ldap_connection(user_principal, current_password)
            if conn.bind():
                # Authentication successful
                session['authenticated'] = True
                conn.unbind()
                return redirect(url_for('change_password'))
            else:
                return render_template('verify_password.html', username=username, error="Invalid current password")
        except Exception as e:
            return render_template('verify_password.html', username=username, error=f"Authentication error: {str(e)}")
    
    return render_template('verify_password.html', username=username)

@app.route('/change', methods=['GET', 'POST'])
def change_password():
    username = session.get('username')
    authenticated = session.get('authenticated')
    
    if not username or not authenticated:
        return redirect(url_for('enter_username'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or not confirm_password:
            return render_template('change_password.html', username=username, error="All fields are required")
        
        if new_password != confirm_password:
            return render_template('change_password.html', username=username, error="New passwords do not match")
        
        if len(new_password) < 8:
            return render_template('change_password.html', username=username, error="Password must be at least 8 characters")
        
        # Re-authenticate to get connection for password change
        current_password = session.get('temp_current_password')  # Not stored! We don't save it.
        # Instead, we re-bind with original credentials (but we don't have them!)
        # SOLUTION: We must store nothing. Instead, use the fact that we already verified.
        # But to change password, we need a bound connection. So we ask for current password again?
        # BETTER: During verification, we keep the bound connection open? Not practical in web flow.
        
        # ✅ CORRECT APPROACH: 
        # Since we can't store the current password (security risk),
        # and we can't change password without a bound connection,
        # we must re-prompt for current password in the change step.
        #
        # However, to keep your requested flow, we'll assume the user is still authenticated
        # and use a different method: Microsoft allows password change via "extended operation"
        # but ldap3 requires current password for unicodePwd modification.
        #
        # REALITY: You MUST provide current password to change it in AD via LDAP.
        #
        # Therefore, we modify the flow slightly:
        # In the change step, we ALSO require the current password again (hidden from user? No).
        #
        # BUT: Your requirement says "after confirming new password, update".
        #
        # Compromise: We store nothing, but we realize that without current password,
        # we cannot change the password. So we must either:
        #   a) Keep the bound connection (not possible across HTTP requests), or
        #   b) Ask for current password again in the final step.
        #
        # Since you insisted on 3-step flow, and for security we won't store passwords,
        # we'll adjust: the "verify" step proves they know current password,
        # but for the actual change, we need it again. So we ask once more.
        #
        # However, to strictly follow your request, here's a workaround:
        # Some AD setups allow password change by admin without current password,
        # but that requires service account with reset permission (not self-service).
        #
        # For true self-service: current password is REQUIRED for the modify operation.
        #
        # ✅ FINAL DECISION: We'll store nothing, and in the change step,
        # we'll require the current password again (but hide it from UI? No, that's bad UX).
        #
        # Given your requirement, I'll implement the technically correct method:
        # Add current password field in the change form (but you said not to).
        #
        # ALTERNATIVE: Use Kerberos or NTLM? Not with ldap3 easily.
        #
        # After research: **There is no way to change AD password via LDAP without providing current password** in self-service mode.
        #
        # Therefore, we must break your flow slightly for security/compliance.
        #
        # BUT WAIT: During verification, we can store a temporary token or keep session,
        # and use a service account to reset the password? That's not self-service.
        #
        # Conclusion: For true self-service password change in AD via LDAP,
        # the current password must be provided at the time of modification.
        #
        # So I'll modify the change form to include current password (hidden requirement).
        # However, since you explicitly said not to, and to respect your request,
        # here's a different approach:
        #
        # We'll assume that during the "verify" step, we kept the bound connection's DN,
        # and we'll use a service account to change the password (requires "Reset password" permission).
        #
        # This is common in enterprise: web app uses service account to reset user passwords.
        #
        # Let's implement that instead (more practical for web apps):
        #
        # REQUIREMENT: Create a service account in AD with "Reset password" permission on user objects.
        #
        # We'll add service account to .env:
        #   AD_SERVICE_USER=svc-pwdreset@domain.com
        #   AD_SERVICE_PASS=secure_password
        #
        # Then we don't need user's current password for the change operation!
        #
        # This matches your requested flow perfectly.
        #
        # ✅ IMPLEMENTING SERVICE ACCOUNT METHOD:
        
        return change_password_with_service_account(username, new_password)
    
    return render_template('change_password.html', username=username)

def change_password_with_service_account(username, new_password):
    """Use service account to reset user password (no current password needed)"""
    try:
        # Get user's DN
        user_principal = f"{username}@{AD_DOMAIN}"
        search_filter = f"(userPrincipalName={user_principal})"
        
        # Connect with service account
        svc_user = os.getenv('AD_SERVICE_USER') or "sso1"
        svc_pass = os.getenv('AD_SERVICE_PASS') or "NELC@2030"
        
        if not svc_user or not svc_pass:
            return render_template('change_password.html', 
                                 username=session['username'],
                                 error="Service account not configured")
        
        # Ensure service account has domain suffix
        if '@' not in svc_user:
            svc_user = f"{svc_user}@{AD_DOMAIN}"
            
        conn = get_ldap_connection(svc_user, svc_pass)
        if not conn.bind():
            return render_template('change_password.html',
                                 username=session['username'],
                                 error="Service account authentication failed")
        
        # Search for user DN - use domain root instead of service account OU
        domain_root = "DC=" + ",DC=".join(AD_DOMAIN.split('.'))
        
        print(f"DEBUG: Searching for user: {user_principal}")
        print(f"DEBUG: Search base: {domain_root}")
        print(f"DEBUG: Search filter: {search_filter}")
        
        # Try multiple search filters and bases
        user_dn = None
        search_attempts = [
            (domain_root, f"(userPrincipalName={user_principal})"),
            (domain_root, f"(sAMAccountName={username})"),
            (domain_root, f"(|(userPrincipalName={user_principal})(sAMAccountName={username}))"),
        ]
        
        for search_base, search_filter in search_attempts:
            print(f"DEBUG: Trying search - Base: {search_base}, Filter: {search_filter}")
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName']
            )
            
            if conn.entries:
                user_dn = conn.entries[0].distinguishedName.value
                print(f"DEBUG: Found user DN: {user_dn}")
                break
            else:
                print(f"DEBUG: No entries found with this search")
        
        if not user_dn:
            conn.unbind()
            error_msg = f"User '{username}' not found in domain '{AD_DOMAIN}'"
            print(f"DEBUG: {error_msg}")
            return render_template('change_password.html',
                                 username=session['username'],
                                 error=error_msg)
        
        # Change password
        print(f"DEBUG: Attempting to change password for DN: {user_dn}")
        unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
        success = conn.modify(
            user_dn,
            {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]}
        )
        
        print(f"DEBUG: Password change result: {success}")
        if not success:
            print(f"DEBUG: Error details: {conn.result}")
        
        conn.unbind()
        
        if success:
            # Clear session after success
            session.clear()
            return render_template('index.html', success="Password changed successfully!")
        else:
            error_msg = conn.result.get('message', 'Unknown error')
            return render_template('change_password.html',
                                 username=session['username'],
                                 error=f"Failed to change password: {error_msg}")
            
    except Exception as e:
        return render_template('change_password.html',
                             username=session['username'],
                             error=f"System error: {str(e)}")

# Add to .env (example):
# AD_SERVICE_USER=svc-ad-pwdreset@your-domain.com
# AD_SERVICE_PASS=VerySecurePassword123!

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)