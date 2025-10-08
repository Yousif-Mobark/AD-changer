import os
import ssl
import random
import secrets
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, render_template, session, redirect, url_for, flash
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, Tls
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# AD Config
AD_SERVER = os.getenv('AD_SERVER')
AD_DOMAIN = os.getenv('AD_DOMAIN')
AD_BASE_DN = os.getenv('AD_BASE_DN')
SKIP_TLS_VERIFY = os.getenv('LDAP_SKIP_TLS_VERIFY', 'False').lower() == 'true'

# Email Config for OTP
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
FROM_EMAIL = os.getenv('FROM_EMAIL', SMTP_USERNAME)

# OTP Configuration
OTP_EXPIRY_MINUTES = int(os.getenv('OTP_EXPIRY_MINUTES', '5'))
OTP_LENGTH = int(os.getenv('OTP_LENGTH', '6'))

def generate_otp():
    """Generate a secure random OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(OTP_LENGTH)])

def send_otp_email(email, otp, username):
    """Send OTP via email"""
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Password Change Verification Code"
        msg['From'] = FROM_EMAIL
        msg['To'] = email
        
        # Render HTML content from template
        html_content = render_template('otp_email.html', 
                                     username=username,
                                     otp=otp,
                                     expiry_minutes=OTP_EXPIRY_MINUTES,
                                     timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Attach HTML content
        msg.attach(MIMEText(html_content, 'html'))
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"OTP email sent successfully to {email} for user {username}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email} for user {username}: {e}")
        return False

def get_user_email(username):
    """Get user email from Active Directory"""
    try:
        # Connect with service account to lookup email
        svc_user = os.getenv('AD_SERVICE_USER') or "sso1"
        svc_pass = os.getenv('AD_SERVICE_PASS') or "NELC@2030"
        
        if '@' not in svc_user:
            svc_user = f"{svc_user}@{AD_DOMAIN}"
            
        conn = get_ldap_connection(svc_user, svc_pass)
        if not conn.bind():
            return None
            
        # Search for user email
        domain_root = "DC=" + ",DC=".join(AD_DOMAIN.split('.'))
        user_principal = f"{username}@{AD_DOMAIN}"
        
        search_attempts = [
            (domain_root, f"(userPrincipalName={user_principal})"),
            (domain_root, f"(sAMAccountName={username})"),
        ]
        
        for search_base, search_filter in search_attempts:
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['mail', 'userPrincipalName']
            )
            
            if conn.entries:
                entry = conn.entries[0]
                email = str(entry.mail) if hasattr(entry, 'mail') and entry.mail else None
                conn.unbind()
                return email if email and email != '[]' else None
                
        conn.unbind()
        return None
    except Exception as e:
        logger.error(f"Error getting user email for {username}: {e}")
        return None

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
        logger.error(f"LDAP connection setup error: {e}")
        raise

@app.route('/', methods=['GET', 'POST'])
def enter_username():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            logger.warning(f"Empty username submitted from IP: {request.remote_addr}")
            return render_template('index.html', error="Username is required")
        
        logger.info(f"Username '{username}' submitted for password change from IP: {request.remote_addr}")
        
        # Get user email for OTP
        user_email = get_user_email(username)
        user_email = username+'@elc.edu.sa' if not user_email else user_email
        if not user_email:
            logger.error(f"Email address not found for user: {username}")
            return render_template('index.html', 
                                 error="Email address not found in Active Directory. Please contact IT support.")
        
        # Generate and send OTP
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
        logger.info(f"Generated OTP for user: {username}, expires at: {otp_expiry}")
        
        if send_otp_email(user_email, otp, username):
            # Store details in session
            session['username'] = username
            session['otp'] = otp
            session['otp_expiry'] = otp_expiry.isoformat()
            session['user_email'] = user_email
            session['authenticated'] = True
            
            logger.info(f"OTP sent successfully to {user_email} for user: {username}")
            return redirect(url_for('change_password'))
        else:
            logger.error(f"Failed to send OTP email for user: {username}")
            return render_template('index.html',
                                 error="Failed to send verification code. Please try again.")
    
    return render_template('index.html')



@app.route('/change', methods=['GET', 'POST'])
def change_password():
    username = session.get('username')
    authenticated = session.get('authenticated')
    
    if not username or not authenticated:
        logger.warning(f"Unauthorized access attempt to change password route from IP: {request.remote_addr}")
        return redirect(url_for('enter_username'))
    
    # Check if OTP session data exists
    if 'otp' not in session or 'otp_expiry' not in session:
        logger.warning(f"Missing OTP session data for user: {username}")
        return redirect(url_for('enter_username'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        user_otp = request.form.get('otp_code', '').strip()
        
        # Validate form inputs
        if not new_password or not confirm_password or not user_otp:
            return render_template('change_password.html', username=username, 
                                 user_email=session.get('user_email'), 
                                 error="All fields are required")
        
        if new_password != confirm_password:
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="New passwords do not match")
        
        if len(new_password) < 8:
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="Password must be at least 8 characters")
        
        # Verify OTP
        stored_otp = session.get('otp')
        otp_expiry_str = session.get('otp_expiry')
        
        if not stored_otp or not otp_expiry_str:
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="OTP session expired. Please restart the process.")
        
        # Check OTP expiry
        try:
            otp_expiry = datetime.fromisoformat(otp_expiry_str)
            if datetime.now() > otp_expiry:
                # Clear expired OTP
                session.pop('otp', None)
                session.pop('otp_expiry', None)
                return render_template('change_password.html', username=username,
                                     user_email=session.get('user_email'),
                                     error="Verification code has expired. Please restart the verification process.")
        except ValueError:
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="Invalid OTP session. Please restart the process.")
        
        # Validate OTP
        if user_otp != stored_otp:
            logger.warning(f"Invalid OTP attempt for user: {username}, provided: {user_otp}")
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="Invalid verification code. Please check and try again.")
        
        # OTP is valid, proceed with password change
        logger.info(f"OTP validated successfully for user: {username}, proceeding with password change")
        result = change_password_with_service_account(username, new_password)
        
        # Clear OTP from session after use
        session.pop('otp', None)
        session.pop('otp_expiry', None)
        
        return result
    
    # GET request - show the form with OTP input
    user_email = session.get('user_email', 'your registered email')
    return render_template('change_password.html', username=username, user_email=user_email)

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP to user's email"""
    username = session.get('username')
    authenticated = session.get('authenticated')
    
    if not username or not authenticated:
        logger.warning(f"Unauthorized resend OTP attempt from IP: {request.remote_addr}")
        return redirect(url_for('enter_username'))
    
    logger.info(f"Resending OTP for user: {username}")
    try:
        # Get user email
        user_email = get_user_email(username)
        user_email = username+'@elc.edu.sa' if not user_email else user_email
        if not user_email:
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="Email address not found. Please contact IT support.")
        
        # Generate new OTP
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
        
        if send_otp_email(user_email, otp, username):
            # Update session with new OTP
            session['otp'] = otp
            session['otp_expiry'] = otp_expiry.isoformat()
            session['user_email'] = user_email
            
            logger.info(f"OTP resent successfully to {user_email} for user: {username}")
            return render_template('change_password.html', username=username,
                                 user_email=user_email,
                                 success="New verification code sent to your email.")
        else:
            logger.error(f"Failed to resend OTP for user: {username}")
            return render_template('change_password.html', username=username,
                                 user_email=session.get('user_email'),
                                 error="Failed to send verification code. Please try again.")
    except Exception as e:
        logger.error(f"Error resending OTP for user {username}: {str(e)}")
        return render_template('change_password.html', username=username,
                             user_email=session.get('user_email'),
                             error=f"Error sending OTP: {str(e)}")

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
        
        logger.info(f"Searching for user: {user_principal}")
        logger.info(f"Search base: {domain_root}")
        logger.info(f"Search filter: {search_filter}")
        
        # Try multiple search filters and bases
        user_dn = None
        search_attempts = [
            (domain_root, f"(userPrincipalName={user_principal})"),
            (domain_root, f"(sAMAccountName={username})"),
            (domain_root, f"(|(userPrincipalName={user_principal})(sAMAccountName={username}))"),
        ]
        
        for search_base, search_filter in search_attempts:
            logger.info(f"Trying search - Base: {search_base}, Filter: {search_filter}")
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName']
            )
            
            if conn.entries:
                user_dn = conn.entries[0].distinguishedName.value
                logger.info(f"Found user DN: {user_dn}")
                break
            else:
                logger.warning(f"No entries found with search - Base: {search_base}, Filter: {search_filter}")
        
        if not user_dn:
            conn.unbind()
            error_msg = f"User '{username}' not found in domain '{AD_DOMAIN}'"
            logger.error(error_msg)
            return render_template('change_password.html',
                                 username=session['username'],
                                 error=error_msg)
        
        # Change password
        logger.info(f"Attempting to change password for DN: {user_dn}")
        unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
        success = conn.modify(
            user_dn,
            {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]}
        )
        
        logger.info(f"Password change result: {success}")
        if not success:
            logger.error(f"Password change failed - Error details: {conn.result}")
        
        conn.unbind()
        
        if success:
            # Clear session after success
            logger.info(f"Password changed successfully for user: {username}")
            session.clear()
            return render_template('index.html', success="Password changed successfully!")
        else:
            error_msg = conn.result.get('message', 'Unknown error')
            logger.error(f"Password change failed for user {username}: {error_msg}")
            return render_template('change_password.html',
                                 username=session['username'],
                                 error=f"Failed to change password: {error_msg}")
            
    except Exception as e:
        logger.error(f"System error during password change for user {username}: {str(e)}")
        return render_template('change_password.html',
                             username=session['username'],
                             error=f"System error: {str(e)}")

# Add to .env (example):
# AD_SERVICE_USER=svc-ad-pwdreset@your-domain.com
# AD_SERVICE_PASS=VerySecurePassword123!

if __name__ == '__main__':
    logger.info("Starting AD Password Changer application")
    app.run(host='0.0.0.0', port=5000, debug=True)