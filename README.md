# AD Password Changer

A secure self-service password change portal for Active Directory users. This web application allows users to change their Active Directory password through a modern, secure interface.

## Features

- Three-step secure password change process
- Dark theme with modern animations
- SSL/TLS support for secure LDAP connections
- Password complexity validation
- Real-time password strength meter
- Responsive design for all devices
- Digital Transformation branding
- Secure service account password change method

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Backend**: Flask (Python)
- **Authentication**: LDAP3 (Active Directory)
- **Security**: SSL/TLS, Python-dotenv for environment variables

## Installation

1. Clone the repository
2. Install the requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file with the following variables:
   ```
   AD_SERVER=ldaps://your-ad-server:636
   AD_DOMAIN=your-domain.com
   AD_BASE_DN=DC=your-domain,DC=com
   AD_SERVICE_USER=service-account-username
   AD_SERVICE_PASS=service-account-password
   SECRET_KEY=your-flask-secret-key
   LDAP_SKIP_TLS_VERIFY=False
   ```

## Running the Application

For development:
```bash
python app.py
```

For production, use a WSGI server like Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Security Considerations

- The application uses a service account to reset passwords (requires appropriate permissions in AD)
- No passwords are stored in the application
- TLS/SSL is used for all LDAP communications
- Session data is encrypted with the Flask secret key

## Application Flow

1. User enters their username
2. User verifies their identity by entering their current password
3. User sets a new password that meets complexity requirements
4. Password is changed in Active Directory

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| AD_SERVER | LDAP server address with protocol | ldaps://ad.company.com:636 |
| AD_DOMAIN | Active Directory domain | company.com |
| AD_BASE_DN | Base Distinguished Name for LDAP searches | DC=company,DC=com |
| AD_SERVICE_USER | Service account username | svc-pwdreset |
| AD_SERVICE_PASS | Service account password | SecureP@ssw0rd! |
| SECRET_KEY | Flask secret key for session encryption | random-string-here |
| LDAP_SKIP_TLS_VERIFY | Skip TLS certificate validation (dev only) | True/False |

## Sponsored by

Digital Transformation

## License

This project is licensed under the MIT License - see the LICENSE file for details.