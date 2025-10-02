# Deployment Guide for AD Password Changer

This guide provides instructions for deploying the AD Password Changer application in a production environment.

## System Requirements

- Python 3.8 or higher
- Pip package manager
- Access to an Active Directory server
- Service account with password reset permissions

## Step 1: Prepare the Environment

Create a dedicated user for running the application:

```bash
sudo useradd -m -s /bin/bash adpasswd
sudo su - adpasswd
```

Clone the repository:

```bash
git clone https://github.com/yourusername/ad_password_changer.git
cd ad_password_changer
```

## Step 2: Install Dependencies

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install the requirements:

```bash
pip install -r requirements.txt
```

## Step 3: Configure the Application

Create a `.env` file in the application root:

```bash
touch .env
chmod 600 .env  # Restrict permissions
```

Edit the `.env` file with your configuration:

```
# AD Server Configuration
AD_SERVER=ldaps://your-ad-server:636
AD_DOMAIN=your-domain.com
AD_BASE_DN=DC=your-domain,DC=com
AD_SERVICE_USER=service-account-username
AD_SERVICE_PASS=service-account-password

# Security (use a strong random key in production)
SECRET_KEY=generate-a-secure-random-string

# SSL/TLS Configuration
LDAP_SKIP_TLS_VERIFY=False
```

## Step 4: Test the Configuration

Run the application in debug mode to verify it works:

```bash
python app.py
```

Access the application at http://localhost:5000 and verify you can connect to Active Directory.

## Step 5: Set Up Production Server

### Option 1: Gunicorn (Recommended)

Install Gunicorn:

```bash
pip install gunicorn
```

Create a systemd service file `/etc/systemd/system/adpasswd.service`:

```ini
[Unit]
Description=AD Password Changer
After=network.target

[Service]
User=adpasswd
Group=adpasswd
WorkingDirectory=/home/adpasswd/ad_password_changer
Environment="PATH=/home/adpasswd/ad_password_changer/venv/bin"
ExecStart=/home/adpasswd/ad_password_changer/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable adpasswd
sudo systemctl start adpasswd
```

### Option 2: Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "--workers=3", "--bind=0.0.0.0:8000", "app:app"]
```

Build and run the Docker container:

```bash
docker build -t ad_password_changer .
docker run -d --name adpasswd -p 8000:8000 --env-file .env ad_password_changer
```

## Step 6: Set Up Reverse Proxy with Nginx

Install Nginx:

```bash
sudo apt-get update
sudo apt-get install -y nginx
```

Create an Nginx configuration file `/etc/nginx/sites-available/adpasswd`:

```nginx
server {
    listen 80;
    server_name password.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site and restart Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/adpasswd /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Step 7: Set Up SSL/TLS with Let's Encrypt

Install Certbot:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
```

Obtain and install the certificate:

```bash
sudo certbot --nginx -d password.yourdomain.com
```

## Step 8: Monitoring and Maintenance

Set up log rotation:

```bash
sudo nano /etc/logrotate.d/adpasswd
```

Add the following configuration:

```
/home/adpasswd/ad_password_changer/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 adpasswd adpasswd
    sharedscripts
    postrotate
        systemctl reload adpasswd.service
    endscript
}
```

## Security Considerations

1. Ensure the `.env` file has restricted permissions
2. Use a valid SSL certificate for both the web application and AD server
3. Audit service account permissions in Active Directory
4. Implement IP restrictions for the application if possible
5. Set up fail2ban to prevent brute force attacks

## Troubleshooting

### LDAP Connection Issues

Check the LDAP configuration:
```bash
ldapsearch -H ldaps://your-ad-server:636 -D "service-account@domain.com" -w "password" -b "DC=domain,DC=com" -s sub "(objectclass=*)" dn
```

### TLS Certificate Verification Failures

If you're having issues with certificate verification, check:
1. The certificate of your AD server is valid
2. The certificate chain is complete
3. The server presenting the certificate matches the hostname

For development only, you can set `LDAP_SKIP_TLS_VERIFY=True` to bypass certificate validation.

### Application Errors

Check the application logs:
```bash
sudo journalctl -u adpasswd.service
```