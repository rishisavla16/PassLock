# secure_password_manager/app.py

import os
import socket
import smtplib
import ssl
import random
import string
from email.message import EmailMessage
from datetime import timedelta
from flask import Flask, render_template, redirect, url_for, request, session, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from authlib.integrations.flask_client import OAuth

from auth import create_user, check_user, User, init_app as init_auth, db, bcrypt
from vault import get_vault, update_vault
from sqlalchemy import text

# --- App Configuration ---
app = Flask(__name__)
# CRITICAL: Use a strong, randomly generated secret key in a real application
# and load it from an environment variable.
# Use a fixed key for dev so sessions don't expire on server restart
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-fixed-for-stability'
# Use DATABASE_URL env var for cloud databases (Neon, Supabase, etc.)
# Fall back to local SQLite for development.
_db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Set a permanent session lifetime for auto-logout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# --- OAuth Configuration ---
# Load OAuth values from environment variables.
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL', '')

# --- Email Configuration (Gmail) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
# Load email credentials from environment variables.
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')

# --- Initializations ---
init_auth(app)

# Create tables at import time so Vercel serverless functions work without
# needing to run the app via __main__.
with app.app_context():
    db.create_all()

csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized_callback():
    """
    Handles unauthorized requests.
    Returns a 401 JSON error for API requests, otherwise redirects to login page.
    """
    if request.path.startswith('/api/'):
        return jsonify(status='error', message='Login required'), 401
    return redirect(url_for('login'))

login_manager.login_view = 'login'
oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)


# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database for session management."""
    return User.query.get(int(user_id))

# --- Session Inactivity Management ---
@app.before_request
def before_request():
    """
    Refreshes the session timeout on each request.
    This implements the server-side auto-logout after 15 minutes of inactivity.
    """
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)
    session.modified = True

@app.after_request
def add_security_headers(response):
    """
    Security: Prevent caching of sensitive pages.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# --- Routes ---
@app.route('/')
def index():
    """Redirects to the vault if logged in, otherwise to login."""
    if current_user.is_authenticated:
        return redirect(url_for('vault_page'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('vault_page'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email:
            email = email.strip().lower()
        
        # Input validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            # If the user exists but has no password (e.g. created via Google),
            # allow them to "register" by setting a password for this account.
            if existing_user.password_hash is None:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                existing_user.password_hash = hashed_password
                db.session.commit()
                
                login_user(existing_user)
                flash('Password set for your existing Google account. You are now logged in.', 'success')
                return redirect(url_for('vault_page'))
            else:
                flash('Email already exists. Please log in.', 'danger')
                return redirect(url_for('register'))

        # Security: Generate a random salt for PBKDF2 on the client-side
        # Here we create the user record, but the vault is still empty.
        # The salt is stored now, to be used for key derivation later.
        pbkdf2_salt = os.urandom(16).hex()
        create_user(email=email, password=password, pbdfk2_salt=pbkdf2_salt)
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('vault_page'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email:
            email = email.strip().lower()
        
        # Check if a user with this email exists first.
        user_by_email = User.query.filter_by(email=email).first()

        # Case 1: Email doesn't exist at all. Give a generic error.
        if not user_by_email:
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')

        # Case 2: Email exists, but was created via Google (no password set).
        # Automatically set the provided password as the manual login password.
        if not user_by_email.password_hash:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user_by_email.password_hash = hashed_password
            db.session.commit()
            
            login_user(user_by_email)
            flash('Manual login enabled. You can now use this password to log in.', 'success')
            return redirect(url_for('vault_page'))

        # Case 3: Email exists and has a password. Now check if the password is correct.
        user = check_user(email, password)
        
        if user:
            # Check if 2FA is enabled for this user
            if user.totp_secret == 'email_enabled':
                # Generate a 6-digit code
                code = ''.join(random.choices(string.digits, k=6))
                
                # Store user ID and code in session temporarily
                session['2fa_user_id'] = user.id
                session['2fa_login_code'] = code
                
                # Send the code via email
                if send_verification_email(user.email, code):
                    return redirect(url_for('login_2fa'))
                else:
                    flash('Failed to send 2FA code. Please try again.', 'danger')
                    return redirect(url_for('login'))
            else:
                # No 2FA, log in directly
                login_user(user)
                return redirect(url_for('vault_page'))
        else:
            flash('Invalid email or password.', 'danger')
            
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """Handles the 2FA verification step during login."""
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        stored_code = session.get('2fa_login_code')
        user_id = session.get('2fa_user_id')
        
        if code and code == stored_code:
            # Code is correct, log the user in
            user = User.query.get(user_id)
            login_user(user)
            
            # Clear temporary session data
            session.pop('2fa_user_id', None)
            session.pop('2fa_login_code', None)
            
            return redirect(url_for('vault_page'))
        else:
            flash('Invalid code. Please try again.', 'danger')
            
    return render_template('login_2fa.html')

@app.route('/login/2fa/resend')
def resend_2fa_code():
    """Resends the 2FA code during login."""
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['2fa_user_id']
    user = User.query.get(user_id)
    
    if user:
        code = ''.join(random.choices(string.digits, k=6))
        session['2fa_login_code'] = code
        if send_verification_email(user.email, code):
            flash('A new verification code has been sent.', 'info')
        else:
            flash('Failed to send email.', 'danger')
            
    return redirect(url_for('login_2fa'))

@app.route('/google/login')
def login_google():
    """Redirects to Google for authentication."""
    # The callback URL must be absolute for the OAuth provider.
    # We use _scheme='https' because the app is running over HTTPS.
    redirect_uri = url_for('callback_google', _external=True, _scheme='https')
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def callback_google():
    """Handles the callback from Google after authentication."""
    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        flash(f'An error occurred during Google authentication. Please try again.', 'danger')
        return redirect(url_for('login'))

    user_info = token.get('userinfo')
    if not user_info:
        flash('Could not fetch user information from Google.', 'danger')
        return redirect(url_for('login'))

    google_id = user_info['sub']
    email = user_info['email']
    if email:
        email = email.strip().lower()
    
    # Find user by Google ID
    user = User.query.filter_by(google_id=google_id).first()

    if not user:
        # If no user with that Google ID, check if an account with that email exists
        # This prevents creating a duplicate account if they first registered with email/password
        user = User.query.filter_by(email=email).first()
        if user:
            # Link existing account to Google ID
            user.google_id = google_id
            db.session.commit()
        else:
            # Create a new user, using their email
            pbkdf2_salt = os.urandom(16).hex()
            user = create_user(email=email, pbdfk2_salt=pbkdf2_salt, google_id=google_id)

    # Check if 2FA is enabled for this user (even for Google Login)
    if user.totp_secret == 'email_enabled':
        code = ''.join(random.choices(string.digits, k=6))
        session['2fa_user_id'] = user.id
        session['2fa_login_code'] = code
        
        if send_verification_email(user.email, code):
            return redirect(url_for('login_2fa'))
        else:
            flash('Failed to send 2FA code.', 'danger')
            return redirect(url_for('login'))

    login_user(user)
    return redirect(url_for('vault_page'))

@app.route('/logout')
@login_required
def logout():
    """Logs the current user out."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/vault')
@login_required
def vault_page():
    """Renders the main vault page."""
    # Check if the user has an encrypted vault stored to determine UI state
    vault_exists = bool(current_user.encrypted_vault)
    return render_template('vault.html', vault_exists=vault_exists)

@app.route('/settings')
@login_required
def settings_page():
    """Renders the user settings page."""
    # Pass the current hint to the template
    return render_template('settings.html', password_hint=current_user.password_hint)

# --- API for Zero-Knowledge Vault ---
@app.route('/api/vault', methods=['GET', 'POST'])
@login_required
def api_vault():
    """
    API endpoint for the client-side JS to interact with the encrypted vault.
    This is the core of the zero-knowledge architecture.
    """
    if request.method == 'GET':
        # Security: The server provides the encrypted blob and the salt.
        # It NEVER sees the master password or the derived key.
        encrypted_vault, pbkdf2_salt = get_vault(current_user.id)
        return jsonify({
            'vault': encrypted_vault or "",
            'salt': pbkdf2_salt
        })

    if request.method == 'POST':
        data = request.get_json()
        encrypted_vault = data.get('vault')
        
        # Basic validation
        if encrypted_vault is None:
            return jsonify({'status': 'error', 'message': 'Missing vault data'}), 400

        # Security: The server receives an opaque, encrypted blob from the client.
        # It stores this blob without any knowledge of its contents.
        update_vault(current_user.id, encrypted_vault)
        return jsonify({'status': 'success'})

@app.route('/api/hint', methods=['POST'])
@login_required
def update_hint():
    """Updates the master password hint for the current user."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

    hint = data.get('hint', '') # Default to empty string

    if len(hint) > 200:
        return jsonify({'status': 'error', 'message': 'Hint cannot exceed 200 characters.'}), 400

    user = User.query.get(current_user.id)
    if user:
        user.password_hint = hint
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Hint updated successfully.'})
    
    return jsonify({'status': 'error', 'message': 'User not found'}), 404

@app.route('/api/change_login_password', methods=['POST'])
@login_required
def change_login_password():
    """Updates the login password for the current user."""
    data = request.get_json()
    new_password = data.get('password')
    
    if not new_password:
        return jsonify({'status': 'error', 'message': 'Password is required'}), 400
        
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    user = User.query.get(current_user.id)
    user.password_hash = hashed_password
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Login password updated successfully.'})

def send_verification_email(to_email, code):
    """Sends a 2FA verification code via email."""
    # Mock sending if credentials are not set
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        print(f"\n[MOCK EMAIL] To: {to_email} | Subject: SecurePM 2FA Code | Code: {code}\n")
        return True

    msg = EmailMessage()
    # Customize your email content here
    msg.set_content(f"""Hello,

Your verification code for PassLock is: 

{code}

Do not share this code with anyone. If you did not request this, please secure your account immediately.

Best regards,
PassLock Security Team""")
    msg['Subject'] = "PassLock Verification Code"
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to_email

    context = ssl.create_default_context()
    try:
        # Use SMTP with STARTTLS (Port 587) to fix timeouts
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        # Fallback: Print code to console so development isn't blocked by email issues
        print(f"\n[FALLBACK EMAIL] To: {to_email} | Code: {code}\n")
        return True

@app.route('/api/2fa/setup', methods=['POST'])
@login_required
def setup_2fa():
    """Generates a 6-digit code and sends it via email for 2FA setup."""
    code = ''.join(random.choices(string.digits, k=6))
    session['2fa_setup_code'] = code
    
    if send_verification_email(current_user.email, code):
        return jsonify({'status': 'success', 'message': 'Verification code sent to email.'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to send email.'}), 500

@app.route('/api/2fa/verify', methods=['POST'])
@login_required
def verify_2fa():
    """Verifies the TOTP code and enables 2FA if correct."""
    data = request.get_json()
    code = data.get('code')
    stored_code = session.get('2fa_setup_code')
    
    if stored_code and code == stored_code:
        user = User.query.get(current_user.id)
        # We use 'email_enabled' as a flag in the totp_secret column
        user.totp_secret = 'email_enabled'
        db.session.commit()
        session.pop('2fa_setup_code', None)
        return jsonify({'status': 'success', 'message': '2FA enabled successfully.'})
    
    return jsonify({'status': 'error', 'message': 'Invalid verification code.'}), 400

@app.route('/api/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disables 2FA for the current user."""
    user = User.query.get(current_user.id)
    user.totp_secret = None
    db.session.commit()
    return jsonify({'status': 'success', 'message': '2FA disabled successfully.'})

@app.route('/api/account', methods=['DELETE'])
@login_required
def delete_account():
    """Permanently deletes the current user's account."""
    user = User.query.get(current_user.id)
    if user:
        db.session.delete(user)
        db.session.commit()
        logout_user()
        return jsonify({'status': 'success', 'message': 'Account deleted successfully.'})
    
    return jsonify({'status': 'error', 'message': 'User not found'}), 404

@app.route('/users')
@login_required
def list_users():
    """Lists all registered users (Debug/Admin view)."""
    if current_user.email != app.config['ADMIN_EMAIL']:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('vault_page'))

    users = User.query.all()
    return render_template('users.html', users=users)

# --- Database Initialization ---
def init_db():
    """Creates the database tables from the models."""
    with app.app_context():
        db.create_all()
    print("Database initialized.")

def get_local_ip():
    """Attempts to determine the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable, just used to find the interface IP
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

if __name__ == '__main__':
    if 'PASTE_YOUR' in app.config['GOOGLE_CLIENT_ID']:
        print("\nCRITICAL WARNING: Google OAuth credentials are not set. Google Login will fail with Error 401.")
        print("Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in app.py or environment variables.\n")
    with app.app_context():
        db.create_all()
    
        # --- Auto-Migration: Add totp_secret if missing ---
        try:
            db.session.execute(text("SELECT totp_secret FROM user LIMIT 1"))
        except Exception:
            print("Migrating database: Adding 'totp_secret' column...")
            db.session.execute(text("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)"))
            db.session.commit()
            print("Migration complete.")

    local_ip = get_local_ip()
    print(f"\n--- ACCESS INSTRUCTIONS ---")
    print(f"Local:  https://127.0.0.1:5000  <-- USE THIS ON PC")
    print(f"Mobile: https://{local_ip}.nip.io:5000")
    print(f"1. In Google Cloud Console, add this to 'Authorized redirect URIs':")
    print(f"   https://{local_ip}.nip.io:5000/google/callback")
    print(f"2. On your phone, access the site using this URL (NOT the IP address):")
    print(f"   https://{local_ip}.nip.io:5000")
    print(f"----------------------------------\n")
    
    app.run(host='0.0.0.0', debug=True, ssl_context='adhoc')
