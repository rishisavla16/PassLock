# secure_password_manager/app.py

import os
from dotenv import load_dotenv
from datetime import timedelta
from flask import Flask, render_template, redirect, url_for, request, session, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from authlib.integrations.flask_client import OAuth
from auth import create_user, check_user, User, init_app as init_auth, db
from vault import get_vault, update_vault

# --- App Configuration ---
load_dotenv()  # Load .env file
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Set a permanent session lifetime for auto-logout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# --- OAuth Configuration ---
# Credentials are loaded from .env — never hardcode secrets in source.
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET', '')

# --- Initializations ---
init_auth(app)
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
        
        # Input validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
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
        
        user = check_user(email, password)
        
        if user:
            login_user(user)
            return redirect(url_for('vault_page'))
        else:
            # Security: Generic error message to prevent username enumeration.
            flash('Invalid email or password.', 'danger')
            
    return render_template('login.html')

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

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# --- Database Initialization ---
def init_db():
    """Creates the database tables from the models."""
    with app.app_context():
        db.create_all()
    print("Database initialized.")

if __name__ == '__main__':
    if 'PASTE_YOUR' in app.config['GOOGLE_CLIENT_ID']:
        print("\nCRITICAL WARNING: Google OAuth credentials are not set. Google Login will fail with Error 401.")
        print("Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in app.py or environment variables.\n")
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True, ssl_context='adhoc')
