# secure_password_manager/auth.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

# --- User Model ---
class User(db.Model, UserMixin):
    """
    User model for the database.
    Stores user identity, hashed login password, and data for vault encryption.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    # For Google OAuth
    google_id = db.Column(db.String(128), unique=True, nullable=True)

    # Security: Stores the bcrypt hash of the LOGIN password.
    # This is separate from the master password used for vault encryption.
    # Made nullable to support passwordless login (e.g., Google).
    password_hash = db.Column(db.String(128), nullable=True)
    
    # Security: Stores the salt for PBKDF2 key derivation.
    # This salt is used CLIENT-SIDE with the master password to derive the encryption key.
    # The server never sees the master password or the derived key.
    pbkdf2_salt = db.Column(db.String(32), nullable=False)
    password_hint = db.Column(db.String(200), nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    
    # Security: Stores the vault as a single encrypted blob.
    # The server cannot decrypt this data.
    encrypted_vault = db.Column(db.Text, nullable=True)

def init_app(app):
    """Initializes the database and bcrypt with the Flask app."""
    db.init_app(app)
    bcrypt.init_app(app)

def create_user(email, pbdfk2_salt, password=None, google_id=None, password_hint=None):
    """
    Creates a new user.
    Security: Hashes the login password with bcrypt before storing if provided.
    """
    hashed_password = None
    if password:
        # Use bcrypt for the login password, as it's a standard for password hashing.
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        email=email, 
        password_hash=hashed_password, 
        pbkdf2_salt=pbdfk2_salt,
        google_id=google_id,
        password_hint=password_hint
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user

def check_user(email, password):
    """
    Verifies a user's login credentials.
    Security: Uses bcrypt's safe comparison function to prevent timing attacks.
    """
    user = User.query.filter_by(email=email).first()
    # Ensure user exists and has a password set before checking
    if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
        return user
    return None
