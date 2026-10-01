# PassLock
A learning-focused password manager demo built with Flask and the Web Crypto API. The vault is encrypted in the browser, so the Flask server stores an opaque encrypted blob rather than the vault contents or the vault key.

> **Demo status:** This project is for education and local experimentation. It has not been hardened or audited for production use.

## How it works

The application has two separate secrets:

- **Login password:** sent to Flask during login and stored as a bcrypt hash.
- **Vault master password:** entered on the vault page and used only in the browser to derive the encryption key.

After login, the browser fetches the user's encrypted vault and PBKDF2 salt from `/api/vault`. It derives an AES key locally, decrypts the vault, and encrypts it again before each save. The server does not receive the master password or derived key.

### Cryptography

- Password hashing: bcrypt
- Key derivation: PBKDF2-HMAC-SHA256 with 310,000 iterations and a per-user random salt
- Vault encryption: AES-256-GCM with a fresh 12-byte random IV for each encryption
- Browser implementation: native Web Crypto API

No custom cryptographic primitives are implemented.

## Features

- Email/password registration and login
- Google OAuth login integration
- Client-side encrypted vault entries
- Add, edit, delete, reveal, and copy vault passwords
- Master-password hint management
- Vault inactivity auto-lock
- Account deletion
- 2-step verification screen for six-digit email codes
- CSRF protection and no-cache headers for sensitive responses

## Two-step verification

The `templates/login_2fa.html` screen is intended to complete login after a verification code has been sent to the user's email address. The expected flow is:

1. Submit the login form.
2. Enter the six-digit code on the 2-step verification screen.
3. Submit **Verify & Login**, or use **Resend Code** to request another code.

This verification code is separate from the vault master password. The master password is still required in the browser to decrypt the vault.

> **Current status:** The template references a `resend_2fa_code` endpoint, but the current Flask source does not define the 2FA generation, email delivery, verification, or login-enforcement routes. The screen is therefore a UI/template for the planned flow, not a complete active 2FA implementation.

## Requirements

- Python 3.9 or newer
- `pip`
- A modern browser with Web Crypto API support

## Run locally

From the project directory, create and activate a virtual environment:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies listed in `requirements.txt`:

```bash
python -m pip install -r requirements.txt
```

Start the development server:

```bash
python app.py
```

Open [https://127.0.0.1:5000](https://127.0.0.1:5000). The development server uses a self-signed, ad-hoc certificate, so your browser will display a certificate warning.

On first use, register an account, log in, and choose a vault master password. Keep the login password and master password distinct if you want the two protections to remain independent.

## Configuration notes

The current demo configuration uses a local SQLite database at `instance/users.db`, creates a new Flask session secret on each process start, and runs Flask in debug mode. These defaults are convenient for learning but unsuitable for deployment.

Google login also requires a Google OAuth client configured for the local callback URL. Before enabling it, replace the placeholder/demo OAuth settings in `app.py` with credentials supplied through a secure environment-based configuration. Never commit real credentials to source control.

## Project layout

```text
app.py                 Flask routes, sessions, OAuth, and API endpoints
auth.py                User model, database setup, and bcrypt authentication
vault.py               Encrypted-vault persistence helpers
static/crypto.js       Browser-side PBKDF2 and AES-GCM operations
static/app.js          Vault unlock, editing, locking, and API calls
templates/             HTML templates for authentication and vault screens
instance/              Local SQLite database files
api/index.py           Deployment entry point
vercel.json            Vercel rewrite configuration
```

## Security limitations

- A compromised or modified frontend can read the master password and decrypted vault while the page is open. Zero-knowledge storage does not protect against XSS, malicious dependencies, or a compromised deployment.
- The login password and vault master password are separate, but the current account-recovery story is intentionally incomplete. Losing the master password means losing access to the vault.
- The Flask development server, debug mode, ad-hoc TLS, generated session secret, and credentials in application configuration must not be used as-is in production.
- The project does not provide a full production security model for sharing, recovery, audit logging, rate limiting, backups, or administrator controls.
- The 2FA template is present, but server-side code generation, delivery, verification, expiry, rate limiting, and enforcement still need to be implemented and tested.
- Clipboard clearing and browser memory cleanup cannot be guaranteed by JavaScript.
- Review and test the deployment platform's database, secret, TLS, session, and logging configuration before exposing the application to real users.

## License

No license has been specified for this demo repository.
