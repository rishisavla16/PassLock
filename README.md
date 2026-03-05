# Secure Password Manager (Zero-Knowledge Demo)

This project is a demo password manager built with Flask and browser-side cryptography.

It is for learning and demonstration.
It is not production ready.

## What this project is trying to do

The server should not know your master password.
The server should also not be able to decrypt your vault.

If the database is leaked, an attacker should only get encrypted vault data and login metadata.

## Security model in plain terms

Assume an attacker gets full access to the server and database files.

The attacker can see:
- username
- password hash (bcrypt, for login only)
- PBKDF2 salt
- encrypted vault blob

The attacker should still not have:
- your master password
- your vault encryption key

The key is derived in the browser from the master password.
Without that password, decrypting the vault is difficult.

## Crypto used

- Login password storage: bcrypt
- Key derivation: PBKDF2-HMAC-SHA256, 310000 iterations, per-user random salt
- Vault encryption: AES-256-GCM with a new random 12-byte IV for each encryption

No custom cryptography is used.

## Run locally

Requirements:
- Python 3
- pip

Create and activate virtual environment:

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-Bcrypt Flask-WTF
```

Start app:

```bash
python app.py
```

Open:

`https://127.0.0.1:5000`

You may see a browser warning because the local certificate is self-signed.

## Important limitations

- This is a demo, not a complete production system.
- XSS is a major risk in zero-knowledge web apps. If malicious JavaScript runs in the page, it can steal secrets.
- Features like account recovery, sharing, audit logs, and full admin controls are not implemented.
- Clipboard auto-clear depends on browser and OS behavior.
- Flask dev server and ad-hoc SSL are for local use only.
