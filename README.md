# CipherShare — Secure File Sharing System with AES Encryption

A **working academic prototype** implementing the research project's ten functional requirements. It uses **Flask, SQLite, and AES-256-GCM authenticated encryption**, with user authentication, permission-based file sharing, an admin console, and activity logging.

## Windows installation (Python 3.10+)

1. Clone the project and open its folder:

```bat
git clone https://github.com/salvation8am/CipherShare-AES.git
cd CipherShare-AES\secure_file_sharing_aes
```

2. Run:
   
```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python create_admin.py
python app.py
```

4. In your browser, open **http://127.0.0.1:5000**. Create regular users from the **Register** page. The admin account is created through `create_admin.py` with a password that you choose.
5. To stop the application press Ctrl+C. Next time, activate the environment and run `python app.py`.

Linux/macOS: use `python3 -m venv .venv`, `source .venv/bin/activate`, and `python3` instead of `python`.

## Recommended demonstration

1. Create an administrator and two users, e.g. `alice` and `bob` (passwords **at least 12 characters**).
2. Log in as Alice, upload a PDF, and verify it appears in **My encrypted files**.
3. Check the `instance/encrypted` directory: the `.bin` contents are **ciphertext**, not the uploaded PDF.
4. Share the file with Bob. Log in as Bob and download it: the recovered PDF should open normally.
5. Log in as an unrelated user and try the same download URL: it is denied (HTTP 404).
6. Revoke Bob's access and verify his download URL is denied after revocation.
7. Log in as admin and show account controls and the audit trail.
8. Tamper with a copied encrypted file in a **disposable test environment** and demonstrate that AES-GCM authentication rejects decryption.

## Architecture

- **Presentation tier:** Jinja HTML templates, CSS and browser forms.
- **Application tier:** Flask routes, account authentication, role checks, permission checks, AES-GCM encryption and decryption, audit events.
- **Data tier:** SQLite database for file metadata/accounts/shares/logs; `instance/encrypted` for encrypted file bytes.

Each file uses a fresh random 96-bit GCM nonce. The ciphertext is authenticated with its file ID as additional authenticated data. Decryption occurs only after a permission check. Files are held in memory when uploaded/decrypted, so a 20 MB limit applies. This is not end-to-end encryption: the application server holds the encryption key and decrypts authorized downloads.

## Security and limitations

This is a **local academic prototype**, not a production-certified healthcare or enterprise deployment. The `instance` folder contains the database and locally generated secret keys. **Back up `instance/.aes_key` securely**: losing it permanently prevents decryption of existing files. Never publish, email, or commit the `instance` folder or environment secrets. On production hosts, supply independent `AES_KEY_B64` (URL-safe base64 of 32 random bytes) and `FLASK_SECRET_KEY` via an external secrets manager or environment variables.

- Use HTTPS and set `SESSION_COOKIE_SECURE=True` in production (local HTTP uses False).
- Default server is intended for local demonstration only. Use a hardened WSGI server and reverse proxy in real deployments.
- The demonstration's single application-wide AES key means compromise of that key can expose all encrypted files; production should use managed envelope encryption and key rotation.
- CSRF verification, password hashing, authorization checks, upload size limits, authenticated encryption, and basic in-memory login throttling are included. Distributed rate limiting, malware scanning, external backups, full operational monitoring, and independent penetration testing are **not** included.
- Disabled users cannot log in or retrieve files. Admins can manage user statuses and view activities, but are **not automatically allowed to decrypt users' files**.
- Filenames are normalized on upload; original file byte content is preserved.

## Test suite

Run from the project folder:

```bash
python -m pytest -v
```

Tests cover registration, logins, file encryption/decryption, sharing, permissions, CSRF, admin-only access, revocation, and ciphertext tampering.

## Dissertation alignment

The app implements Chapter Three's user registration, login, role authorization, file upload, AES encryption, storage, sharing, download/decryption, and administration. Use screenshots of **your actual running copy** and results from **your own tests** when revising Chapter Four. Do not treat interface mockups or standalone cipher benchmarks as application-level proof.

# CipherShare
Secure file sharing web app using AES encryption.

## Features
- User registration and login
- AES-encrypted file upload and download
- Share and revoke file access
- Admin panel

## Setup
pip install -r requirements.txt
python create_admin.py
python app.py

## Tests
pytest

## Tech
Python, Flask, SQLite, AES
