"""AES-256-GCM secure file sharing prototype for academic demonstration."""
import base64
import functools
import io
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
MAX_SIZE = 20 * 1024 * 1024


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(DATABASE=str(BASE / 'instance' / 'secure_files.sqlite3'),
                      STORAGE_DIR=str(BASE / 'instance' / 'encrypted'),
                      MAX_CONTENT_LENGTH=MAX_SIZE, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=False)
    if test_config:
        app.config.update(test_config)
    inst = Path(app.config['DATABASE']).parent
    inst.mkdir(parents=True, exist_ok=True)
    Path(app.config['STORAGE_DIR']).mkdir(parents=True, exist_ok=True)

    # Production deployments should pass both secrets through environment variables.
    # For a local demo, a persistent per-installation secret is generated once.
    def load_secret(env_name, path, length):
        val = os.environ.get(env_name)
        if val:
            return val
        if path.exists():
            return path.read_text().strip()
        value = secrets.token_urlsafe(length)
        path.write_text(value)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return value

    if not app.config.get('SECRET_KEY'):
        app.secret_key = load_secret('FLASK_SECRET_KEY', inst / '.flask_secret', 48)
    configured_aes = app.config.get('AES_KEY_B64') or load_secret('AES_KEY_B64', inst / '.aes_key', 32)
    # Local demo generated value is base64-url-safe encoded bytes; environmental key must also decode to 32 bytes.
    try:
        aes_key = base64.urlsafe_b64decode(configured_aes + '=' * (-len(configured_aes) % 4))
    except Exception as e:
        raise RuntimeError('AES_KEY_B64 must contain a base64-encoded 32-byte AES key') from e
    if len(aes_key) != 32:
        raise RuntimeError('AES_KEY_B64 must decode to exactly 32 bytes')
    cipher = AESGCM(aes_key)
    attempts = {}

    def db():
        if 'db' not in g:
            con = sqlite3.connect(app.config['DATABASE'])
            con.row_factory = sqlite3.Row
            con.execute('PRAGMA foreign_keys=ON')
            g.db = con
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        con = g.pop('db', None)
        if con is not None:
            con.close()

    def setup_db():
        con = sqlite3.connect(app.config['DATABASE'])
        con.execute('PRAGMA foreign_keys=ON')
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user'
          CHECK (role IN ('user','admin')), active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files (
          id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
          original_name TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE,
          file_size INTEGER NOT NULL, nonce BLOB NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS shares (
          file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
          recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TEXT NOT NULL, PRIMARY KEY(file_id,recipient_id));
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
          action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
        ''')
        con.commit()
        con.close()
    setup_db()

    def now():
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    def audit(action, detail=''):
        uid = session.get('uid')
        db().execute('INSERT INTO audit(actor_id,action,detail,created_at) VALUES(?,?,?,?)',
                     (uid, action, str(detail)[:200], now()))
        db().commit()

    @app.before_request
    def before_request():
        g.user = None
        if 'uid' in session:
            g.user = db().execute('SELECT * FROM users WHERE id=? AND active=1',
                                  (session['uid'],)).fetchone()
            if g.user is None:
                session.clear()
        if request.method == 'POST':
            if not secrets.compare_digest(str(session.get('csrf', '')), str(request.form.get('csrf', ''))) or not session.get('csrf'):
                abort(400, description='Invalid or missing form security token')

    @app.context_processor
    def context():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_hex(32)
        return {'csrf_token': session['csrf'], 'current_user': getattr(g, 'user', None)}

    def login_required(fn):
        @functools.wraps(fn)
        def decorated(*args, **kwargs):
            if g.user is None:
                flash('Please log in first.', 'warning')
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return decorated

    def admin_required(fn):
        @functools.wraps(fn)
        @login_required
        def decorated(*args, **kwargs):
            if g.user['role'] != 'admin':
                abort(403)
            return fn(*args, **kwargs)
        return decorated

    @app.errorhandler(RequestEntityTooLarge)
    def large_file(_):
        flash('File is too large. Maximum upload size is 20 MB.', 'danger')
        return redirect(url_for('dashboard') if g.user else url_for('login'))

    @app.route('/')
    def index():
        return redirect(url_for('dashboard') if g.user else url_for('login'))

    @app.route('/register', methods=['GET','POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            pw = request.form.get('password','')
            if not (3 <= len(username) <= 40) or not username.replace('_','').isalnum():
                flash('Username must be 3–40 letters, numbers, or underscores.', 'danger')
            elif len(pw) < 12:
                flash('Password must contain at least 12 characters.', 'danger')
            else:
                try:
                    db().execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',
                                 (username,generate_password_hash(pw),'user',now()))
                    db().commit()
                    flash('Account created. You can now log in.', 'success')
                    return redirect(url_for('login'))
                except sqlite3.IntegrityError:
                    flash('Username is already taken.', 'danger')
        return render_template('register.html', title='Register')

    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            pw = request.form.get('password','')
            ip = request.remote_addr or 'unknown'
            key = (ip,username.casefold())
            t = time.monotonic()
            attempts[key] = [x for x in attempts.get(key,[]) if t-x < 300]
            if len(attempts[key]) >= 8:
                flash('Too many login attempts. Try again in five minutes.', 'danger')
            else:
                user = db().execute('SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1', (username,)).fetchone()
                if user and check_password_hash(user['password_hash'],pw):
                    session.clear()
                    session['uid'] = user['id']
                    session['csrf'] = secrets.token_hex(32)
                    attempts.pop(key,None)
                    audit('LOGIN','Successful authentication')
                    return redirect(url_for('dashboard'))
                attempts[key].append(t)
                flash('Invalid username or password.', 'danger')
        return render_template('login.html', title='Login')

    @app.post('/logout')
    @login_required
    def logout():
        audit('LOGOUT','User logged out')
        session.clear()
        flash('You have logged out.', 'success')
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        owned = db().execute('SELECT f.*, (SELECT count(*) FROM shares s WHERE s.file_id=f.id) AS shares_count FROM files f WHERE owner_id=? ORDER BY created_at DESC', (g.user['id'],)).fetchall()
        shared = db().execute('SELECT f.*,u.username AS owner_name FROM files f JOIN shares s ON f.id=s.file_id JOIN users u ON u.id=f.owner_id WHERE s.recipient_id=? ORDER BY s.created_at DESC',(g.user['id'],)).fetchall()
        recipients = db().execute('SELECT id,username FROM users WHERE active=1 AND id!=? ORDER BY username',(g.user['id'],)).fetchall()
        return render_template('dashboard.html',title='Dashboard', owned=owned, shared=shared, recipients=recipients)

    @app.post('/upload')
    @login_required
    def upload():
        item = request.files.get('file')
        if item is None or not item.filename:
            flash('Select a file to upload.', 'danger')
            return redirect(url_for('dashboard'))
        name = secure_filename(item.filename)
        if not name:
            flash('Invalid filename.', 'danger')
            return redirect(url_for('dashboard'))
        content = item.read(MAX_SIZE+1)
        if len(content)>MAX_SIZE:
            flash('File must be 20 MB or smaller.', 'danger')
            return redirect(url_for('dashboard'))
        file_id = str(uuid.uuid4())
        storage_name = file_id+'.bin'
        nonce = os.urandom(12)
        # Authenticated additional data binds ciphertext to immutable database ID.
        encrypted = cipher.encrypt(nonce,content,file_id.encode('ascii'))
        path = Path(app.config['STORAGE_DIR']) / storage_name
        path.write_bytes(encrypted)
        try:
            db().execute('INSERT INTO files(id,owner_id,original_name,storage_name,file_size,nonce,created_at) VALUES(?,?,?,?,?,?,?)',
                         (file_id,g.user['id'],name,storage_name,len(content),nonce,now()))
            db().commit()
        except Exception:
            path.unlink(missing_ok=True)
            raise
        audit('UPLOAD',f'{file_id} / {name}')
        flash('File encrypted with AES-256-GCM and saved.', 'success')
        return redirect(url_for('dashboard'))

    def accessible_file(file_id):
        row = db().execute('''SELECT f.* FROM files f WHERE f.id=? AND
            (f.owner_id=? OR EXISTS(SELECT 1 FROM shares s WHERE s.file_id=f.id AND s.recipient_id=?))''',
            (file_id,g.user['id'],g.user['id'])).fetchone()
        if row is None:
            abort(404)
        return row

    @app.get('/download/<file_id>')
    @login_required
    def download(file_id):
        row = accessible_file(file_id)
        encrypted = (Path(app.config['STORAGE_DIR']) / row['storage_name']).read_bytes()
        try:
            content = cipher.decrypt(row['nonce'],encrypted,row['id'].encode('ascii'))
        except InvalidTag:
            audit('INTEGRITY_FAILURE',file_id)
            abort(409,description='Encrypted file integrity verification failed')
        audit('DOWNLOAD',file_id)
        return send_file(io.BytesIO(content),as_attachment=True,download_name=row['original_name'],mimetype='application/octet-stream')

    @app.post('/share/<file_id>')
    @login_required
    def share(file_id):
        file = db().execute('SELECT * FROM files WHERE id=? AND owner_id=?',(file_id,g.user['id'])).fetchone()
        if not file:
            abort(404)
        try:
            recipient_id = int(request.form.get('recipient_id',''))
        except ValueError:
            abort(400)
        recipient = db().execute('SELECT id FROM users WHERE id=? AND active=1 AND id!=?',(recipient_id,g.user['id'])).fetchone()
        if not recipient:
            flash('Choose a valid recipient.', 'danger')
        else:
            db().execute('INSERT OR IGNORE INTO shares(file_id,recipient_id,created_at) VALUES(?,?,?)',(file_id,recipient_id,now()))
            db().commit()
            audit('SHARE',f'{file_id} to user {recipient_id}')
            flash('File shared with selected user.', 'success')
        return redirect(url_for('dashboard'))

    @app.post('/revoke/<file_id>/<int:recipient_id>')
    @login_required
    def revoke(file_id,recipient_id):
        owner = db().execute('SELECT 1 FROM files WHERE id=? AND owner_id=?',(file_id,g.user['id'])).fetchone()
        if not owner:
            abort(404)
        db().execute('DELETE FROM shares WHERE file_id=? AND recipient_id=?',(file_id,recipient_id))
        db().commit()
        audit('REVOKE',f'{file_id} from {recipient_id}')
        flash('Sharing permission revoked.', 'success')
        return redirect(url_for('file_shares',file_id=file_id))

    @app.get('/shares/<file_id>')
    @login_required
    def file_shares(file_id):
        file = db().execute('SELECT * FROM files WHERE id=? AND owner_id=?',(file_id,g.user['id'])).fetchone()
        if not file:
            abort(404)
        shares = db().execute('SELECT s.*,u.username FROM shares s JOIN users u ON u.id=s.recipient_id WHERE s.file_id=? ORDER BY u.username',(file_id,)).fetchall()
        return render_template('shares.html',title='Manage sharing',file=file,shares=shares)

    @app.post('/delete/<file_id>')
    @login_required
    def delete_file(file_id):
        file = db().execute('SELECT * FROM files WHERE id=? AND owner_id=?',(file_id,g.user['id'])).fetchone()
        if not file:
            abort(404)
        db().execute('DELETE FROM files WHERE id=?',(file_id,))
        db().commit()
        (Path(app.config['STORAGE_DIR']) / file['storage_name']).unlink(missing_ok=True)
        audit('DELETE',file_id)
        flash('File deleted.', 'success')
        return redirect(url_for('dashboard'))

    @app.get('/admin')
    @admin_required
    def admin():
        users = db().execute('SELECT id,username,role,active,created_at FROM users ORDER BY id').fetchall()
        events = db().execute('SELECT a.*,u.username FROM audit a LEFT JOIN users u ON a.actor_id=u.id ORDER BY a.id DESC LIMIT 100').fetchall()
        counts = {'users':db().execute('SELECT count(*) FROM users').fetchone()[0], 'files':db().execute('SELECT count(*) FROM files').fetchone()[0], 'shares':db().execute('SELECT count(*) FROM shares').fetchone()[0]}
        return render_template('admin.html',title='Administration',users=users,events=events,counts=counts)

    @app.post('/admin/user/<int:user_id>/toggle')
    @admin_required
    def toggle_user(user_id):
        target = db().execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not target:
            abort(404)
        if user_id == g.user['id'] or target['role']=='admin':
            abort(403,description='Administrator accounts cannot be disabled here')
        db().execute('UPDATE users SET active=? WHERE id=?',(0 if target['active'] else 1,user_id))
        db().commit()
        audit('USER_STATUS',f'{user_id} active={0 if target["active"] else 1}')
        flash('User status updated.', 'success')
        return redirect(url_for('admin'))

    return app


app = create_app()
if __name__ == '__main__':
    app.run(debug=False)
