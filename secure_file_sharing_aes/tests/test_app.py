import base64
import io
import sqlite3

import pytest

from app import create_app


@pytest.fixture
def app(tmp_path):
    app = create_app({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-only',
        'AES_KEY_B64': base64.urlsafe_b64encode(b'K'*32).decode(),
        'DATABASE': str(tmp_path/'db.sqlite3'),
        'STORAGE_DIR': str(tmp_path/'encrypted'),
    })
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    client.get('/login')
    with client.session_transaction() as s:
        return s['csrf']


def register(client, name, password='a-long-test-password'):
    return client.post('/register',data={'csrf':csrf(client),'username':name,'password':password},follow_redirects=True)


def login(client, name, password='a-long-test-password'):
    return client.post('/login',data={'csrf':csrf(client),'username':name,'password':password},follow_redirects=True)


def logout(client):
    return client.post('/logout',data={'csrf':csrf(client)},follow_redirects=True)


def test_registration_and_authentication(client):
    r=register(client,'alice')
    assert b'Account created' in r.data
    assert b'Invalid username or password' in login(client,'alice','wrong').data
    assert b'Secure file dashboard' in login(client,'alice').data
    assert b'logged out' in logout(client).data


def test_upload_encrypt_share_revoke_and_decrypt(app,client):
    register(client,'alice')
    register(client,'bob')
    register(client,'charlie')
    login(client,'alice')
    raw=b'%PDF-1.4 secret binary example\x00\xff'
    r=client.post('/upload',data={'csrf':csrf(client),'file':(io.BytesIO(raw),'report.pdf')},content_type='multipart/form-data',follow_redirects=True)
    assert b'File encrypted' in r.data
    with sqlite3.connect(app.config['DATABASE']) as db:
        file_id,storage_name,nonce=db.execute('SELECT id,storage_name,nonce FROM files').fetchone()
        bob=db.execute("SELECT id FROM users WHERE username='bob'").fetchone()[0]
    from pathlib import Path
    encrypted_path=Path(app.config['STORAGE_DIR'])/storage_name
    assert raw not in encrypted_path.read_bytes()
    assert len(nonce)==12
    assert client.get('/download/'+file_id).data==raw
    r=client.post('/share/'+file_id,data={'csrf':csrf(client),'recipient_id':bob},follow_redirects=True)
    assert b'File shared' in r.data
    logout(client)
    login(client,'charlie')
    assert client.get('/download/'+file_id).status_code==404
    logout(client)
    login(client,'bob')
    assert client.get('/download/'+file_id).data==raw
    logout(client)
    login(client,'alice')
    r=client.post(f'/revoke/{file_id}/{bob}',data={'csrf':csrf(client)},follow_redirects=True)
    assert b'revoked' in r.data
    logout(client)
    login(client,'bob')
    assert client.get('/download/'+file_id).status_code==404
    logout(client)
    login(client,'alice')
    data=bytearray(encrypted_path.read_bytes())
    data[-1]^=1
    encrypted_path.write_bytes(data)
    assert client.get('/download/'+file_id).status_code==409


def test_csrf_and_admin_permissions(app,client):
    register(client,'alice')
    login(client,'alice')
    assert client.get('/admin').status_code==403
    assert client.post('/upload',data={}).status_code==400
    assert client.post('/admin/user/1/toggle',data={'csrf':csrf(client)}).status_code==403
    with sqlite3.connect(app.config['DATABASE']) as db:
        db.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',('root','unused','admin','today'))
        db.commit()
    logout(client)
    # Admin password is set using an actual Werkzeug password hash.
    from werkzeug.security import generate_password_hash
    with sqlite3.connect(app.config['DATABASE']) as db:
        db.execute("UPDATE users SET password_hash=? WHERE username='root'",(generate_password_hash('an-admin-password'),))
        db.commit()
    login(client,'root','an-admin-password')
    assert client.get('/admin').status_code==200
    with sqlite3.connect(app.config['DATABASE']) as db:
        alice=db.execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    assert client.post(f'/admin/user/{alice}/toggle',data={'csrf':csrf(client)},follow_redirects=True).status_code==200
    logout(client)
    assert b'Invalid username or password' in login(client,'alice').data
