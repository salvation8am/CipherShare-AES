"""Create the first administrator without a default password."""
import getpass
import sqlite3
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash
from app import app

with app.app_context():
    username = input('Administrator username: ').strip()
    password = getpass.getpass('Administrator password (12+ characters): ')
    if len(username)<3 or len(username)>40 or not username.replace('_','').isalnum() or len(password)<12:
        raise SystemExit('Invalid username or password: use 3-40 letters/numbers/underscores and a password of at least 12 characters.')
    con = sqlite3.connect(app.config['DATABASE'])
    try:
        con.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',
                    (username,generate_password_hash(password),'admin',datetime.now(timezone.utc).isoformat()))
        con.commit()
        print('Administrator created successfully.')
    except sqlite3.IntegrityError:
        print('Username already exists. Choose another.')
    finally:
        con.close()
