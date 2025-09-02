import sqlite3
import hashlib
import binascii
import secrets

DATABASE = './app.db'

def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        100_000
    )
    hash_hex = binascii.hexlify(pwd_hash).decode()
    return salt, hash_hex

def add_admin_user(uwin, username, password):
    salt, hashed_password = hash_password(password)
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO Users (uwin, username, hashed_password, salt, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (uwin, username, hashed_password, salt, 'admin'))
            conn.commit()
        print(f"Admin user '{username}' with UWIN '{uwin}' added successfully.")
    except sqlite3.IntegrityError as e:
        print(f"Error: User with username or UWIN already exists. Details: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    add_admin_user('UWIN001', 'admin', 'admin')
