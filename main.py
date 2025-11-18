from fastapi import FastAPI, HTTPException
import sqlite3
import os
import re
import hashlib
import hmac

app = FastAPI(title="Secure Login Demo")

# Database configuration
DB_FILE = 'users.db'

# Password hashing utilities
def hash_password(password: str, salt: bytes = None) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256. Returns salt$hash as hex strings."""
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + '$' + dk.hex()

def verify_password(stored: str, provided: str) -> bool:
    """Verify a provided password against the stored salt$hash using constant-time comparison."""
    try:
        salt_hex, dk_hex = stored.split('$')
        salt = bytes.fromhex(salt_hex)
        dk = bytes.fromhex(dk_hex)
        new_dk = hashlib.pbkdf2_hmac('sha256', provided.encode('utf-8'), salt, 100000)
        return hmac.compare_digest(dk, new_dk)
    except Exception:
        return False

# Create a simple SQLite database with a users table
def init_db(db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Insert some test users with hashed passwords
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", hash_password('password123')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("user1", hash_password('secret456')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("test", hash_password('test789')))

    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/")
async def root():
    return {"message": "Secure Login Demo - Visit /login endpoint"}

def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """
    Secure login function replacing the previous vulnerable implementation.

    This function uses parameterized queries to prevent SQL injection and
    verifies passwords by comparing secure password hashes using a constant-time
    comparison to mitigate timing attacks.
    """
    # Basic server-side validation (defense-in-depth)
    # Allow only typical username characters and reasonable length
    if not re.match(r'^[A-Za-z0-9_.-]{3,30}$', username):
        return None

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Use parameterized query to avoid SQL injection
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        stored_hash = row[2]
        if verify_password(stored_hash, password):
            return row
        else:
            return None

    except Exception as e:
        # Re-raise for the caller to handle/log appropriately
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Secure login endpoint that uses parameterized queries and hashed passwords"""
    try:
        user = vulnerable_login_query(username, password)

        if user:
            return {
                "status": "success",
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1]
                }
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
