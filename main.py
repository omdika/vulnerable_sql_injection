from fastapi import FastAPI, HTTPException
import sqlite3
import os
import hashlib
import hmac
import binascii

app = FastAPI(title="Secure Login Demo")

# Database configuration
DB_FILE = 'users.db'

# Password hashing utilities using PBKDF2-HMAC-SHA256
def hash_password(password: str, salt: bytes = None) -> str:
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256.

    Returns a string in the format: iterations$salt_hex$hash_hex
    """
    if salt is None:
        salt = os.urandom(16)
    iterations = 100_000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f"{iterations}${binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against the stored PBKDF2-HMAC-SHA256 value."""
    try:
        iterations_str, salt_hex, hash_hex = stored.split('$')
        iterations = int(iterations_str)
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(hash_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(dk, expected)
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
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                   ('admin', hash_password('password123')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                   ('user1', hash_password('secret456')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                   ('test', hash_password('test789')))

    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/")
async def root():
    return {"message": "Secure Login Demo - Visit /login endpoint"}


def safe_login_query(username: str, password: str, db_file=DB_FILE):
    """
    Secure login function that uses parameterized queries and verifies hashed passwords.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Parameterized query prevents SQL injection by keeping user input separate from SQL syntax
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        stored_password = row[2]
        if verify_password(password, stored_password):
            return row
        else:
            return None
    except Exception as e:
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Secure login endpoint that uses parameterized queries and hashed password verification"""
    try:
        user = safe_login_query(username, password)

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
