from fastapi import FastAPI, HTTPException
import sqlite3
import os
import hashlib
import hmac
import binascii
import re

app = FastAPI(title="Secure Login Demo")

# Database configuration
DB_FILE = 'users.db'

# Password hashing configuration
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16  # bytes

# Create a simple SQLite database with a users table
def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 (sha256).

    Returns a string in the format: salt_hex$hash_hex
    """
    salt = os.urandom(SALT_SIZE)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return f"{binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"


def verify_password(stored: str, provided: str) -> bool:
    """Verify a provided password against the stored salt$hash string."""
    try:
        salt_hex, hash_hex = stored.split('$')
        salt = binascii.unhexlify(salt_hex)
        expected_hash = binascii.unhexlify(hash_hex)
        dk = hashlib.pbkdf2_hmac('sha256', provided.encode('utf-8'), salt, PBKDF2_ITERATIONS)
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(dk, expected_hash)
    except Exception:
        return False


def init_db(db_file=DB_FILE):
    """Initialize the database and insert test users with hashed passwords."""
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Insert some test users with hashed passwords using parameterized queries
        users = [
            ('admin', 'password123'),
            ('user1', 'secret456'),
            ('test', 'test789')
        ]

        for uname, pwd in users:
            hashed = hash_password(pwd)
            cursor.execute(
                "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                (uname, hashed)
            )

        conn.commit()


@app.on_event("startup")
async def startup_event():
    init_db()


@app.get("/")
async def root():
    return {"message": "Secure Login Demo - Visit /login endpoint"}


def validate_username(username: str) -> bool:
    """Basic validation for username: length and allowed characters.

    This is defense-in-depth and not relied upon for SQL protection.
    """
    if not username:
        return False
    if len(username) < 3 or len(username) > 30:
        return False
    # Allow alphanumeric and limited punctuation
    return bool(re.match(r'^[A-Za-z0-9_.-]+$', username))


def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """
    SAFE LOGIN FUNCTION - Uses parameterized queries and secure password verification.
    """
    # Input validation (defense in depth)
    if not validate_username(username):
        return None

    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            # Parameterized query prevents SQL injection
            cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:
                return None

            user_id, user_name, stored_password = row
            if verify_password(stored_password, password):
                return (user_id, user_name)
            else:
                return None
    except Exception as e:
        # Do not leak internal errors to callers in production; return None or raise a generic error
        raise e


@app.post("/login")
async def login(username: str, password: str):
    """Secure login endpoint that uses parameterized queries and hashed passwords."""
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
        # Avoid exposing internals in error responses
        return {
            "status": "error",
            "message": "Internal server error"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
