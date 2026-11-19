"""SQLite storage for the JWKS server: keys, users, and auth logs.

Every query uses sqlite3 "?" placeholders so that values are bound by the
driver and never interpolated into the SQL text (prevents SQL injection).

Private keys are stored AES-encrypted (see ``crypto.py``); this module only
ever sees and stores opaque ciphertext blobs.
"""
import sqlite3
import time

DB_FILE = "totally_not_my_privateKeys.db"

CREATE_KEYS_SQL = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

CREATE_AUTH_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""


def connect(db_file=DB_FILE):
    """Open (creating if needed) the database and ensure the schema exists."""
    conn = sqlite3.connect(db_file, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    for sql in (CREATE_KEYS_SQL, CREATE_USERS_SQL, CREATE_AUTH_LOGS_SQL):
        conn.execute(sql)
    conn.commit()
    return conn


# --- keys ---------------------------------------------------------------

def insert_key(conn, blob, exp):
    """Store an (encrypted) private key that expires at unix time `exp`.

    Returns the new key's kid.
    """
    cur = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (blob, int(exp)))
    conn.commit()
    return cur.lastrowid


def get_key(conn, expired=False, now=None):
    """Return one (kid, blob, exp) row, either expired or still valid.

    Returns None if no matching key exists.
    """
    now = int(time.time()) if now is None else int(now)
    if expired:
        query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
    else:
        query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
    return conn.execute(query, (now,)).fetchone()


def get_valid_keys(conn, now=None):
    """Return all (kid, blob, exp) rows that have not yet expired."""
    now = int(time.time()) if now is None else int(now)
    return conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ?", (now,)
    ).fetchall()


# --- users --------------------------------------------------------------

def insert_user(conn, username, password_hash, email=None):
    """Create a user and return its id.

    Raises sqlite3.IntegrityError if the username or email is already taken.
    """
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
        (username, password_hash, email),
    )
    conn.commit()
    return cur.lastrowid


def get_user(conn, username):
    """Return (id, password_hash) for `username`, or None if unknown."""
    return conn.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()


def touch_last_login(conn, user_id):
    """Set a user's last_login to the current time."""
    conn.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,)
    )
    conn.commit()


# --- auth logs ----------------------------------------------------------

def log_auth(conn, request_ip, user_id=None):
    """Record a successful POST /auth request."""
    conn.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request_ip, user_id),
    )
    conn.commit()
