"""JWKS server backed by a SQLite key store.

Endpoints:
    POST /register               -> create a user, returns {"password": <uuid4>}
    POST /auth                   -> signed JWT (``?expired`` signs with an expired key)
    GET  /.well-known/jwks.json  -> public JWKs for all unexpired keys

Private keys are AES-encrypted in the database with a key taken from the
NOT_MY_KEY environment variable. POST /auth is rate limited per client IP and
every successful request is recorded in the auth_logs table.
"""
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import binascii
import json
import sqlite3
import threading
import time
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

import crypto
import database

hostName = "localhost"
serverPort = 8080

RATE_LIMIT = 10        # requests ...
RATE_WINDOW = 1.0      # ... per this many seconds


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def generate_pem():
    """Generate a new RSA private key serialized as PKCS1 PEM bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def check_keys_decrypt(conn, aes_key):
    """Raise RuntimeError if any stored key can't be decrypted with `aes_key`."""
    for kid, blob in conn.execute("SELECT kid, key FROM keys"):
        try:
            crypto.decrypt(aes_key, blob)
        except InvalidTag:
            raise RuntimeError(
                f"key {kid} in the database cannot be decrypted: NOT_MY_KEY differs "
                "from the one used to create it, or the database predates "
                "encryption. Use the original NOT_MY_KEY or delete the database."
            ) from None


def ensure_keys(conn, aes_key, now=None):
    """Make sure the DB holds at least one valid and one expired key."""
    now = int(time.time()) if now is None else int(now)
    if database.get_key(conn, expired=False, now=now) is None:
        database.insert_key(conn, crypto.encrypt(aes_key, generate_pem()), now + 3600)
    if database.get_key(conn, expired=True, now=now) is None:
        database.insert_key(conn, crypto.encrypt(aes_key, generate_pem()), now - 3600)


class RateLimiter:
    """Sliding-window limiter: at most `limit` hits per `window` seconds per client."""

    def __init__(self, limit=RATE_LIMIT, window=RATE_WINDOW, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self.clock = clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client):
        """Record a hit for `client`; return False if it exceeds the limit."""
        now = self.clock()
        with self._lock:
            hits = self._hits[client]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def username_from_request(headers, body):
    """Extract the username from HTTP Basic auth or a JSON body, else None."""
    auth = headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
            return decoded.split(":", 1)[0] or None
        except (binascii.Error, UnicodeDecodeError):
            pass
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(data, dict) and isinstance(data.get("username"), str):
        return data["username"]
    return None


class MyServer(BaseHTTPRequestHandler):
    # Set on the class before serving (see make_server).
    db = None
    aes_key = None
    limiter = None

    def _send(self, status, body=None, content_type="application/json"):
        """Send a response with an optional body."""
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body is not None:
            self.wfile.write(body)

    def _send_json(self, status, obj):
        self._send(status, json.dumps(obj).encode("utf-8"))

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _method_not_allowed(self):
        self._send(405)

    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_HEAD = _method_not_allowed

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/auth":
            self._auth()
        elif path == "/register":
            self._register()
        else:
            self._method_not_allowed()

    def _register(self):
        try:
            data = json.loads(self._read_body())
        except (ValueError, UnicodeDecodeError):
            data = None
        if not isinstance(data, dict):
            self._send_json(400, {"error": "body must be a JSON object"})
            return
        username, email = data.get("username"), data.get("email")
        if not isinstance(username, str) or not username:
            self._send_json(400, {"error": "username is required"})
            return
        if email is not None and not isinstance(email, str):
            self._send_json(400, {"error": "email must be a string"})
            return

        password = str(uuid.uuid4())
        try:
            database.insert_user(self.db, username, crypto.hash_password(password), email)
        except sqlite3.IntegrityError:
            self._send_json(409, {"error": "username or email already registered"})
            return
        self._send_json(201, {"password": password})

    def _auth(self):
        client_ip = self.client_address[0]
        if not self.limiter.allow(client_ip):
            self._send_json(429, {"error": "too many requests"})
            return

        # Credentials are not verified (mocked, as in earlier projects); the
        # username is only used to attribute the request in auth_logs.
        username = username_from_request(self.headers, self._read_body())

        expired = 'expired' in parse_qs(urlparse(self.path).query)
        row = database.get_key(self.db, expired=expired)
        if row is None:
            self._send_json(500, {"error": "no suitable key available"})
            return

        kid, blob, exp = row
        pem = crypto.decrypt(self.aes_key, blob)
        token_payload = {"user": username or "username", "exp": exp}
        encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256",
                                 headers={"kid": str(kid)})

        user = database.get_user(self.db, username) if username else None
        user_id = user[0] if user else None
        database.log_auth(self.db, client_ip, user_id)
        if user_id is not None:
            database.touch_last_login(self.db, user_id)

        self._send(200, encoded_jwt.encode("utf-8"), "text/plain")

    def do_GET(self):
        if urlparse(self.path).path != "/.well-known/jwks.json":
            self._method_not_allowed()
            return

        jwks = []
        for kid, blob, _exp in database.get_valid_keys(self.db):
            pem = crypto.decrypt(self.aes_key, blob)
            public = serialization.load_pem_private_key(pem, password=None) \
                .public_key().public_numbers()
            jwks.append({
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(public.n),
                "e": int_to_base64(public.e),
            })
        self._send_json(200, {"keys": jwks})


def make_server(host=hostName, port=serverPort, db_file=database.DB_FILE):
    """Load the AES key, open the DB, seed keys, and build the HTTP server."""
    MyServer.aes_key = crypto.load_key()
    MyServer.db = database.connect(db_file)
    MyServer.limiter = RateLimiter()
    try:
        check_keys_decrypt(MyServer.db, MyServer.aes_key)
    except RuntimeError:
        MyServer.db.close()
        raise
    ensure_keys(MyServer.db, MyServer.aes_key)
    return HTTPServer((host, port), MyServer)


if __name__ == "__main__":  # pragma: no cover
    try:
        webServer = make_server()
    except RuntimeError as err:
        raise SystemExit(f"error: {err}")
    print(f"Serving on http://{hostName}:{serverPort} (Ctrl+C to stop)", flush=True)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    MyServer.db.close()
