"""Tests for the SQLite-backed JWKS server."""
import base64
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid

from argon2 import PasswordHasher
from cryptography.exceptions import InvalidTag
import jwt

import crypto
import database
import main

TEST_SECRET = "unit-test-secret-not-a-real-key"


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.key = crypto.load_key({crypto.ENV_VAR: TEST_SECRET})

    def test_load_key_requires_env(self):
        with self.assertRaises(RuntimeError):
            crypto.load_key({})
        with self.assertRaises(RuntimeError):
            crypto.load_key({crypto.ENV_VAR: ""})

    def test_load_key_reads_os_environ(self):
        old = os.environ.get(crypto.ENV_VAR)
        os.environ[crypto.ENV_VAR] = TEST_SECRET
        try:
            self.assertEqual(crypto.load_key(), self.key)
        finally:
            if old is None:
                del os.environ[crypto.ENV_VAR]
            else:
                os.environ[crypto.ENV_VAR] = old

    def test_round_trip_and_random_nonce(self):
        a = crypto.encrypt(self.key, b"secret pem")
        b = crypto.encrypt(self.key, b"secret pem")
        self.assertNotEqual(a, b)
        self.assertNotIn(b"secret pem", a)
        self.assertEqual(crypto.decrypt(self.key, a), b"secret pem")

    def test_wrong_key_or_tampering_fails(self):
        blob = crypto.encrypt(self.key, b"secret pem")
        other = crypto.load_key({crypto.ENV_VAR: "something else"})
        with self.assertRaises(InvalidTag):
            crypto.decrypt(other, blob)
        tampered = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            crypto.decrypt(self.key, tampered)

    def test_hash_password_is_argon2id(self):
        hashed = crypto.hash_password("hunter2")
        self.assertTrue(hashed.startswith("$argon2id$"))
        self.assertTrue(PasswordHasher().verify(hashed, "hunter2"))


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = database.connect(":memory:")
        self.key = crypto.load_key({crypto.ENV_VAR: TEST_SECRET})

    def tearDown(self):
        self.conn.close()

    def test_schema_created(self):
        tables = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"keys", "users", "auth_logs"} <= tables)

    def test_empty_db_has_no_keys(self):
        self.assertIsNone(database.get_key(self.conn))
        self.assertIsNone(database.get_key(self.conn, expired=True))
        self.assertEqual(database.get_valid_keys(self.conn), [])

    def test_insert_and_select_by_expiry(self):
        now = int(time.time())
        valid = database.insert_key(self.conn, b"valid", now + 100)
        expired = database.insert_key(self.conn, b"expired", now - 100)
        self.assertEqual(database.get_key(self.conn)[0], valid)
        self.assertEqual(database.get_key(self.conn, expired=True)[0], expired)
        self.assertEqual([r[0] for r in database.get_valid_keys(self.conn)], [valid])

    def test_injection_value_is_stored_literally(self):
        payload = b"x'); DROP TABLE keys; --"
        kid = database.insert_key(self.conn, payload, time.time() + 100)
        self.assertEqual(database.get_key(self.conn)[:2], (kid, payload))
        self.assertEqual(database.get_valid_keys(self.conn)[0][0], kid)
        uid = database.insert_user(self.conn, "x' OR '1'='1", "hash")
        self.assertIsNone(database.get_user(self.conn, "' OR '1'='1"))
        self.assertEqual(database.get_user(self.conn, "x' OR '1'='1")[0], uid)

    def test_users_unique_and_last_login(self):
        uid = database.insert_user(self.conn, "alice", "h", "a@example.com")
        self.assertEqual(database.get_user(self.conn, "alice"), (uid, "h"))
        self.assertIsNone(database.get_user(self.conn, "bob"))
        with self.assertRaises(sqlite3.IntegrityError):
            database.insert_user(self.conn, "alice", "h2")
        with self.assertRaises(sqlite3.IntegrityError):
            database.insert_user(self.conn, "alice2", "h2", "a@example.com")
        database.touch_last_login(self.conn, uid)
        last = self.conn.execute(
            "SELECT last_login FROM users WHERE id = ?", (uid,)).fetchone()[0]
        self.assertIsNotNone(last)

    def test_log_auth(self):
        uid = database.insert_user(self.conn, "alice", "h")
        database.log_auth(self.conn, "1.2.3.4", uid)
        database.log_auth(self.conn, "5.6.7.8")
        rows = self.conn.execute(
            "SELECT request_ip, user_id, request_timestamp FROM auth_logs ORDER BY id"
        ).fetchall()
        self.assertEqual([r[:2] for r in rows], [("1.2.3.4", uid), ("5.6.7.8", None)])
        self.assertTrue(all(r[2] for r in rows))

    def test_ensure_keys_seeds_once_encrypted(self):
        main.ensure_keys(self.conn, self.key)
        main.ensure_keys(self.conn, self.key)
        rows = self.conn.execute("SELECT key FROM keys").fetchall()
        self.assertEqual(len(rows), 2)
        for (blob,) in rows:
            self.assertNotIn(b"PRIVATE KEY", bytes(blob))
            self.assertIn(b"BEGIN RSA PRIVATE KEY", crypto.decrypt(self.key, blob))

    def test_check_keys_decrypt(self):
        main.ensure_keys(self.conn, self.key)
        main.check_keys_decrypt(self.conn, self.key)
        other = crypto.load_key({crypto.ENV_VAR: "wrong"})
        with self.assertRaises(RuntimeError):
            main.check_keys_decrypt(self.conn, other)

    def test_make_server_rejects_wrong_key(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, path)
        conn = database.connect(path)
        main.ensure_keys(conn, crypto.load_key({crypto.ENV_VAR: "original"}))
        conn.close()
        saved = main.MyServer.db
        old = os.environ.get(crypto.ENV_VAR)
        os.environ[crypto.ENV_VAR] = "different"
        try:
            with self.assertRaises(RuntimeError):
                main.make_server("127.0.0.1", 0, path)
        finally:
            main.MyServer.db = saved
            if old is None:
                del os.environ[crypto.ENV_VAR]
            else:
                os.environ[crypto.ENV_VAR] = old

    def test_int_to_base64(self):
        self.assertEqual(main.int_to_base64(65537), "AQAB")
        self.assertEqual(main.int_to_base64(1), "AQ")


class RateLimiterTests(unittest.TestCase):
    def test_sliding_window(self):
        now = [100.0]
        limiter = main.RateLimiter(limit=3, window=1.0, clock=lambda: now[0])
        self.assertEqual([limiter.allow("a") for _ in range(4)],
                         [True, True, True, False])
        self.assertTrue(limiter.allow("b"))  # limits are per client
        now[0] += 0.5
        self.assertFalse(limiter.allow("a"))
        now[0] += 0.5  # first three hits have now left the window
        self.assertTrue(limiter.allow("a"))


class UsernameParsingTests(unittest.TestCase):
    def basic(self, value):
        return {"Authorization": "Basic " + base64.b64encode(value).decode()}

    def test_basic_auth(self):
        self.assertEqual(main.username_from_request(self.basic(b"bob:pw"), b""), "bob")

    def test_json_body(self):
        body = json.dumps({"username": "carol", "password": "x"}).encode()
        self.assertEqual(main.username_from_request({}, body), "carol")

    def test_invalid_inputs(self):
        self.assertIsNone(main.username_from_request(
            {"Authorization": "Basic !!!"}, b""))
        self.assertIsNone(main.username_from_request(self.basic(b"\xff:pw"), b""))
        self.assertIsNone(main.username_from_request(self.basic(b":pw"), b""))
        self.assertIsNone(main.username_from_request({}, b"not json"))
        self.assertIsNone(main.username_from_request({}, b"[1, 2]"))
        self.assertIsNone(main.username_from_request({}, b'{"username": 5}'))


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ[crypto.ENV_VAR] = TEST_SECRET
        fd, cls.db_file = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls.server = main.make_server("127.0.0.1", 0, cls.db_file)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        main.MyServer.db.close()
        os.remove(cls.db_file)

    def setUp(self):
        # Fresh limiter per test so tests don't throttle each other.
        main.MyServer.limiter = main.RateLimiter()

    def request(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            with err:
                return err.code, err.read()

    def post_json(self, path, obj):
        return self.request("POST", path, json.dumps(obj).encode(),
                            {"Content-Type": "application/json"})

    def jwks(self):
        status, body = self.request("GET", "/.well-known/jwks.json")
        self.assertEqual(status, 200)
        return json.loads(body)["keys"]

    def db(self):
        conn = database.connect(self.db_file)
        self.addCleanup(conn.close)
        return conn

    def log_count(self):
        return self.db().execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]

    def test_db_file_has_encrypted_valid_and_expired_keys(self):
        conn = self.db()
        self.assertIsNotNone(database.get_key(conn))
        self.assertIsNotNone(database.get_key(conn, expired=True))
        for (blob,) in conn.execute("SELECT key FROM keys"):
            self.assertNotIn(b"PRIVATE KEY", bytes(blob))

    def test_valid_jwt_verifies_against_jwks(self):
        status, token = self.post_json("/auth", {"username": "userABC",
                                                 "password": "password123"})
        self.assertEqual(status, 200)
        kid = jwt.get_unverified_header(token)["kid"]
        jwk = next(k for k in self.jwks() if k["kid"] == kid)
        key = jwt.PyJWK.from_dict(jwk).key
        claims = jwt.decode(token, key, algorithms=["RS256"])
        self.assertEqual(claims["user"], "userABC")

    def test_expired_jwt_not_in_jwks(self):
        status, token = self.request("POST", "/auth?expired=true")
        self.assertEqual(status, 200)
        kid = jwt.get_unverified_header(token)["kid"]
        self.assertNotIn(kid, [k["kid"] for k in self.jwks()])
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertLess(claims["exp"], time.time())

    def test_register_then_auth_is_logged(self):
        username = "user-" + uuid.uuid4().hex
        status, body = self.post_json("/register", {"username": username,
                                                    "email": username + "@ex.com"})
        self.assertEqual(status, 201)
        password = json.loads(body)["password"]
        self.assertEqual(uuid.UUID(password).version, 4)

        user_id, password_hash = database.get_user(self.db(), username)
        self.assertNotIn(password, password_hash)
        self.assertTrue(PasswordHasher().verify(password_hash, password))

        status, _ = self.post_json("/auth", {"username": username, "password": password})
        self.assertEqual(status, 200)
        conn = self.db()
        ip, logged_id, ts = conn.execute(
            "SELECT request_ip, user_id, request_timestamp FROM auth_logs "
            "ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual((ip, logged_id), ("127.0.0.1", user_id))
        self.assertIsNotNone(ts)
        last_login = conn.execute(
            "SELECT last_login FROM users WHERE id = ?", (user_id,)).fetchone()[0]
        self.assertIsNotNone(last_login)

    def test_register_without_email(self):
        status, body = self.post_json("/register", {"username": "u-" + uuid.uuid4().hex})
        self.assertEqual(status, 201)
        self.assertIn("password", json.loads(body))

    def test_register_duplicate(self):
        username = "dup-" + uuid.uuid4().hex
        self.assertEqual(self.post_json("/register", {"username": username})[0], 201)
        self.assertEqual(self.post_json("/register", {"username": username})[0], 409)

    def test_register_bad_input(self):
        for body in [b"", b"not json", b"[1]", b'{"email": "a@b.c"}',
                     b'{"username": ""}', b'{"username": "x", "email": 5}']:
            with self.subTest(body=body):
                status, _ = self.request("POST", "/register", body,
                                         {"Content-Type": "application/json"})
                self.assertEqual(status, 400)

    def test_rate_limit(self):
        before = self.log_count()
        statuses = [self.request("POST", "/auth")[0] for _ in range(main.RATE_LIMIT + 5)]
        self.assertEqual(statuses, [200] * main.RATE_LIMIT + [429] * 5)
        # Only the successful requests were logged.
        self.assertEqual(self.log_count() - before, main.RATE_LIMIT)
        # Other endpoints are not limited.
        self.assertEqual(self.request("GET", "/.well-known/jwks.json")[0], 200)

    def test_bad_methods_and_paths(self):
        for method, path in [("PUT", "/auth"), ("PATCH", "/auth"), ("DELETE", "/auth"),
                             ("HEAD", "/auth"), ("GET", "/auth"), ("GET", "/register"),
                             ("POST", "/.well-known/jwks.json"), ("POST", "/nope")]:
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path)[0], 405)

    def test_auth_without_suitable_key(self):
        saved = main.MyServer.db
        main.MyServer.db = database.connect(":memory:")
        try:
            before = self.log_count()
            self.assertEqual(self.request("POST", "/auth")[0], 500)
            self.assertEqual(self.log_count(), before)
        finally:
            main.MyServer.db.close()
            main.MyServer.db = saved


if __name__ == "__main__":
    unittest.main()
