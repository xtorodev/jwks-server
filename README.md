# JWKS Server

A small JWKS server backed by SQLite (`totally_not_my_privateKeys.db`).

| Endpoint | Description |
| --- | --- |
| `POST /register` | Body `{"username": "...", "email": "..."}`. Creates a user and returns `{"password": "<uuid4>"}` (201). |
| `POST /auth` | Returns a signed RS256 JWT. `?expired` signs with an expired key. Rate limited to 10 requests/second per IP (429 when exceeded). Successful requests are logged to `auth_logs`. |
| `GET /.well-known/jwks.json` | Public keys for all unexpired signing keys. |

## Security

- Private keys are encrypted at rest with AES-256-GCM (random nonce per key,
  stored in front of the ciphertext). The AES key is derived from the
  `NOT_MY_KEY` environment variable, which must be set. Never commit it.
- Passwords are generated with UUIDv4 and stored as Argon2id hashes.
- All SQL uses parameterized queries.

## Running

```sh
python -m venv env
env/bin/python -m pip install -r requirements.txt
export NOT_MY_KEY='some long random secret'
env/bin/python main.py          # listens on localhost:8080
```

## Tests

```sh
env/bin/python -m coverage run --source=. --omit='env/*' -m unittest test_server
env/bin/python -m coverage report -m
env/bin/python -m flake8 --max-line-length=100 --exclude=env,Docs .
```
