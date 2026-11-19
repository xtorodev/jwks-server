# JWKS Server

A small JWKS server backed by SQLite (`totally_not_my_privateKeys.db`).

| Endpoint | Description |
| --- | --- |
| `POST /register` | Body `{"username": "...", "email": "..."}` (email optional). Creates a user and returns `{"password": "<uuid4>"}` (201). Returns 400 for a missing username or invalid JSON, 409 if the username or email is taken. |
| `POST /auth` | Returns a signed RS256 JWT. `?expired` signs with an expired key. Credentials (Basic auth or JSON body) are not verified; the username is only used to attribute the request. Rate limited to 10 requests/second per IP (429 when exceeded). Successful requests are logged to `auth_logs`. |
| `GET /.well-known/jwks.json` | Public keys for all unexpired signing keys. |

Any other method or path returns 405.

## Security

- Private keys are encrypted at rest with AES-256-GCM (random nonce per key,
  stored in front of the ciphertext). The AES key is derived from the
  `NOT_MY_KEY` environment variable, which must be set. Never commit it.
- Passwords are generated with UUIDv4 and stored as Argon2id hashes.
- All SQL uses parameterized queries.

## Running

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export NOT_MY_KEY='some long random secret'
.venv/bin/python main.py        # listens on localhost:8080
```

The database is created on first start and seeded with one valid and one
expired key. Keys are encrypted with the `NOT_MY_KEY` in use at that time; if
the server is later started with a different value it exits with an error.
Either restore the original value or delete `totally_not_my_privateKeys.db`.

## Tests

```sh
.venv/bin/python -m coverage run --source=. --omit='.venv/*' -m unittest test_server
.venv/bin/python -m coverage report -m
.venv/bin/python -m flake8 --max-line-length=100 --exclude=.venv .
```

## Gradebot

With the [Gradebot](https://github.com/jh125486/CSCE3550) executable in the
project directory (it is gitignored):

```sh
./gradebot project-3 --run=".venv/bin/python main.py" -e "NOT_MY_KEY=some long random secret"
```

Screenshots of the results: `gradebot_output.png` (Gradebot) and
`test_suite.png` (test suite with coverage).
