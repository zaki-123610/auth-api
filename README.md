# Auth API

Signup / login API built with Node.js, Express 5, `jsonwebtoken`, bcrypt and PostgreSQL (Neon), using raw parameterized SQL through `pg`.

**Live:** `https://<your-service>.onrender.com` _(placeholder: replace after deploying)_

## Features

- `POST /auth/signup`: validated email + password, bcrypt (cost 12) hash, email stored lowercase and unique
- `POST /auth/login`: returns a short-lived HS256 access token (15 min, claims `sub`, `iat`, `exp`) and a refresh token
- `GET /auth/me`: protected route behind a Bearer-token middleware
- `POST /auth/refresh`: exchanges a refresh token for a new pair (rotation)
- `POST /auth/logout`: revokes the session of a refresh token
- Tables are created on startup if they don't exist
- 34 tests (Node test runner + supertest) against an in-memory Postgres (`pg-mem`), so no database is needed to run them

## Security choices

| Concern | What the API does |
| --- | --- |
| Password storage | bcrypt with cost 12. Passwords must be 8+ characters with a letter and a number, and at most 72 bytes (bcrypt silently ignores anything longer). |
| User enumeration on login | Unknown email and wrong password return the same `401 Invalid email or password`. For an unknown email the password is still compared against a dummy bcrypt hash, so both cases take the same time (measured: 169 ms vs 170 ms median). |
| JWT | Signed and verified with `HS256` only (`algorithms: ['HS256']`), so `alg: none` and algorithm-switching tokens are rejected. Expiry is enforced. The `sub` must belong to an existing user. |
| Secret | `JWT_SECRET` comes from the environment. The app refuses to start if it is missing or shorter than 32 characters. |
| Refresh tokens | 256-bit random opaque tokens. Only their SHA-256 hash is stored, so a database leak doesn't expose usable tokens. Each refresh rotates the token, and a token can only be exchanged once (atomic `UPDATE ... RETURNING`). |
| Refresh token theft | Each login starts a token *family*. Replaying an already-rotated token revokes the whole family, which logs out both the attacker and the victim of that session. Other sessions of the user are untouched. |
| SQL injection | Every query uses `$1`-style parameters; no user input is concatenated into SQL. |
| Brute force | `express-rate-limit` on signup and login: 10 requests per 15 min per IP, then `429`. |
| HTTP hardening | `helmet` headers, 10 kB JSON body limit (`413` above), `Cache-Control: no-store` on auth responses, `WWW-Authenticate: Bearer` on `401`. |
| Error leakage | One error handler returns JSON `{ "error": "..." }`. Unexpected errors are logged server-side and answered with a generic `500`, never a stack trace. |

Trade-offs, kept on purpose:
- Signup returns `409` for an existing email (required by the challenge), which reveals that the email is registered. Rate limiting reduces how much can be learned this way.
- The rate-limit counters live in memory, which is fine for one instance. Multiple instances would need a shared store such as Redis.

## Endpoints

All bodies are JSON. Errors look like `{ "error": "message" }`, and validation errors add a `details` object per field.

| Method | Path | Body | Success | Errors |
| --- | --- | --- | --- | --- |
| POST | `/auth/signup` | `{ email, password }` | `201 { user: { id, email, createdAt } }` | 400, 409, 429 |
| POST | `/auth/login` | `{ email, password }` | `200 { tokenType, accessToken, expiresIn, refreshToken }` | 400, 401, 429 |
| GET | `/auth/me` | header `Authorization: Bearer <accessToken>` | `200 { user }` | 401 |
| POST | `/auth/refresh` | `{ refreshToken }` | `200` new token pair | 400, 401 |
| POST | `/auth/logout` | `{ refreshToken }` | `204` | 400 |
| GET | `/health` | none | `200 { status: "ok" }` | none |

Example:

```bash
curl -X POST http://localhost:3000/auth/signup -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"correct-horse-42"}'

curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"correct-horse-42"}'

curl http://localhost:3000/auth/me -H "Authorization: Bearer <accessToken>"
```

## Run locally

Requires Node.js 20.12+ and a Neon database.

```bash
npm install
cp .env.example .env
```

Fill in `.env`:
- `DATABASE_URL`: the Neon connection string. Use `sslmode=verify-full`. Neon's default `sslmode=require` also works but makes `pg` print a deprecation warning.
- `JWT_SECRET`: generate one with `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`

```bash
npm start        # or: npm run dev (restarts on file changes)
npm test         # no database needed
```

## Deploy on Render

1. Push the repository to GitHub.
2. On Render: **New > Web Service**, then pick the repository.
3. Runtime **Node**, build command `npm ci`, start command `npm start`.
4. Environment variables: `DATABASE_URL` (Neon), `JWT_SECRET` (a new random value, not the local one), `TRUST_PROXY=1`. Don't set `PORT`: Render provides it.
5. Health check path: `/health`.
6. Deploy, then replace the live link at the top of this README.

## Project structure

```
src/
  server.js            entry point: env, config, schema, listen, graceful shutdown
  app.js               Express app (helmet, body limit, routes, error handling)
  config.js            environment validation
  db/                  pool, schema bootstrap, user and refresh-token queries
  middleware/          authenticate (JWT), rate limiter, error handler
  routes/auth.js       /auth endpoints
  services/            bcrypt, JWT/refresh token helpers, session rotation
  utils/               input validation, HttpError
tests/                 auth flow and config/startup tests
```
