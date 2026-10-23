import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { createTestContext, TEST_ENV } from './helpers.js';

const PASSWORD = 'correct-horse-42';

let app;
let db;

before(async () => {
  ({ app, db } = await createTestContext());
});

after(async () => {
  await db.end();
});

function signup(email, password = PASSWORD) {
  return request(app).post('/auth/signup').send({ email, password });
}

function login(email, password = PASSWORD) {
  return request(app).post('/auth/login').send({ email, password });
}

function me(authorization) {
  const req = request(app).get('/auth/me');
  return authorization === undefined ? req : req.set('Authorization', authorization);
}

function refresh(refreshToken) {
  return request(app).post('/auth/refresh').send({ refreshToken });
}

async function registeredUser() {
  const email = `user-${randomUUID()}@example.com`;
  const res = await signup(email);
  assert.equal(res.status, 201);
  return { email, user: res.body.user };
}

describe('GET /', () => {
  it('describes the API, its endpoints and the repository', async () => {
    const res = await request(app).get('/');

    assert.equal(res.status, 200);
    assert.equal(res.body.name, 'Auth API');
    assert.equal(res.body.status, 'ok');
    assert.equal(res.body.repository, 'https://github.com/zaki-123610/auth-api');
    assert.deepEqual(
      res.body.endpoints.filter((endpoint) => endpoint.authRequired),
      [{ method: 'GET', path: '/auth/me', authRequired: true }],
    );
    assert.ok(res.body.endpoints.every((e) => typeof e.method === 'string' && typeof e.path === 'string'));
  });

  it('only lists endpoints that exist, with accurate auth requirements', async () => {
    const { endpoints } = (await request(app).get('/')).body;

    for (const { method, path, authRequired } of endpoints) {
      const res = await request(app)[method.toLowerCase()](path);
      assert.notEqual(res.status, 404, `${method} ${path}`);
      assert.equal(res.status === 401, authRequired, `${method} ${path} returned ${res.status}`);
    }
  });
});

describe('POST /auth/signup', () => {
  it('creates a user, stores a lowercase email and a bcrypt hash, never returns the hash', async () => {
    const res = await signup('  Alice@Example.COM ');

    assert.equal(res.status, 201);
    assert.deepEqual(Object.keys(res.body.user).sort(), ['createdAt', 'email', 'id']);
    assert.equal(res.body.user.email, 'alice@example.com');
    assert.doesNotMatch(JSON.stringify(res.body), /password|\$2[aby]\$/i);

    const { rows } = await db.query('SELECT email, password_hash FROM users WHERE id = $1', [res.body.user.id]);
    assert.equal(rows[0].email, 'alice@example.com');
    assert.match(rows[0].password_hash, /^\$2b\$12\$/);
  });

  it('returns 409 when the email is already registered, whatever its case', async () => {
    await signup('bob@example.com');
    const res = await signup('BOB@example.com');

    assert.equal(res.status, 409);
    assert.equal(res.body.error, 'An account with this email already exists');
  });

  it('returns 400 with per-field details for invalid input', async () => {
    const cases = [
      [{ email: 'not-an-email', password: PASSWORD }, 'email', 'Email must be a valid email address'],
      [{ email: 'user@localhost', password: PASSWORD }, 'email', 'Email must be a valid email address'],
      [{ password: PASSWORD }, 'email', 'Email is required'],
      [{ email: 'short@example.com', password: 'abc123' }, 'password', 'Password must be at least 8 characters long'],
      [{ email: 'digits@example.com', password: '12345678' }, 'password', 'Password must contain at least one letter and one number'],
      [{ email: 'letters@example.com', password: 'abcdefgh' }, 'password', 'Password must contain at least one letter and one number'],
      [{ email: 'long@example.com', password: `a1${'x'.repeat(71)}` }, 'password', 'Password must be at most 72 bytes long'],
      [{ email: { $ne: '' }, password: PASSWORD }, 'email', 'Email is required'],
    ];

    for (const [body, field, message] of cases) {
      const res = await request(app).post('/auth/signup').send(body);
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.equal(res.body.error, 'Validation failed');
      assert.equal(res.body.details[field], message);
    }
  });

  it('returns 400 when the body is missing', async () => {
    const res = await request(app).post('/auth/signup');

    assert.equal(res.status, 400);
    assert.deepEqual(res.body.details, { email: 'Email is required', password: 'Password is required' });
  });
});

describe('POST /auth/login', () => {
  it('returns an HS256 access token with sub, iat and a 15 minute exp, plus a refresh token', async () => {
    const { email, user } = await registeredUser();
    const res = await login(email.toUpperCase());

    assert.equal(res.status, 200);
    assert.equal(res.body.tokenType, 'Bearer');
    assert.equal(res.body.expiresIn, 900);
    assert.equal(typeof res.body.refreshToken, 'string');

    const { header, payload } = jwt.decode(res.body.accessToken, { complete: true });
    assert.equal(header.alg, 'HS256');
    assert.equal(payload.sub, user.id);
    assert.equal(payload.exp - payload.iat, 900);
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('returns the same 401 for a wrong password and an unknown email', async () => {
    const { email } = await registeredUser();
    const wrongPassword = await login(email, 'wrong-password-1');
    const unknownEmail = await login('nobody@example.com');

    assert.equal(wrongPassword.status, 401);
    assert.equal(unknownEmail.status, 401);
    assert.deepEqual(wrongPassword.body, { error: 'Invalid email or password' });
    assert.deepEqual(unknownEmail.body, wrongPassword.body);
  });

  it('returns 400 when email or password is missing', async () => {
    const res = await request(app).post('/auth/login').send({ email: 'a@example.com' });

    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'Email and password are required');
  });
});

describe('GET /auth/me', () => {
  let user;
  let accessToken;

  before(async () => {
    const registered = await registeredUser();
    user = registered.user;
    accessToken = (await login(registered.email)).body.accessToken;
  });

  it('returns the current user for a valid token', async () => {
    const res = await me(`Bearer ${accessToken}`);

    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { user });
  });

  it('returns 401 without a token', async () => {
    const res = await me();

    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'Missing or malformed Authorization header');
    assert.equal(res.headers['www-authenticate'], 'Bearer');
  });

  it('returns 401 for a malformed Authorization header', async () => {
    for (const header of [accessToken, `Basic ${accessToken}`, 'Bearer', `Bearer ${accessToken} extra`]) {
      const res = await me(header);
      assert.equal(res.status, 401, header);
    }
  });

  it('returns 401 for an invalid token', async () => {
    const [header, payload] = accessToken.split('.');
    const forgedPayload = Buffer.from(JSON.stringify({ sub: randomUUID(), exp: 9999999999 })).toString('base64url');
    const tokens = [
      'not.a.jwt',
      `${header}.${forgedPayload}.${accessToken.split('.')[2]}`,
      jwt.sign({ sub: user.id }, 'a-different-secret-that-is-also-long-enough', { algorithm: 'HS256' }),
      jwt.sign({ sub: user.id }, TEST_ENV.JWT_SECRET, { algorithm: 'HS512' }),
      `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${payload}.`,
    ];

    for (const token of tokens) {
      const res = await me(`Bearer ${token}`);
      assert.equal(res.status, 401, token);
      assert.equal(res.body.error, 'Invalid access token');
    }
  });

  it('returns 401 for an expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = jwt.sign({ sub: user.id, iat: now - 1000, exp: now - 100 }, TEST_ENV.JWT_SECRET, {
      algorithm: 'HS256',
    });
    const res = await me(`Bearer ${expired}`);

    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'Access token has expired');
  });

  it('returns 401 for a correctly signed token whose user does not exist', async () => {
    for (const sub of [randomUUID(), 'not-a-uuid']) {
      const token = jwt.sign({ sub }, TEST_ENV.JWT_SECRET, { algorithm: 'HS256', expiresIn: 60 });
      const res = await me(`Bearer ${token}`);
      assert.equal(res.status, 401, sub);
      assert.equal(res.body.error, 'Invalid access token');
    }
  });
});

describe('POST /auth/refresh', () => {
  it('rotates the refresh token and returns a working access token', async () => {
    const { email, user } = await registeredUser();
    const first = (await login(email)).body;
    const res = await refresh(first.refreshToken);

    assert.equal(res.status, 200);
    assert.notEqual(res.body.refreshToken, first.refreshToken);
    assert.equal((await me(`Bearer ${res.body.accessToken}`)).body.user.id, user.id);
    assert.equal((await refresh(first.refreshToken)).status, 401);
  });

  it('stores only a SHA-256 hash of the refresh token', async () => {
    const { email, user } = await registeredUser();
    const { refreshToken } = (await login(email)).body;

    const { rows } = await db.query('SELECT token_hash FROM refresh_tokens WHERE user_id = $1', [user.id]);
    assert.deepEqual(rows, [{ token_hash: createHash('sha256').update(refreshToken).digest('hex') }]);
  });

  it('revokes the whole session when a rotated token is replayed, without touching other sessions', async () => {
    const { email } = await registeredUser();
    const stolen = (await login(email)).body.refreshToken;
    const otherSession = (await login(email)).body.refreshToken;
    const rotated = (await refresh(stolen)).body.refreshToken;

    const replay = await refresh(stolen);
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error, 'Invalid or expired refresh token');
    assert.equal((await refresh(rotated)).status, 401);
    assert.equal((await refresh(otherSession)).status, 200);
  });

  it('returns 401 for an unknown or expired refresh token', async () => {
    const { email, user } = await registeredUser();
    const { refreshToken } = (await login(email)).body;
    await db.query('UPDATE refresh_tokens SET expires_at = $1 WHERE user_id = $2', [
      new Date(Date.now() - 60_000),
      user.id,
    ]);

    assert.equal((await refresh('this-token-was-never-issued')).status, 401);
    assert.equal((await refresh(refreshToken)).status, 401);
  });

  it('returns 400 when refreshToken is missing', async () => {
    const res = await request(app).post('/auth/refresh').send({});

    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'refreshToken is required');
  });
});

describe('POST /auth/logout', () => {
  it('revokes the refresh token', async () => {
    const { email } = await registeredUser();
    const { refreshToken } = (await login(email)).body;
    const res = await request(app).post('/auth/logout').send({ refreshToken });

    assert.equal(res.status, 204);
    assert.equal((await refresh(refreshToken)).status, 401);
  });

  it('returns 204 for an unknown token so it reveals nothing', async () => {
    const res = await request(app).post('/auth/logout').send({ refreshToken: 'unknown-token' });

    assert.equal(res.status, 204);
  });
});

describe('rate limiting', () => {
  it('returns 429 once the login limit is exceeded', async () => {
    const limited = await createTestContext({ rateLimit: 2 });
    const attempt = () => request(limited.app).post('/auth/login').send({ email: 'x@example.com', password: PASSWORD });

    assert.equal((await attempt()).status, 401);
    assert.equal((await attempt()).status, 401);
    const res = await attempt();
    assert.equal(res.status, 429);
    assert.deepEqual(res.body, { error: 'Too many requests, please try again later' });
    assert.ok(res.headers.ratelimit);

    await limited.db.end();
  });

  it('returns 429 once the signup limit is exceeded', async () => {
    const limited = await createTestContext({ rateLimit: 1 });
    const attempt = () => request(limited.app).post('/auth/signup').send({});

    assert.equal((await attempt()).status, 400);
    assert.equal((await attempt()).status, 429);

    await limited.db.end();
  });
});

describe('hardening', () => {
  it('sets security headers', async () => {
    const res = await request(app).get('/health');

    assert.equal(res.status, 200);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-powered-by'], undefined);
    assert.ok(res.headers['content-security-policy']);
  });

  it('rejects bodies over the size limit with 413', async () => {
    const res = await request(app)
      .post('/auth/signup')
      .send({ email: 'big@example.com', password: 'x'.repeat(20_000) });

    assert.equal(res.status, 413);
    assert.deepEqual(res.body, { error: 'Request body is too large' });
  });

  it('returns a JSON error without a stack trace for malformed JSON', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": ');

    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Request body must be valid JSON' });
  });

  it('returns JSON 404 for unknown routes', async () => {
    const res = await request(app).get('/nope');

    assert.equal(res.status, 404);
    assert.deepEqual(res.body, { error: 'Route not found' });
  });

  it('returns a generic 500 without internals when the database fails', async () => {
    const broken = await createTestContext();
    await broken.db.query('DROP TABLE refresh_tokens; DROP TABLE users;');
    const originalConsoleError = console.error;
    console.error = () => {};

    try {
      const res = await request(broken.app).post('/auth/login').send({ email: 'a@example.com', password: PASSWORD });
      assert.equal(res.status, 500);
      assert.deepEqual(res.body, { error: 'Internal server error' });
    } finally {
      console.error = originalConsoleError;
      await broken.db.end();
    }
  });
});
