import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../src/config.js';
import { TEST_ENV } from './helpers.js';

const SERVER_PATH = fileURLToPath(new URL('../src/server.js', import.meta.url));

describe('loadConfig', () => {
  it('loads a valid environment with secure defaults', () => {
    const config = loadConfig(TEST_ENV);

    assert.equal(config.port, 3000);
    assert.equal(config.trustProxy, 0);
    assert.equal(config.jwt.accessTokenTtlSeconds, 900);
    assert.ok(Object.isFrozen(config));
  });

  it('throws when JWT_SECRET is missing', () => {
    assert.throws(() => loadConfig({ ...TEST_ENV, JWT_SECRET: undefined }), /JWT_SECRET is not set/);
  });

  it('throws when JWT_SECRET is shorter than 32 characters', () => {
    assert.throws(() => loadConfig({ ...TEST_ENV, JWT_SECRET: 'change-me' }), /at least 32 characters/);
  });

  it('throws when DATABASE_URL is missing', () => {
    assert.throws(() => loadConfig({ ...TEST_ENV, DATABASE_URL: '' }), /DATABASE_URL is not set/);
  });

  it('throws on an invalid PORT or TRUST_PROXY', () => {
    assert.throws(() => loadConfig({ ...TEST_ENV, PORT: 'abc' }), /PORT/);
    assert.throws(() => loadConfig({ ...TEST_ENV, TRUST_PROXY: 'true' }), /TRUST_PROXY/);
  });
});

describe('server startup', () => {
  function startServer(env) {
    const cwd = mkdtempSync(join(tmpdir(), 'auth-api-'));
    try {
      return spawnSync(process.execPath, [SERVER_PATH], { cwd, env, encoding: 'utf8', timeout: 10_000 });
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  }

  it('refuses to start when JWT_SECRET is missing', () => {
    const env = { ...process.env, DATABASE_URL: TEST_ENV.DATABASE_URL };
    delete env.JWT_SECRET;
    const result = startServer(env);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Refusing to start: JWT_SECRET is not set/);
  });

  it('refuses to start when JWT_SECRET is too short', () => {
    const result = startServer({ ...process.env, DATABASE_URL: TEST_ENV.DATABASE_URL, JWT_SECRET: 'too-short' });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Refusing to start: JWT_SECRET must be at least 32 characters long/);
  });
});
