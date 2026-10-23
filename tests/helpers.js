import { newDb } from 'pg-mem';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { initSchema } from '../src/db/schema.js';

export const TEST_ENV = Object.freeze({
  JWT_SECRET: 'test-secret-0123456789-abcdefghijklmnopqrstuvwxyz',
  DATABASE_URL: 'postgresql://unused-in-tests',
});

export async function createTestContext({ rateLimit = 1000 } = {}) {
  const { Pool } = newDb().adapters.createPg();
  const db = new Pool();
  await initSchema(db);

  const config = {
    ...loadConfig(TEST_ENV),
    authRateLimit: { windowMs: 60_000, limit: rateLimit },
  };

  return { app: createApp({ db, config }), db, config };
}
