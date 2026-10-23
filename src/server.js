import { existsSync } from 'node:fs';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { createPool } from './db/pool.js';
import { initSchema } from './db/schema.js';

if (existsSync('.env')) {
  process.loadEnvFile('.env');
}

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(`Refusing to start: ${err.message}`);
  process.exit(1);
}

const pool = createPool(config.databaseUrl);

try {
  await initSchema(pool);
} catch (err) {
  console.error(`Refusing to start: could not initialize the database (${err.message})`);
  process.exit(1);
}

const server = createApp({ db: pool, config }).listen(config.port, (err) => {
  if (err) {
    console.error(`Refusing to start: ${err.message}`);
    process.exit(1);
  }
  console.log(`Auth API listening on port ${config.port}`);
});

function shutdown(signal) {
  console.log(`${signal} received, shutting down`);
  server.close(() => {
    pool.end().finally(() => process.exit(0));
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
