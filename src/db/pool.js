import pg from 'pg';

export function createPool(connectionString) {
  const pool = new pg.Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });

  // Neon closes idle connections; without this listener the error would crash the process.
  pool.on('error', (err) => {
    console.error('Idle database client error:', err.message);
  });

  return pool;
}
