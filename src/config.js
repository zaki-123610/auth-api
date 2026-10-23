const MIN_JWT_SECRET_LENGTH = 32;

function parsePort(value) {
  const port = Number(value ?? 3000);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error('PORT must be an integer between 0 and 65535');
  }
  return port;
}

function parseTrustProxy(value) {
  const hops = Number(value ?? 0);
  if (!Number.isInteger(hops) || hops < 0) {
    throw new Error('TRUST_PROXY must be a non-negative integer (number of proxy hops)');
  }
  return hops;
}

export function loadConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error('JWT_SECRET is not set');
  }
  if (jwtSecret.length < MIN_JWT_SECRET_LENGTH) {
    throw new Error(`JWT_SECRET must be at least ${MIN_JWT_SECRET_LENGTH} characters long`);
  }
  if (!env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not set');
  }

  return Object.freeze({
    port: parsePort(env.PORT),
    databaseUrl: env.DATABASE_URL,
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    jsonBodyLimit: '10kb',
    jwt: Object.freeze({
      secret: jwtSecret,
      accessTokenTtlSeconds: 15 * 60,
    }),
    refreshTokenTtlMs: 7 * 24 * 60 * 60 * 1000,
    authRateLimit: Object.freeze({
      windowMs: 15 * 60 * 1000,
      limit: 10,
    }),
  });
}
