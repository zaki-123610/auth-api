import { createHash, randomBytes } from 'node:crypto';
import jwt from 'jsonwebtoken';

const JWT_ALGORITHM = 'HS256';

export function signAccessToken(userId, { secret, accessTokenTtlSeconds }) {
  return jwt.sign({}, secret, {
    algorithm: JWT_ALGORITHM,
    subject: userId,
    expiresIn: accessTokenTtlSeconds,
  });
}

export function verifyAccessToken(token, { secret }) {
  return jwt.verify(token, secret, { algorithms: [JWT_ALGORITHM] });
}

export function generateRefreshToken() {
  return randomBytes(32).toString('base64url');
}

// Refresh tokens are 256 random bits, so a fast hash is enough (no brute force possible).
export function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}
