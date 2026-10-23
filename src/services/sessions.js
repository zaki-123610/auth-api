import { randomUUID } from 'node:crypto';
import {
  consumeRefreshToken,
  findRefreshToken,
  insertRefreshToken,
  revokeFamily,
} from '../db/refreshTokens.js';
import { generateRefreshToken, hashToken, signAccessToken } from './tokens.js';

async function issueTokens(db, config, userId, familyId) {
  const refreshToken = generateRefreshToken();
  await insertRefreshToken(db, {
    userId,
    familyId,
    tokenHash: hashToken(refreshToken),
    expiresAt: new Date(Date.now() + config.refreshTokenTtlMs),
  });

  return {
    tokenType: 'Bearer',
    accessToken: signAccessToken(userId, config.jwt),
    expiresIn: config.jwt.accessTokenTtlSeconds,
    refreshToken,
  };
}

export function startSession(db, config, userId) {
  return issueTokens(db, config, userId, randomUUID());
}

export async function refreshSession(db, config, refreshToken) {
  const tokenHash = hashToken(refreshToken);
  const session = await consumeRefreshToken(db, tokenHash);
  if (session) {
    return issueTokens(db, config, session.userId, session.familyId);
  }

  // A revoked token being replayed means it leaked: end the whole session it belongs to.
  const stored = await findRefreshToken(db, tokenHash);
  if (stored?.revokedAt) {
    await revokeFamily(db, stored.familyId);
  }
  return null;
}

export async function endSession(db, refreshToken) {
  const stored = await findRefreshToken(db, hashToken(refreshToken));
  if (stored) {
    await revokeFamily(db, stored.familyId);
  }
}
