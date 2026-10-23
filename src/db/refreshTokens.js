import { randomUUID } from 'node:crypto';

export async function insertRefreshToken(db, { userId, familyId, tokenHash, expiresAt }) {
  await db.query(
    'INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5)',
    [randomUUID(), userId, familyId, tokenHash, expiresAt],
  );
}

// Atomically revokes a still-valid token, so a token can only be exchanged once.
export async function consumeRefreshToken(db, tokenHash) {
  const { rows } = await db.query(
    `UPDATE refresh_tokens SET revoked_at = now()
     WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
     RETURNING user_id, family_id`,
    [tokenHash],
  );
  return rows[0] ? { userId: rows[0].user_id, familyId: rows[0].family_id } : null;
}

export async function findRefreshToken(db, tokenHash) {
  const { rows } = await db.query(
    'SELECT family_id, revoked_at FROM refresh_tokens WHERE token_hash = $1',
    [tokenHash],
  );
  return rows[0] ? { familyId: rows[0].family_id, revokedAt: rows[0].revoked_at } : null;
}

export async function revokeFamily(db, familyId) {
  await db.query(
    'UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL',
    [familyId],
  );
}
