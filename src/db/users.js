import { randomUUID } from 'node:crypto';

const UNIQUE_VIOLATION = '23505';

function toUser(row) {
  return row ? { id: row.id, email: row.email, createdAt: row.created_at } : null;
}

export async function createUser(db, { email, passwordHash }) {
  try {
    const { rows } = await db.query(
      'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, created_at',
      [randomUUID(), email, passwordHash],
    );
    return toUser(rows[0]);
  } catch (err) {
    if (err.code === UNIQUE_VIOLATION) {
      return null;
    }
    throw err;
  }
}

export async function findUserById(db, id) {
  const { rows } = await db.query('SELECT id, email, created_at FROM users WHERE id = $1', [id]);
  return toUser(rows[0]);
}

export async function findCredentialsByEmail(db, email) {
  const { rows } = await db.query('SELECT id, password_hash FROM users WHERE email = $1', [email]);
  return rows[0] ? { id: rows[0].id, passwordHash: rows[0].password_hash } : null;
}
