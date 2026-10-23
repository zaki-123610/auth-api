import { randomBytes } from 'node:crypto';
import bcrypt from 'bcrypt';

export const BCRYPT_COST = 12;

// Compared against when the email is unknown, so both login failures take the same time.
const dummyHash = bcrypt.hash(randomBytes(32).toString('hex'), BCRYPT_COST);

export function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_COST);
}

export async function verifyPassword(password, passwordHash) {
  if (!passwordHash) {
    await bcrypt.compare(password, await dummyHash);
    return false;
  }
  return bcrypt.compare(password, passwordHash);
}
