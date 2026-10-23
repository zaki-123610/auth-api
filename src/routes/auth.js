import { Router } from 'express';
import { createUser, findCredentialsByEmail } from '../db/users.js';
import { authenticate } from '../middleware/authenticate.js';
import { createAuthRateLimiter } from '../middleware/rateLimit.js';
import { hashPassword, verifyPassword } from '../services/passwords.js';
import { endSession, refreshSession, startSession } from '../services/sessions.js';
import { HttpError } from '../utils/httpError.js';
import { validateLogin, validateRefreshToken, validateSignup } from '../utils/validation.js';

export function createAuthRouter({ db, config }) {
  const router = Router();

  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  router.post('/signup', createAuthRateLimiter(config.authRateLimit), async (req, res) => {
    const { email, password } = validateSignup(req.body);
    const user = await createUser(db, { email, passwordHash: await hashPassword(password) });
    if (!user) {
      throw new HttpError(409, 'An account with this email already exists');
    }
    res.status(201).json({ user });
  });

  router.post('/login', createAuthRateLimiter(config.authRateLimit), async (req, res) => {
    const { email, password } = validateLogin(req.body);
    const credentials = await findCredentialsByEmail(db, email);
    const passwordMatches = await verifyPassword(password, credentials?.passwordHash);
    if (!credentials || !passwordMatches) {
      throw new HttpError(401, 'Invalid email or password');
    }
    res.json(await startSession(db, config, credentials.id));
  });

  router.post('/refresh', async (req, res) => {
    const tokens = await refreshSession(db, config, validateRefreshToken(req.body));
    if (!tokens) {
      throw new HttpError(401, 'Invalid or expired refresh token');
    }
    res.json(tokens);
  });

  router.post('/logout', async (req, res) => {
    await endSession(db, validateRefreshToken(req.body));
    res.status(204).end();
  });

  router.get('/me', authenticate({ db, config }), (req, res) => {
    res.json({ user: req.user });
  });

  return router;
}
