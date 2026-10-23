import { findUserById } from '../db/users.js';
import { verifyAccessToken } from '../services/tokens.js';
import { HttpError } from '../utils/httpError.js';

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/i;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function authenticate({ db, config }) {
  return async (req, res, next) => {
    const match = BEARER_PATTERN.exec(req.get('Authorization') ?? '');
    if (!match) {
      throw new HttpError(401, 'Missing or malformed Authorization header');
    }

    let payload;
    try {
      payload = verifyAccessToken(match[1], config.jwt);
    } catch (err) {
      throw new HttpError(401, err.name === 'TokenExpiredError' ? 'Access token has expired' : 'Invalid access token');
    }

    if (typeof payload.sub !== 'string' || !UUID_PATTERN.test(payload.sub)) {
      throw new HttpError(401, 'Invalid access token');
    }

    const user = await findUserById(db, payload.sub);
    if (!user) {
      throw new HttpError(401, 'Invalid access token');
    }

    req.user = user;
    next();
  };
}
