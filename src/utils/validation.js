import { HttpError } from './httpError.js';

// WHATWG HTML email syntax, additionally requiring a dot in the domain.
const EMAIL_PATTERN =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const MAX_EMAIL_LENGTH = 254;
const MIN_PASSWORD_LENGTH = 8;
// bcrypt silently ignores everything after the first 72 bytes.
const MAX_PASSWORD_BYTES = 72;
const MAX_REFRESH_TOKEN_LENGTH = 256;

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function emailError(email) {
  if (typeof email !== 'string' || email.trim() === '') {
    return 'Email is required';
  }
  const normalized = normalizeEmail(email);
  if (normalized.length > MAX_EMAIL_LENGTH || !EMAIL_PATTERN.test(normalized)) {
    return 'Email must be a valid email address';
  }
  return null;
}

function passwordError(password) {
  if (typeof password !== 'string' || password === '') {
    return 'Password is required';
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters long`;
  }
  if (!/\p{L}/u.test(password) || !/\p{Nd}/u.test(password)) {
    return 'Password must contain at least one letter and one number';
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    return `Password must be at most ${MAX_PASSWORD_BYTES} bytes long`;
  }
  return null;
}

export function validateSignup(body) {
  const { email, password } = body ?? {};
  const details = {};
  const emailMessage = emailError(email);
  const passwordMessage = passwordError(password);
  if (emailMessage) details.email = emailMessage;
  if (passwordMessage) details.password = passwordMessage;

  if (Object.keys(details).length > 0) {
    throw new HttpError(400, 'Validation failed', details);
  }
  return { email: normalizeEmail(email), password };
}

export function validateLogin(body) {
  const { email, password } = body ?? {};
  if (typeof email !== 'string' || email.trim() === '' || typeof password !== 'string' || password === '') {
    throw new HttpError(400, 'Email and password are required');
  }
  return { email: normalizeEmail(email), password };
}

export function validateRefreshToken(body) {
  const { refreshToken } = body ?? {};
  if (typeof refreshToken !== 'string' || refreshToken === '' || refreshToken.length > MAX_REFRESH_TOKEN_LENGTH) {
    throw new HttpError(400, 'refreshToken is required');
  }
  return refreshToken;
}
