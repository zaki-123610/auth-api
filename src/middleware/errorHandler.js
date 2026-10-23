import { HttpError } from '../utils/httpError.js';

const BODY_PARSER_MESSAGES = {
  'entity.parse.failed': 'Request body must be valid JSON',
  'entity.too.large': 'Request body is too large',
};

function sendError(res, status, message, details) {
  if (status === 401) {
    res.set('WWW-Authenticate', 'Bearer');
  }
  res.status(status).json(details ? { error: message, details } : { error: message });
}

export function notFound(req, res) {
  sendError(res, 404, 'Route not found');
}

export function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }
  if (err instanceof HttpError) {
    return sendError(res, err.status, err.message, err.details);
  }
  if (err.expose && err.status >= 400 && err.status < 500) {
    return sendError(res, err.status, BODY_PARSER_MESSAGES[err.type] ?? err.message);
  }

  console.error(err);
  sendError(res, 500, 'Internal server error');
}
