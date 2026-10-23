const API_INFO = Object.freeze({
  name: 'Auth API',
  status: 'ok',
  repository: 'https://github.com/zaki-123610/auth-api',
  endpoints: [
    { method: 'GET', path: '/', authRequired: false },
    { method: 'GET', path: '/health', authRequired: false },
    { method: 'POST', path: '/auth/signup', authRequired: false },
    { method: 'POST', path: '/auth/login', authRequired: false },
    { method: 'POST', path: '/auth/refresh', authRequired: false },
    { method: 'POST', path: '/auth/logout', authRequired: false },
    { method: 'GET', path: '/auth/me', authRequired: true },
  ],
});

export function getApiInfo(req, res) {
  res.json(API_INFO);
}
