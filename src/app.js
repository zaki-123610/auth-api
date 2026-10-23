import express from 'express';
import helmet from 'helmet';
import { errorHandler, notFound } from './middleware/errorHandler.js';
import { createAuthRouter } from './routes/auth.js';

export function createApp({ db, config }) {
  const app = express();

  app.set('trust proxy', config.trustProxy);
  app.use(helmet());
  app.use(express.json({ limit: config.jsonBodyLimit }));

  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });
  app.use('/auth', createAuthRouter({ db, config }));

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
