import 'dotenv/config';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { SqlVaultDatabase } from './config/database.js';
import { createApiRouter } from './routes/apiRoutes.js';
import { AuthService } from './services/AuthService.js';

export function createApp(storagePath = process.env.DB_STORAGE_PATH || ':memory:') {
  const app = express();
  const db = new SqlVaultDatabase(storagePath);
  const authService = new AuthService(db);

  app.use(helmet());
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
      credentials: true,
    })
  );
  app.use(express.json());
  app.use(cookieParser());

  app.get('/api/health', (_req, res) => {
    res.status(200).json({
      service: 'fortress-jwt-rbac-api',
      status: 'healthy',
      zeroTrustFeatures: ['In-Memory JWT', 'HttpOnly Refresh Rotation', 'Bcrypt', 'RBAC'],
    });
  });

  app.use('/api', createApiRouter(db, authService));

  return { app, db, authService };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT || 4000);
  const { app } = createApp();
  app.listen(port, () => {
    console.log(`[fortress-jwt-rbac] Zero-Trust REST API listening on http://localhost:${port}`);
  });
}
