import { createApp } from '../server/src/index.js';

const storagePath =
  process.env.DB_STORAGE_PATH || (process.env.VERCEL ? '/tmp/fortress-vault.db' : ':memory:');

const { app } = createApp(storagePath);

export default app;
