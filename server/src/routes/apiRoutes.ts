import crypto from 'node:crypto';
import { Router, Response } from 'express';
import { SqlVaultDatabase } from '../config/database.js';
import {
  AuthenticatedRequest,
  createAuthMiddleware,
  requirePermission,
} from '../middleware/rbacMiddleware.js';
import { AuthService } from '../services/AuthService.js';

const REFRESH_COOKIE_NAME = 'fortress_rt';

export function createApiRouter(db: SqlVaultDatabase, authService: AuthService): Router {
  const router = Router();
  const requireAuth = createAuthMiddleware(authService);

  const setHttpOnlyRefreshCookie = (res: Response, rawToken: string): void => {
    res.cookie(REFRESH_COOKIE_NAME, rawToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  };

  router.post('/auth/login', (req, res) => {
    const { email, password } = req.body as { email?: string; password?: string };
    if (!email || !password) {
      res.status(400).json({ error: 'MISSING_FIELDS', message: 'Email and password are required.' });
      return;
    }

    try {
      const session = authService.authenticate(email, password);
      setHttpOnlyRefreshCookie(res, session.refreshTokenRaw);

      res.status(200).json({
        accessToken: session.accessToken,
        user: session.user,
        securityMetadata: {
          tokenStorage: 'IN_MEMORY_CLOSURE_ONLY',
          refreshCookie: 'HTTP_ONLY_SAME_SITE_STRICT',
          passwordHashAlgorithm: 'BCRYPT_12_ROUNDS',
        },
      });
    } catch {
      res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Credenciais inválidas. Verifique o e-mail e a senha.',
      });
    }
  });

  router.post('/auth/refresh', (req, res) => {
    const rawRefresh = req.cookies?.[REFRESH_COOKIE_NAME] as string | undefined;
    if (!rawRefresh) {
      res.status(401).json({ error: 'NO_REFRESH_COOKIE', message: 'No HttpOnly refresh cookie present.' });
      return;
    }

    try {
      const rotatedSession = authService.rotateRefreshToken(rawRefresh);
      setHttpOnlyRefreshCookie(res, rotatedSession.refreshTokenRaw);

      res.status(200).json({
        accessToken: rotatedSession.accessToken,
        user: rotatedSession.user,
      });
    } catch (err) {
      res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
      const code = err instanceof Error ? err.message : 'REFRESH_FAILED';
      res.status(401).json({ error: code });
    }
  });

  router.post('/auth/logout', (req, res) => {
    const rawRefresh = req.cookies?.[REFRESH_COOKIE_NAME] as string | undefined;
    if (rawRefresh) {
      authService.revokeSessionByRefreshToken(rawRefresh);
    }
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
    res.status(200).json({ status: 'LOGGED_OUT' });
  });

  router.get(
    '/approvals',
    requireAuth,
    requirePermission('approvals:read'),
    (_req: AuthenticatedRequest, res: Response) => {
      res.status(200).json({ approvals: db.listApprovals() });
    }
  );

  router.post(
    '/approvals/:id/decision',
    requireAuth,
    requirePermission('approvals:approve'),
    (req: AuthenticatedRequest, res: Response) => {
      const { id } = req.params;
      const { decision } = req.body as { decision?: 'APPROVED' | 'REJECTED' };

      if (decision !== 'APPROVED' && decision !== 'REJECTED') {
        res.status(400).json({ error: 'INVALID_DECISION' });
        return;
      }

      const actor = req.auth!;
      const updated = db.updateApprovalStatus(id, decision, actor.email);
      if (!updated) {
        res.status(404).json({ error: 'APPROVAL_NOT_FOUND' });
        return;
      }

      db.appendAuditLog({
        id: crypto.randomUUID(),
        actorEmail: actor.email,
        actorRole: actor.role,
        action: `APPROVAL_${decision}`,
        resourceId: id,
        details: `Changed financial approval "${updated.title}" status to ${decision}.`,
        timestamp: new Date().toISOString(),
      });

      res.status(200).json({ approval: updated });
    }
  );

  router.get(
    '/audit-logs',
    requireAuth,
    requirePermission('audit:read'),
    (_req: AuthenticatedRequest, res: Response) => {
      res.status(200).json({ logs: db.listAuditLogs(25) });
    }
  );

  return router;
}
