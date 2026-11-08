import crypto from 'node:crypto';
import { Router, Response } from 'express';
import { SqlVaultDatabase } from '../config/database.js';
import {
  AuthenticatedRequest,
  createAuthMiddleware,
  requirePermission,
  requireRoles,
} from '../middleware/rbacMiddleware.js';
import { AuthService } from '../services/AuthService.js';
import {
  MAX_SAFE_APPROVAL_CENTS,
  ROLE_APPROVAL_LIMIT_CENTS,
} from '../types/domain.js';

export const REFRESH_COOKIE_NAME = 'fortress_rt';

/**
 * Validates that a financial amount in cents is a positive safe integer within the system bounds.
 * Blocks negative numbers, zero, floats, NaN, Infinity, and values > MAX_SAFE_APPROVAL_CENTS.
 */
export function isValidApprovalAmountCents(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= MAX_SAFE_APPROVAL_CENTS
  );
}

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
    const { email, password } = req.body as { email?: unknown; password?: unknown };
    if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password) {
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

  router.post('/auth/refresh', async (req, res) => {
    const rawRefresh = req.cookies?.[REFRESH_COOKIE_NAME] as string | undefined;
    if (!rawRefresh || typeof rawRefresh !== 'string') {
      res.status(401).json({ error: 'NO_REFRESH_COOKIE', message: 'No HttpOnly refresh cookie present.' });
      return;
    }

    try {
      const rotatedSession = await authService.rotateRefreshTokenAsync(rawRefresh);
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
    if (rawRefresh && typeof rawRefresh === 'string') {
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
    '/approvals',
    requireAuth,
    requirePermission('approvals:create'),
    (req: AuthenticatedRequest, res: Response) => {
      const { title, vendor, amountCents } = req.body as {
        title?: unknown;
        vendor?: unknown;
        amountCents?: unknown;
      };

      if (typeof title !== 'string' || title.trim().length < 3) {
        res.status(400).json({ error: 'INVALID_TITLE', message: 'Title must be at least 3 characters.' });
        return;
      }

      if (typeof vendor !== 'string' || vendor.trim().length < 2) {
        res.status(400).json({ error: 'INVALID_VENDOR', message: 'Vendor name is required.' });
        return;
      }

      if (!isValidApprovalAmountCents(amountCents)) {
        res.status(400).json({
          error: 'INVALID_AMOUNT_CENTS',
          message: `amountCents must be a positive safe integer between 1 and ${MAX_SAFE_APPROVAL_CENTS}.`,
        });
        return;
      }

      const actor = req.auth!;
      const now = new Date().toISOString();
      const created = db.createApproval({
        id: `APR-${crypto.randomInt(1000, 9999)}`,
        title: title.trim(),
        vendor: vendor.trim(),
        amountCents,
        status: 'PENDING',
        requestedBy: actor.email,
        decidedBy: null,
        createdAt: now,
        updatedAt: now,
      });

      res.status(201).json({ approval: created });
    }
  );

  router.post(
    '/approvals/:id/decision',
    requireAuth,
    requirePermission('approvals:approve'),
    (req: AuthenticatedRequest, res: Response) => {
      const id = String(req.params.id);
      const { decision } = req.body as { decision?: unknown };

      if (decision !== 'APPROVED' && decision !== 'REJECTED') {
        res.status(400).json({ error: 'INVALID_DECISION' });
        return;
      }

      const existing = db.findApprovalById(id);
      if (!existing) {
        res.status(404).json({ error: 'APPROVAL_NOT_FOUND' });
        return;
      }

      if (existing.status !== 'PENDING') {
        res.status(409).json({
          error: 'APPROVAL_ALREADY_FINALIZED',
          message: `Approval ${id} was already ${existing.status}.`,
        });
        return;
      }

      const actor = req.auth!;
      const roleLimitCents = ROLE_APPROVAL_LIMIT_CENTS[actor.role];

      if (existing.amountCents > roleLimitCents) {
        res.status(403).json({
          error: 'RBAC_AMOUNT_LIMIT_EXCEEDED',
          message: `Role "${actor.role}" ceiling is ${roleLimitCents} cents, but batch "${id}" requires ${existing.amountCents} cents. ADMIN clearance required.`,
        });
        return;
      }

      const updated = db.updateApprovalStatus(id, decision, actor.email);

      db.appendAuditLog({
        id: crypto.randomUUID(),
        actorEmail: actor.email,
        actorRole: actor.role,
        action: `APPROVAL_${decision}`,
        resourceId: id,
        details: `Changed financial approval "${existing.title}" status to ${decision}.`,
        timestamp: new Date().toISOString(),
      });

      res.status(200).json({ approval: updated });
    }
  );

  /**
   * ADMIN-only endpoint to revoke an entire session family by ID (`sessions:revoke`).
   */
  router.post(
    '/sessions/:familyId/revoke',
    requireAuth,
    requireRoles(['ADMIN']),
    requirePermission('sessions:revoke'),
    (req: AuthenticatedRequest, res: Response) => {
      const familyId = String(req.params.familyId);
      const revokedCount = authService.revokeFamilyById(familyId);
      res.status(200).json({ familyId, revokedCount });
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
