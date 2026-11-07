import { NextFunction, Request, Response } from 'express';
import { AuthService } from '../services/AuthService.js';
import { AccessTokenPayload, Permission, UserRole } from '../types/domain.js';

export interface AuthenticatedRequest extends Request {
  auth?: AccessTokenPayload;
}

/**
 * Middleware that validates the In-Memory Bearer JWT Access Token
 * and enforces granular Role-Based Access Control (RBAC).
 */
export function createAuthMiddleware(authService: AuthService) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Missing or malformed Authorization Bearer token.',
      });
      return;
    }

    const token = authHeader.slice(7).trim();
    try {
      req.auth = authService.verifyAccessToken(token);
      next();
    } catch {
      res.status(401).json({
        error: 'TOKEN_EXPIRED_OR_INVALID',
        message: 'In-memory Access Token is invalid or expired. Trigger silent HttpOnly refresh.',
      });
    }
  };
}

export function requireRoles(allowedRoles: readonly UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.auth) {
      res.status(401).json({ error: 'UNAUTHORIZED' });
      return;
    }

    if (!allowedRoles.includes(req.auth.role)) {
      res.status(403).json({
        error: 'RBAC_FORBIDDEN_ROLE',
        message: `Role "${req.auth.role}" does not have clearance. Required: ${allowedRoles.join(', ')}`,
      });
      return;
    }

    next();
  };
}

export function requirePermission(permission: Permission) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.auth) {
      res.status(401).json({ error: 'UNAUTHORIZED' });
      return;
    }

    if (!req.auth.permissions.includes(permission)) {
      res.status(403).json({
        error: 'RBAC_FORBIDDEN_PERMISSION',
        message: `Missing required RBAC permission "${permission}" for role "${req.auth.role}".`,
      });
      return;
    }

    next();
  };
}
