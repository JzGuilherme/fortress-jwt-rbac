import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { SqlVaultDatabase } from '../config/database.js';
import {
  AccessTokenPayload,
  ROLE_PERMISSIONS,
  UserRecord,
} from '../types/domain.js';

export interface AuthSessionResult {
  accessToken: string;
  refreshTokenRaw: string;
  user: {
    id: string;
    name: string;
    email: string;
    role: UserRecord['role'];
    department: string;
    permissions: readonly string[];
  };
}

/**
 * Zero-Trust Authentication & Refresh Token Rotation Engine.
 * - Verifies credentials with Bcrypt
 * - Issues short-lived In-Memory JWT Access Tokens
 * - Rotates HttpOnly Refresh Tokens and revokes the entire token family if reuse is detected
 */
export class AuthService {
  public constructor(
    private readonly db: SqlVaultDatabase,
    private readonly accessSecret: string = process.env.JWT_ACCESS_SECRET || 'dev-in-memory-access-secret-key',
    private readonly refreshSecret: string = process.env.JWT_REFRESH_SECRET || 'dev-httponly-refresh-secret-key'
  ) {}

  public authenticate(email: string, plainPassword: string): AuthSessionResult {
    const user = this.db.findUserByEmail(email);
    if (!user) {
      throw new Error('INVALID_CREDENTIALS');
    }

    const passwordMatches = bcrypt.compareSync(plainPassword, user.passwordHash);
    if (!passwordMatches) {
      throw new Error('INVALID_CREDENTIALS');
    }

    const familyId = crypto.randomUUID();
    const session = this.issueTokenPair(user, familyId);

    this.db.appendAuditLog({
      id: crypto.randomUUID(),
      actorEmail: user.email,
      actorRole: user.role,
      action: 'AUTH_LOGIN_SUCCESS',
      resourceId: familyId,
      details: 'Issued In-Memory JWT + HttpOnly Refresh Cookie',
      timestamp: new Date().toISOString(),
    });

    return session;
  }

  /**
   * Rotates a Refresh Token from the HttpOnly cookie.
   * Implements OWASP Refresh Token Reuse Detection: if an already-used token is presented,
   * the entire token family is immediately revoked to neutralize token theft.
   */
  public rotateRefreshToken(rawRefreshToken: string): AuthSessionResult {
    if (!rawRefreshToken) {
      throw new Error('MISSING_REFRESH_TOKEN');
    }

    const tokenHash = this.hashToken(rawRefreshToken);
    const storedToken = this.db.findRefreshTokenByHash(tokenHash);

    if (!storedToken) {
      throw new Error('INVALID_REFRESH_TOKEN');
    }

    if (storedToken.isRevoked) {
      throw new Error('REVOKED_REFRESH_TOKEN');
    }

    // Reuse detection: token was already rotated once! Compromised token family!
    if (storedToken.isUsed) {
      this.db.revokeRefreshTokenFamily(storedToken.familyId);
      const compromisedUser = this.db.findUserById(storedToken.userId);
      if (compromisedUser) {
        this.db.appendAuditLog({
          id: crypto.randomUUID(),
          actorEmail: compromisedUser.email,
          actorRole: compromisedUser.role,
          action: 'SECURITY_TOKEN_REUSE_DETECTED',
          resourceId: storedToken.familyId,
          details: 'Attempted reuse of rotated HttpOnly refresh token. Entire session family revoked.',
          timestamp: new Date().toISOString(),
        });
      }
      throw new Error('TOKEN_REUSE_BREACH_DETECTED');
    }

    if (Date.now() > storedToken.expiresAt) {
      throw new Error('EXPIRED_REFRESH_TOKEN');
    }

    const user = this.db.findUserById(storedToken.userId);
    if (!user) {
      throw new Error('USER_NOT_FOUND');
    }

    this.db.markRefreshTokenUsed(storedToken.id);

    return this.issueTokenPair(user, storedToken.familyId);
  }

  public revokeSessionByRefreshToken(rawRefreshToken: string): void {
    if (!rawRefreshToken) {
      return;
    }
    const tokenHash = this.hashToken(rawRefreshToken);
    const stored = this.db.findRefreshTokenByHash(tokenHash);
    if (stored) {
      this.db.revokeRefreshTokenFamily(stored.familyId);
    }
  }

  public verifyAccessToken(token: string): AccessTokenPayload {
    try {
      const decoded = jwt.verify(token, this.accessSecret) as AccessTokenPayload;
      return decoded;
    } catch {
      throw new Error('INVALID_OR_EXPIRED_ACCESS_TOKEN');
    }
  }

  private issueTokenPair(user: UserRecord, familyId: string): AuthSessionResult {
    const permissions = ROLE_PERMISSIONS[user.role];

    const payload: AccessTokenPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      permissions,
    };

    const accessToken = jwt.sign(payload, this.accessSecret, {
      expiresIn: '15m',
      issuer: 'fortress-jwt-rbac',
    });

    const refreshTokenRaw =
      crypto.randomBytes(48).toString('base64url') +
      '.' +
      crypto.createHmac('sha256', this.refreshSecret).update(familyId).digest('base64url');

    const tokenHash = this.hashToken(refreshTokenRaw);
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

    this.db.saveRefreshToken({
      id: crypto.randomUUID(),
      userId: user.id,
      familyId,
      tokenHash,
      isUsed: false,
      isRevoked: false,
      expiresAt: Date.now() + sevenDaysMs,
      createdAt: new Date().toISOString(),
    });

    return {
      accessToken,
      refreshTokenRaw,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        permissions,
      },
    };
  }

  private hashToken(rawToken: string): string {
    return crypto.createHash('sha256').update(rawToken).digest('hex');
  }
}
