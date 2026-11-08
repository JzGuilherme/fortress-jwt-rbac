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
 * - Issues short-lived In-Memory JWT Access Tokens signed strictly with HS256
 * - Rejects `alg: "none"` or algorithm confusion attacks via explicit `algorithms: ['HS256']`
 * - Deduplicates concurrent in-flight refresh requests for the exact same token (Mutex Map)
 * - Uses atomic SQLite `BEGIN IMMEDIATE TRANSACTION` for Refresh Token Rotation & Reuse Breach Detection
 */
export class AuthService {
  private readonly inFlightRotations = new Map<string, Promise<AuthSessionResult>>();

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
   * Concurrent-safe async wrapper for Refresh Token Rotation.
   * If 5 parallel requests arrive with the exact same `rawRefreshToken` within the same tick,
   * they share the single in-flight rotation promise instead of triggering a false-positive breach.
   */
  public async rotateRefreshTokenAsync(rawRefreshToken: string): Promise<AuthSessionResult> {
    if (!rawRefreshToken) {
      throw new Error('MISSING_REFRESH_TOKEN');
    }

    const existingPromise = this.inFlightRotations.get(rawRefreshToken);
    if (existingPromise) {
      return existingPromise;
    }

    const rotationPromise = new Promise<AuthSessionResult>((resolve, reject) => {
      try {
        const result = this.rotateRefreshToken(rawRefreshToken);
        resolve(result);
      } catch (err) {
        reject(err);
      }
    }).finally(() => {
      this.inFlightRotations.delete(rawRefreshToken);
    });

    this.inFlightRotations.set(rawRefreshToken, rotationPromise);
    return rotationPromise;
  }

  /**
   * Synchronous atomic Refresh Token Rotation with OWASP Reuse Breach Detection.
   * Executed inside an atomic SQLite `BEGIN IMMEDIATE TRANSACTION`.
   */
  public rotateRefreshToken(rawRefreshToken: string): AuthSessionResult {
    if (!rawRefreshToken) {
      throw new Error('MISSING_REFRESH_TOKEN');
    }

    const tokenHash = this.hashToken(rawRefreshToken);

    const breachDetected = this.db.runInTransaction<AuthSessionResult | 'BREACH_REVOKED'>(() => {
      const storedToken = this.db.findRefreshTokenByHash(tokenHash);

      if (!storedToken) {
        throw new Error('INVALID_REFRESH_TOKEN');
      }

      if (storedToken.isRevoked) {
        throw new Error('REVOKED_REFRESH_TOKEN');
      }

      // OWASP Reuse Detection: Token was already rotated! Compromised token family!
      // CRITICAL: We MUST commit the family revocation (`is_revoked = 1`) before throwing!
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
        return 'BREACH_REVOKED';
      }

      if (Date.now() > storedToken.expiresAt) {
        throw new Error('EXPIRED_REFRESH_TOKEN');
      }

      const user = this.db.findUserById(storedToken.userId);
      if (!user) {
        throw new Error('USER_NOT_FOUND');
      }

      const nextSession = this.buildNextTokenPair(user, storedToken.familyId);
      const nextTokenHash = this.hashToken(nextSession.refreshTokenRaw);

      const marked = this.db.markRefreshTokenUsedAtomically(
        storedToken.id,
        Date.now(),
        nextTokenHash
      );

      if (!marked) {
        this.db.revokeRefreshTokenFamily(storedToken.familyId);
        return 'BREACH_REVOKED';
      }

      this.db.saveRefreshToken({
        id: crypto.randomUUID(),
        userId: user.id,
        familyId: storedToken.familyId,
        tokenHash: nextTokenHash,
        isUsed: false,
        isRevoked: false,
        usedAt: null,
        replacedByTokenHash: null,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
        createdAt: new Date().toISOString(),
      });

      return nextSession;
    });

    if (breachDetected === 'BREACH_REVOKED') {
      throw new Error('TOKEN_REUSE_BREACH_DETECTED');
    }

    return breachDetected;
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

  public revokeFamilyById(familyId: string): number {
    return this.db.revokeRefreshTokenFamily(familyId);
  }

  /**
   * Verifies the Bearer JWT with strict algorithm pinning (`HS256`) and issuer validation.
   * Blocks `alg: "none"`, empty signatures, or tampered payloads.
   */
  public verifyAccessToken(token: string): AccessTokenPayload {
    try {
      const decoded = jwt.verify(token, this.accessSecret, {
        algorithms: ['HS256'],
        issuer: 'fortress-jwt-rbac',
      }) as AccessTokenPayload;

      if (
        !decoded ||
        typeof decoded !== 'object' ||
        !decoded.sub ||
        !decoded.role ||
        !Array.isArray(decoded.permissions)
      ) {
        throw new Error('MALFORMED_TOKEN_CLAIMS');
      }

      return decoded;
    } catch {
      throw new Error('INVALID_OR_EXPIRED_ACCESS_TOKEN');
    }
  }

  private issueTokenPair(user: UserRecord, familyId: string): AuthSessionResult {
    const session = this.buildNextTokenPair(user, familyId);
    const tokenHash = this.hashToken(session.refreshTokenRaw);

    this.db.saveRefreshToken({
      id: crypto.randomUUID(),
      userId: user.id,
      familyId,
      tokenHash,
      isUsed: false,
      isRevoked: false,
      usedAt: null,
      replacedByTokenHash: null,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      createdAt: new Date().toISOString(),
    });

    return session;
  }

  private buildNextTokenPair(user: UserRecord, familyId: string): AuthSessionResult {
    const permissions = ROLE_PERMISSIONS[user.role];

    const payload: AccessTokenPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      permissions,
    };

    const accessToken = jwt.sign(payload, this.accessSecret, {
      algorithm: 'HS256',
      expiresIn: '15m',
      issuer: 'fortress-jwt-rbac',
    });

    const refreshTokenRaw =
      crypto.randomBytes(48).toString('base64url') +
      '.' +
      crypto.createHmac('sha256', this.refreshSecret).update(familyId).digest('base64url');

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
