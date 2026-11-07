import assert from 'node:assert/strict';
import test from 'node:test';
import { SqlVaultDatabase } from '../src/config/database.js';
import { AuthService } from '../src/services/AuthService.js';
import { ROLE_PERMISSIONS } from '../src/types/domain.js';

test('Authenticates seeded user with Bcrypt and issues In-Memory JWT + Refresh Token', () => {
  const db = new SqlVaultDatabase(':memory:');
  const auth = new AuthService(db, 'test-access-secret', 'test-refresh-secret');

  const session = auth.authenticate('admin@fortress.io', 'Fortress@Admin2026');

  assert.equal(session.user.role, 'ADMIN');
  assert.ok(session.accessToken.length > 30);
  assert.ok(session.refreshTokenRaw.length > 40);

  const verifiedPayload = auth.verifyAccessToken(session.accessToken);
  assert.equal(verifiedPayload.email, 'admin@fortress.io');
  assert.equal(verifiedPayload.role, 'ADMIN');
  assert.deepEqual(verifiedPayload.permissions, ROLE_PERMISSIONS.ADMIN);
});

test('Rotates HttpOnly Refresh Token and revokes entire family if token reuse breach occurs', () => {
  const db = new SqlVaultDatabase(':memory:');
  const auth = new AuthService(db, 'test-access-secret', 'test-refresh-secret');

  const initialSession = auth.authenticate('finance@fortress.io', 'Fortress@Finance2026');
  const firstRefreshToken = initialSession.refreshTokenRaw;

  // Legitimate first rotation
  const rotatedSession = auth.rotateRefreshToken(firstRefreshToken);
  assert.notEqual(rotatedSession.refreshTokenRaw, firstRefreshToken);

  // Attacker attempts to replay the already-used firstRefreshToken
  assert.throws(
    () => auth.rotateRefreshToken(firstRefreshToken),
    /TOKEN_REUSE_BREACH_DETECTED/
  );

  // Even the newly rotated token is now revoked because the entire family was compromised!
  assert.throws(
    () => auth.rotateRefreshToken(rotatedSession.refreshTokenRaw),
    /REVOKED_REFRESH_TOKEN/
  );
});

test('Enforces RBAC permission matrix across ADMIN, FINANCE_MANAGER and AUDITOR', () => {
  assert.equal(ROLE_PERMISSIONS.ADMIN.includes('approvals:approve'), true);
  assert.equal(ROLE_PERMISSIONS.FINANCE_MANAGER.includes('approvals:approve'), true);
  assert.equal(ROLE_PERMISSIONS.AUDITOR.includes('approvals:approve'), false);
  assert.equal(ROLE_PERMISSIONS.AUDITOR.includes('audit:read'), true);
});
