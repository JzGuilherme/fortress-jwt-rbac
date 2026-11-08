export type UserRole = 'ADMIN' | 'FINANCE_MANAGER' | 'AUDITOR';

export type Permission =
  | 'approvals:read'
  | 'approvals:create'
  | 'approvals:approve'
  | 'approvals:reject'
  | 'audit:read'
  | 'sessions:revoke';

export const ROLE_PERMISSIONS: Record<UserRole, readonly Permission[]> = {
  ADMIN: [
    'approvals:read',
    'approvals:create',
    'approvals:approve',
    'approvals:reject',
    'audit:read',
    'sessions:revoke',
  ],
  FINANCE_MANAGER: [
    'approvals:read',
    'approvals:create',
    'approvals:approve',
    'approvals:reject',
    'audit:read',
  ],
  AUDITOR: ['approvals:read', 'audit:read'],
};

/**
 * Financial Approval Ceiling (Alçada Máxima em Centavos):
 * - AUDITOR: 0 (Read-Only)
 * - FINANCE_MANAGER: R$ 25.000,00 (2_500_000 cents)
 * - ADMIN: Unlimited up to MAX_SAFE_APPROVAL_CENTS (R$ 10.000.000,00 = 1_000_000_000 cents)
 */
export const MAX_SAFE_APPROVAL_CENTS = 1_000_000_000;

export const ROLE_APPROVAL_LIMIT_CENTS: Record<UserRole, number> = {
  ADMIN: MAX_SAFE_APPROVAL_CENTS,
  FINANCE_MANAGER: 2_500_000,
  AUDITOR: 0,
};

export interface UserRecord {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  department: string;
  createdAt: string;
}

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  familyId: string;
  tokenHash: string;
  isUsed: boolean;
  isRevoked: boolean;
  usedAt: number | null;
  replacedByTokenHash: string | null;
  expiresAt: number;
  createdAt: string;
}

export interface FinancialApprovalRecord {
  id: string;
  title: string;
  vendor: string;
  amountCents: number;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  requestedBy: string;
  decidedBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditLogRecord {
  id: string;
  actorEmail: string;
  actorRole: UserRole;
  action: string;
  resourceId: string;
  details: string;
  timestamp: string;
}

export interface AccessTokenPayload {
  sub: string;
  email: string;
  name: string;
  role: UserRole;
  permissions: readonly Permission[];
}
