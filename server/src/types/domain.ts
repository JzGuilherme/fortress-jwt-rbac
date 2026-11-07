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
