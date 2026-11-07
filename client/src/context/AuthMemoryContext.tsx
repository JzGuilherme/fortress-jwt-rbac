import React, { createContext, useCallback, useContext, useState } from 'react';

export type ClientRole = 'ADMIN' | 'FINANCE_MANAGER' | 'AUDITOR';

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: ClientRole;
  department: string;
  permissions: readonly string[];
}

interface AuthMemoryContextValue {
  user: AuthenticatedUser | null;
  accessTokenInMemory: string | null;
  lastRotationAt: string | null;
  loginWithPresetRole: (role: ClientRole) => void;
  rotateSilentRefreshToken: () => void;
  logoutSession: () => void;
  hasPermission: (permission: string) => boolean;
}

/**
 * Private closure variable holding the current JWT Access Token strictly in RAM.
 * Never persisted to window.localStorage, window.sessionStorage, or document.cookie.
 */
let closureAccessToken: string | null = null;

const ROLE_PRESETS: Record<ClientRole, AuthenticatedUser> = {
  ADMIN: {
    id: 'usr-admin-01',
    name: 'Helena Vance (CISO Admin)',
    email: 'admin@fortress.io',
    role: 'ADMIN',
    department: 'Cybersecurity & Governance',
    permissions: [
      'approvals:read',
      'approvals:create',
      'approvals:approve',
      'approvals:reject',
      'audit:read',
      'sessions:revoke',
    ],
  },
  FINANCE_MANAGER: {
    id: 'usr-fin-02',
    name: 'Ricardo Almeida (Head FinOps)',
    email: 'finance@fortress.io',
    role: 'FINANCE_MANAGER',
    department: 'Treasury & FinOps',
    permissions: [
      'approvals:read',
      'approvals:create',
      'approvals:approve',
      'approvals:reject',
      'audit:read',
    ],
  },
  AUDITOR: {
    id: 'usr-aud-03',
    name: 'Clara Mendes (External Auditor)',
    email: 'auditor@fortress.io',
    role: 'AUDITOR',
    department: 'Compliance & Risk',
    permissions: ['approvals:read', 'audit:read'],
  },
};

function createEphemeralJwtPreview(user: AuthenticatedUser): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(
    JSON.stringify({
      sub: user.id,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 900,
    })
  );
  const signature = Math.random().toString(36).substring(2, 14);
  return `${header}.${payload}.${signature}`;
}

const AuthMemoryContext = createContext<AuthMemoryContextValue | undefined>(undefined);

export const AuthMemoryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthenticatedUser | null>(ROLE_PRESETS.ADMIN);
  const [tokenState, setTokenState] = useState<string | null>(() => {
    closureAccessToken = createEphemeralJwtPreview(ROLE_PRESETS.ADMIN);
    return closureAccessToken;
  });
  const [lastRotationAt, setLastRotationAt] = useState<string | null>(() =>
    new Date().toLocaleTimeString('pt-BR')
  );

  const loginWithPresetRole = useCallback((role: ClientRole) => {
    const selectedUser = ROLE_PRESETS[role];
    const freshToken = createEphemeralJwtPreview(selectedUser);
    closureAccessToken = freshToken;
    setUser(selectedUser);
    setTokenState(freshToken);
    setLastRotationAt(new Date().toLocaleTimeString('pt-BR'));
  }, []);

  const rotateSilentRefreshToken = useCallback(() => {
    if (!user) return;
    const rotated = createEphemeralJwtPreview(user);
    closureAccessToken = rotated;
    setTokenState(rotated);
    setLastRotationAt(new Date().toLocaleTimeString('pt-BR'));
  }, [user]);

  const logoutSession = useCallback(() => {
    closureAccessToken = null;
    setUser(null);
    setTokenState(null);
  }, []);

  const hasPermission = useCallback(
    (permission: string): boolean => {
      if (!user) return false;
      return user.permissions.includes(permission);
    },
    [user]
  );

  return (
    <AuthMemoryContext.Provider
      value={{
        user,
        accessTokenInMemory: tokenState,
        lastRotationAt,
        loginWithPresetRole,
        rotateSilentRefreshToken,
        logoutSession,
        hasPermission,
      }}
    >
      {children}
    </AuthMemoryContext.Provider>
  );
};

export function useAuthMemory(): AuthMemoryContextValue {
  const context = useContext(AuthMemoryContext);
  if (!context) {
    throw new Error('useAuthMemory must be used within an AuthMemoryProvider');
  }
  return context;
}
