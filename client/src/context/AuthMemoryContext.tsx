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

/**
 *Notice: `accessToken` is INTENTIONALLY EXCLUDED from `AuthMemoryContextValue`
 * and never stored in `useState` or `useRef`. This prevents any XSS payload from
 * scraping the raw JWT out of DOM `_reactFiber` / `memoizedState` hooks!
 */
export interface AuthMemoryContextValue {
  user: AuthenticatedUser | null;
  isAuthenticated: boolean;
  maskedTokenPreview: string;
  lastRotationAt: string | null;
  loginWithPresetRole: (role: ClientRole) => void;
  rotateSilentRefreshToken: () => Promise<void>;
  logoutSession: () => void;
  hasPermission: (permission: string) => boolean;
  authFetch: (input: string, init?: RequestInit) => Promise<Response>;
}

/**
 * MODULE-PRIVATE CLOSURE VAULT (Zero React Fiber Exposure & Zero Storage Exposure)
 */
let closureAccessToken: string | null = null;
let inFlightRefreshPromise: Promise<string> | null = null;
let refreshNetworkTransport: (() => Promise<string>) | null = null;

/**
 * Allows injecting a custom refresh transport (for deterministic concurrency tests or custom API gateways).
 */
export function setRefreshTransportForVault(transport: (() => Promise<string>) | null): void {
  refreshNetworkTransport = transport;
}

/**
 * Single-flight Mutex Refresh Coordinator.
 * If 5 API requests fail with 401 or trigger refresh at the exact same millisecond,
 * ONLY 1 refresh call is executed; the other 4 await the shared `inFlightRefreshPromise`.
 */
export async function triggerDeduplicatedSilentRefresh(
  currentRole: ClientRole = 'ADMIN'
): Promise<string> {
  if (inFlightRefreshPromise !== null) {
    return inFlightRefreshPromise;
  }

  inFlightRefreshPromise = (async () => {
    try {
      if (refreshNetworkTransport) {
        const freshToken = await refreshNetworkTransport();
        closureAccessToken = freshToken;
        return freshToken;
      }

      const freshToken = createEphemeralJwtForRole(ROLE_PRESETS[currentRole]);
      closureAccessToken = freshToken;
      return freshToken;
    } finally {
      inFlightRefreshPromise = null;
    }
  })();

  return inFlightRefreshPromise;
}

/**
 * Executes an authenticated HTTP request by injecting the `Authorization: Bearer` header
 * directly from the module-private closure without exposing the raw token to React state.
 */
export async function executeVaultAuthFetch(
  input: string,
  init: RequestInit = {},
  customFetch: typeof fetch = fetch
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (closureAccessToken) {
    headers.set('Authorization', `Bearer ${closureAccessToken}`);
  }

  const firstResponse = await customFetch(input, {
    ...init,
    headers,
    credentials: 'include',
  });

  if (firstResponse.status !== 401) {
    return firstResponse;
  }

  // Token expired -> Join single-flight Mutex silent refresh queue
  const refreshedToken = await triggerDeduplicatedSilentRefresh();
  const retryHeaders = new Headers(init.headers);
  retryHeaders.set('Authorization', `Bearer ${refreshedToken}`);

  return customFetch(input, {
    ...init,
    headers: retryHeaders,
    credentials: 'include',
  });
}

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

function createEphemeralJwtForRole(user: AuthenticatedUser): string {
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

function buildMaskedPreview(rawToken: string | null): string {
  if (!rawToken) return 'REVOKED';
  return `${rawToken.slice(0, 14)}...[REDACTED_IN_RAM_CLOSURE]...${rawToken.slice(-6)}`;
}

// Initialize default closure token outside React state
closureAccessToken = createEphemeralJwtForRole(ROLE_PRESETS.ADMIN);

const AuthMemoryContext = createContext<AuthMemoryContextValue | undefined>(undefined);

export const AuthMemoryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthenticatedUser | null>(ROLE_PRESETS.ADMIN);
  const [maskedTokenPreview, setMaskedTokenPreview] = useState<string>(() =>
    buildMaskedPreview(closureAccessToken)
  );
  const [lastRotationAt, setLastRotationAt] = useState<string | null>(() =>
    new Date().toLocaleTimeString('pt-BR')
  );

  const loginWithPresetRole = useCallback((role: ClientRole) => {
    const selectedUser = ROLE_PRESETS[role];
    const freshToken = createEphemeralJwtForRole(selectedUser);
    closureAccessToken = freshToken;
    setUser(selectedUser);
    setMaskedTokenPreview(buildMaskedPreview(freshToken));
    setLastRotationAt(new Date().toLocaleTimeString('pt-BR'));
  }, []);

  const rotateSilentRefreshToken = useCallback(async () => {
    if (!user) return;
    const rotated = await triggerDeduplicatedSilentRefresh(user.role);
    setMaskedTokenPreview(buildMaskedPreview(rotated));
    setLastRotationAt(new Date().toLocaleTimeString('pt-BR'));
  }, [user]);

  const logoutSession = useCallback(() => {
    closureAccessToken = null;
    setUser(null);
    setMaskedTokenPreview('REVOKED');
  }, []);

  const hasPermission = useCallback(
    (permission: string): boolean => {
      if (!user) return false;
      return user.permissions.includes(permission);
    },
    [user]
  );

  const authFetch = useCallback((input: string, init?: RequestInit) => {
    return executeVaultAuthFetch(input, init);
  }, []);

  return (
    <AuthMemoryContext.Provider
      value={{
        user,
        isAuthenticated: user !== null && closureAccessToken !== null,
        maskedTokenPreview,
        lastRotationAt,
        loginWithPresetRole,
        rotateSilentRefreshToken,
        logoutSession,
        hasPermission,
        authFetch,
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
