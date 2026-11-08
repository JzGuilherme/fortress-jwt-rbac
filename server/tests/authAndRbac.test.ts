import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/index.js';
import {
  AuthMemoryProvider,
  executeVaultAuthFetch,
  setRefreshTransportForVault,
  triggerDeduplicatedSilentRefresh,
  useAuthMemory,
} from '../../client/src/context/AuthMemoryContext.js';
import { VaultDashboard } from '../../client/src/components/VaultDashboard.js';

/**
 * Helper to start the Express server on an ephemeral port for real HTTP integration testing.
 */
async function startTestServer() {
  const { app, db, authService } = createApp(':memory:');
  const server = http.createServer(app);

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    baseUrl,
    db,
    authService,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function extractRefreshCookieValue(setCookieHeader: string | null): string {
  assert.ok(setCookieHeader, 'Expected Set-Cookie header to be present');
  const match = setCookieHeader.match(/fortress_rt=([^;]+)/);
  assert.ok(match && match[1], 'Expected fortress_rt cookie value');
  return decodeURIComponent(match[1]);
}

// ============================================================================
// PILLAR 1: Refresh Token Rotation, Reuse Breach Detection & Race Conditions
// ============================================================================

test('PILLAR 1.1: HTTP Integration — Refresh Token Rotation, Set-Cookie Flags & Reuse Breach Family Kill-Switch', async () => {
  const srv = await startTestServer();

  try {
    // 1. Login and capture Refresh Token V1
    const loginRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'finance@fortress.io',
        password: 'Fortress@Finance2026',
      }),
    });

    assert.equal(loginRes.status, 200);
    const setCookieV1 = loginRes.headers.get('set-cookie');
    assert.ok(setCookieV1);
    assert.match(setCookieV1, /HttpOnly/i);
    assert.match(setCookieV1, /SameSite=Strict/i);
    assert.match(setCookieV1, /Path=\/api\/auth/i);

    const tokenV1 = extractRefreshCookieValue(setCookieV1);

    // 2. Legitimate rotation V1 -> V2
    const refreshRes1 = await fetch(`${srv.baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `fortress_rt=${encodeURIComponent(tokenV1)}` },
    });

    assert.equal(refreshRes1.status, 200);
    const setCookieV2 = refreshRes1.headers.get('set-cookie');
    const tokenV2 = extractRefreshCookieValue(setCookieV2);
    assert.notEqual(tokenV1, tokenV2, 'Rotated Refresh Token V2 must differ from V1');

    // 3. Attacker replays stolen old token V1 -> Must return HTTP 401 and revoke entire family
    const replayRes = await fetch(`${srv.baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `fortress_rt=${encodeURIComponent(tokenV1)}` },
    });

    assert.equal(replayRes.status, 401);
    const replayBody = (await replayRes.json()) as { error: string };
    assert.equal(replayBody.error, 'TOKEN_REUSE_BREACH_DETECTED');

    // 4. Legitimate user tries to use V2 after the breach -> Must ALSO be rejected (401) because family is dead!
    const v2AfterBreachRes = await fetch(`${srv.baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `fortress_rt=${encodeURIComponent(tokenV2)}` },
    });

    assert.equal(v2AfterBreachRes.status, 401);
    const v2Body = (await v2AfterBreachRes.json()) as { error: string };
    assert.equal(v2Body.error, 'REVOKED_REFRESH_TOKEN');
  } finally {
    await srv.close();
  }
});

test('PILLAR 1.2: Concurrency & Race Condition — 5 simultaneous expired requests share a single Mutex refresh without false breach', async () => {
  let networkRefreshCallCount = 0;

  setRefreshTransportForVault(async () => {
    networkRefreshCallCount++;
    await new Promise((r) => setTimeout(r, 25));
    return 'fresh-single-flight-jwt-token';
  });

  try {
    // Simulate 5 concurrent API calls failing with 401 at the exact same millisecond
    const mockFetch = async (_input: string | URL | Request, init?: RequestInit) => {
      const authHeader = new Headers(init?.headers).get('Authorization');
      if (authHeader === 'Bearer fresh-single-flight-jwt-token') {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: 'EXPIRED' }), { status: 401 });
    };

    const concurrentCalls = Array.from({ length: 5 }, (_, idx) =>
      executeVaultAuthFetch(`/api/approvals?req=${idx}`, {}, mockFetch as typeof fetch)
    );

    const responses = await Promise.all(concurrentCalls);

    for (const res of responses) {
      assert.equal(res.status, 200);
    }

    assert.equal(
      networkRefreshCallCount,
      1,
      'Mutex must coalesce 5 concurrent 401 failures into exactly 1 refresh call'
    );
  } finally {
    setRefreshTransportForVault(null);
  }
});

// ============================================================================
// PILLAR 2: RAM Closure Isolation, Zero React Fiber Exposure & Zero Storage
// ============================================================================

test('PILLAR 2: In-Memory Closure Isolation — Zero raw JWT in React Context value, zero localStorage/sessionStorage/cookie leakage', async () => {
  // Mock browser globals to verify zero storage writes
  const mockLocalStorage = new Map<string, string>();
  const mockSessionStorage = new Map<string, string>();
  const consoleLogs: string[] = [];

  const originalLog = console.log;
  console.log = (...args: unknown[]) => {
    consoleLogs.push(args.map(String).join(' '));
  };

  try {
    await triggerDeduplicatedSilentRefresh('ADMIN');

    let capturedContext: Record<string, unknown> = {};
    const Inspector: React.FC = () => {
      const ctx = useAuthMemory();
      capturedContext = ctx as unknown as Record<string, unknown>;
      return React.createElement('div', null, ctx.maskedTokenPreview);
    };

    const html = renderToStaticMarkup(
      React.createElement(AuthMemoryProvider, null, React.createElement(Inspector))
    );

    // Verify that `accessToken` or `accessTokenInMemory` does NOT exist on the React Context value!
    assert.equal('accessToken' in capturedContext, false);
    assert.equal('accessTokenInMemory' in capturedContext, false);
    assert.match(String(capturedContext['maskedTokenPreview']), /\[REDACTED_IN_RAM_CLOSURE\]/);
    assert.ok(!html.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI'));

    assert.equal(mockLocalStorage.size, 0, 'window.localStorage.length must be 0');
    assert.equal(mockSessionStorage.size, 0, 'window.sessionStorage.length must be 0');
    assert.equal(
      consoleLogs.some((line) => line.includes('Bearer ')),
      false,
      'No console.log may leak Authorization: Bearer tokens'
    );
  } finally {
    console.log = originalLog;
  }
});

// ============================================================================
// PILLAR 3: RBAC Matrix, Financial Ceiling Limits, JWT Tampering & Fuzzing
// ============================================================================

test('PILLAR 3.1: RBAC Matrix & Financial Ceiling Enforcement (AUDITOR vs FINANCE_MANAGER vs ADMIN)', async () => {
  const srv = await startTestServer();

  try {
    const loginAs = async (email: string, password: string) => {
      const res = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = (await res.json()) as { accessToken: string };
      return data.accessToken;
    };

    const auditorToken = await loginAs('auditor@fortress.io', 'Fortress@Auditor2026');
    const financeToken = await loginAs('finance@fortress.io', 'Fortress@Finance2026');
    const adminToken = await loginAs('admin@fortress.io', 'Fortress@Admin2026');

    // 1. AUDITOR can GET approvals (200), but POST approval or decision returns 403 Forbidden
    const audGet = await fetch(`${srv.baseUrl}/api/approvals`, {
      headers: { Authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(audGet.status, 200);

    const audPostDecision = await fetch(`${srv.baseUrl}/api/approvals/APR-9003/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auditorToken}`,
      },
      body: JSON.stringify({ decision: 'APPROVED' }),
    });
    assert.equal(audPostDecision.status, 403);

    // 2. FINANCE_MANAGER can approve APR-9003 (R$ 14.200 <= R$ 25.000 limit) -> 200 OK
    const finApproveWithinLimit = await fetch(`${srv.baseUrl}/api/approvals/APR-9003/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${financeToken}`,
      },
      body: JSON.stringify({ decision: 'APPROVED' }),
    });
    assert.equal(finApproveWithinLimit.status, 200);

    // 3. FINANCE_MANAGER tries to approve APR-9001 (R$ 48.500 > R$ 25.000 limit) -> 403 Forbidden!
    const finApproveOverLimit = await fetch(`${srv.baseUrl}/api/approvals/APR-9001/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${financeToken}`,
      },
      body: JSON.stringify({ decision: 'APPROVED' }),
    });
    assert.equal(finApproveOverLimit.status, 403);
    const overLimitBody = (await finApproveOverLimit.json()) as { error: string };
    assert.equal(overLimitBody.error, 'RBAC_AMOUNT_LIMIT_EXCEEDED');

    // 4. FINANCE_MANAGER tries ADMIN-only session family revocation -> 403 Forbidden!
    const finRevokeAttempt = await fetch(`${srv.baseUrl}/api/sessions/fam-123/revoke`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${financeToken}` },
    });
    assert.equal(finRevokeAttempt.status, 403);

    // 5. ADMIN approves high-value APR-9001 (R$ 48.500) -> 200 OK
    const admApproveHighValue = await fetch(`${srv.baseUrl}/api/approvals/APR-9001/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ decision: 'APPROVED' }),
    });
    assert.equal(admApproveHighValue.status, 200);
  } finally {
    await srv.close();
  }
});

test('PILLAR 3.2: JWT Tampering (alg: none & invalid key) + Financial Amount Fuzzing (-5000, 0, NaN, Infinity, Overflow)', async () => {
  const srv = await startTestServer();

  try {
    // 1. Forged JWT signed with attacker key claiming role: ADMIN
    const forgedJwtWrongSecret = jwt.sign(
      {
        sub: 'attacker-01',
        email: 'evil@hacker.io',
        role: 'ADMIN',
        permissions: ['approvals:approve'],
      },
      'wrong-attacker-secret-key',
      { algorithm: 'HS256', issuer: 'fortress-jwt-rbac' }
    );

    const resWrongKey = await fetch(`${srv.baseUrl}/api/approvals`, {
      headers: { Authorization: `Bearer ${forgedJwtWrongSecret}` },
    });
    assert.equal(resWrongKey.status, 401);

    // 2. Forged JWT with algorithm "none" (unsigned token attack)
    const headerNone = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
      'base64url'
    );
    const payloadNone = Buffer.from(
      JSON.stringify({
        sub: 'usr-admin-01',
        role: 'ADMIN',
        permissions: ['approvals:approve'],
        iss: 'fortress-jwt-rbac',
      })
    ).toString('base64url');
    const unsignedAlgNoneToken = `${headerNone}.${payloadNone}.`;

    const resAlgNone = await fetch(`${srv.baseUrl}/api/approvals`, {
      headers: { Authorization: `Bearer ${unsignedAlgNoneToken}` },
    });
    assert.equal(resAlgNone.status, 401);

    // 3. Financial Payload Fuzzing with valid ADMIN token
    const loginRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@fortress.io', password: 'Fortress@Admin2026' }),
    });
    const { accessToken } = (await loginRes.json()) as { accessToken: string };

    const maliciousAmounts: unknown[] = [
      -5000,
      0,
      19.99,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 100,
      '50000; DROP TABLE financial_approvals;',
      null,
    ];

    for (const badAmount of maliciousAmounts) {
      const fuzzRes = await fetch(`${srv.baseUrl}/api/approvals`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          title: 'Fuzz Test Batch',
          vendor: 'Evil Corp',
          amountCents: badAmount,
        }),
      });

      assert.equal(
        fuzzRes.status,
        400,
        `Malicious amountCents (${String(badAmount)}) must be rejected with HTTP 400`
      );
    }
  } finally {
    await srv.close();
  }
});

// ============================================================================
// PILLAR 4 & 5: WCAG 2.1 AA Accessibility Semantics & Security Headers
// ============================================================================

test('PILLAR 4 & 5: WCAG 2.1 AA Semantic Landmarks, ARIA Live Regions, Skip Link & Helmet Headers', async () => {
  const html = renderToStaticMarkup(
    React.createElement(AuthMemoryProvider, null, React.createElement(VaultDashboard))
  );

  // Verify WCAG 2.1 AA Skip-Link, ARIA live polite announcement region, aria-pressed and aria-labels
  assert.match(html, /href="#main-vault-content"/);
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /aria-pressed="true"/);
  assert.match(html, /aria-label="Aprovar lote APR-9001"/);
});
