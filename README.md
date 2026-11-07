# Fortress JWT & RBAC Vault 🏰🔐

[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Node.js & Express](https://img.shields.io/badge/Node.js-Express%20REST-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Security: Zero-Trust JWT](https://img.shields.io/badge/Auth-In--Memory%20JWT%20%2B%20HttpOnly-10B981?style=for-the-badge)](https://owasp.org/)
[![Accessibility: WCAG 2.1 AA](https://img.shields.io/badge/A11y-WCAG%202.1%20AA-8B5CF6?style=for-the-badge)](https://www.w3.org/WAI/WCAG21/quickref/)

**Full-Stack Zero-Trust Access & Financial Approval Vault** engineered with **Node.js, Express, TypeScript, SQL (SQLite), React 18, Vite, Tailwind CSS, shadcn/ui, and Framer Motion**.

---

## 🖥️ Live UI Preview & Accessibility Showcase

### 1. CISO Admin View — In-Memory JWT Telemetry & Full RBAC Write Access
The `ADMIN` and `FINANCE_MANAGER` roles hold the `approvals:approve` and `approvals:reject` permissions, unlocking write actions on high-value FinOps batches while keeping `window.localStorage` completely empty (`length === 0`):

![Fortress Vault Admin View](docs/screenshots/dashboard-admin-view.jpg)

### 2. External Auditor View — RBAC Read-Only Enforcement, WCAG Focus Ring & Breach Audit Trail
Switching to the `AUDITOR` role dynamically restricts the session scope to `approvals:read` and `audit:read`. Write actions are locked both in the UI and at the Express REST middleware layer, while full keyboard focus rings (`3px solid #10B981`) and `aria-live` regions guarantee **WCAG 2.1 AA** compliance:

![Fortress Vault Auditor Read-Only & WCAG View](docs/screenshots/dashboard-auditor-readonly-wcag.jpg)

---

## 🎯 The Real-World Security Problem Solved

Over 90% of modern Single-Page Applications (SPAs) suffer from a critical architectural flaw: **storing JWT tokens inside `localStorage` or `sessionStorage`**. If any Cross-Site Scripting (XSS) vector occurs — even through a compromised third-party NPM dependency — an attacker can execute `localStorage.getItem('token')` and exfiltrate executive credentials instantly.

**Fortress JWT & RBAC Vault** eliminates this attack surface end-to-end:

1. **Short-Lived JWT Strictly in RAM (`In-Memory Closure`):**
   On the React client (`AuthMemoryContext.tsx`), the 15-minute `accessToken` lives **exclusively inside a private JavaScript closure in memory**, never touching `localStorage`, `sessionStorage`, or DOM-accessible cookies.
2. **Rotating Refresh Tokens in `HttpOnly` Cookies + Reuse Breach Detection:**
   The 7-day `refreshToken` is transmitted strictly via `Set-Cookie` with `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`. On every silent refresh (`/api/auth/refresh`), the previous token is marked as used and replaced. If an attacker replays an already-rotated token, the backend detects the breach (`TOKEN_REUSE_BREACH_DETECTED`), revokes the entire token family in SQL, and logs a critical security event.
3. **Adaptive `Bcrypt` Hashing & Granular `RBAC` Matrix:**
   Passwords are hashed using **Bcrypt**, and every endpoint is guarded by declarative role and permission middleware (`ADMIN`, `FINANCE_MANAGER`, `AUDITOR`).
4. **Native `WCAG 2.1 Level AA` Accessibility:**
   Built with **Tailwind CSS + shadcn/ui patterns + Framer Motion** (`useReducedMotion`), featuring a keyboard Skip-Link, high-contrast focus rings, semantic ARIA states (`aria-pressed`, `aria-live="polite"`), and screen-reader announcements.

---

## 🏗️ Zero-Trust Authentication & RBAC Sequence

```mermaid
sequenceDiagram
    autonumber
    participant UI as React 18 UI (Closure Memory)
    participant API as Express REST API (RBAC + Bcrypt)
    participant DB as SQL Database (Users, Tokens & Audit)

    UI->>API: POST /api/auth/login (email, password)
    API->>DB: SELECT user & Bcrypt.compare(password, hash)
    API->>DB: INSERT refresh_token_family (token_hash, expires_at)
    API-->>UI: 200 OK { accessToken (15m) } + Set-Cookie: fortress_rt (HttpOnly, SameSite=Strict)
    Note over UI: accessToken stored ONLY in RAM (Zero localStorage)

    UI->>API: POST /api/approvals/:id/decision (Authorization: Bearer <accessToken>)
    API->>API: Middleware verifyJwt + requirePermission('approvals:approve')
    API->>DB: UPDATE financial_approvals + INSERT audit_logs
    API-->>UI: 200 OK (Batch Approved)

    Note over UI,API: 15m Expiration -> Silent Refresh via HttpOnly Cookie
    UI->>API: POST /api/auth/refresh (Browser sends HttpOnly cookie automatically)
    API->>DB: Verify if token was already used (OWASP Token Reuse Breach Detection)
    API->>DB: Mark old token used & issue new Refresh Token in the same family
    API-->>UI: 200 OK { newAccessToken } + New HttpOnly Cookie
```

---

## 🔐 RBAC Permission Matrix

| Permission Slug | `ADMIN` (CISO) | `FINANCE_MANAGER` (FinOps) | `AUDITOR` (Compliance) |
| :--- | :---: | :---: | :---: |
| `approvals:read` | ✅ | ✅ | ✅ |
| `approvals:create` | ✅ | ✅ | ❌ |
| `approvals:approve` | ✅ | ✅ | ❌ |
| `approvals:reject` | ✅ | ✅ | ❌ |
| `audit:read` | ✅ | ✅ | ✅ |
| `sessions:revoke` | ✅ | ❌ | ❌ |

---

## 📂 Project Architecture

```text
fortress-jwt-rbac/
├── docs/
│   └── screenshots/
│       ├── dashboard-admin-view.jpg
│       └── dashboard-auditor-readonly-wcag.jpg
├── server/
│   ├── src/
│   │   ├── config/
│   │   │   └── database.ts            # Relational SQLite layer (users, refresh_tokens, approvals, audit_logs)
│   │   ├── middleware/
│   │   │   └── rbacMiddleware.ts      # Bearer JWT verification + Role & Permission guards
│   │   ├── services/
│   │   │   └── AuthService.ts         # Bcrypt verification, JWT issuer & Refresh Token reuse detection
│   │   ├── routes/
│   │   │   └── apiRoutes.ts           # Express RESTful endpoints (/api/auth/*, /api/approvals/*, /api/audit-logs)
│   │   ├── types/
│   │   │   └── domain.ts              # Strict TypeScript RBAC & domain contracts
│   │   └── index.ts                   # Express bootstrap + Helmet + CORS Credentials + CookieParser
│   └── tests/
│       └── authAndRbac.test.ts        # Automated Node 22 test suite (Bcrypt, Token Rotation Breach & RBAC)
├── client/
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthMemoryContext.tsx  # Private RAM closure storing Access Token + Silent Refresh simulator
│   │   ├── components/
│   │   │   ├── ui/
│   │   │   │   └── Primitives.tsx     # Accessible shadcn/ui-style Button & Badge primitives
│   │   │   └── VaultDashboard.tsx     # WCAG 2.1 AA interactive FinOps & RBAC dashboard with Framer Motion
│   │   ├── App.tsx
│   │   └── main.tsx
├── docker-compose.yml
├── Dockerfile
├── vercel.json
└── package.json
```

---

## 🚀 Getting Started (Local & Docker)

### 1. Clone, Install & Run Automated Tests
```bash
git clone https://github.com/JzGuilherme/fortress-jwt-rbac.git
cd fortress-jwt-rbac
cp .env.example .env
npm install
npm test
npm run typecheck
```

### 2. Start Full-Stack Development Servers
```bash
# Terminal 1: Node.js + Express Zero-Trust REST API (http://localhost:4000)
npm run dev:server

# Terminal 2: React 18 + Vite + Tailwind CSS UI (http://localhost:5173)
npm run dev:client
```

### 3. Run via Docker Compose
```bash
docker compose up -d --build
```

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for full details.
