# Fortress JWT & RBAC Vault 🏰🔐

[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Node.js & Express](https://img.shields.io/badge/Node.js-Express%20REST-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Security: Zero-Trust JWT](https://img.shields.io/badge/Auth-In--Memory%20JWT%20%2B%20HttpOnly-10B981?style=for-the-badge)](https://owasp.org/)
[![Accessibility: WCAG 2.1 AA](https://img.shields.io/badge/A11y-WCAG%202.1%20AA-8B5CF6?style=for-the-badge)](https://www.w3.org/WAI/WCAG21/quickref/)

**Cofre Full-Stack de Autenticação Zero-Trust e Governança de Alçadas Financeiras (RBAC)** construído com **Node.js, Express, TypeScript, SQL (SQLite), React 18, Vite, Tailwind CSS, shadcn/ui e Framer Motion**.

---

## 🎯 O Problema Real de Mercado Resolvido

Mais de 90% das aplicações SPA modernas cometem um erro crítico de segurança: **armazenam o token JWT no `localStorage` ou `sessionStorage` do navegador**. Caso ocorra qualquer vulnerabilidade de *Cross-Site Scripting (XSS)* — até mesmo via pacote NPM de terceiros — um atacante consegue ler `localStorage.getItem('token')` e sequestrar a conta do executivo.

O **Fortress JWT & RBAC Vault** elimina esse vetor de ataque de ponta a ponta:

1. **JWT de Curta Duração Exclusivamente em Memória (`In-Memory Access Token`):**
   No Front-End React, o `accessToken` (15 minutos) vive **apenas em uma variável privada dentro de um Closure/Contexto em memória RAM**, jamais tocando no `localStorage`, `sessionStorage` ou cookies acessíveis via `document.cookie`.
2. **Refresh Token Rotativo em Cookie `HttpOnly` + Detecção de Roubo de Sessão:**
   O `refreshToken` (7 dias) é transmitido exclusivamente via cabeçalho `Set-Cookie` com as flags `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`. A cada renovação silenciosa (*Silent Refresh*), o token antigo é invalidado no banco SQL e substituído por um novo (**Refresh Token Rotation**). Se um token antigo for reutilizado, o sistema detecta o sequestro e revoga toda a família de sessões do usuário imediatamente.
3. **Senhas com `Bcrypt` & Controle de Acesso Baseado em Cargos (`RBAC`):**
   Hashing adaptativo com **Bcrypt** e matriz de permissões granular (`ADMIN`, `FINANCE_MANAGER`, `AUDITOR`) validada tanto no middleware da API RESTful quanto na renderização condicional da UI.
4. **Acessibilidade Nativa (`WCAG 2.1 Nível AA`):**
   Interface desenhada com **Tailwind CSS + padrões shadcn/ui + Framer Motion** respeitando `prefers-reduced-motion`, navegação integral por teclado (`Skip to main content`, `Focus Visible`, `aria-live="polite"`, `role="alert"` e contraste mínimo de `4.5:1`).

---

## 🏗️ Arquitetura de Segurança Zero-Trust

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
    Note over UI: accessToken salvo APENAS em memória RAM (Zero localStorage)

    UI->>API: POST /api/approvals/:id/approve (Authorization: Bearer <accessToken>)
    API->>API: Middleware verifyJwt + requireRole(['ADMIN', 'FINANCE_MANAGER'])
    API->>DB: UPDATE financial_approvals + INSERT audit_logs
    API-->>UI: 200 OK (Transação Aprovada)

    Note over UI,API: Expiração de 15m -> Silent Refresh Automático
    UI->>API: POST /api/auth/refresh (Envia Cookie HttpOnly automaticamente)
    API->>DB: Verifica se token já foi usado (Anti-Replay Breach Detection)
    API->>DB: Revoga token antigo e grava novo Refresh Token na família
    API-->>UI: 200 OK { newAccessToken } + Novo Cookie HttpOnly
```

---

## 📂 Estrutura do Projeto

```text
fortress-jwt-rbac/
├── server/
│   ├── src/
│   │   ├── config/
│   │   │   └── database.ts            # Camada SQL (SQLite Nativo) com tabelas users, refresh_tokens, approvals e audit_logs
│   │   ├── middleware/
│   │   │   ├── authMiddleware.ts      # Validação estrita do Bearer JWT
│   │   │   └── rbacMiddleware.ts      # Guarda de rotas por Role e Permission (RBAC)
│   │   ├── services/
│   │   │   ├── AuthService.ts         # Bcrypt, emissão JWT, rotação de Refresh Token e revogação de família
│   │   │   └── ApprovalVaultService.ts # Fluxo de alçadas financeiras e trilha de auditoria SQL
│   │   ├── routes/
│   │   │   └── apiRoutes.ts           # Endpoints RESTful (/api/auth/*, /api/approvals/*, /api/audit)
│   │   ├── types/
│   │   │   └── domain.ts              # Contratos TypeScript de RBAC, JWT e Entidades
│   │   └── index.ts                   # Bootstrap Express + Helmet + CORS Credentials + CookieParser
│   └── tests/
│       └── authAndRbac.test.ts        # Suíte de testes automatizados (Bcrypt, JWT, Rotação e RBAC)
├── client/
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthMemoryContext.tsx  # Guarda o Access Token estritamente em memória RAM + Silent Refresh
│   │   ├── components/
│   │   │   ├── ui/                    # Componentes acessíveis padrão shadcn/ui (Button, Badge, Card, Alert)
│   │   │   ├── RbacGuard.tsx          # Proteção visual declarativa por Role/Permissão
│   │   │   └── VaultDashboard.tsx     # Painel WCAG 2.1 AA com animações Framer Motion
│   │   ├── App.tsx
│   │   └── main.tsx
├── docker-compose.yml
├── Dockerfile
├── vercel.json
└── package.json
```

---

## 🚀 Como Executar Localmente ou com Docker

### 1. Instalação e Testes Automatizados
```bash
git clone https://github.com/JzGuilherme/fortress-jwt-rbac.git
cd fortress-jwt-rbac
cp .env.example .env
npm install
npm test
```

### 2. Rodando Back-End e Front-End
```bash
# Terminal 1: API RESTful Node.js + Express (Porta 4000)
npm run dev:server

# Terminal 2: Front-End React + Vite + Tailwind (Porta 5173)
npm run dev:client
```

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja [LICENSE](LICENSE) para mais detalhes.
