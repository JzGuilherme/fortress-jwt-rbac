import React, { useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import {
  CheckCircle2,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  XCircle,
} from 'lucide-react';
import { ClientRole, useAuthMemory } from '../context/AuthMemoryContext';
import { Badge, Button } from './ui/Primitives';

interface ApprovalItem {
  id: string;
  title: string;
  vendor: string;
  amountFormatted: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  decidedBy: string | null;
}

const INITIAL_APPROVALS: ApprovalItem[] = [
  {
    id: 'APR-9001',
    title: 'Renovação Cluster Kubernetes Multi-AZ Produção',
    vendor: 'Amazon Web Services (AWS)',
    amountFormatted: 'R$ 48.500,00',
    status: 'PENDING',
    decidedBy: null,
  },
  {
    id: 'APR-9002',
    title: 'Contrato Anual Auditoria Pentest & AppSec',
    vendor: 'CrowdStrike Security Labs',
    amountFormatted: 'R$ 29.000,00',
    status: 'APPROVED',
    decidedBy: 'admin@fortress.io',
  },
  {
    id: 'APR-9003',
    title: 'Licenciamento Enterprise Tokens Gemini 2.5 Flash',
    vendor: 'Google Cloud Platform',
    amountFormatted: 'R$ 14.200,00',
    status: 'PENDING',
    decidedBy: null,
  },
];

export const VaultDashboard: React.FC = () => {
  const {
    user,
    maskedTokenPreview,
    lastRotationAt,
    loginWithPresetRole,
    rotateSilentRefreshToken,
    hasPermission,
  } = useAuthMemory();

  const shouldReduceMotion = useReducedMotion();
  const [approvals, setApprovals] = useState<ApprovalItem[]>(INITIAL_APPROVALS);
  const [liveAnnouncement, setLiveAnnouncement] = useState<string>(
    'Sessão Zero-Trust iniciada com token JWT isolado em memória RAM.'
  );

  const handleRoleSwitch = (role: ClientRole) => {
    loginWithPresetRole(role);
    setLiveAnnouncement(
      `Perfil RBAC alterado para ${role}. Novo Access Token emitido em memória.`
    );
  };

  const handleDecision = (id: string, decision: 'APPROVED' | 'REJECTED') => {
    if (!hasPermission('approvals:approve') || !user) {
      setLiveAnnouncement(
        `Acesso bloqueado pelo RBAC: o cargo ${user?.role} não possui permissão de aprovação financeira.`
      );
      return;
    }

    setApprovals((prev) =>
      prev.map((item) =>
        item.id === id ? { ...item, status: decision, decidedBy: user.email } : item
      )
    );
    setLiveAnnouncement(`Solicitação ${id} marcada como ${decision} por ${user.email}.`);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* WCAG 2.1 AA Skip Navigation Link */}
      <a
        href="#main-vault-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:rounded-lg focus:bg-emerald-500 focus:px-4 focus:py-2 focus:font-bold focus:text-slate-950"
      >
        Pular para o conteúdo principal (WCAG 2.1 AA)
      </a>

      {/* Screen Reader ARIA Live Region */}
      <div role="status" aria-live="polite" className="sr-only">
        {liveAnnouncement}
      </div>

      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-emerald-400">
              <ShieldCheck className="h-6 w-6" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white">
                Fortress JWT &amp; RBAC Vault
              </h1>
              <p className="text-xs text-slate-400">
                In-Memory JWT • HttpOnly Rotating Cookie • Bcrypt • WCAG 2.1 AA
              </p>
            </div>
          </div>

          {/* RBAC Role Switcher for Interactive Audit */}
          <nav aria-label="Simulador de Cargos RBAC" className="flex items-center gap-2">
            {(['ADMIN', 'FINANCE_MANAGER', 'AUDITOR'] as ClientRole[]).map((role) => (
              <Button
                key={role}
                variant={user?.role === role ? 'primary' : 'secondary'}
                onClick={() => handleRoleSwitch(role)}
                aria-pressed={user?.role === role}
              >
                <UserCheck className="h-4 w-4" aria-hidden="true" />
                {role}
              </Button>
            ))}
          </nav>
        </div>
      </header>

      <main id="main-vault-content" className="mx-auto max-w-6xl space-y-6 px-6 py-8">
        {/* Zero-Trust Telemetry Banner */}
        <motion.section
          aria-labelledby="security-telemetry-heading"
          initial={shouldReduceMotion ? false : { opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid gap-4 md:grid-cols-3"
        >
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="flex items-center justify-between">
              <span
                id="security-telemetry-heading"
                className="text-xs font-semibold uppercase tracking-wider text-emerald-400"
              >
                1. JWT em Memória RAM (Closure)
              </span>
              <KeyRound className="h-4 w-4 text-emerald-400" aria-hidden="true" />
            </div>
            <p className="mt-2 font-mono text-xs break-all text-slate-300">
              {maskedTokenPreview}
            </p>
            <p className="mt-2 text-xs text-slate-400">
              <code>window.localStorage.length === 0</code> (Fora da árvore React Fiber)
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-purple-400">
                2. Cookie HttpOnly Rotativo
              </span>
              <Lock className="h-4 w-4 text-purple-400" aria-hidden="true" />
            </div>
            <p className="mt-2 text-sm font-medium text-white">
              Última Rotação Silenciosa: <span className="text-emerald-300">{lastRotationAt}</span>
            </p>
            <div className="mt-3">
              <Button
                variant="outline"
                onClick={() => {
                  void rotateSilentRefreshToken();
                  setLiveAnnouncement('Refresh token rotacionado via Cookie HttpOnly.');
                }}
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                Simular Silent Refresh (15m)
              </Button>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">
                3. Escopo RBAC Ativo
              </span>
              <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
            </div>
            <p className="mt-2 text-sm font-semibold text-white">{user?.name}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {user?.permissions.map((perm) => (
                <Badge key={perm} tone="emerald">
                  {perm}
                </Badge>
              ))}
            </div>
          </div>
        </motion.section>

        {/* Financial Approvals Table */}
        <section
          aria-labelledby="approvals-heading"
          className="rounded-xl border border-slate-800 bg-slate-900/70 p-6"
        >
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h2 id="approvals-heading" className="text-base font-bold text-white">
                Cofre de Alçadas Financeiras (Protegido por RBAC)
              </h2>
              <p className="text-xs text-slate-400">
                Apenas cargos com a permissão <code>approvals:approve</code> (ADMIN e FINANCE_MANAGER) podem aprovar ou rejeitar lotes.
              </p>
            </div>
            <Badge tone={hasPermission('approvals:approve') ? 'emerald' : 'amber'}>
              {hasPermission('approvals:approve')
                ? 'Permissão de Escrita Ativa'
                : 'Modo Somente Leitura (AUDITOR)'}
            </Badge>
          </div>

          <div className="mt-4 divide-y divide-slate-800">
            {approvals.map((item) => (
              <div
                key={item.id}
                className="flex flex-wrap items-center justify-between gap-4 py-4"
              >
                <div>
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-xs text-slate-400">{item.id}</span>
                    <h3 className="font-semibold text-white">{item.title}</h3>
                    <Badge
                      tone={
                        item.status === 'APPROVED'
                          ? 'emerald'
                          : item.status === 'REJECTED'
                            ? 'rose'
                            : 'amber'
                      }
                    >
                      {item.status}
                    </Badge>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    Fornecedor: <strong className="text-slate-200">{item.vendor}</strong> • Valor:{' '}
                    <strong className="text-emerald-300">{item.amountFormatted}</strong>
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="primary"
                    disabled={!hasPermission('approvals:approve') || item.status !== 'PENDING'}
                    onClick={() => handleDecision(item.id, 'APPROVED')}
                    aria-label={`Aprovar lote ${item.id}`}
                  >
                    <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                    Aprovar
                  </Button>
                  <Button
                    variant="danger"
                    disabled={!hasPermission('approvals:approve') || item.status !== 'PENDING'}
                    onClick={() => handleDecision(item.id, 'REJECTED')}
                    aria-label={`Rejeitar lote ${item.id}`}
                  >
                    <XCircle className="h-4 w-4" aria-hidden="true" />
                    Rejeitar
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
};
