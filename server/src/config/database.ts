import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs';
import {
  AuditLogRecord,
  FinancialApprovalRecord,
  RefreshTokenRecord,
  UserRecord,
  UserRole,
} from '../types/domain.js';

/**
 * Native SQLite Repository Layer (Node 22+ `node:sqlite`) providing atomic transactions
 * for Users, Rotating Refresh Token Families, Financial Approvals, and Immutable Audit Trails.
 */
export class SqlVaultDatabase {
  private readonly db: DatabaseSync;

  constructor(storagePath = ':memory:') {
    this.db = new DatabaseSync(storagePath);
    this.initializeSchema();
    this.seedDefaultData();
  }

  public runInTransaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE TRANSACTION');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('ADMIN', 'FINANCE_MANAGER', 'AUDITOR')),
        department TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        family_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        is_used INTEGER NOT NULL DEFAULT 0,
        is_revoked INTEGER NOT NULL DEFAULT 0,
        used_at INTEGER NULL,
        replaced_by_token_hash TEXT NULL,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
      CREATE INDEX IF NOT EXISTS idx_rt_token_hash ON refresh_tokens(token_hash);

      CREATE TABLE IF NOT EXISTS financial_approvals (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        vendor TEXT NOT NULL,
        amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
        status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
        requested_by TEXT NOT NULL,
        decided_by TEXT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        actor_email TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        details TEXT NOT NULL,
        timestamp TEXT NOT NULL
      );
    `);
  }

  private seedDefaultData(): void {
    const countStmt = this.db.prepare('SELECT COUNT(*) as total FROM users');
    const row = countStmt.get() as { total: number };
    if (row.total > 0) {
      return;
    }

    const saltRounds = 10;
    const now = new Date().toISOString();

    const seedUsers: Array<{
      id: string;
      name: string;
      email: string;
      pass: string;
      role: UserRole;
      dept: string;
    }> = [
      {
        id: 'usr-admin-01',
        name: 'Helena Vance (CISO Admin)',
        email: 'admin@fortress.io',
        pass: 'Fortress@Admin2026',
        role: 'ADMIN',
        dept: 'Cybersecurity & Governance',
      },
      {
        id: 'usr-fin-02',
        name: 'Ricardo Almeida (Head FinOps)',
        email: 'finance@fortress.io',
        pass: 'Fortress@Finance2026',
        role: 'FINANCE_MANAGER',
        dept: 'Treasury & FinOps',
      },
      {
        id: 'usr-aud-03',
        name: 'Clara Mendes (External Auditor)',
        email: 'auditor@fortress.io',
        pass: 'Fortress@Auditor2026',
        role: 'AUDITOR',
        dept: 'Compliance & Risk',
      },
    ];

    const insertUser = this.db.prepare(`
      INSERT INTO users (id, name, email, password_hash, role, department, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const u of seedUsers) {
      const hash = bcrypt.hashSync(u.pass, saltRounds);
      insertUser.run(u.id, u.name, u.email, hash, u.role, u.dept, now);
    }

    const insertApproval = this.db.prepare(`
      INSERT INTO financial_approvals (id, title, vendor, amount_cents, status, requested_by, decided_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // High-value item (> R$ 25.000,00 -> Requires ADMIN clearance, exceeds FINANCE_MANAGER ceiling)
    insertApproval.run(
      'APR-9001',
      'Renovação Cluster Kubernetes Multi-AZ Produção',
      'Amazon Web Services (AWS)',
      4850000,
      'PENDING',
      'finance@fortress.io',
      null,
      now,
      now
    );

    insertApproval.run(
      'APR-9002',
      'Contrato Anual Auditoria Pentest & AppSec',
      'CrowdStrike Security Labs',
      2900000,
      'APPROVED',
      'admin@fortress.io',
      'admin@fortress.io',
      now,
      now
    );

    // Medium-value item (<= R$ 25.000,00 -> Within FINANCE_MANAGER ceiling of R$ 25k)
    insertApproval.run(
      'APR-9003',
      'Licenciamento Enterprise Tokens Gemini 2.5 Flash',
      'Google Cloud Platform',
      1420000,
      'PENDING',
      'finance@fortress.io',
      null,
      now,
      now
    );
  }

  public findUserByEmail(email: string): UserRecord | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)');
    const row = stmt.get(email.trim()) as Record<string, unknown> | undefined;
    return row ? this.mapUser(row) : null;
  }

  public findUserById(id: string): UserRecord | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE id = ?');
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    return row ? this.mapUser(row) : null;
  }

  public saveRefreshToken(record: RefreshTokenRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO refresh_tokens (
        id, user_id, family_id, token_hash, is_used, is_revoked, used_at, replaced_by_token_hash, expires_at, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      record.id,
      record.userId,
      record.familyId,
      record.tokenHash,
      record.isUsed ? 1 : 0,
      record.isRevoked ? 1 : 0,
      record.usedAt,
      record.replacedByTokenHash,
      record.expiresAt,
      record.createdAt
    );
  }

  public findRefreshTokenByHash(tokenHash: string): RefreshTokenRecord | null {
    const stmt = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?');
    const row = stmt.get(tokenHash) as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }

    return {
      id: String(row.id),
      userId: String(row.user_id),
      familyId: String(row.family_id),
      tokenHash: String(row.token_hash),
      isUsed: Number(row.is_used) === 1,
      isRevoked: Number(row.is_revoked) === 1,
      usedAt: row.used_at !== null && row.used_at !== undefined ? Number(row.used_at) : null,
      replacedByTokenHash: row.replaced_by_token_hash ? String(row.replaced_by_token_hash) : null,
      expiresAt: Number(row.expires_at),
      createdAt: String(row.created_at),
    };
  }

  /**
   * Atomically marks a refresh token as used only if it is currently unused (`is_used = 0`).
   * Returns true if this caller won the atomic update, false if another concurrent request already used it.
   */
  public markRefreshTokenUsedAtomically(
    id: string,
    usedAt: number,
    replacedByTokenHash: string
  ): boolean {
    const stmt = this.db.prepare(`
      UPDATE refresh_tokens
      SET is_used = 1, used_at = ?, replaced_by_token_hash = ?
      WHERE id = ? AND is_used = 0 AND is_revoked = 0
    `);
    const res = stmt.run(usedAt, replacedByTokenHash, id);
    return Number(res.changes) === 1;
  }

  public revokeRefreshTokenFamily(familyId: string): number {
    const stmt = this.db.prepare('UPDATE refresh_tokens SET is_revoked = 1 WHERE family_id = ?');
    const result = stmt.run(familyId);
    return Number(result.changes);
  }

  public findApprovalById(id: string): FinancialApprovalRecord | null {
    const stmt = this.db.prepare('SELECT * FROM financial_approvals WHERE id = ?');
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    return row ? this.mapApproval(row) : null;
  }

  public createApproval(record: FinancialApprovalRecord): FinancialApprovalRecord {
    const stmt = this.db.prepare(`
      INSERT INTO financial_approvals (id, title, vendor, amount_cents, status, requested_by, decided_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      record.id,
      record.title,
      record.vendor,
      record.amountCents,
      record.status,
      record.requestedBy,
      record.decidedBy,
      record.createdAt,
      record.updatedAt
    );
    return record;
  }

  public listApprovals(): FinancialApprovalRecord[] {
    const stmt = this.db.prepare('SELECT * FROM financial_approvals ORDER BY created_at DESC');
    const rows = stmt.all() as Array<Record<string, unknown>>;
    return rows.map((r) => this.mapApproval(r));
  }

  public updateApprovalStatus(
    id: string,
    status: 'APPROVED' | 'REJECTED',
    decidedBy: string
  ): FinancialApprovalRecord | null {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE financial_approvals
      SET status = ?, decided_by = ?, updated_at = ?
      WHERE id = ?
    `);
    const res = stmt.run(status, decidedBy, now, id);
    if (Number(res.changes) === 0) {
      return null;
    }

    return this.findApprovalById(id);
  }

  public appendAuditLog(log: AuditLogRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_logs (id, actor_email, actor_role, action, resource_id, details, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      log.id,
      log.actorEmail,
      log.actorRole,
      log.action,
      log.resourceId,
      log.details,
      log.timestamp
    );
  }

  public listAuditLogs(limit = 30): AuditLogRecord[] {
    const stmt = this.db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?');
    const rows = stmt.all(limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: String(r.id),
      actorEmail: String(r.actor_email),
      actorRole: String(r.actor_role) as UserRole,
      action: String(r.action),
      resourceId: String(r.resource_id),
      details: String(r.details),
      timestamp: String(r.timestamp),
    }));
  }

  private mapApproval(r: Record<string, unknown>): FinancialApprovalRecord {
    return {
      id: String(r.id),
      title: String(r.title),
      vendor: String(r.vendor),
      amountCents: Number(r.amount_cents),
      status: String(r.status) as FinancialApprovalRecord['status'],
      requestedBy: String(r.requested_by),
      decidedBy: r.decided_by ? String(r.decided_by) : null,
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at),
    };
  }

  private mapUser(row: Record<string, unknown>): UserRecord {
    return {
      id: String(row.id),
      name: String(row.name),
      email: String(row.email),
      passwordHash: String(row.password_hash),
      role: String(row.role) as UserRole,
      department: String(row.department),
      createdAt: String(row.created_at),
    };
  }
}
