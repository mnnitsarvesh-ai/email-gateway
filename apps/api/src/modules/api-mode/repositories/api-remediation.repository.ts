import { Injectable } from '@nestjs/common';
import { PrismaReadService, uuidv7 } from '@email-gateway/common';
import {
  type ApiCopyRemediationAction,
  type ApiCopyRemediationState,
  type ApiCopyStatus,
  type ApiRemediationActionKind,
  type ApiRemediationPolicyMode,
  type ApiRemediationStatus,
  type ApiRemediationTrigger,
  type ActorType,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { MAILBOX_PROFILES } from './api-mode.repository';

type Tx = Prisma.TransactionClient;

/** One `api_remediation_policies` row (document as stored; validated before it was written). */
export interface PolicyRow {
  id: bigint;
  publicId: string;
  domainId: bigint | null;
  mode: ApiRemediationPolicyMode;
  document: Prisma.JsonValue;
  documentSha256: string;
  rowVersion: number;
  updatedAt: Date;
}

export interface DomainPolicyRow extends PolicyRow {
  domain: { publicId: string; name: string };
}

export interface PolicyWrite {
  mode: ApiRemediationPolicyMode;
  document: Prisma.InputJsonValue;
  documentSha256: string;
  updatedByUserId: bigint | null;
}

/** A remediation action as the views read it (provider ids never selected; counts only). */
export interface RemediationRow {
  id: bigint;
  publicId: string;
  action: ApiRemediationActionKind;
  trigger: ApiRemediationTrigger;
  status: ApiRemediationStatus;
  reasonCode: string | null;
  attempts: number;
  locateAttempts: number;
  lastErrorCode: string | null;
  lastHttpStatus: number | null;
  generation: number;
  mailboxPublicId: string;
  mailboxAddress: string;
  connectionPublicId: string;
  detectionPublicId: string | null;
  quarantineEntryPublicId: string | null;
  createdAt: Date;
  nextAttemptAt: Date | null;
  verdictAt: Date | null;
  startedAt: Date | null;
  completedAt: Date | null;
  updatedAt: Date;
}

export interface RemediationDetailRow extends RemediationRow {
  decision: Prisma.JsonValue | null;
  requestedByType: ActorType;
  requestedByUserPublicId: string | null;
  requestReason: string | null;
  /** `provider_refs` reduced to its container and the counts of its id lists. */
  providerRefs: { container: string | null; before: number; after: number } | null;
  reversesPublicId: string | null;
  reversedByPublicId: string | null;
  releasePublicId: string | null;
}

export interface RemediationFilter {
  status?: ApiRemediationStatus[];
  action?: ApiRemediationActionKind[];
  trigger?: ApiRemediationTrigger[];
  mailboxPublicId?: string;
  connectionPublicId?: string;
  detectionPublicId?: string;
}

/** The copy of a manual request, locked (`FOR UPDATE`), with its grant fact. */
export interface CopyFacts {
  id: bigint;
  receivedAt: Date;
  publicId: string;
  organizationId: bigint;
  messageId: bigint;
  apiConnectionId: bigint;
  mailboxId: bigint;
  status: ApiCopyStatus;
  verdictAuthority: 'copy' | 'inline';
  remediationState: ApiCopyRemediationState;
  remediationAction: ApiCopyRemediationAction | null;
  remediationGeneration: number;
  lastActionId: bigint | null;
  grantActive: boolean;
}

/** An action row locked for a retry. */
export interface LockedRemediation {
  id: bigint;
  publicId: string;
  action: ApiRemediationActionKind;
  status: ApiRemediationStatus;
  quarantineEntryId: bigint | null;
  copyId: bigint;
  copyReceivedAt: Date;
  generation: number;
  rowVersion: number;
}

const num = (v: unknown): number => Number(v);
const nullableNum = (v: unknown): number | null => (v === null || v === undefined ? null : num(v));

/** The JSON id lists of `provider_refs` → their sizes (ids never leave the repository). */
function refsSummary(value: unknown): RemediationDetailRow['providerRefs'] {
  const doc = typeof value === 'string' ? safeJson(value) : value;
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const refs = doc as { before?: unknown; after?: unknown; container?: unknown };
  const container = typeof refs.container === 'string' ? refs.container : null;
  return {
    container,
    before: Array.isArray(refs.before) ? refs.before.length : 0,
    after: Array.isArray(refs.after) ? refs.after.length : 0,
  };
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/**
 * Data access of the API-mode remediation routes (step API-2 §3, R2, R12, R13;
 * docs/plan/steps/36-api-mode-remediation.md; ADR-0101): the organization and per-domain
 * remediation policies (CAS on `row_version`; the organization row locked first so creations
 * serialize), the remediation history with signed keyset pages, the copy and action locks of the
 * manual requests and the retry. Every query is filtered by the scope's organization (foreign ids
 * read as missing). `provider_refs` is reduced to its container and counts before it leaves this
 * class; the action rows the api queues are written by `RemediationActionWriter`.
 */
@Injectable()
export class ApiRemediationRepository {
  constructor(private readonly reader: PrismaReadService) {}

  // ---- policies (R13 #1-#4) ------------------------------------------------------------------

  private readonly policySelect = {
    id: true,
    publicId: true,
    domainId: true,
    mode: true,
    document: true,
    documentSha256: true,
    rowVersion: true,
    updatedAt: true,
  } satisfies Prisma.ApiRemediationPolicySelect;

  /** The organization row and the domain rows of non-deleted domains (replica by default). */
  async policies(
    scope: TenantScope,
    client?: Tx,
  ): Promise<{ organization: PolicyRow | null; domains: DomainPolicyRow[] }> {
    const db = client ?? this.reader.client;
    const rows = await db.apiRemediationPolicy.findMany({
      where: tenantWhere(scope),
      select: {
        ...this.policySelect,
        domain: { select: { publicId: true, name: true, status: true } },
      },
      orderBy: { id: 'asc' },
      take: 1000,
    });
    let organization: PolicyRow | null = null;
    const domains: DomainPolicyRow[] = [];
    for (const { domain, ...row } of rows) {
      if (row.domainId === null) organization = row;
      else if (domain !== null && domain.status !== 'deleted') {
        domains.push({ ...row, domain: { publicId: domain.publicId, name: domain.name } });
      }
    }
    domains.sort((a, b) => (a.domain.name < b.domain.name ? -1 : 1));
    return { organization, domains };
  }

  /** Serializes the organization's policy writes (lock order: organization, then domain). */
  async lockOrganization(tx: Tx, scope: TenantScope): Promise<boolean> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR UPDATE`;
    return rows.length === 1;
  }

  /** The scope's non-deleted domain, locked (`FOR UPDATE`). */
  async lockDomain(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<{ id: bigint; publicId: string; name: string } | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint; publicId: string; name: string }>>`
      SELECT id, public_id AS publicId, name FROM domains
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
        AND status <> 'deleted'
      FOR UPDATE`;
    const row = rows[0];
    return row === undefined ? null : { ...row, id: BigInt(row.id) };
  }

  /** The policy row of one scope (organization: `domainId` null), locked when it exists. */
  async lockPolicy(tx: Tx, scope: TenantScope, domainId: bigint | null): Promise<PolicyRow | null> {
    const scopeKey = domainId ?? 0n;
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM api_remediation_policies
      WHERE organization_id = ${scope.organizationId} AND scope_key = ${scopeKey}
      FOR UPDATE`;
    const id = ids[0]?.id;
    if (id === undefined) return null;
    return tx.apiRemediationPolicy.findFirst({
      where: tenantWhere(scope, { id: BigInt(id), domainId }),
      select: this.policySelect,
    });
  }

  async createPolicy(
    tx: Tx,
    scope: TenantScope,
    domainId: bigint | null,
    write: PolicyWrite,
  ): Promise<PolicyRow> {
    return tx.apiRemediationPolicy.create({
      data: {
        publicId: uuidv7(),
        organizationId: scope.organizationId,
        domainId,
        mode: write.mode,
        document: write.document,
        documentSha256: write.documentSha256,
        updatedByUserId: write.updatedByUserId,
      },
      select: this.policySelect,
    });
  }

  /** CAS on `row_version` (+1); false when the version moved. */
  async updatePolicy(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    write: PolicyWrite,
  ): Promise<boolean> {
    const { count } = await tx.apiRemediationPolicy.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: {
        mode: write.mode,
        document: write.document,
        documentSha256: write.documentSha256,
        updatedByUserId: write.updatedByUserId,
        rowVersion: { increment: 1 },
      },
    });
    return count === 1;
  }

  async policyById(tx: Tx, scope: TenantScope, id: bigint): Promise<PolicyRow | null> {
    return tx.apiRemediationPolicy.findFirst({
      where: tenantWhere(scope, { id }),
      select: this.policySelect,
    });
  }

  async deletePolicy(tx: Tx, scope: TenantScope, id: bigint): Promise<boolean> {
    const { count } = await tx.apiRemediationPolicy.deleteMany({
      where: tenantWhere(scope, { id }),
    });
    return count === 1;
  }

  // ---- history (R13 #5, #6) ------------------------------------------------------------------

  private actionSql(scope: TenantScope, where: Prisma.Sql, limit: number): Prisma.Sql {
    return Prisma.sql`
      SELECT a.id, a.public_id AS publicId, a.action, a.\`trigger\` AS triggerKind, a.status,
             a.reason_code AS reasonCode, a.attempts, a.locate_attempts AS locateAttempts,
             a.last_error_code AS lastErrorCode, a.last_http_status AS lastHttpStatus,
             a.generation, mb.public_id AS mailboxPublicId, mb.primary_address AS mailboxAddress,
             pc.public_id AS connectionPublicId, c.public_id AS detectionPublicId,
             q.public_id AS quarantineEntryPublicId, a.created_at AS createdAt,
             a.next_attempt_at AS nextAttemptAt, a.verdict_at AS verdictAt,
             a.started_at AS startedAt, a.completed_at AS completedAt, a.updated_at AS updatedAt
      FROM api_remediation_actions a
      JOIN api_mailboxes mb ON mb.id = a.mailbox_id AND mb.organization_id = a.organization_id
      JOIN api_mode_connections ac
        ON ac.id = a.api_connection_id AND ac.organization_id = a.organization_id
      JOIN provider_connections pc
        ON pc.id = ac.provider_connection_id AND pc.organization_id = a.organization_id
      LEFT JOIN api_message_copies c
        ON c.id = a.copy_id AND c.received_at = a.copy_received_at
       AND c.organization_id = a.organization_id
      LEFT JOIN quarantine_messages q
        ON q.id = a.quarantine_entry_id AND q.organization_id = a.organization_id
      WHERE a.organization_id = ${scope.organizationId} AND ${where}
      ORDER BY a.created_at DESC, a.id DESC
      LIMIT ${limit}`;
  }

  private toRow(r: Record<string, unknown>): RemediationRow {
    return {
      id: BigInt(r.id as bigint),
      publicId: r.publicId as string,
      action: r.action as ApiRemediationActionKind,
      trigger: r.triggerKind as ApiRemediationTrigger,
      status: r.status as ApiRemediationStatus,
      reasonCode: (r.reasonCode as string | null) ?? null,
      attempts: num(r.attempts),
      locateAttempts: num(r.locateAttempts),
      lastErrorCode: (r.lastErrorCode as string | null) ?? null,
      lastHttpStatus: nullableNum(r.lastHttpStatus),
      generation: num(r.generation),
      mailboxPublicId: r.mailboxPublicId as string,
      mailboxAddress: r.mailboxAddress as string,
      connectionPublicId: r.connectionPublicId as string,
      detectionPublicId: (r.detectionPublicId as string | null) ?? null,
      quarantineEntryPublicId: (r.quarantineEntryPublicId as string | null) ?? null,
      createdAt: r.createdAt as Date,
      nextAttemptAt: (r.nextAttemptAt as Date | null) ?? null,
      verdictAt: (r.verdictAt as Date | null) ?? null,
      startedAt: (r.startedAt as Date | null) ?? null,
      completedAt: (r.completedAt as Date | null) ?? null,
      updatedAt: r.updatedAt as Date,
    };
  }

  /** A page in `[from, to)` of `created_at`, newest first (replica; keyset `(created_at, id)`). */
  async remediations(
    scope: TenantScope,
    filter: RemediationFilter,
    range: { from: Date; to: Date },
    page: { take: number; before?: { at: Date; id: bigint } },
  ): Promise<RemediationRow[]> {
    const terms: Prisma.Sql[] = [
      Prisma.sql`a.created_at >= ${range.from}`,
      Prisma.sql`a.created_at < ${range.to}`,
    ];
    if (filter.status) terms.push(Prisma.sql`a.status IN (${Prisma.join(filter.status)})`);
    if (filter.action) terms.push(Prisma.sql`a.action IN (${Prisma.join(filter.action)})`);
    if (filter.trigger) terms.push(Prisma.sql`a.\`trigger\` IN (${Prisma.join(filter.trigger)})`);
    if (filter.mailboxPublicId !== undefined) {
      terms.push(Prisma.sql`mb.public_id = ${filter.mailboxPublicId}`);
    }
    if (filter.connectionPublicId !== undefined) {
      terms.push(Prisma.sql`pc.public_id = ${filter.connectionPublicId}`);
    }
    if (filter.detectionPublicId !== undefined) {
      terms.push(Prisma.sql`c.public_id = ${filter.detectionPublicId}`);
    }
    if (page.before !== undefined) {
      terms.push(
        Prisma.sql`(a.created_at < ${page.before.at} OR (a.created_at = ${page.before.at} AND a.id < ${page.before.id}))`,
      );
    }
    const rows = await this.reader.client.$queryRaw<Array<Record<string, unknown>>>(
      this.actionSql(scope, Prisma.join(terms, ' AND '), page.take),
    );
    return rows.map((r) => this.toRow(r));
  }

  /** One action by public id with its links (replica unless a client is given). */
  async remediation(
    scope: TenantScope,
    publicId: string,
    client?: Tx,
  ): Promise<RemediationDetailRow | null> {
    const db = client ?? this.reader.client;
    const rows = await db.$queryRaw<Array<Record<string, unknown>>>(
      this.actionSql(scope, Prisma.sql`a.public_id = ${publicId}`, 1),
    );
    const base = rows[0];
    if (base === undefined) return null;
    const row = this.toRow(base);
    const extra = await db.$queryRaw<Array<Record<string, unknown>>>`
      SELECT a.decision, a.requested_by_type AS requestedByType, a.request_reason AS requestReason,
             a.provider_refs AS providerRefs, u.public_id AS requestedByUserPublicId,
             rv.public_id AS reversesPublicId, rb.public_id AS reversedByPublicId,
             rl.release_public_id AS releasePublicId
      FROM api_remediation_actions a
      LEFT JOIN users u ON u.id = a.requested_by_user_id
      LEFT JOIN api_remediation_actions rv
        ON rv.id = a.reverses_action_id AND rv.organization_id = a.organization_id
      LEFT JOIN api_remediation_actions rb
        ON rb.id = a.reversed_by_action_id AND rb.organization_id = a.organization_id
      LEFT JOIN quarantine_release_logs rl
        ON rl.id = a.release_log_id AND rl.organization_id = a.organization_id
      WHERE a.id = ${row.id} AND a.organization_id = ${scope.organizationId}`;
    const e = extra[0] ?? {};
    const decision = e.decision;
    return {
      ...row,
      decision:
        typeof decision === 'string'
          ? (safeJson(decision) as Prisma.JsonValue)
          : ((decision as Prisma.JsonValue | undefined) ?? null),
      requestedByType: (e.requestedByType as ActorType | undefined) ?? 'system',
      requestedByUserPublicId: (e.requestedByUserPublicId as string | null | undefined) ?? null,
      requestReason: (e.requestReason as string | null | undefined) ?? null,
      providerRefs: refsSummary(e.providerRefs),
      reversesPublicId: (e.reversesPublicId as string | null | undefined) ?? null,
      reversedByPublicId: (e.reversedByPublicId as string | null | undefined) ?? null,
      releasePublicId: (e.releasePublicId as string | null | undefined) ?? null,
    };
  }

  // ---- manual requests (R12) -----------------------------------------------------------------

  /**
   * The scope's copy by public id with the grant fact, locked (`FOR UPDATE`) unless `lock` is
   * false (the restore that delegates to the quarantine release keeps the quarantine's lock order,
   * message → entry, and relies on the unique action key instead).
   */
  async lockCopy(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
    lock = true,
  ): Promise<CopyFacts | null> {
    const locked = lock
      ? await tx.$queryRaw<Array<{ id: bigint; receivedAt: Date }>>`
          SELECT id, received_at AS receivedAt FROM api_message_copies
          WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
          FOR UPDATE`
      : await tx.$queryRaw<Array<{ id: bigint; receivedAt: Date }>>`
          SELECT id, received_at AS receivedAt FROM api_message_copies
          WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}`;
    const key = locked[0];
    if (key === undefined) return null;
    const row = await tx.apiMessageCopy.findFirst({
      where: tenantWhere(scope, { id: BigInt(key.id), receivedAt: key.receivedAt }),
      select: {
        id: true,
        receivedAt: true,
        publicId: true,
        organizationId: true,
        messageId: true,
        apiConnectionId: true,
        mailboxId: true,
        status: true,
        verdictAuthority: true,
        remediationState: true,
        remediationAction: true,
        remediationGeneration: true,
        lastActionId: true,
      },
    });
    if (row === null) return null;
    const grant = await tx.apiModeConnection.findFirst({
      where: tenantWhere(scope, { id: row.apiConnectionId }),
      select: {
        providerConnection: {
          select: {
            grants: {
              where: { profile: { in: MAILBOX_PROFILES }, status: 'active' },
              select: { id: true },
              take: 1,
            },
          },
        },
      },
    });
    return { ...row, grantActive: (grant?.providerConnection.grants.length ?? 0) > 0 };
  }

  /** True when an action of the copy (other than `exceptId`) is pending or in progress. */
  async hasActiveAction(
    tx: Tx,
    scope: TenantScope,
    copy: { id: bigint; receivedAt: Date },
    exceptId: bigint | null = null,
  ): Promise<boolean> {
    const row = await tx.apiRemediationAction.findFirst({
      where: tenantWhere(scope, {
        copyId: copy.id,
        copyReceivedAt: copy.receivedAt,
        status: { in: ['pending', 'in_progress'] as ApiRemediationStatus[] },
        ...(exceptId !== null && { id: { not: exceptId } }),
      }),
      select: { id: true },
    });
    return row !== null;
  }

  /** The copy's latest succeeded remediation of `action` (the one a reversal undoes). */
  async lastSucceeded(
    tx: Tx,
    scope: TenantScope,
    copy: { id: bigint; receivedAt: Date; remediationGeneration: number },
    action: ApiRemediationActionKind,
  ): Promise<{ id: bigint } | null> {
    return tx.apiRemediationAction.findFirst({
      where: tenantWhere(scope, {
        copyId: copy.id,
        copyReceivedAt: copy.receivedAt,
        action,
        status: 'succeeded' as const,
        reversedByActionId: null,
      }),
      select: { id: true },
      orderBy: { id: 'desc' },
    });
  }

  /** The copy's latest mailbox-located quarantine entry (public id and state). */
  async entryOfCopy(
    tx: Tx,
    scope: TenantScope,
    copy: { id: bigint; receivedAt: Date },
  ): Promise<{ publicId: string; state: string } | null> {
    const row = await tx.quarantineMessage.findFirst({
      where: tenantWhere(scope, {
        apiCopyId: copy.id,
        apiCopyReceivedAt: copy.receivedAt,
        location: 'mailbox' as const,
      }),
      select: { publicId: true, status: true },
      orderBy: { id: 'desc' },
    });
    return row === null ? null : { publicId: row.publicId, state: row.status };
  }

  /** The scope's action by public id, locked (`FOR UPDATE`). */
  async lockRemediation(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<{ row: LockedRemediation; copyGeneration: number } | null> {
    // Lock order of every writer (api routes and the mailbox-worker's outcomes): the copy row
    // first, then the action row. The action's copy key is immutable, so an unlocked read finds
    // the copy to lock.
    const keys = await tx.$queryRaw<Array<{ copyId: bigint; copyReceivedAt: Date }>>`
      SELECT copy_id AS copyId, copy_received_at AS copyReceivedAt FROM api_remediation_actions
      WHERE public_id = ${publicId} AND organization_id = ${scope.organizationId}`;
    const key = keys[0];
    if (key === undefined) return null;
    const copies = await tx.$queryRaw<Array<{ generation: number | bigint }>>`
      SELECT remediation_generation AS generation FROM api_message_copies
      WHERE id = ${BigInt(key.copyId)} AND received_at = ${key.copyReceivedAt}
        AND organization_id = ${scope.organizationId}
      FOR UPDATE`;
    const copy = copies[0];
    if (copy === undefined) return null;
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM api_remediation_actions
      WHERE public_id = ${publicId} AND organization_id = ${scope.organizationId}
      FOR UPDATE`;
    const id = ids[0]?.id;
    if (id === undefined) return null;
    const row = await tx.apiRemediationAction.findFirst({
      where: tenantWhere(scope, { id: BigInt(id) }),
      select: {
        id: true,
        publicId: true,
        action: true,
        status: true,
        quarantineEntryId: true,
        copyId: true,
        copyReceivedAt: true,
        generation: true,
        rowVersion: true,
      },
    });
    return row === null ? null : { row, copyGeneration: Number(copy.generation) };
  }

  /**
   * R12 retry: a `failed` row back to `pending`, due now, attempts and locate attempts reset
   * (CAS on `row_version`); false when the row moved.
   */
  async retry(tx: Tx, scope: TenantScope, row: LockedRemediation, now: Date): Promise<boolean> {
    const { count } = await tx.apiRemediationAction.updateMany({
      where: tenantWhere(scope, {
        id: row.id,
        rowVersion: row.rowVersion,
        status: 'failed' as const,
      }),
      data: {
        status: 'pending',
        attempts: 0,
        locateAttempts: 0,
        nextAttemptAt: now,
        leaseUntil: null,
        reasonCode: null,
        lastErrorCode: null,
        lastHttpStatus: null,
        startedAt: null,
        completedAt: null,
        rowVersion: { increment: 1 },
      },
    });
    return count === 1;
  }
}
