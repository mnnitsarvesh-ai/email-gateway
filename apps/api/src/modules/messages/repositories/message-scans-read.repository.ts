import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { LifecycleMessageRow } from './message-lifecycle-read.repository';

const scanSelect = {
  id: true,
  lifecycleRound: true,
  scanKind: true,
  status: true,
  scanVerdict: true,
  reasonCodes: true,
  requiredEngines: true,
  startedAt: true,
  completedAt: true,
  deadlineAt: true,
} satisfies Prisma.EmailScanSelect;

export type ScanRoundRow = Prisma.EmailScanGetPayload<{ select: typeof scanSelect }>;

const engineResultSelect = {
  scanId: true,
  engine: true,
  engineVersion: true,
  outcome: true,
  score: true,
  requiredScore: true,
  action: true,
  reasonCodes: true,
  errorCode: true,
  settingsVersion: true,
  durationMs: true,
  evidence: true,
  attempt: true,
  isFinal: true,
  completedAt: true,
} satisfies Prisma.ScanEngineResultSelect;

export type EngineResultRow = Prisma.ScanEngineResultGetPayload<{
  select: typeof engineResultSelect;
}>;

const authSelect = {
  scanId: true,
  engine: true,
  spf: true,
  spfDomain: true,
  dkim: true,
  dkimSignatures: true,
  dmarc: true,
  dmarcPolicy: true,
  dmarcDomain: true,
  arc: true,
} satisfies Prisma.EmailAuthResultSelect;

export type AuthResultRow = Prisma.EmailAuthResultGetPayload<{ select: typeof authSelect }>;

/** Most engine rows one page reads: ≤ 20 rounds × (attempts of every engine). */
const MAX_ENGINE_ROWS = 2_000;

const attachmentResultSelect = {
  scanId: true,
  attachmentId: true,
  partIndex: true,
  sha256: true,
  sizeBytes: true,
  detectedType: true,
  typeFamily: true,
  typeMismatch: true,
  verdict: true,
  reasonCodes: true,
  clamavSignature: true,
  clamavEngineVersion: true,
  clamavDbVersion: true,
  yaraBundleId: true,
  yaraMatches: true,
  archive: true,
  knownHashSeverity: true,
  // Not `cache_result` / `duration_ms`: never shown to tenants (they reveal the cross-tenant
  // content cache, step 4.2 A10/A16).
} satisfies Prisma.AttachmentScanResultSelect;

export type AttachmentResultRow = Prisma.AttachmentScanResultGetPayload<{
  select: typeof attachmentResultSelect;
}>;

export interface AttachmentPartRow {
  partIndex: number;
  filename: string | null;
  declaredContentType: string | null;
}

export interface SandboxSubmissionRow {
  id: bigint;
  scanId: bigint;
  attachmentId: bigint;
  status: 'pending' | 'submitted' | 'completed' | 'failed' | 'expired';
}

/**
 * Most per-attachment rows one page reads: ≤ 20 rounds × ATTACHMENT_MAX_PER_MESSAGE (100, the
 * engine scans at most that many attachments per round, step 4.2 A3).
 */
const MAX_ATTACHMENT_ROWS = 2_000;

/**
 * Read-only, tenant-scoped scan reads (step 4.1 S16) on the replica (`PrismaReadService`, with
 * the writer fallback above the lag threshold; ADR-0014, §2.0 invariant 6). Every query matches
 * the organization of the caller's scope and the message's `(message_id, received_at)`, so the
 * partitioned tables are pruned and another tenant's rows are never read.
 */
@Injectable()
export class MessageScansReadRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** Rounds newest first, below `beforeRound` when given (`(message_id, lifecycle_round)` key). */
  rounds(
    scope: TenantScope,
    message: LifecycleMessageRow,
    page: { take: number; beforeRound?: number },
  ): Promise<ScanRoundRow[]> {
    return this.db.emailScan.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.beforeRound !== undefined && { lifecycleRound: { lt: page.beforeRound } }),
      }),
      select: scanSelect,
      orderBy: [{ lifecycleRound: 'desc' }, { id: 'desc' }],
      take: page.take,
    });
  }

  /** Every engine row (attempts and finals) of the given scans, by engine and attempt. */
  engineResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<EngineResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.scanEngineResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: engineResultSelect,
      orderBy: [{ scanId: 'desc' }, { engine: 'asc' }, { attempt: 'asc' }],
      take: MAX_ENGINE_ROWS,
    });
  }

  /**
   * The per-attachment results of the given scans (step 4.2 A16, A18), by round and part index.
   * File contents and entry names are never stored there.
   */
  attachmentResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<AttachmentResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.attachmentScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: attachmentResultSelect,
      orderBy: [{ scanId: 'desc' }, { partIndex: 'asc' }],
      take: MAX_ATTACHMENT_ROWS,
    });
  }

  /**
   * Display metadata of the message's attachments by part index (`email_attachments`, joined on
   * `(message_id, part_index, received_at)`): the sanitized filename and the declared type.
   */
  attachmentParts(
    scope: TenantScope,
    message: LifecycleMessageRow,
    partIndexes: readonly number[],
  ): Promise<AttachmentPartRow[]> {
    if (partIndexes.length === 0) return Promise.resolve([]);
    return this.db.emailAttachment.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        partIndex: { in: [...new Set(partIndexes)] },
      }),
      select: { partIndex: true, filename: true, declaredContentType: true },
      take: MAX_ATTACHMENT_ROWS,
    });
  }

  /** The sandbox submissions of the given scans (step 4.2 A11), one per scan and attachment. */
  sandboxSubmissions(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<SandboxSubmissionRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.sandboxSubmission.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: { id: true, scanId: true, attachmentId: true, status: true },
      take: MAX_ATTACHMENT_ROWS,
    });
  }

  /** The authentication results of the given scans (one per scan and engine). */
  authResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<AuthResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.emailAuthResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: authSelect,
      orderBy: [{ scanId: 'desc' }, { engine: 'asc' }],
    });
  }
}
