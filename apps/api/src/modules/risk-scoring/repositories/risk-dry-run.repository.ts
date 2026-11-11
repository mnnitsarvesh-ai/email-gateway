import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

const messageSelect = {
  id: true,
  receivedAt: true,
  organizationId: true,
  direction: true,
  attachmentCount: true,
  recipientCount: true,
} satisfies Prisma.EmailMessageSelect;

export type DryRunMessageRow = Prisma.EmailMessageGetPayload<{ select: typeof messageSelect }> & {
  publicId: string;
};

const scanSelect = {
  id: true,
  messageId: true,
  receivedAt: true,
  organizationId: true,
  lifecycleRound: true,
  scanKind: true,
  status: true,
  requiredEngines: true,
  riskProfileVersionId: true,
} satisfies Prisma.EmailScanSelect;

export type DryRunScanRow = Prisma.EmailScanGetPayload<{ select: typeof scanSelect }>;

/** The columns of a final the scorer's input reads (R12), as the email-worker reads them. */
const finalSelect = {
  engine: true,
  outcome: true,
  errorCode: true,
  reasonCodes: true,
  score: true,
  engineVersion: true,
  settingsVersion: true,
  attempt: true,
  completedAt: true,
} satisfies Prisma.ScanEngineResultSelect;

export type DryRunFinalRow = Prisma.ScanEngineResultGetPayload<{ select: typeof finalSelect }>;

const authSelect = {
  spf: true,
  dkim: true,
  dmarc: true,
  dmarcPolicy: true,
  arc: true,
} satisfies Prisma.EmailAuthResultSelect;

export type DryRunAuthRow = Prisma.EmailAuthResultGetPayload<{ select: typeof authSelect }>;

const becSelect = {
  deterministicVerdict: true,
  verdict: true,
  rules: true,
} satisfies Prisma.BecScanResultSelect;

export type DryRunBecRow = Prisma.BecScanResultGetPayload<{ select: typeof becSelect }>;

const dlpSelect = {
  action: true,
  verdict: true,
  coverage: true,
  categories: true,
} satisfies Prisma.DlpScanResultSelect;

export type DryRunDlpRow = Prisma.DlpScanResultGetPayload<{ select: typeof dlpSelect }>;

const storedSelect = {
  revision: true,
  score: true,
  level: true,
  recommendedAction: true,
  inputSha256: true,
  profileSha256: true,
} satisfies Prisma.MessageRiskScoreSelect;

export type DryRunStoredRow = Prisma.MessageRiskScoreGetPayload<{ select: typeof storedSelect }>;

/** The round's row set of the dry-run (R12 `RoundRows` before mapping). */
export interface DryRunRows {
  finals: DryRunFinalRow[];
  auth: DryRunAuthRow | null;
  bec: DryRunBecRow | null;
  dlp: DryRunDlpRow | null;
}

/**
 * Read-only, tenant-scoped reads of the dry-run (step 5.1 R12, R15) on the replica
 * (`PrismaReadService`, writer fallback above the lag threshold). It reads exactly the rows and
 * columns the email-worker scores in the completion transaction, so a dry-run with the round's
 * profile reproduces the stored `input_sha256`. Every query matches the scope's organization
 * and the message's `(message_id, received_at)`; this repository has no write method.
 */
@Injectable()
export class RiskDryRunRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  async message(scope: TenantScope, publicId: string): Promise<DryRunMessageRow | null> {
    const identity = await this.db.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true },
    });
    if (!identity) return null;
    const message = await this.db.emailMessage.findFirst({
      where: tenantWhere(scope, { id: identity.id, receivedAt: identity.receivedAt }),
      select: messageSelect,
    });
    return message ? { ...message, publicId: identity.publicId } : null;
  }

  scan(
    scope: TenantScope,
    message: DryRunMessageRow,
    scanId: bigint,
  ): Promise<DryRunScanRow | null> {
    return this.db.emailScan.findFirst({
      where: tenantWhere(scope, {
        id: scanId,
        messageId: message.id,
        receivedAt: message.receivedAt,
      }),
      select: scanSelect,
    });
  }

  /** The final engine rows, the rspamd authentication row and the BEC and DLP results. */
  async roundRows(
    scope: TenantScope,
    message: DryRunMessageRow,
    scanId: bigint,
  ): Promise<DryRunRows> {
    const key = { messageId: message.id, receivedAt: message.receivedAt, scanId };
    const [finals, auth, bec, dlp] = await Promise.all([
      this.db.scanEngineResult.findMany({
        where: tenantWhere(scope, { ...key, isFinal: true }),
        select: finalSelect,
        orderBy: { engine: 'asc' },
        take: 16,
      }),
      this.db.emailAuthResult.findFirst({
        where: tenantWhere(scope, { ...key, engine: 'rspamd' }),
        select: authSelect,
      }),
      this.db.becScanResult.findFirst({ where: tenantWhere(scope, key), select: becSelect }),
      this.db.dlpScanResult.findFirst({ where: tenantWhere(scope, key), select: dlpSelect }),
    ]);
    return { finals, auth, bec, dlp };
  }

  /** The stored score of `revision` of the round, if any. */
  storedScore(
    scope: TenantScope,
    message: DryRunMessageRow,
    scanId: bigint,
    revision: 0 | 1,
  ): Promise<DryRunStoredRow | null> {
    return this.db.messageRiskScore.findFirst({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId,
        revision,
      }),
      select: storedSelect,
    });
  }
}
