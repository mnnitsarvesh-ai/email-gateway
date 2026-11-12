/**
 * Fixtures of the step 5.3 quarantine suites (WP4; reusable by WP5): quarantine entries as the
 * policy-engine writes them (§3 columns, never `subject`), a completed scan round with its risk
 * row (as integration/policies.test.ts builds it), decoded parts and the EML in MinIO, the
 * quarantine routes as one caller, and the cleanup of everything a suite inserted (quarantine
 * tables through the tenant purge, message rows, scan rows, outbox rows, S3 objects).
 */
import { createHash, randomUUID } from 'node:crypto';
import type {
  MessageDirection,
  Prisma,
  QuarantineEntryKind,
  QuarantineReason,
  QuarantineStatus,
  RiskLevel,
} from '@email-gateway/database';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import type { Test } from 'supertest';
import { systemScope } from '../../src/auth-contracts/tenant-scope';
import { QuarantineTenantDataRepository } from '../../src/modules/tenant-data/quarantine-tenant-data.repository';
import type { IntegrationApp } from './app';
import { uniqueIp } from './http';
import { deleteLifecycleFixtures, type LifecycleMessage } from './lifecycle';
import { mailBucketClient, s3Commands } from './probe-cleanup';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

export interface EntryOptions {
  rcptSeq?: number;
  state?: QuarantineStatus;
  kind?: QuarantineEntryKind;
  reason?: QuarantineReason;
  riskLevel?: RiskLevel | null;
  riskScore?: number | null;
  hardBlocks?: string[];
  direction?: MessageDirection;
  recipientAddress?: string;
  userId?: bigint | null;
  envelopeFrom?: string;
  quarantinedAt?: Date;
  decisivePolicyPublicId?: string | null;
  hasAttachments?: boolean;
  approvalRequestId?: bigint | null;
  lifecycleRound?: number;
}

export interface FixtureEntry {
  id: bigint;
  publicId: string;
}

/** One `quarantine_messages` row of the message (the policy-engine's column set, §3). */
export async function insertEntry(
  ctx: IntegrationApp,
  message: LifecycleMessage,
  o: EntryOptions = {},
): Promise<FixtureEntry> {
  const rcptSeq = o.rcptSeq ?? 0;
  const recipient = await ctx.prisma.emailRecipient.findFirst({
    where: { messageId: message.id, receivedAt: message.receivedAt, rcptSeq },
    select: { id: true, address: true },
  });
  const quarantinedAt = o.quarantinedAt ?? new Date(message.receivedAt.getTime() + 5_000);
  const hardBlocks = o.hardBlocks ?? [];
  const row = await ctx.prisma.quarantineMessage.create({
    data: {
      organizationId: message.organizationId,
      messageId: message.id,
      messageReceivedAt: message.receivedAt,
      lifecycleRound: o.lifecycleRound ?? 0,
      recipientId: recipient?.id ?? BigInt(900_000 + rcptSeq),
      rcptSeq,
      recipientAddress: (
        o.recipientAddress ??
        recipient?.address ??
        'alice@acme.example'
      ).toLowerCase(),
      userId: o.userId ?? null,
      direction: o.direction ?? 'inbound',
      kind: o.kind ?? 'quarantine',
      origin: 'policy',
      reason: o.reason ?? 'spam',
      status: o.state ?? 'held',
      envelopeFrom: o.envelopeFrom ?? `sender-${message.organizationId.toString()}@fixture.example`,
      headerFrom: null,
      hasAttachments: o.hasAttachments ?? false,
      attachmentCount: o.hasAttachments === true ? 1 : 0,
      sizeBytes: 512,
      riskScore: o.riskScore === undefined ? 120 : o.riskScore,
      riskLevel: o.riskLevel === undefined ? 'low' : o.riskLevel,
      recommendedAction: 'tag',
      riskVerdict: 'spam',
      hasHardBlock: hardBlocks.length > 0,
      hardBlocks,
      reasonCodes: ['policy.disposition.quarantine'],
      floorReasons: hardBlocks.length > 0 ? ['hard_block'] : [],
      primaryEngine: hardBlocks.length > 0 ? 'attachment' : 'rspamd',
      decisionSource: o.decisivePolicyPublicId ? 'tenant_rule' : 'platform_default',
      decisivePolicyPublicId: o.decisivePolicyPublicId ?? null,
      decisivePolicyVersionNo: o.decisivePolicyPublicId ? 1 : null,
      decisiveRuleId: o.decisivePolicyPublicId ? 'r1' : null,
      explanation: [{ code: 'summary', params: { disposition: 'quarantine' } }],
      explanationText: 'Final disposition quarantine (fixture).',
      emlObjectKey: message.emlObjectKey,
      quarantinedAt,
      expiresAt: new Date(quarantinedAt.getTime() + 30 * 86_400_000),
      stateChangedAt: quarantinedAt,
      approvalRequestId: o.approvalRequestId ?? null,
    },
    select: { id: true, publicId: true },
  });
  return row;
}

/** A pending approval request of the entry (as the policy-engine / a release writes it). */
export async function insertApproval(
  ctx: IntegrationApp,
  entry: FixtureEntry,
  organizationId: bigint,
  o: {
    kind?: 'policy_review' | 'release_approval' | 'release_request';
    reasons?: string[];
    requestedByUserId?: bigint | null;
    expiresAt?: Date;
  } = {},
): Promise<{ id: bigint; publicId: string }> {
  const approval = await ctx.prisma.quarantineApprovalRequest.create({
    data: {
      organizationId,
      quarantineMessageId: entry.id,
      kind: o.kind ?? 'release_request',
      approvalReasons: o.reasons ?? [],
      requestedByType: o.requestedByUserId ? 'user' : 'system',
      requestedByUserId: o.requestedByUserId ?? null,
      expiresAt: o.expiresAt ?? new Date(Date.now() + 86_400_000),
    },
    select: { id: true, publicId: true },
  });
  await ctx.prisma.quarantineMessage.update({
    where: { id: entry.id },
    data: { status: 'pending_approval', approvalRequestId: approval.id },
  });
  return approval;
}

/**
 * A completed round of the message (rspamd clean final, authentication row, the revision-0
 * risk row computed by `@email-gateway/risk-scoring`), completed `completedAgoMs` ago.
 */
export async function insertCompletedRound(
  ctx: IntegrationApp,
  message: LifecycleMessage,
  o: { round?: number; completedAgoMs?: number } = {},
): Promise<{ scanId: bigint }> {
  const round = o.round ?? 0;
  const completedAt = new Date(Date.now() - (o.completedAgoMs ?? 60_000));
  const startedAt = new Date(completedAt.getTime() - 2_000);
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: round === 0 ? 'initial' : 'rescan',
      status: 'completed',
      lifecycleRound: round,
      scanVerdict: 'clean',
      requiredEngines: ['rspamd'],
      reasonCodes: [],
      startedAt,
      completedAt,
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'rspamd',
      engineVersion: '3.13.2',
      outcome: 'clean',
      score: 1.5,
      requiredScore: 15,
      durationMs: 120,
      attempt: 1,
      isFinal: true,
      reasonCodes: [],
      settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
      evidence: { signals: [] },
      completedAt,
    },
  });
  const auth = {
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    dmarcPolicy: 'reject',
    arc: 'none',
  } as const;
  await ctx.prisma.emailAuthResult.create({
    data: { ...base, scanId: scan.id, engine: 'rspamd', ...auth },
  });
  const msg = await ctx.prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
  });
  const risk = scoreRisk(
    buildScoringInput(
      {
        scan: {
          requiredEngines: ['rspamd'],
          scanKind: round === 0 ? 'initial' : 'rescan',
          lifecycleRound: round,
          status: 'completed',
        },
        message: {
          direction: msg.direction,
          attachmentCount: 0,
          recipientCount: msg.recipientCount,
        },
        finals: [
          {
            engine: 'rspamd',
            outcome: 'clean',
            errorCode: null,
            reasonCodes: [],
            score: '1.5',
            engineVersion: '3.13.2',
            settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
            attempt: 1,
            completedAt,
          },
        ],
        auth,
        bec: null,
        dlp: null,
      },
      0,
    ),
    platformProfile('rsk-default/1'),
  );
  await ctx.prisma.messageRiskScore.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: round,
      revision: 0,
      direction: msg.direction,
      ...riskResultToRowJson(risk),
      explanation: risk.explanation.lines,
      profileVersionId: null,
      durationUs: 250,
    },
  });
  return { scanId: scan.id };
}

/** Writes an object to the mail bucket (MinIO) and records it for cleanup. */
export async function putObject(
  objects: string[],
  key: string,
  body: Buffer | string,
): Promise<void> {
  const { s3, bucket } = mailBucketClient();
  try {
    await s3.send(
      new (s3Commands().PutObjectCommand)({ Bucket: bucket, Key: key, Body: body as never }),
    );
    objects.push(key);
  } finally {
    s3.destroy();
  }
}

export async function deleteObjects(objects: string[]): Promise<void> {
  const { s3, bucket } = mailBucketClient();
  try {
    for (const key of objects.splice(0)) {
      await s3.send(new (s3Commands().DeleteObjectCommand)({ Bucket: bucket, Key: key }));
    }
  } finally {
    s3.destroy();
  }
}

/** The parse row of the message with its decoded text/html part keys (step 3.1 columns). */
export async function insertParse(
  ctx: IntegrationApp,
  message: LifecycleMessage,
  parts: { textKey?: string | null; htmlKey?: string | null; textSize?: number; htmlSize?: number },
): Promise<void> {
  await ctx.prisma.emailMessageParse.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      status: 'parsed',
      parserVersion: 'fixture/1',
      textBodyObjectKey: parts.textKey ?? null,
      htmlBodyObjectKey: parts.htmlKey ?? null,
      textBodySizeBytes: parts.textSize ?? null,
      htmlBodySizeBytes: parts.htmlSize ?? null,
      startedAt: message.receivedAt,
      completedAt: message.receivedAt,
    },
  });
}

/** Everything the quarantine suites inserted for the organizations (writer). */
export async function deleteQuarantineFixtures(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<void> {
  const where = { organizationId: { in: [...organizationIds] } };
  const p = ctx.prisma;
  await p.archiveLegalHold.deleteMany({ where });
  const purge = ctx.get(QuarantineTenantDataRepository);
  for (const id of organizationIds) await purge.purgeOrganization(systemScope(id));
  await p.messageOutbox.deleteMany({ where: { ...where, aggregateType: 'quarantine' } });
  await p.archiveRetentionPolicy.deleteMany({ where });
  await p.archiveSetting.deleteMany({ where });
  await p.emailArchive.deleteMany({ where });
  await p.messageRiskScore.deleteMany({ where });
  await p.emailAuthResult.deleteMany({ where });
  await p.scanEngineResult.deleteMany({ where });
  await p.attachmentScanResult.deleteMany({ where });
  await p.urlScanResult.deleteMany({ where });
  await p.messageUrl.deleteMany({ where });
  await p.emailAttachment.deleteMany({ where });
  await p.emailHeader.deleteMany({ where });
  await p.policyExecutionLog.deleteMany({ where });
  await p.emailScan.deleteMany({ where });
  await deleteLifecycleFixtures(ctx, organizationIds);
}

/** The quarantine routes as one caller (each request from its own client IP). */
export class QuarantineApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  get(path: string, query: Record<string, string> = {}): Test {
    return this.ctx.http
      .get(`/api/v1/quarantine${path}`)
      .query(query)
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
  }

  post(path: string, body: unknown, key: string | null = `it-${randomUUID()}`): Test {
    const req = this.ctx.http
      .post(`/api/v1/quarantine${path}`)
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
    if (key !== null) req.set('Idempotency-Key', key);
    return req.send(body as object);
  }

  put(path: string, body: unknown): Test {
    return this.ctx.http
      .put(`/api/v1/quarantine${path}`)
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp())
      .send(body as object);
  }
}

/** A search window around now (bounded range of Q9). */
export function windowAround(now = Date.now()): { from: string; to: string } {
  return {
    from: new Date(now - 7 * 86_400_000).toISOString(),
    to: new Date(now + 86_400_000).toISOString(),
  };
}

export const fixtureSha = sha;
export type { Prisma };
