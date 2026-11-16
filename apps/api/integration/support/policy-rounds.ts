/**
 * Stored rounds and evaluations for the policy suites (step 7.3, integration/policy-builder.test.ts):
 * a completed round of a lifecycle message (Rspamd clean final, authentication row and the
 * revision-0 risk row as the email-worker writes them), the organization's active snapshot read
 * on the writer (the policy-engine's view) and the stored evaluation of a round as the engine
 * writes it (`evaluatePolicyPerRecipient` → `evaluationResultToRow` + `perRecipientToRowFields`).
 * The same construction as integration/policies.test.ts (step 5.2); rows are inserted on the
 * writer. Test code only.
 */
import { createHash } from 'node:crypto';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicyPerRecipient,
  evaluationResultToRow,
  type PerRecipientEvaluation,
  type PolicyRoundRows,
  type PolicySnapshotSource,
  perRecipientToRowFields,
} from '@email-gateway/policy-dsl';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import type { IntegrationApp } from './app';
import type { FixtureOrganization } from './fixtures';
import type { LifecycleMessage } from './lifecycle';

export interface InsertedRound {
  scanId: bigint;
  round: number;
  completedAt: Date;
  rows: (directory: PolicyRoundRows['directory']) => PolicyRoundRows;
}

/** A completed round `round` of `message` (scan, Rspamd final, auth, revision-0 risk). */
export async function insertCleanRound(
  ctx: IntegrationApp,
  message: LifecycleMessage,
  round = 0,
): Promise<InsertedRound> {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000 + round * 10_000);
  const completedAt = new Date(startedAt.getTime() + 2_000);
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const scanKind = round === 0 ? ('initial' as const) : ('rescan' as const);
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind,
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
  const final = await ctx.prisma.scanEngineResult.findFirstOrThrow({
    where: { scanId: scan.id, isFinal: true },
  });
  const msg = await ctx.prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
  });
  const risk = scoreRisk(
    buildScoringInput(
      {
        scan: { requiredEngines: ['rspamd'], scanKind, lifecycleRound: round, status: 'completed' },
        message: {
          direction: msg.direction,
          attachmentCount: 0,
          recipientCount: msg.recipientCount,
        },
        finals: [
          {
            engine: final.engine,
            outcome: final.outcome,
            errorCode: final.errorCode,
            reasonCodes: final.reasonCodes,
            score: final.score === null ? null : final.score.toString(),
            engineVersion: final.engineVersion,
            settingsVersion: final.settingsVersion,
            attempt: final.attempt,
            completedAt: final.completedAt,
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
  const riskJson = riskResultToRowJson(risk);
  await ctx.prisma.messageRiskScore.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: round,
      revision: 0,
      direction: msg.direction,
      ...riskJson,
      explanation: risk.explanation.lines,
      profileVersionId: null,
      durationUs: 250,
    },
  });
  const recipients = await ctx.prisma.emailRecipient.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { rcptSeq: 'asc' },
  });
  const rows = (directory: PolicyRoundRows['directory']): PolicyRoundRows => ({
    trigger: 'scanned',
    message: {
      direction: msg.direction,
      envelopeFrom: msg.envelopeFrom,
      headerFrom: msg.headerFrom,
      clientIp: msg.clientIp,
      clientName: msg.clientName,
      sizeBytes: msg.sizeBytes,
      recipientCount: msg.recipientCount,
      attachmentCount: msg.attachmentCount,
      lifecycleRound: round,
    },
    recipients: recipients.map((r) => ({ rcptSeq: r.rcptSeq, address: r.address })),
    scan: {
      scanId: scan.id,
      lifecycleRound: round,
      scanKind,
      status: 'completed',
      scanVerdict: 'clean',
      reasonCodes: [],
      requiredEngines: ['rspamd'],
      completedAt,
    },
    parseFailedAt: null,
    finals: [{ engine: 'rspamd', outcome: 'clean', reasonCodes: [] }],
    auth,
    bec: null,
    dlp: null,
    risk: [{ revision: 0, ...riskJson }],
    attachments: [],
    attachmentResults: [],
    urls: [],
    urlResults: [],
    urlRewrite: null,
    directory,
  });
  return { scanId: scan.id, round, completedAt, rows };
}

/** The active snapshot source of the organization (writer) and its version ids by `<id>#<no>`. */
export interface WriterSnapshot extends PolicySnapshotSource {
  ids: Record<string, string>;
}

/** The active snapshot source of the organization read on the writer (the engine's view). */
export async function writerSnapshot(
  ctx: IntegrationApp,
  org: FixtureOrganization,
): Promise<WriterSnapshot> {
  const settings = await ctx.prisma.policySettings.findFirst({ where: { organizationId: org.id } });
  const policies = await ctx.prisma.emailPolicy.findMany({
    where: {
      organizationId: org.id,
      status: 'active',
      deletedAt: null,
      activeVersionId: { not: null },
    },
  });
  const versions = await ctx.prisma.policyVersion.findMany({
    where: { id: { in: policies.map((p) => p.activeVersionId!) }, status: 'published' },
  });
  const active = policies.flatMap((p) => {
    const v = versions.find((x) => x.id === p.activeVersionId);
    return v ? [{ policy: p, version: v }] : [];
  });
  return {
    generation: (settings?.generation ?? 0n).toString(),
    settings: settings?.settings ?? null,
    platformDefaultId: 'pol-default/1',
    policies: active.map(({ policy, version }) => ({
      publicId: policy.publicId,
      versionNo: version.version,
      definition: version.definition,
      definitionSha256: version.definitionSha256,
    })),
    ids: Object.fromEntries(
      active.map(({ policy, version }) => [
        `${policy.publicId}#${version.version}`,
        version.id.toString(),
      ]),
    ),
  };
}

/**
 * Evaluates the round under the organization's active snapshot (writer) and stores the
 * evaluation exactly as the policy-engine maps it; returns the evaluation.
 */
export async function storeEvaluation(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  message: LifecycleMessage,
  round: InsertedRound,
): Promise<PerRecipientEvaluation> {
  const snap = await writerSnapshot(ctx, org);
  const evaluation = evaluatePolicyPerRecipient(
    buildPolicyInput(round.rows({ departmentsByAddress: {}, usersByAddress: {} })),
    compileSnapshot(snap),
  );
  const json = evaluationResultToRow(evaluation.message, { policyVersionIds: snap.ids });
  const split = perRecipientToRowFields(evaluation);
  await ctx.prisma.policyExecutionLog.create({
    data: {
      ...json,
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: org.id,
      scanId: BigInt(json.scanId!),
      decisivePolicyVersionId:
        json.decisivePolicyVersionId === null ? null : BigInt(json.decisivePolicyVersionId),
      policyGeneration: BigInt(json.policyGeneration),
      delivery: json.delivery ?? undefined,
      overrideDetail: json.overrideDetail ?? undefined,
      recipientSplit: split.recipientSplit,
      recipientDecisions: split.recipientDecisions ?? undefined,
      durationUs: 300,
      evaluatedAt: round.completedAt,
    } as never,
  });
  return evaluation;
}

const sha = (rows: unknown) =>
  createHash('sha256')
    .update(JSON.stringify(rows, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)))
    .digest('hex');

/**
 * Checksums of every table a validation or dry-run could write for one organization: the policy
 * tables, the stored evaluations, the audit log, the idempotency keys and the outbox count.
 */
export async function policyChecksums(ctx: IntegrationApp, org: FixtureOrganization) {
  const where = { organizationId: org.id };
  const orderBy = { id: 'asc' as const };
  return {
    policies: sha(await ctx.prisma.emailPolicy.findMany({ where, orderBy })),
    versions: sha(await ctx.prisma.policyVersion.findMany({ where, orderBy })),
    settings: sha(await ctx.prisma.policySettings.findMany({ where, orderBy })),
    evaluations: sha(await ctx.prisma.policyExecutionLog.findMany({ where, orderBy })),
    audit: sha(await ctx.prisma.auditLog.findMany({ where, orderBy })),
    idempotency: sha(await ctx.prisma.apiIdempotencyKey.findMany({ where, orderBy })),
    outbox: await ctx.prisma.messageOutbox.count({ where }),
  };
}
