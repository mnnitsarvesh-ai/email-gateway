import { canonicalJson, sha256Hex } from '@email-gateway/policy-dsl';
import type { Prisma } from '@email-gateway/database';
import type { Fixtures } from './harness';

/**
 * Step API-4 helpers of the parity suite (synthetic `it-apiparity-*` organizations only): the scan
 * round rows the email-worker's detect scan commits for a copy (`email_scans`, the final engine
 * rows, the rspamd authentication row, the risk row and, optionally, the DLP row) and tenant
 * policies published as the api publishes them (version, pointer, generation + 1). Codes, enums
 * and synthetic values only.
 */

export type RiskShape = {
  verdict: 'clean' | 'spam' | 'suspicious' | 'phishing' | 'malware' | 'bec';
  level: 'none' | 'low' | 'medium' | 'high' | 'critical';
  score: number;
  recommendedAction: 'deliver' | 'tag' | 'quarantine' | 'block';
  hardBlocks?: Array<'hb.malware_attachment' | 'hb.known_phishing'>;
};

export const CLEAN_RISK: RiskShape = {
  verdict: 'clean',
  level: 'none',
  score: 20,
  recommendedAction: 'deliver',
};

/** The rows of one detect scan round (round 0) of a registry copy message; returns the scan id. */
export async function scanRound(
  fx: Fixtures,
  organizationId: bigint,
  message: { id: bigint; receivedAt: Date },
  input: {
    risk?: RiskShape;
    direction?: 'inbound' | 'outbound' | 'internal';
    dlp?: { action: 'alert' | 'require_approval' | 'quarantine' | 'block'; category: string };
  } = {},
): Promise<bigint> {
  const risk = input.risk ?? CLEAN_RISK;
  const base = { receivedAt: message.receivedAt, messageId: message.id, organizationId };
  const scan = await fx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: risk.verdict === 'clean' ? 'clean' : 'suspicious',
      requiredEngines: input.dlp ? ['rspamd', 'dlp'] : ['rspamd'],
      reasonCodes: [],
      startedAt: message.receivedAt,
      completedAt: message.receivedAt,
    },
    select: { id: true },
  });
  const engine = (engineName: string, outcome: 'clean' | 'suspicious') =>
    fx.prisma.scanEngineResult.create({
      data: {
        ...base,
        scanId: scan.id,
        engine: engineName,
        isFinal: true,
        outcome,
        durationMs: 5,
        completedAt: message.receivedAt,
        reasonCodes: [],
      },
    });
  await engine('rspamd', 'clean');
  await fx.prisma.emailAuthResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'rspamd',
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      arc: 'none',
    },
  });
  if (input.dlp) {
    await engine('dlp', 'suspicious');
    await fx.prisma.dlpScanResult.create({
      data: {
        ...base,
        scanId: scan.id,
        lifecycleRound: 0,
        direction: input.direction ?? 'inbound',
        engineVersion: 'dlp/it',
        rulesVersion: 'r1',
        settingsVersion: 's1',
        policyVersion: 'p1',
        extractorVersion: 'x1',
        verdict: 'suspicious',
        action: input.dlp.action,
        actionSource: 'default_policy',
        coverage: 'complete',
        coverageDetail: {},
        categories: [{ category: input.dlp.category, maxSeverity: 'high' }],
        findings: [],
        policy: {},
        findingCount: 1,
        evidenceStatus: 'none',
        durationMs: 3,
      },
    });
  }
  const hardBlocks = [...(risk.hardBlocks ?? [])].sort().map((id) => ({ id, action: 'block' }));
  await fx.prisma.messageRiskScore.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      revision: 0,
      direction: input.direction ?? 'inbound',
      status: 'scored',
      score: risk.score,
      level: risk.level,
      verdict: risk.verdict,
      recommendedAction: risk.recommendedAction,
      hardBlocks,
      reasonCodes: hardBlocks.length > 0 ? ['attachment.malware_signature'] : [],
      contributions: [],
      groups: {},
      engines: [{ engine: 'rspamd', status: 'definite', outcome: 'clean' }],
      failures: [],
      floors: [],
      trust: {},
      evidence: { aiRaiseOnly: false },
      explanation: [],
      explanationText: '',
      profileSource: 'platform',
      profileIdText: 'rsk-default/1',
      profileSha256: '0'.repeat(64),
      inputSha256: '0'.repeat(64),
      scorerVersion: 'risk/1',
      signalMapVersion: 'map/1',
      inputVersion: 'risk-input/1',
      durationUs: 10,
    },
  });
  return scan.id;
}

/** A `policy-dsl/1` document (direction, priority, rules). */
export const policyDoc = (direction: string, rules: unknown[], priority = 100) => ({
  dslVersion: 'policy-dsl/1',
  direction,
  priority,
  rules,
});

/** A rule matching every message of a direction. */
export const ruleFor = (
  direction: 'inbound' | 'outbound' | 'internal',
  id: string,
  actions: unknown[],
  extra: Record<string, unknown> = {},
) => ({
  id,
  priority: 10,
  when: { field: 'direction', op: 'equals', value: direction },
  actions,
  ...extra,
});

/**
 * A tenant policy published as the api does (5.2): the policy row (one per name), a published
 * version with the canonical hash, the pointer, and `policy_settings.generation + 1`, in one
 * transaction. `settings` (e.g. `{ alerts: { enabled: true } }`) replaces the policy settings.
 */
export async function publishPolicy(
  fx: Fixtures,
  organizationId: bigint,
  name: string,
  doc: ReturnType<typeof policyDoc>,
  settings: Record<string, unknown> = {},
): Promise<{ publicId: string; versionNo: number }> {
  return fx.prisma.$transaction(async (tx) => {
    const settingsJson = settings as Prisma.InputJsonValue;
    const row = await tx.policySettings.upsert({
      where: { organizationId },
      create: {
        organizationId,
        generation: 0,
        settings: settingsJson,
        settingsSha256: sha256Hex(canonicalJson(settings)),
      },
      update: { settings: settingsJson, settingsSha256: sha256Hex(canonicalJson(settings)) },
    });
    const policy =
      (await tx.emailPolicy.findFirst({ where: { organizationId, name } })) ??
      (await tx.emailPolicy.create({
        data: {
          organizationId,
          name,
          direction: doc.direction as 'inbound',
          priority: doc.priority,
          status: 'draft',
        },
      }));
    const last = await tx.policyVersion.aggregate({
      where: { policyId: policy.id },
      _max: { version: true },
    });
    const versionNo = (last._max.version ?? 0) + 1;
    const version = await tx.policyVersion.create({
      data: {
        organizationId,
        policyId: policy.id,
        version: versionNo,
        status: 'published',
        definition: doc as unknown as Prisma.InputJsonValue,
        definitionSha256: sha256Hex(canonicalJson(doc)),
        dslVersion: 'policy-dsl/1',
        references: { departmentIds: [], userIds: [] },
        ruleCount: doc.rules.length,
        publishedAt: new Date(),
      },
    });
    await tx.emailPolicy.update({
      where: { id: policy.id },
      data: { activeVersionId: version.id, status: 'active', rowVersion: { increment: 1 } },
    });
    await tx.policySettings.update({
      where: { id: row.id },
      data: { generation: { increment: 1 }, rowVersion: { increment: 1 } },
    });
    return { publicId: policy.publicId, versionNo };
  });
}

/** Deactivates every tenant policy of an organization (generation + 1). */
export async function clearPolicies(fx: Fixtures, organizationId: bigint): Promise<void> {
  await fx.prisma.$transaction(async (tx) => {
    await tx.emailPolicy.updateMany({
      where: { organizationId },
      data: { status: 'disabled' as never, rowVersion: { increment: 1 } },
    });
    await tx.policySettings.updateMany({
      where: { organizationId },
      data: { generation: { increment: 1 }, rowVersion: { increment: 1 } },
    });
  });
}
