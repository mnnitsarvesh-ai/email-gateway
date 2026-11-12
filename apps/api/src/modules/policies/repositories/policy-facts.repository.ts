import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

/** Safety bound of the per-message lists (the builder caps and flags truncation itself). */
const MAX_LIST_ROWS = 5_000;

const messageSelect = {
  id: true,
  receivedAt: true,
  organizationId: true,
  direction: true,
  envelopeFrom: true,
  headerFrom: true,
  clientIp: true,
  clientName: true,
  sizeBytes: true,
  recipientCount: true,
  attachmentCount: true,
  lifecycleRound: true,
} satisfies Prisma.EmailMessageSelect;
export type FactsMessageRow = Prisma.EmailMessageGetPayload<{ select: typeof messageSelect }> & {
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
  scanVerdict: true,
  reasonCodes: true,
  requiredEngines: true,
  completedAt: true,
} satisfies Prisma.EmailScanSelect;
export type FactsScanRow = Prisma.EmailScanGetPayload<{ select: typeof scanSelect }>;

/** The stored evaluation columns `rowToEvaluationView` reads (P10; no internal ids). */
export const evaluationSelect = {
  id: true,
  receivedAt: true,
  messageId: true,
  evaluationSeq: true,
  scanId: true,
  trigger: true,
  direction: true,
  disposition: true,
  decisionSource: true,
  decisivePolicyPublicId: true,
  decisiveRuleId: true,
  action: true,
  finalVerdict: true,
  riskScore: true,
  overrideApplied: true,
  actions: true,
  matchedRules: true,
  trace: true,
  floor: true,
  recommendation: true,
  overrideDetail: true,
  clamps: true,
  reasonCodes: true,
  delivery: true,
  deliveredObject: true,
  explanation: true,
  explanationText: true,
  policyGeneration: true,
  snapshotSha256: true,
  policyVersions: true,
  platformDefaultId: true,
  dslVersion: true,
  evaluatorVersion: true,
  inputVersion: true,
  inputSha256: true,
  tzdataVersion: true,
  durationUs: true,
  evaluatedAt: true,
  // Step 5.3 (Q4): per-recipient decisions of the round (null/false for 5.2 rows).
  recipientSplit: true,
  recipientDecisions: true,
} satisfies Prisma.PolicyExecutionLogSelect;
export type EvaluationRow = Prisma.PolicyExecutionLogGetPayload<{
  select: typeof evaluationSelect;
}>;

/** The stored rows of one finished round (P8 before mapping). */
export interface RoundFactRows {
  recipients: Array<{ rcptSeq: number; address: string }>;
  finals: Array<{ engine: string; outcome: string; reasonCodes: Prisma.JsonValue }>;
  auth: {
    spf: string | null;
    dkim: string | null;
    dmarc: string | null;
    dmarcPolicy: string | null;
    arc: string | null;
  } | null;
  bec: { deterministicVerdict: string; verdict: string; rules: Prisma.JsonValue } | null;
  dlp: { action: string; verdict: string; coverage: string; categories: Prisma.JsonValue } | null;
  risk: Array<{
    revision: number;
    status: string;
    score: number;
    level: string;
    verdict: string;
    recommendedAction: string;
    hardBlocks: Prisma.JsonValue;
    reasonCodes: Prisma.JsonValue;
    failures: Prisma.JsonValue;
    engines: Prisma.JsonValue;
    evidence: Prisma.JsonValue;
  }>;
  attachments: Array<{
    partIndex: number;
    filename: string | null;
    declaredContentType: string | null;
    detectedContentType: string | null;
    sizeBytes: number;
    sha256: string;
    archiveInfo: Prisma.JsonValue;
  }>;
  attachmentResults: Array<{
    partIndex: number;
    detectedType: string;
    typeFamily: string;
    typeMismatch: boolean;
    verdict: string;
    reasonCodes: Prisma.JsonValue;
    archive: Prisma.JsonValue;
  }>;
  urls: Array<{
    urlSeq: number;
    host: string;
    registrableDomain: string | null;
    scheme: string;
    hostKind: string;
    truncated: boolean;
  }>;
  urlResults: Array<{
    urlSeq: number;
    verdict: string;
    reasonCodes: Prisma.JsonValue;
    rewritten: boolean;
  }>;
  urlRewrite: { status: string; skipReason: string | null } | null;
}

/** The active snapshot source of the organization as read from the replica (P12). */
export interface SnapshotRows {
  generation: bigint;
  settings: Prisma.JsonValue | null;
  policies: Array<{
    policyId: bigint;
    publicId: string;
    versionNo: number;
    definition: Prisma.JsonValue;
    definitionSha256: string;
  }>;
}

/** Memberships of the given normalized addresses in the referenced departments/users (P5). */
export interface DirectoryRows {
  /** `[address, departmentPublicId]` pairs (address members and active user members). */
  departmentPairs: Array<[string, string]>;
  /** `[address, userPublicId]` pairs of active, non-deleted referenced users. */
  userPairs: Array<[string, string]>;
}

/**
 * Read-only, tenant-scoped reads of the policy test and dry-run (step 5.2 P8, P12, P22, P23) on
 * the replica (`PrismaReadService`, writer fallback above the lag threshold): the organization's
 * active snapshot source, a version of a policy, the stored rows of one round (the same tables and
 * columns the policy-engine assembles `PolicyRoundRows` from), directory memberships and the
 * stored evaluation. Every query matches the scope's organization and, for message rows, the
 * message's `(message_id, received_at)`. This repository has no write method.
 */
@Injectable()
export class PolicyFactsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  // ------------------------------------------------------------------------- snapshot

  async snapshot(scope: TenantScope): Promise<SnapshotRows> {
    const [settings, policies] = await Promise.all([
      this.db.policySettings.findFirst({
        where: tenantWhere(scope),
        select: { generation: true, settings: true },
      }),
      this.db.emailPolicy.findMany({
        where: tenantWhere(scope, {
          status: 'active' as const,
          deletedAt: null,
          activeVersionId: { not: null },
        }),
        select: { id: true, publicId: true, activeVersionId: true },
        take: 1000,
      }),
    ]);
    const versions =
      policies.length === 0
        ? []
        : await this.db.policyVersion.findMany({
            where: tenantWhere(scope, {
              id: { in: policies.map((p) => p.activeVersionId!) },
              status: 'published' as const,
            }),
            select: {
              id: true,
              policyId: true,
              version: true,
              definition: true,
              definitionSha256: true,
            },
          });
    const out: SnapshotRows['policies'] = [];
    for (const p of policies) {
      const v = versions.find((x) => x.id === p.activeVersionId && x.policyId === p.id);
      if (!v) continue;
      out.push({
        policyId: p.id,
        publicId: p.publicId,
        versionNo: v.version,
        definition: v.definition,
        definitionSha256: v.definitionSha256,
      });
    }
    return {
      generation: settings?.generation ?? 0n,
      settings: settings?.settings ?? null,
      policies: out,
    };
  }

  /** A non-archived policy's version (draft or published) by number. */
  async policyVersion(
    scope: TenantScope,
    policyPublicId: string,
    versionNo: number,
  ): Promise<{
    policyId: bigint;
    publicId: string;
    status: string;
    definition: Prisma.JsonValue;
    definitionSha256: string;
  } | null> {
    const policy = await this.db.emailPolicy.findFirst({
      where: tenantWhere(scope, { publicId: policyPublicId, deletedAt: null }),
      select: { id: true, publicId: true, status: true },
    });
    if (!policy || policy.status === 'archived') return null;
    const version = await this.db.policyVersion.findFirst({
      where: tenantWhere(scope, { policyId: policy.id, version: versionNo }),
      select: { status: true, definition: true, definitionSha256: true },
    });
    if (!version) return null;
    return { policyId: policy.id, publicId: policy.publicId, ...version };
  }

  // -------------------------------------------------------------------------- directory

  /**
   * Memberships (P5) of `addresses` (normalized) in the referenced departments and users of the
   * organization: address members match their stored normalized address; user members and
   * referenced users match the user's `email` while `status = active` and not deleted.
   */
  async directory(
    scope: TenantScope,
    addresses: readonly string[],
    refs: { departmentIds: readonly string[]; userIds: readonly string[] },
  ): Promise<DirectoryRows> {
    const out: DirectoryRows = { departmentPairs: [], userPairs: [] };
    if (addresses.length === 0) return out;
    const wanted = new Set(addresses);
    const users = await this.db.user.findMany({
      where: tenantWhere(scope, {
        email: { in: [...addresses] },
        status: 'active' as const,
        deletedAt: null,
      }),
      select: { id: true, publicId: true, email: true },
      take: MAX_LIST_ROWS,
    });
    const emailOf = new Map(users.map((u) => [u.id, u.email.toLowerCase()]));
    const userRefs = new Set(refs.userIds);
    for (const u of users) {
      const email = u.email.toLowerCase();
      if (userRefs.has(u.publicId) && wanted.has(email)) out.userPairs.push([email, u.publicId]);
    }
    if (refs.departmentIds.length === 0) return out;
    const departments = await this.db.tenantDepartment.findMany({
      where: tenantWhere(scope, { publicId: { in: [...refs.departmentIds] } }),
      select: { id: true, publicId: true },
    });
    if (departments.length === 0) return out;
    const deptPublic = new Map(departments.map((d) => [d.id, d.publicId]));
    const members = await this.db.tenantDepartmentMember.findMany({
      where: tenantWhere(scope, {
        departmentId: { in: departments.map((d) => d.id) },
        OR: [
          { address: { in: [...addresses] } },
          ...(users.length > 0 ? [{ userId: { in: users.map((u) => u.id) } }] : []),
        ],
      }),
      select: { departmentId: true, address: true, userId: true },
      take: MAX_LIST_ROWS,
    });
    for (const m of members) {
      const dept = deptPublic.get(m.departmentId);
      if (dept === undefined) continue;
      const address = m.address ?? (m.userId === null ? undefined : emailOf.get(m.userId));
      if (address !== undefined && wanted.has(address)) out.departmentPairs.push([address, dept]);
    }
    return out;
  }

  // --------------------------------------------------------------------------- the round

  async message(scope: TenantScope, publicId: string): Promise<FactsMessageRow | null> {
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

  scan(scope: TenantScope, message: FactsMessageRow, scanId: bigint): Promise<FactsScanRow | null> {
    return this.db.emailScan.findFirst({
      where: tenantWhere(scope, {
        id: scanId,
        messageId: message.id,
        receivedAt: message.receivedAt,
      }),
      select: scanSelect,
    });
  }

  /** Every row the input builder reads for the round (P8): by message and by the round's scan. */
  async roundRows(
    scope: TenantScope,
    message: FactsMessageRow,
    scanId: bigint,
  ): Promise<RoundFactRows> {
    const byMessage = { messageId: message.id, receivedAt: message.receivedAt };
    const byScan = { ...byMessage, scanId };
    const [
      recipients,
      finals,
      auth,
      bec,
      dlp,
      risk,
      attachments,
      attachmentResults,
      urls,
      urlResults,
      urlRewrite,
    ] = await Promise.all([
      this.db.emailRecipient.findMany({
        where: tenantWhere(scope, byMessage),
        select: { rcptSeq: true, address: true },
        orderBy: { rcptSeq: 'asc' },
        take: MAX_LIST_ROWS,
      }),
      this.db.scanEngineResult.findMany({
        where: tenantWhere(scope, { ...byScan, isFinal: true }),
        select: { engine: true, outcome: true, reasonCodes: true },
        orderBy: { engine: 'asc' },
        take: 32,
      }),
      this.db.emailAuthResult.findFirst({
        where: tenantWhere(scope, { ...byScan, engine: 'rspamd' }),
        select: { spf: true, dkim: true, dmarc: true, dmarcPolicy: true, arc: true },
      }),
      this.db.becScanResult.findFirst({
        where: tenantWhere(scope, byScan),
        select: { deterministicVerdict: true, verdict: true, rules: true },
      }),
      this.db.dlpScanResult.findFirst({
        where: tenantWhere(scope, byScan),
        select: { action: true, verdict: true, coverage: true, categories: true },
      }),
      this.db.messageRiskScore.findMany({
        where: tenantWhere(scope, byScan),
        select: {
          revision: true,
          status: true,
          score: true,
          level: true,
          verdict: true,
          recommendedAction: true,
          hardBlocks: true,
          reasonCodes: true,
          failures: true,
          engines: true,
          evidence: true,
        },
        orderBy: { revision: 'asc' },
        take: 4,
      }),
      this.db.emailAttachment.findMany({
        where: tenantWhere(scope, byMessage),
        select: {
          partIndex: true,
          filename: true,
          declaredContentType: true,
          detectedContentType: true,
          sizeBytes: true,
          sha256: true,
          archiveInfo: true,
        },
        orderBy: { partIndex: 'asc' },
        take: MAX_LIST_ROWS,
      }),
      this.db.attachmentScanResult.findMany({
        where: tenantWhere(scope, byScan),
        select: {
          partIndex: true,
          detectedType: true,
          typeFamily: true,
          typeMismatch: true,
          verdict: true,
          reasonCodes: true,
          archive: true,
        },
        orderBy: { partIndex: 'asc' },
        take: MAX_LIST_ROWS,
      }),
      this.db.messageUrl.findMany({
        where: tenantWhere(scope, byMessage),
        select: {
          urlSeq: true,
          host: true,
          registrableDomain: true,
          scheme: true,
          hostKind: true,
          truncated: true,
        },
        orderBy: { urlSeq: 'asc' },
        take: MAX_LIST_ROWS,
      }),
      this.db.urlScanResult.findMany({
        where: tenantWhere(scope, byScan),
        select: { urlSeq: true, verdict: true, reasonCodes: true, rewritten: true },
        orderBy: { urlSeq: 'asc' },
        take: MAX_LIST_ROWS,
      }),
      this.db.urlRewrite.findFirst({
        where: tenantWhere(scope, byScan),
        select: { status: true, skipReason: true },
      }),
    ]);
    return {
      recipients,
      finals,
      auth,
      bec,
      dlp,
      risk,
      attachments,
      attachmentResults,
      urls,
      urlResults,
      urlRewrite,
    };
  }

  /** The stored evaluation of the round (by scan), if any. */
  storedEvaluation(
    scope: TenantScope,
    message: FactsMessageRow,
    scanId: bigint,
  ): Promise<EvaluationRow | null> {
    return this.db.policyExecutionLog.findFirst({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId,
      }),
      select: evaluationSelect,
      orderBy: { evaluationSeq: 'desc' },
    });
  }
}
