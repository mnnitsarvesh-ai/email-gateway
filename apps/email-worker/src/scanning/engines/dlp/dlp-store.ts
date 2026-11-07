import type { PrismaClient } from '@email-gateway/database';
import {
  CompiledPatternCache,
  DlpDictionarySet,
  type DlpExceptionSnapshot,
  type DlpPolicySnapshot,
  type LoadedPattern,
  loadTenantPatterns,
  type TenantDictionaryInput,
  type TenantPatternInput,
} from '@email-gateway/dlp';
import {
  DLP_DIRECTIONS,
  type DlpDirection,
  type DlpRuleConditions,
  dlpExceptionFiltersSchema,
} from '@email-gateway/security-contracts';
import { TtlLru } from '../url/url-store';
import type { DlpRead } from './dlp-metrics';

/**
 * The writer reads of the dlp engine (step 4.5 D3 steps 2–3, §6). Every read selects and
 * verifies its identifying columns (organization, message, `received_at`, direction, part order,
 * tenant ownership, enabled/expiry filters); a result that does not belong to the request throws
 * `InconsistentDlpReadError` (the Prisma 6.19 wrong-read defect, step 4.2 §6), which the engine
 * turns into the retryable attempt failure `error`/`inconsistent_read` and
 * `scan_dlp_inconsistent_reads_total{read}` — never into a verdict.
 *
 * Tenant data (policies with rules, exceptions, custom patterns compiled once per row version,
 * dictionaries in one phrase trie, the compliance row, active domains) is cached per organization
 * for DLP_TENANT_DATA_CACHE_TTL_MS (≤ 1 000 organizations): a change made through the api applies
 * within the TTL. Snapshot ids are the rows' **public ids** (UUIDv7): the stored result and the
 * incident event carry them as they are (D14, D20); the internal ids of policies and rules are
 * kept beside them for `dlp_scan_results.matched_policy_id` / `matched_rule_id`.
 */

export class InconsistentDlpReadError extends Error {
  override readonly name = 'InconsistentDlpReadError';

  constructor(
    readonly read: DlpRead,
    readonly check: string,
  ) {
    super(`inconsistent ${read} read: ${check}`);
  }
}

const sameTime = (a: unknown, b: Date): boolean => a instanceof Date && a.getTime() === b.getTime();

const parseJson = (value: unknown): unknown => {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
};

const stringList = (value: unknown, max: number): string[] => {
  const parsed = parseJson(value);
  return Array.isArray(parsed)
    ? parsed.filter((v): v is string => typeof v === 'string').slice(0, max)
    : [];
};

/** Most active tenant domains (external-recipient classification, as the bec engine). */
export const DLP_MAX_TENANT_DOMAINS = 1_000;
/** Most organizations in the tenant data LRU (D3 step 3). */
export const DLP_TENANT_CACHE_SIZE = 1_000;

export interface DlpReadScope {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  direction: DlpDirection;
}

export interface DlpMessageRow {
  subject: string | null;
  envelopeFrom: string;
  headerFrom: string | null;
  /** Recipients of the SMTP transaction (more than loaded → `rcptTruncated`, D11). */
  recipientCount: number;
}

export interface DlpBodyRef {
  key: string | null;
  sha256: string | null;
  sizeBytes: number | null;
}

export interface DlpParseRow {
  status: string;
  limitsExceeded: string[];
  attachmentCount: number | null;
  textBody: DlpBodyRef;
  htmlBody: DlpBodyRef;
}

export interface DlpAttachmentRow {
  partIndex: number;
  filename: string | null;
  declaredContentType: string | null;
  sizeBytes: number;
  sha256: string;
  objectKey: string | null;
  flags: string[];
}

/** The compliance row (D17), evaluated at use time (`aadhaar_review_due_at > now`). */
export interface DlpComplianceRow {
  aadhaarEnabled: boolean;
  aadhaarBasis: string | null;
  aadhaarReference: string | null;
  aadhaarAttested: boolean;
  aadhaarReviewDueAt: Date | null;
}

/** One organization's DLP data snapshot (D3 step 3). */
export interface DlpTenantRecord {
  tenantDomains: string[];
  policies: DlpPolicySnapshot[];
  /** Public id → internal id of every loaded policy and rule (matched_policy_id / _rule_id). */
  internalIds: Map<string, bigint>;
  exceptions: DlpExceptionSnapshot[];
  patterns: LoadedPattern[];
  /** Public ids of stored patterns that no longer validate (`dlp.custom.pattern_invalid`). */
  invalidPatterns: string[];
  dictionaries: DlpDictionarySet;
  compliance: DlpComplianceRow | null;
}

export interface DlpTenantLimits {
  policies: number;
  rulesPerPolicy: number;
  exceptions: number;
  patterns: number;
  dictionaries: number;
  dictionaryMaxTerms: number;
  patternMaxLength: number;
}

export interface DlpStore {
  loadMessage(scope: DlpReadScope): Promise<DlpMessageRow>;
  loadParse(scope: DlpReadScope): Promise<DlpParseRow | null>;
  /** At most `limit` rows ordered by part index. */
  loadAttachments(scope: DlpReadScope, limit: number): Promise<DlpAttachmentRow[]>;
  tenantData(organizationId: bigint): Promise<DlpTenantRecord>;
}

/** D17: NI2 runs only with an enabled, attested, referenced basis whose review is not due. */
export function aadhaarEnabled(row: DlpComplianceRow | null, now: Date): boolean {
  return (
    row !== null &&
    row.aadhaarEnabled &&
    row.aadhaarAttested &&
    row.aadhaarBasis !== null &&
    row.aadhaarReference !== null &&
    row.aadhaarReference.length > 0 &&
    row.aadhaarReviewDueAt !== null &&
    row.aadhaarReviewDueAt.getTime() > now.getTime()
  );
}

const directionsOf = (value: unknown): DlpDirection[] =>
  stringList(value, 3).filter((d): d is DlpDirection =>
    (DLP_DIRECTIONS as readonly string[]).includes(d),
  );

/** Prisma implementation on the **writer** (§2.0: the scan stage reads the writer only). */
export class PrismaDlpStore implements DlpStore {
  private readonly tenants: TtlLru<string, DlpTenantRecord>;
  /**
   * Compiled custom patterns per (organization, row version), kept across tenant reloads (D9).
   * The worker runs only the deterministic validation steps: the wall-clock cost probe is the
   * api's write-time gate, so the worker's own load never invalidates an accepted pattern.
   */
  private readonly patternCache = new CompiledPatternCache();
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly limits: DlpTenantLimits,
    options: { ttlMs: number; now?: () => Date; onInvalidTenantRow?: (count: number) => void },
  ) {
    this.now = options.now ?? (() => new Date());
    this.onInvalid = options.onInvalidTenantRow ?? (() => undefined);
    this.tenants = new TtlLru(DLP_TENANT_CACHE_SIZE, Math.max(0, options.ttlMs), () =>
      this.now().getTime(),
    );
  }

  private readonly onInvalid: (count: number) => void;

  async loadMessage(scope: DlpReadScope): Promise<DlpMessageRow> {
    const row = await this.prisma.emailMessage.findFirst({
      where: {
        id: scope.messageId,
        receivedAt: scope.receivedAt,
        organizationId: scope.organizationId,
      },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        subject: true,
        envelopeFrom: true,
        headerFrom: true,
        recipientCount: true,
      },
    });
    // The round service loaded this row before the call: a miss is a wrong read.
    if (!row) throw new InconsistentDlpReadError('message', 'message row absent');
    if (
      row.id !== scope.messageId ||
      row.organizationId !== scope.organizationId ||
      !sameTime(row.receivedAt, scope.receivedAt) ||
      row.direction !== scope.direction
    ) {
      throw new InconsistentDlpReadError('message', 'identity echo');
    }
    return {
      subject: row.subject,
      envelopeFrom: row.envelopeFrom,
      headerFrom: row.headerFrom,
      recipientCount: row.recipientCount,
    };
  }

  async loadParse(scope: DlpReadScope): Promise<DlpParseRow | null> {
    const row = await this.prisma.emailMessageParse.findFirst({
      where: {
        messageId: scope.messageId,
        receivedAt: scope.receivedAt,
        organizationId: scope.organizationId,
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        status: true,
        limitsExceeded: true,
        attachmentCount: true,
        textBodyObjectKey: true,
        textBodySha256: true,
        textBodySizeBytes: true,
        htmlBodyObjectKey: true,
        htmlBodySha256: true,
        htmlBodySizeBytes: true,
      },
    });
    if (!row) return null;
    if (
      row.messageId !== scope.messageId ||
      row.organizationId !== scope.organizationId ||
      !sameTime(row.receivedAt, scope.receivedAt)
    ) {
      throw new InconsistentDlpReadError('parse', 'identity echo');
    }
    return {
      status: row.status,
      limitsExceeded: stringList(row.limitsExceeded, 64),
      attachmentCount: row.attachmentCount,
      textBody: {
        key: row.textBodyObjectKey,
        sha256: row.textBodySha256,
        sizeBytes: row.textBodySizeBytes,
      },
      htmlBody: {
        key: row.htmlBodyObjectKey,
        sha256: row.htmlBodySha256,
        sizeBytes: row.htmlBodySizeBytes,
      },
    };
  }

  async loadAttachments(scope: DlpReadScope, limit: number): Promise<DlpAttachmentRow[]> {
    const rows = await this.prisma.emailAttachment.findMany({
      where: {
        messageId: scope.messageId,
        receivedAt: scope.receivedAt,
        organizationId: scope.organizationId,
      },
      orderBy: { partIndex: 'asc' },
      take: limit,
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        partIndex: true,
        filename: true,
        declaredContentType: true,
        sizeBytes: true,
        sha256: true,
        objectKey: true,
        flags: true,
      },
    });
    let previous = -1;
    for (const r of rows) {
      if (
        r.messageId !== scope.messageId ||
        r.organizationId !== scope.organizationId ||
        !sameTime(r.receivedAt, scope.receivedAt)
      ) {
        throw new InconsistentDlpReadError('attachments', 'identity echo');
      }
      if (r.partIndex <= previous) throw new InconsistentDlpReadError('attachments', 'part order');
      previous = r.partIndex;
    }
    return rows.map((r) => ({
      partIndex: r.partIndex,
      filename: r.filename,
      declaredContentType: r.declaredContentType,
      sizeBytes: r.sizeBytes,
      sha256: r.sha256,
      objectKey: r.objectKey,
      flags: stringList(r.flags, 32),
    }));
  }

  async tenantData(organizationId: bigint): Promise<DlpTenantRecord> {
    const key = organizationId.toString();
    const cached = this.tenants.get(key);
    if (cached) return cached;
    const record = await this.loadTenant(organizationId);
    this.tenants.set(key, record);
    return record;
  }

  private async loadTenant(organizationId: bigint): Promise<DlpTenantRecord> {
    const now = this.now();
    const { limits } = this;
    const [domains, policies, exceptions, patterns, dictionaries, compliance] = await Promise.all([
      this.prisma.domain.findMany({
        where: { organizationId, status: 'active', deletedAt: null },
        orderBy: { id: 'asc' },
        take: DLP_MAX_TENANT_DOMAINS,
        select: { organizationId: true, name: true, status: true, deletedAt: true },
      }),
      this.prisma.dlpPolicy.findMany({
        where: { organizationId, enabled: true },
        orderBy: { id: 'asc' },
        take: limits.policies,
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          enabled: true,
          mode: true,
          priority: true,
          directions: true,
          version: true,
          rules: {
            where: { enabled: true },
            orderBy: { id: 'asc' },
            take: limits.rulesPerPolicy,
            select: {
              id: true,
              publicId: true,
              organizationId: true,
              policyId: true,
              enabled: true,
              priority: true,
              conditions: true,
              action: true,
              version: true,
            },
          },
        },
      }),
      this.prisma.dlpException.findMany({
        where: { organizationId, enabled: true, expiresAt: { gt: now } },
        orderBy: { id: 'asc' },
        take: limits.exceptions,
        select: {
          publicId: true,
          organizationId: true,
          scope: true,
          value: true,
          policyId: true,
          ruleId: true,
          filters: true,
          expiresAt: true,
          enabled: true,
          version: true,
          policy: { select: { publicId: true, organizationId: true } },
          rule: { select: { publicId: true, organizationId: true } },
        },
      }),
      this.prisma.dlpCustomPattern.findMany({
        where: { organizationId, enabled: true },
        orderBy: { id: 'asc' },
        take: limits.patterns,
        select: {
          publicId: true,
          organizationId: true,
          enabled: true,
          pattern: true,
          caseInsensitive: true,
          validator: true,
          contextKeywords: true,
          requireContext: true,
          severity: true,
          baseConfidence: true,
          maskStyle: true,
          version: true,
        },
      }),
      this.prisma.dlpKeywordDictionary.findMany({
        where: { organizationId, enabled: true },
        orderBy: { id: 'asc' },
        take: limits.dictionaries,
        select: {
          publicId: true,
          organizationId: true,
          enabled: true,
          category: true,
          terms: true,
          severity: true,
          baseConfidence: true,
          minMatches: true,
          version: true,
        },
      }),
      this.prisma.dlpComplianceSettings.findUnique({
        where: { organizationId },
        select: {
          organizationId: true,
          aadhaarEnabled: true,
          aadhaarBasis: true,
          aadhaarReference: true,
          aadhaarAttested: true,
          aadhaarReviewDueAt: true,
        },
      }),
    ]);
    const echo = (rows: ReadonlyArray<{ organizationId: bigint }>, check: string): void => {
      if (rows.some((r) => r.organizationId !== organizationId)) {
        throw new InconsistentDlpReadError('tenant', check);
      }
    };
    echo(domains, 'domains');
    if (domains.some((d) => d.status !== 'active' || d.deletedAt !== null)) {
      throw new InconsistentDlpReadError('tenant', 'domain status');
    }
    echo(policies, 'policies');
    echo(exceptions, 'exceptions');
    echo(patterns, 'patterns');
    echo(dictionaries, 'dictionaries');
    if ([...policies, ...patterns, ...dictionaries, ...exceptions].some((r) => !r.enabled)) {
      throw new InconsistentDlpReadError('tenant', 'enabled');
    }
    if (exceptions.some((e) => e.expiresAt.getTime() <= now.getTime())) {
      throw new InconsistentDlpReadError('tenant', 'exception expiry');
    }
    if (compliance && compliance.organizationId !== organizationId) {
      throw new InconsistentDlpReadError('tenant', 'compliance');
    }

    const internalIds = new Map<string, bigint>();
    const policySnapshots: DlpPolicySnapshot[] = policies.map((p) => {
      internalIds.set(p.publicId, p.id);
      for (const r of p.rules) {
        if (r.organizationId !== organizationId || r.policyId !== p.id || !r.enabled) {
          throw new InconsistentDlpReadError('tenant', 'rule echo');
        }
        internalIds.set(r.publicId, r.id);
      }
      return {
        id: p.publicId,
        version: p.version,
        enabled: p.enabled,
        mode: p.mode,
        priority: p.priority,
        directions: directionsOf(p.directions),
        rules: p.rules.map((r) => ({
          id: r.publicId,
          version: r.version,
          enabled: r.enabled,
          priority: r.priority,
          // Re-validated by evaluateDlpPolicy (an invalid stored rule is ignored there).
          conditions: parseJson(r.conditions) as DlpRuleConditions,
          action: r.action,
        })),
      };
    });

    const exceptionSnapshots: DlpExceptionSnapshot[] = exceptions.map((e) => {
      if (
        (e.policyId !== null && (!e.policy || e.policy.organizationId !== organizationId)) ||
        (e.ruleId !== null && (!e.rule || e.rule.organizationId !== organizationId))
      ) {
        throw new InconsistentDlpReadError('tenant', 'exception target echo');
      }
      const filters = dlpExceptionFiltersSchema.safeParse(parseJson(e.filters));
      return {
        id: e.publicId,
        version: e.version,
        scope: e.scope,
        value: e.value.toLowerCase(),
        policyId: e.policy?.publicId ?? null,
        ruleId: e.rule?.publicId ?? null,
        // An unreadable filter never widens an exception: it removes nothing.
        filters:
          e.filters === null
            ? null
            : filters.success
              ? filters.data
              : { detectors: [], categories: [] },
        expiresAt: e.expiresAt,
        enabled: e.enabled,
      };
    });

    const patternInputs: TenantPatternInput[] = patterns.map((p) => ({
      id: p.publicId,
      version: p.version,
      pattern: p.pattern,
      caseInsensitive: p.caseInsensitive,
      validator: p.validator,
      contextKeywords: stringList(p.contextKeywords, 64),
      requireContext: p.requireContext,
      severity: p.severity,
      baseConfidence: Number(p.baseConfidence),
      maskStyle: p.maskStyle,
    }));
    const compiled = loadTenantPatterns(
      patternInputs,
      { maxLength: limits.patternMaxLength, costProbe: false },
      this.patternCache,
    );
    const dictionaryInputs: TenantDictionaryInput[] = dictionaries.map((d) => ({
      id: d.publicId,
      version: d.version,
      category: d.category,
      terms: stringList(d.terms, limits.dictionaryMaxTerms + 1),
      severity: d.severity,
      baseConfidence: Number(d.baseConfidence),
      minMatches: d.minMatches,
    }));
    const set = DlpDictionarySet.create(dictionaryInputs, { maxTerms: limits.dictionaryMaxTerms });
    const invalid = compiled.invalid.length + set.invalid.length;
    if (invalid > 0) this.onInvalid(invalid);

    return {
      tenantDomains: domains.map((d) => d.name.toLowerCase()),
      policies: policySnapshots,
      internalIds,
      exceptions: exceptionSnapshots,
      patterns: compiled.loaded,
      invalidPatterns: [...compiled.invalid, ...set.invalid],
      dictionaries: set,
      compliance: compliance
        ? {
            aadhaarEnabled: compliance.aadhaarEnabled,
            aadhaarBasis: compliance.aadhaarBasis,
            aadhaarReference: compliance.aadhaarReference,
            aadhaarAttested: compliance.aadhaarAttested,
            aadhaarReviewDueAt: compliance.aadhaarReviewDueAt,
          }
        : null,
    };
  }
}
