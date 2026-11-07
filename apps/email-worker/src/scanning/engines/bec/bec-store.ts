import type { PrismaClient } from '@email-gateway/database';
import type {
  BecHeaders,
  ExecutiveProfile,
  HistoryInfraEntry,
  HistoryRow,
  SuppressionRule,
  TrustedSender,
  VendorProfile,
} from '@email-gateway/bec';
import type { AuthResultRow } from '@email-gateway/bec';
import type { BecRead } from './bec-metrics';
import { TtlLru } from '../url/url-store';

/**
 * The writer reads of the bec engine (step 4.4 B4 steps 2–3, B12, §6). Every read selects and
 * verifies its identifying columns (organization, message, `received_at`, `scan_id`, scope and
 * key hash where applicable); a result that does not belong to the request throws
 * `InconsistentBecReadError` (the Prisma 6.19 wrong-read defect, step 4.2 §6), which the engine
 * turns into the retryable attempt failure `error`/`inconsistent_read` and
 * `scan_bec_inconsistent_reads_total{read}` — never into a verdict.
 */

export class InconsistentBecReadError extends Error {
  override readonly name = 'InconsistentBecReadError';

  constructor(
    readonly read: BecRead,
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

/** A bounded string array of a JSON column (non-strings dropped). */
export const stringList = (value: unknown, max: number): string[] => {
  const parsed = parseJson(value);
  return Array.isArray(parsed)
    ? parsed.filter((v): v is string => typeof v === 'string').slice(0, max)
    : [];
};

/** Most stored headers read per message (step 3.1 MIME_MAX_STORED_HEADERS ≤ 500; B4: ≤ 200). */
export const BEC_MAX_HEADERS = 200;
/** Most URL results read per round (U4 ≤ 200 per message). */
export const BEC_MAX_URL_RESULTS = 200;
/** Most active tenant domains used as protected entries (as the url engine). */
export const BEC_MAX_TENANT_DOMAINS = 1_000;
/** Most organizations in the tenant data LRU (B4 step 3). */
export const BEC_TENANT_CACHE_SIZE = 1_000;

/** The ids every read of one engine call is scoped by (trusted context, never headers). */
export interface BecReadScope {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  scanId: bigint;
  round: number;
}

export interface BecRoundRow {
  round: number;
  scanKind: 'initial' | 'rescan';
  requiredEngines: string[];
}

export interface BecFinalRow {
  engine: string;
  outcome: string;
}

export interface BecBodyRef {
  key: string | null;
  sha256: string | null;
  sizeBytes: number | null;
}

export interface BecParseRow {
  status: string;
  limitsExceeded: string[];
  /** The step 3.1 parse defects (bounded); `stored_headers_truncated` marks an incomplete header set. */
  defects: string[];
  textBody: BecBodyRef;
  htmlBody: BecBodyRef;
}

export interface BecUrlResultRow {
  urlSeq: number;
  verdict: 'clean' | 'unknown' | 'suspicious' | 'malicious';
  reasonCodes: string[];
  host: string | null;
  registrableDomain: string | null;
}

/** Tenant data of one organization (B4 step 3), cached per organization. */
export interface BecTenantRecord {
  tenantDomains: string[];
  executives: ExecutiveProfile[];
  vendors: VendorProfile[];
  trustedSenders: TrustedSender[];
  suppressions: SuppressionRule[];
  /** The url engine's tenant settings row (`scan_engine_settings`, engine `url`), or null. */
  urlSettingsRow: { settings: unknown; version: number } | null;
}

export interface BecTenantLimits {
  executives: number;
  vendors: number;
  trustedSenders: number;
  suppressions: number;
}

export interface BecHistoryRead {
  keyHash: string;
  row: HistoryRow;
}

/** The stored top-level headers of a message, grouped by name in `seq` order. */
export interface BecHeaderRead {
  headers: BecHeaders;
  /** More than BEC_MAX_HEADERS rows are stored: the rows after the cap were not read. */
  truncated: boolean;
}

export interface BecStore {
  loadRound(scope: BecReadScope): Promise<BecRoundRow | null>;
  loadFinals(scope: BecReadScope, engines: readonly string[]): Promise<BecFinalRow[]>;
  loadAuth(scope: BecReadScope, engine: string): Promise<AuthResultRow | null>;
  loadUrlResults(scope: BecReadScope): Promise<BecUrlResultRow[]>;
  loadHeaders(scope: BecReadScope): Promise<BecHeaderRead>;
  loadParse(scope: BecReadScope): Promise<BecParseRow | null>;
  loadSubject(scope: BecReadScope): Promise<string | null>;
  tenantData(organizationId: bigint): Promise<BecTenantRecord>;
  loadHistory(
    organizationId: bigint,
    scope: 'sender' | 'pair',
    keyHashes: readonly string[],
  ): Promise<BecHistoryRead[]>;
}

const AUTH_OUTCOMES = new Set([
  'pass',
  'fail',
  'softfail',
  'neutral',
  'none',
  'temperror',
  'permerror',
]);
const URL_VERDICTS = new Set(['clean', 'unknown', 'suspicious', 'malicious']);

function infraEntries(value: unknown): HistoryInfraEntry[] {
  const parsed = parseJson(value);
  if (!Array.isArray(parsed)) return [];
  const out: HistoryInfraEntry[] = [];
  for (const item of parsed.slice(0, 16)) {
    if (typeof item !== 'object' || item === null) continue;
    const { fp, count, lastSeenAt } = item as Record<string, unknown>;
    if (typeof fp !== 'string' || typeof count !== 'number' || typeof lastSeenAt !== 'string') {
      continue;
    }
    out.push({ fp, count, lastSeenAt });
  }
  return out;
}

/**
 * Prisma implementation on the **writer** (§2.0: the scan stage reads and writes the writer
 * only). The tenant data is cached per organization for `ttlMs` (BEC_TENANT_DATA_CACHE_TTL_MS,
 * ≤ 1 000 organizations): a change made through the api applies within the TTL.
 */
export class PrismaBecStore implements BecStore {
  private readonly tenants: TtlLru<string, BecTenantRecord>;
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly limits: BecTenantLimits,
    options: { ttlMs: number; now?: () => Date },
  ) {
    this.now = options.now ?? (() => new Date());
    this.tenants = new TtlLru(BEC_TENANT_CACHE_SIZE, Math.max(0, options.ttlMs), () =>
      this.now().getTime(),
    );
  }

  async loadRound(scope: BecReadScope): Promise<BecRoundRow | null> {
    const row = await this.prisma.emailScan.findFirst({
      where: { id: scope.scanId, receivedAt: scope.receivedAt },
      select: {
        id: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        scanKind: true,
        requiredEngines: true,
      },
    });
    if (!row) return null;
    if (
      row.id !== scope.scanId ||
      row.messageId !== scope.messageId ||
      row.organizationId !== scope.organizationId ||
      !sameTime(row.receivedAt, scope.receivedAt) ||
      row.lifecycleRound !== scope.round
    ) {
      throw new InconsistentBecReadError('scan', 'identity echo');
    }
    return {
      round: row.lifecycleRound,
      scanKind: row.scanKind === 'rescan' ? 'rescan' : 'initial',
      requiredEngines: stringList(row.requiredEngines, 16),
    };
  }

  async loadFinals(scope: BecReadScope, engines: readonly string[]): Promise<BecFinalRow[]> {
    if (engines.length === 0) return [];
    const rows = await this.prisma.scanEngineResult.findMany({
      where: {
        scanId: scope.scanId,
        receivedAt: scope.receivedAt,
        isFinal: true,
        engine: { in: [...engines] },
      },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        engine: true,
        isFinal: true,
        outcome: true,
      },
    });
    const seen = new Set<string>();
    for (const r of rows) {
      if (
        r.scanId !== scope.scanId ||
        r.messageId !== scope.messageId ||
        r.organizationId !== scope.organizationId ||
        !sameTime(r.receivedAt, scope.receivedAt) ||
        !r.isFinal ||
        !engines.includes(r.engine) ||
        seen.has(r.engine)
      ) {
        throw new InconsistentBecReadError('finals', 'identity echo');
      }
      seen.add(r.engine);
    }
    return rows.map((r) => ({ engine: r.engine, outcome: r.outcome }));
  }

  async loadAuth(scope: BecReadScope, engine: string): Promise<AuthResultRow | null> {
    const row = await this.prisma.emailAuthResult.findFirst({
      where: { scanId: scope.scanId, receivedAt: scope.receivedAt, engine },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        engine: true,
        spf: true,
        spfDomain: true,
        dkim: true,
        dkimSignatures: true,
        dmarc: true,
        dmarcPolicy: true,
        dmarcDomain: true,
        arc: true,
      },
    });
    if (!row) return null;
    if (
      row.scanId !== scope.scanId ||
      row.messageId !== scope.messageId ||
      row.organizationId !== scope.organizationId ||
      !sameTime(row.receivedAt, scope.receivedAt) ||
      row.engine !== engine
    ) {
      throw new InconsistentBecReadError('auth', 'identity echo');
    }
    const outcome = (v: string | null): AuthResultRow['spf'] =>
      v !== null && AUTH_OUTCOMES.has(v) ? (v as AuthResultRow['spf']) : null;
    const signatures = parseJson(row.dkimSignatures);
    return {
      spf: outcome(row.spf),
      spfDomain: row.spfDomain,
      dkim: outcome(row.dkim),
      dkimSignatures: Array.isArray(signatures)
        ? signatures
            .filter(
              (s): s is { domain: string; result: string; selector?: string | null } =>
                typeof s === 'object' &&
                s !== null &&
                typeof (s as { domain?: unknown }).domain === 'string' &&
                typeof (s as { result?: unknown }).result === 'string',
            )
            .slice(0, 10)
        : [],
      dmarc: outcome(row.dmarc),
      dmarcPolicy: row.dmarcPolicy,
      dmarcDomain: row.dmarcDomain,
      arc: outcome(row.arc),
    };
  }

  /** `url_scan_results` of the round (≤ 200 by `url_seq`) joined in code with `message_urls`. */
  async loadUrlResults(scope: BecReadScope): Promise<BecUrlResultRow[]> {
    const results = await this.prisma.urlScanResult.findMany({
      where: { scanId: scope.scanId, receivedAt: scope.receivedAt },
      orderBy: { urlSeq: 'asc' },
      take: BEC_MAX_URL_RESULTS,
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        urlSeq: true,
        urlSha256: true,
        verdict: true,
        reasonCodes: true,
      },
    });
    let previous = -1;
    for (const r of results) {
      if (
        r.scanId !== scope.scanId ||
        r.messageId !== scope.messageId ||
        r.organizationId !== scope.organizationId ||
        !sameTime(r.receivedAt, scope.receivedAt) ||
        r.urlSeq <= previous ||
        !URL_VERDICTS.has(r.verdict)
      ) {
        throw new InconsistentBecReadError('urls', 'result echo');
      }
      previous = r.urlSeq;
    }
    if (results.length === 0) return [];
    const urls = await this.prisma.messageUrl.findMany({
      where: {
        messageId: scope.messageId,
        receivedAt: scope.receivedAt,
        organizationId: scope.organizationId,
        urlSeq: { in: results.map((r) => r.urlSeq) },
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        urlSeq: true,
        urlSha256: true,
        host: true,
        registrableDomain: true,
      },
    });
    const bySeq = new Map<number, (typeof urls)[number]>();
    for (const u of urls) {
      if (
        u.messageId !== scope.messageId ||
        u.organizationId !== scope.organizationId ||
        !sameTime(u.receivedAt, scope.receivedAt) ||
        bySeq.has(u.urlSeq)
      ) {
        throw new InconsistentBecReadError('urls', 'message_urls echo');
      }
      bySeq.set(u.urlSeq, u);
    }
    return results.map((r) => {
      const url = bySeq.get(r.urlSeq);
      // A result always names a stored URL of the message with the same hash (U16 read-back).
      if (!url || url.urlSha256 !== r.urlSha256) {
        throw new InconsistentBecReadError('urls', 'seq/hash join');
      }
      return {
        urlSeq: r.urlSeq,
        verdict: r.verdict,
        reasonCodes: stringList(r.reasonCodes, 32),
        host: url.host,
        registrableDomain: url.registrableDomain,
      };
    });
  }

  async loadHeaders(scope: BecReadScope): Promise<BecHeaderRead> {
    const rows = await this.prisma.emailHeader.findMany({
      where: {
        messageId: scope.messageId,
        receivedAt: scope.receivedAt,
        organizationId: scope.organizationId,
      },
      orderBy: { seq: 'asc' },
      // One row past the cap tells a complete set of exactly BEC_MAX_HEADERS rows from a
      // truncated read (MIME_MAX_STORED_HEADERS may be up to 500).
      take: BEC_MAX_HEADERS + 1,
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        seq: true,
        name: true,
        value: true,
      },
    });
    const headers: Record<string, string[]> = {};
    let previous = -1;
    for (const r of rows.slice(0, BEC_MAX_HEADERS)) {
      if (
        r.messageId !== scope.messageId ||
        r.organizationId !== scope.organizationId ||
        !sameTime(r.receivedAt, scope.receivedAt) ||
        r.seq <= previous
      ) {
        throw new InconsistentBecReadError('headers', 'identity echo');
      }
      previous = r.seq;
      (headers[r.name] ??= []).push(r.value);
    }
    return { headers, truncated: rows.length > BEC_MAX_HEADERS };
  }

  async loadParse(scope: BecReadScope): Promise<BecParseRow | null> {
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
        defects: true,
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
      throw new InconsistentBecReadError('parse', 'identity echo');
    }
    return {
      status: row.status,
      limitsExceeded: stringList(row.limitsExceeded, 64),
      defects: stringList(row.defects, 64),
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

  async loadSubject(scope: BecReadScope): Promise<string | null> {
    const row = await this.prisma.emailMessage.findFirst({
      where: {
        id: scope.messageId,
        receivedAt: scope.receivedAt,
        organizationId: scope.organizationId,
      },
      select: { id: true, receivedAt: true, organizationId: true, subject: true },
    });
    if (!row) throw new InconsistentBecReadError('message', 'message row absent');
    if (
      row.id !== scope.messageId ||
      row.organizationId !== scope.organizationId ||
      !sameTime(row.receivedAt, scope.receivedAt)
    ) {
      throw new InconsistentBecReadError('message', 'identity echo');
    }
    return row.subject;
  }

  async tenantData(organizationId: bigint): Promise<BecTenantRecord> {
    const key = organizationId.toString();
    const cached = this.tenants.get(key);
    if (cached) return cached;
    const record = await this.loadTenant(organizationId);
    this.tenants.set(key, record);
    return record;
  }

  private async loadTenant(organizationId: bigint): Promise<BecTenantRecord> {
    const now = this.now();
    const unexpired = { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] };
    const [domains, executives, vendors, trusted, suppressions, urlRow] = await Promise.all([
      this.prisma.domain.findMany({
        where: { organizationId, status: 'active', deletedAt: null },
        orderBy: { id: 'asc' },
        take: BEC_MAX_TENANT_DOMAINS,
        select: { organizationId: true, name: true, status: true, deletedAt: true },
      }),
      this.prisma.becExecutiveProfile.findMany({
        where: { organizationId, enabled: true },
        orderBy: { id: 'asc' },
        take: this.limits.executives,
        select: {
          organizationId: true,
          publicId: true,
          displayName: true,
          aliases: true,
          knownAddresses: true,
          enabled: true,
        },
      }),
      this.prisma.becVendorProfile.findMany({
        where: { organizationId, enabled: true },
        orderBy: { id: 'asc' },
        take: this.limits.vendors,
        select: {
          organizationId: true,
          publicId: true,
          name: true,
          aliases: true,
          domains: true,
          knownSenders: true,
          paymentChangeSensitive: true,
          enabled: true,
        },
      }),
      this.prisma.becTrustedSender.findMany({
        where: { organizationId, ...unexpired },
        orderBy: { id: 'asc' },
        take: this.limits.trustedSenders,
        select: {
          organizationId: true,
          publicId: true,
          kind: true,
          value: true,
          expiresAt: true,
        },
      }),
      this.prisma.becSuppressionRule.findMany({
        where: { organizationId, expiresAt: { gt: now } },
        orderBy: { id: 'asc' },
        take: this.limits.suppressions,
        select: {
          organizationId: true,
          publicId: true,
          reasonCode: true,
          senderScope: true,
          senderValue: true,
          expiresAt: true,
        },
      }),
      this.prisma.scanEngineSetting.findUnique({
        where: { organizationId_engine: { organizationId, engine: 'url' } },
        select: { organizationId: true, engine: true, settings: true, version: true },
      }),
    ]);
    const echo = (rows: ReadonlyArray<{ organizationId: bigint }>, check: string): void => {
      if (rows.some((r) => r.organizationId !== organizationId)) {
        throw new InconsistentBecReadError('tenant', check);
      }
    };
    echo(domains, 'domains');
    if (domains.some((d) => d.status !== 'active' || d.deletedAt !== null)) {
      throw new InconsistentBecReadError('tenant', 'domain status');
    }
    echo(executives, 'executives');
    echo(vendors, 'vendors');
    echo(trusted, 'trusted senders');
    echo(suppressions, 'suppressions');
    if ([...executives, ...vendors].some((p) => !p.enabled)) {
      throw new InconsistentBecReadError('tenant', 'profile enabled');
    }
    if (
      trusted.some((t) => t.expiresAt !== null && t.expiresAt.getTime() <= now.getTime()) ||
      suppressions.some((s) => s.expiresAt.getTime() <= now.getTime())
    ) {
      throw new InconsistentBecReadError('tenant', 'expiry');
    }
    if (urlRow && (urlRow.organizationId !== organizationId || urlRow.engine !== 'url')) {
      throw new InconsistentBecReadError('tenant', 'url settings');
    }
    return {
      tenantDomains: domains.map((d) => d.name.toLowerCase()),
      executives: executives.map((e) => ({
        publicId: e.publicId,
        name: e.displayName,
        aliases: stringList(e.aliases, 10),
        knownAddresses: stringList(e.knownAddresses, 20).map((a) => a.toLowerCase()),
      })),
      vendors: vendors.map((v) => ({
        publicId: v.publicId,
        name: v.name,
        aliases: stringList(v.aliases, 10),
        domains: stringList(v.domains, 20).map((d) => d.toLowerCase()),
        knownSenders: stringList(v.knownSenders, 50).map((a) => a.toLowerCase()),
        paymentChangeSensitive: v.paymentChangeSensitive,
      })),
      trustedSenders: trusted.map((t) => ({
        publicId: t.publicId,
        kind: t.kind,
        value: t.value.toLowerCase(),
        expiresAt: t.expiresAt,
      })),
      suppressions: suppressions.map((s) => ({
        publicId: s.publicId,
        reasonCode: s.reasonCode,
        senderScope: s.senderScope,
        senderValue: s.senderValue.toLowerCase(),
        expiresAt: s.expiresAt,
      })),
      urlSettingsRow: urlRow ? { settings: urlRow.settings, version: urlRow.version } : null,
    };
  }

  /** B12 reads: rows of one scope by key hash (≤ 51), echo-checked on org + scope + hash. */
  async loadHistory(
    organizationId: bigint,
    scope: 'sender' | 'pair',
    keyHashes: readonly string[],
  ): Promise<BecHistoryRead[]> {
    if (keyHashes.length === 0) return [];
    const rows = await this.prisma.becContactHistory.findMany({
      where: { organizationId, scope, keyHash: { in: [...keyHashes] } },
      take: keyHashes.length,
      select: {
        organizationId: true,
        scope: true,
        keyHash: true,
        messageCount: true,
        firstSeenAt: true,
        lastSeenAt: true,
        infra: true,
      },
    });
    const requested = new Set(keyHashes);
    const seen = new Set<string>();
    for (const r of rows) {
      if (
        r.organizationId !== organizationId ||
        r.scope !== scope ||
        !requested.has(r.keyHash) ||
        seen.has(r.keyHash)
      ) {
        throw new InconsistentBecReadError('history', 'key echo');
      }
      seen.add(r.keyHash);
    }
    return rows.map((r) => ({
      keyHash: r.keyHash,
      row: {
        messageCount: r.messageCount,
        firstSeenAt: r.firstSeenAt,
        lastSeenAt: r.lastSeenAt,
        infra: scope === 'sender' ? infraEntries(r.infra) : null,
      },
    }));
  }
}
