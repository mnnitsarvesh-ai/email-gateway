import type { Prisma } from '@email-gateway/database';
import {
  resolveUrlSettings,
  type UrlEffectiveSettings,
  type UrlPlatformSettings,
  URL_PLATFORM_DEFAULTS,
  MESSAGE_DIRECTIONS,
} from '@email-gateway/security-contracts';
import {
  checkRewriteEligibility,
  type RewriteLimits,
  type RewriteSkipReason,
  signToken,
  type TokenKey,
  tokenExpiry,
} from '@email-gateway/url-security';
import { type InconsistencySink, wrongRead } from '../evaluation/errors';
import type { BodyEditPlan } from './policy-copy';

/**
 * URL_REWRITE after the scan (step 5.3 Q23, ADR-0049): the policy-engine rewrites the delivered
 * copy itself when a tenant rule demands it and the round was skipped only because the tenant's
 * 4.3 setting was off (`disabled`, `direction`). The tenant's URL settings are resolved like the
 * email-worker's url engine (`resolveUrlSettings` on the `scan_engine_settings` row of engine
 * `url`; an invalid row falls back to the platform settings) except that `enabled` and the
 * direction are forced on. Tokens are signed with the current click-token key only (sign only;
 * the click-service resolves them by `(org, message, received_at, url_seq)` against the round's
 * `message_urls`, independent of which service signed).
 */

/** Final parse statuses whose bodies are complete unless a limit hit (as the url engine). */
const COMPLETE_PARSE_STATUSES: ReadonlySet<string> = new Set([
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
]);
/** Parse limits that make the URL extraction incomplete (step 4.3 U4 E1, as the url engine). */
const INCOMPLETE_PARSE_LIMITS: ReadonlySet<string> = new Set([
  'body_size',
  'message_size',
  'nesting_depth',
  'part_count',
  'header_count',
  'header_line_length',
  'header_block_size',
  'parse_timeout',
  'decoded_ratio',
  'total_decoded_size',
]);

/** E1 of step 4.3: the stored parse is complete enough to rewrite. */
export function parseComplete(status: string, limits: readonly string[]): boolean {
  return (
    COMPLETE_PARSE_STATUSES.has(status) &&
    !limits.some((l) => INCOMPLETE_PARSE_LIMITS.has(l) || l.startsWith('header_'))
  );
}

export interface PolicyUrlRewriteConfig {
  /** POLICY_URL_REWRITE_ENABLED. */
  enabled: boolean;
  /** URL_TOKEN_KEY_CURRENT / _ID (null only when disabled). */
  key: TokenKey | null;
  clickBaseUrl: string;
  defaultExpiryDays: number;
  maxExpiryDays: number;
  dkimSignedPolicy: 'rewrite' | 'skip';
  limits: RewriteLimits;
}

/** The writer facts of a message the copy pipeline needs (Q22 structure, Q23 URL map). */
export interface CopyFacts {
  /** `email_message_parses.structure` content types in document order; null when unknown. */
  structure: Array<{ contentType: string }> | null;
  contentComplete: boolean;
  urls: Array<{ urlSha256: string; urlSeq: number; truncated: boolean; eligible: boolean }>;
  urlSettings: UrlEffectiveSettings;
}

export interface CopyFactsRef {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** `structure` JSON → content types (null when not a list of `{ contentType }`). */
export function structureTypes(structure: unknown): Array<{ contentType: string }> | null {
  if (!Array.isArray(structure)) return null;
  const out: Array<{ contentType: string }> = [];
  for (const node of structure) {
    if (!isRecord(node) || typeof node.contentType !== 'string') return null;
    out.push({ contentType: node.contentType });
  }
  return out;
}

const count = (sources: unknown, key: string): number => {
  if (!isRecord(sources)) return 0;
  const v = sources[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
};

/** The platform URL settings with rewriting forced on in every direction (Q23). */
export function policyUrlPlatform(config: PolicyUrlRewriteConfig): UrlPlatformSettings {
  return {
    scanTimeFetch: URL_PLATFORM_DEFAULTS.scanTimeFetch,
    rewrite: {
      enabled: true,
      directions: [...MESSAGE_DIRECTIONS],
      defaultExpiryDays: config.defaultExpiryDays,
      maxExpiryDays: config.maxExpiryDays,
      dkimSignedPolicy: config.dkimSignedPolicy,
    },
    dynamicInspection: URL_PLATFORM_DEFAULTS.dynamicInspection,
  };
}

/**
 * Writer reads of the copy pipeline (echo-checked on message, organization and `received_at`):
 * the parse row (status, limits, structure), the message's `message_urls` (hash, seq, truncated,
 * body sources) and the tenant's url engine settings row.
 */
export class CopyFactsReader {
  constructor(
    private readonly config: PolicyUrlRewriteConfig,
    private readonly sink: InconsistencySink,
  ) {}

  async read(tx: Prisma.TransactionClient, ref: CopyFactsRef): Promise<CopyFacts> {
    const parse = await tx.emailMessageParse.findFirst({
      where: { messageId: ref.messageId, receivedAt: ref.receivedAt },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        status: true,
        limitsExceeded: true,
        structure: true,
      },
    });
    if (parse !== null) {
      if (
        parse.messageId !== ref.messageId ||
        parse.organizationId !== ref.organizationId ||
        parse.receivedAt.getTime() !== ref.receivedAt.getTime()
      ) {
        wrongRead(this.sink, 'parse_structure', 'parse echo');
      }
    }
    const urls = await tx.messageUrl.findMany({
      where: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        urlSeq: true,
        urlSha256: true,
        truncated: true,
        sources: true,
      },
      orderBy: { urlSeq: 'asc' },
    });
    for (const u of urls) {
      if (
        u.messageId !== ref.messageId ||
        u.organizationId !== ref.organizationId ||
        u.receivedAt.getTime() !== ref.receivedAt.getTime()
      ) {
        wrongRead(this.sink, 'message_urls', 'url echo');
      }
    }
    const row = await tx.scanEngineSetting.findFirst({
      where: { organizationId: ref.organizationId, engine: 'url' },
      select: { organizationId: true, engine: true, settings: true },
    });
    if (row !== null && (row.organizationId !== ref.organizationId || row.engine !== 'url')) {
      wrongRead(this.sink, 'url_settings', 'settings echo');
    }
    const platform = policyUrlPlatform(this.config);
    const resolved = resolveUrlSettings(platform, row?.settings ?? null);
    const fallback = resolved.ok ? resolved : resolveUrlSettings(platform, null);
    if (!fallback.ok) throw new Error('the platform URL settings are invalid');
    const limits = Array.isArray(parse?.limitsExceeded)
      ? (parse.limitsExceeded as unknown[]).filter((l): l is string => typeof l === 'string')
      : [];
    return {
      structure: parse === null ? null : structureTypes(parse.structure),
      contentComplete: parse !== null && parseComplete(parse.status, limits),
      urls: urls.map((u) => ({
        urlSha256: u.urlSha256,
        urlSeq: u.urlSeq,
        truncated: u.truncated,
        eligible:
          !u.truncated && (count(u.sources, 'html_href') > 0 || count(u.sources, 'text') > 0),
      })),
      urlSettings: fallback.settings,
    };
  }
}

/**
 * Q23 eligibility of the policy rewrite with `enabled`/direction forced on, then the rewrite
 * plan (URL map, tenant rewrite policy, click base, signer with the expiry of the 4.3 settings
 * from `now`). A deterministic refusal returns its skip reason.
 */
export function planPolicyUrlRewrite(
  facts: CopyFacts,
  config: PolicyUrlRewriteConfig,
  ctx: {
    direction: string;
    messageSizeBytes: number;
    organizationId: bigint;
    messageId: bigint;
    receivedAt: Date;
    now: Date;
  },
): { plan: NonNullable<BodyEditPlan['urlRewrite']> } | { skip: RewriteSkipReason } {
  if (!config.enabled || config.key === null) return { skip: 'disabled' };
  const reason = checkRewriteEligibility({
    enabled: true,
    direction: ctx.direction,
    directions: [ctx.direction],
    contentComplete: facts.contentComplete,
    messageSizeBytes: ctx.messageSizeBytes,
    maxMessageBytes: config.limits.maxMessageBytes,
    contentTypes: (facts.structure ?? []).map((n) => n.contentType),
    eligibleUrls: facts.urls.filter((u) => u.eligible).length,
  });
  if (reason !== null) return { skip: reason };
  if (facts.structure === null) return { skip: 'structure_mismatch' };
  const key = config.key;
  const settings = facts.urlSettings;
  const expiresAt = tokenExpiry(
    ctx.now,
    Math.min(settings.rewrite.expiryDays, config.maxExpiryDays),
    config.maxExpiryDays,
  );
  return {
    plan: {
      urlMap: new Map(
        facts.urls.map((u) => [u.urlSha256, { seq: u.urlSeq, truncated: u.truncated }]),
      ),
      policy: {
        plainText: settings.rewrite.plainText,
        excludedDomains: settings.rewrite.excludedDomains,
        allowedDomains: settings.allowedDomains,
        dkimSignedPolicy: settings.rewrite.dkimSignedPolicy,
      },
      clickBaseUrl: config.clickBaseUrl,
      sign: (seq) =>
        signToken(
          {
            organizationId: ctx.organizationId,
            messageId: ctx.messageId,
            receivedAtMs: ctx.receivedAt.getTime(),
            urlSeq: seq,
            expiresAt,
          },
          key,
        ),
      limits: config.limits,
    },
  };
}
