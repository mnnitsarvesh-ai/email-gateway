import { Inject, Injectable } from '@nestjs/common';
import { type Counter, MetricsService, PrismaService, RedisService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { parseIpKey } from '../connectors/addresses';

/** Version of the cached JSON (a new layout gets a new number; older entries are misses). */
export const RESTRICTION_CACHE_VERSION = 1;
/** Rows cached per organization (`ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG`, enforced at creation). */
export const MAX_ACTIVE_RESTRICTIONS_PER_ORG = 500;

/** `sa:ato:r:{organizationId}` (D14). */
export const restrictionCacheKey = (organizationId: bigint): string => `sa:ato:r:${organizationId}`;

export type RestrictionMode = 'reject' | 'defer';

const decimal = z.string().regex(/^\d{1,20}$/);
const hexBytes = z.string().regex(/^(?:[0-9a-f]{2}){4,16}$/);
const cachedRow = z.strictObject({
  kind: z.enum(['send_block', 'auth_block']),
  scope: z.enum(['mailbox', 'connector', 'connector_ip']),
  connectorId: decimal.nullable(),
  mailboxSha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .nullable(),
  ipVersion: z.union([z.literal(4), z.literal(6)]).nullable(),
  rangeStart: hexBytes.nullable(),
  rangeEnd: hexBytes.nullable(),
  mode: z.enum(['reject', 'defer']),
  expiresAt: z.number().int(),
});
const cachedEntry = z.strictObject({
  version: z.literal(RESTRICTION_CACHE_VERSION),
  rows: z.array(cachedRow).max(MAX_ACTIVE_RESTRICTIONS_PER_ORG),
});
type CachedRow = z.infer<typeof cachedRow>;

interface RestrictionRow {
  kind: string;
  scope: string;
  connectorId: bigint | null;
  mailboxSha256: string | null;
  ipVersion: number | null;
  rangeStart: Uint8Array | null;
  rangeEnd: Uint8Array | null;
  mode: string;
  expiresAt: Date;
}

/** SHA-256 of the lower-cased address (equals `atoMailboxSha256` of security-contracts). */
export function mailboxSha256(address: string): string {
  return createHash('sha256').update(address.toLowerCase(), 'utf8').digest('hex');
}

export type AtoRestrictionConfig = Pick<
  SmtpAdapterConfig,
  'SMTP_ATO_RESTRICTION_CACHE_SECONDS' | 'SMTP_ATO_ENFORCEMENT_ENABLED'
>;

/**
 * ATO enforcement lookups of the smtp-adapter (step 8.4 D14, ADR-0073): the active rows of
 * `ato_smtp_restrictions` of one organization, cached in Redis as one JSON entry
 * (`sa:ato:r:{organizationId}`, TTL SMTP_ATO_RESTRICTION_CACHE_SECONDS) loaded from the writer.
 * Expired rows are ignored at read time (the expiry sweeper only flips their status later).
 * The outbox tail deletes the key on `ato.restriction.changed.v1` (DomainCacheInvalidator).
 *
 * **Fail closed:** unlike the read-through domain cache, a Redis or database error propagates,
 * so the policy service tempfails the recipient and the SASL server closes the auth connection
 * (both temporary). SMTP_ATO_ENFORCEMENT_ENABLED=false (kill switch) answers "no restriction"
 * without any lookup.
 */
@Injectable()
export class AtoRestrictionService {
  private readonly logger: Logger;
  private readonly lookups: Counter<'result'>;
  private readonly enforced: Counter<'kind' | 'mode'>;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    metrics: MetricsService,
    @Inject(ADAPTER_CONFIG) private readonly config: AtoRestrictionConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'ato-restrictions' });
    this.lookups = metrics.counter(
      'smtp_ato_restriction_lookups_total',
      'ATO restriction cache lookups by result (hit, miss, error)',
      ['result'],
    );
    this.enforced = metrics.counter(
      'smtp_ato_restrictions_enforced_total',
      'Submissions and authentications refused by an ATO restriction',
      ['kind', 'mode'],
    );
  }

  get enforcementEnabled(): boolean {
    return this.config.SMTP_ATO_ENFORCEMENT_ENABLED;
  }

  /**
   * The mode of an active `send_block` on the connector or on the envelope sender's mailbox
   * (`reject` wins over `defer` when both match); null when none. Throws on Redis or database
   * errors (fail closed).
   */
  async sendBlock(
    organizationId: bigint,
    connectorId: bigint,
    senderAddress: string,
    now: Date = new Date(),
  ): Promise<RestrictionMode | null> {
    if (!this.enforcementEnabled) return null;
    const rows = await this.active(organizationId, now);
    if (rows.length === 0) return null;
    const connector = connectorId.toString();
    const mailbox = senderAddress === '' ? null : mailboxSha256(senderAddress);
    let mode: RestrictionMode | null = null;
    for (const row of rows) {
      if (row.kind !== 'send_block') continue;
      const match =
        (row.scope === 'connector' && row.connectorId === connector) ||
        (row.scope === 'mailbox' && mailbox !== null && row.mailboxSha256 === mailbox);
      if (match && (mode === null || row.mode === 'reject')) mode = row.mode;
    }
    if (mode !== null) this.enforced.inc({ kind: 'send_block', mode });
    return mode;
  }

  /**
   * Whether an active `auth_block` covers the connector (scope `connector`) or the connector
   * and the client IP (scope `connector_ip`, CIDR range). Throws on Redis or database errors.
   */
  async authBlocked(
    organizationId: bigint,
    connectorId: bigint,
    clientIp: string,
    now: Date = new Date(),
  ): Promise<boolean> {
    if (!this.enforcementEnabled) return false;
    const rows = await this.active(organizationId, now);
    if (rows.length === 0) return false;
    const connector = connectorId.toString();
    const ip = parseIpKey(clientIp);
    const blocked = rows.some((row) => {
      if (row.kind !== 'auth_block' || row.connectorId !== connector) return false;
      if (row.scope === 'connector') return true;
      if (row.scope !== 'connector_ip' || !ip || row.ipVersion !== ip.version) return false;
      const ipHex = ip.bytes.toString('hex');
      return (
        row.rangeStart !== null &&
        row.rangeEnd !== null &&
        row.rangeStart.length === ipHex.length &&
        row.rangeStart <= ipHex &&
        ipHex <= row.rangeEnd
      );
    });
    if (blocked) this.enforced.inc({ kind: 'auth_block', mode: 'reject' });
    return blocked;
  }

  /** Deletes the cached entry (outbox tail); errors propagate to the tail, which retries. */
  async invalidate(organizationId: bigint): Promise<void> {
    await this.redis.client.del(restrictionCacheKey(organizationId));
  }

  /** Active, unexpired rows of the organization (cache, else writer). */
  private async active(organizationId: bigint, now: Date): Promise<CachedRow[]> {
    const key = restrictionCacheKey(organizationId);
    let raw: string | null;
    try {
      raw = await this.redis.client.get(key);
    } catch (err) {
      this.lookups.inc({ result: 'error' });
      throw err;
    }
    let rows: CachedRow[] | null = null;
    if (raw !== null) {
      const parsed = safeParse(raw);
      if (parsed) {
        rows = parsed.rows;
        this.lookups.inc({ result: 'hit' });
      } else {
        this.logger.warn(
          { organizationId: String(organizationId) },
          'unusable cache entry; reloading',
        );
      }
    }
    if (rows === null) {
      try {
        rows = await this.load(organizationId, now);
        await this.redis.client.set(
          key,
          JSON.stringify({ version: RESTRICTION_CACHE_VERSION, rows }),
          'EX',
          this.config.SMTP_ATO_RESTRICTION_CACHE_SECONDS,
        );
      } catch (err) {
        this.lookups.inc({ result: 'error' });
        throw err;
      }
      this.lookups.inc({ result: 'miss' });
    }
    const nowMs = now.getTime();
    return rows.filter((row) => row.expiresAt > nowMs);
  }

  private async load(organizationId: bigint, now: Date): Promise<CachedRow[]> {
    const rows = await this.prisma.$queryRaw<RestrictionRow[]>`
      SELECT kind, scope, connector_id AS connectorId, mailbox_sha256 AS mailboxSha256,
             ip_version AS ipVersion, range_start AS rangeStart, range_end AS rangeEnd,
             mode, expires_at AS expiresAt
      FROM ato_smtp_restrictions
      WHERE organization_id = ${organizationId} AND status = 'active'
        AND expires_at > ${now}
      ORDER BY id
      LIMIT ${MAX_ACTIVE_RESTRICTIONS_PER_ORG}`;
    return rows.map((row) =>
      cachedRow.parse({
        kind: row.kind,
        scope: row.scope,
        connectorId: row.connectorId === null ? null : String(row.connectorId),
        mailboxSha256: row.mailboxSha256,
        ipVersion: row.ipVersion === null ? null : Number(row.ipVersion),
        rangeStart: row.rangeStart === null ? null : Buffer.from(row.rangeStart).toString('hex'),
        rangeEnd: row.rangeEnd === null ? null : Buffer.from(row.rangeEnd).toString('hex'),
        mode: row.mode,
        expiresAt: new Date(row.expiresAt).getTime(),
      }),
    );
  }
}

function safeParse(raw: string): z.infer<typeof cachedEntry> | null {
  try {
    const parsed = cachedEntry.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}
