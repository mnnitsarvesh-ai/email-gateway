import type { PrismaClient } from '@email-gateway/database';
import { ATO_MODES, type AtoMode } from '@email-gateway/ato-detection';
import { InconsistentReadError } from '../shared/errors';
import { big } from '../shared/db';

/** The ATO feature key of `organization_features` (D21; `false` in every plan). */
export const ATO_FEATURE_KEY = 'ato_detection';

/** What the no-op fast paths and the detection need to know about an organization (D3). */
export interface OrgContext {
  id: bigint;
  exists: boolean;
  active: boolean;
  /** `organizations.kind` (`customer`, `platform`, …). */
  kind: string;
  featureEnabled: boolean;
  /** When the operator enabled the feature (catch-up start bound), null when off. */
  featureEnabledAt: Date | null;
  /** `ato_settings.settings.mode`; `monitor` when no settings row exists yet (D21). */
  mode: AtoMode;
  timeZone: string;
  /** Whether an active tenant policy references an `ato.*` field (D13 policy hint). */
  hasAtoPolicyRule: boolean;
}

/** ATO is on for the organization: exists, active, feature enabled, mode not `off` (D3). */
export const atoEnabled = (ctx: OrgContext): boolean =>
  ctx.exists && ctx.active && ctx.featureEnabled && ctx.mode !== 'off';

interface Entry {
  value: OrgContext;
  expiresAt: number;
}

/**
 * Per-organization context with a TTL (`ATO_SETTINGS_CACHE_SECONDS`), read on the writer and
 * echo-checked. Also resolves the platform organization (`kind = 'platform'`, cached).
 */
export class OrgContextCache {
  private readonly cache = new Map<string, Entry>();
  private platform: { id: bigint | null; expiresAt: number } | null = null;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly ttlMs: number,
    private readonly now: () => Date = () => new Date(),
    private readonly maxEntries = 10_000,
    /**
     * TEST SEAM (integration suites only): the organization treated as the platform organization,
     * so the unknown-account path runs against a synthetic organization and the real platform
     * organization's ATO feature is never enabled (D21). Never set by the module.
     */
    private readonly platformOverride?: bigint,
  ) {}

  invalidate(organizationId?: bigint): void {
    if (organizationId === undefined) this.cache.clear();
    else this.cache.delete(organizationId.toString());
  }

  async get(organizationId: bigint): Promise<OrgContext> {
    const key = organizationId.toString();
    const t = this.now().getTime();
    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > t) return hit.value;
    const value = await this.load(organizationId);
    if (this.cache.size >= this.maxEntries) this.cache.clear();
    this.cache.set(key, { value, expiresAt: t + this.ttlMs });
    return value;
  }

  async platformOrganizationId(): Promise<bigint | null> {
    if (this.platformOverride !== undefined) return this.platformOverride;
    const t = this.now().getTime();
    if (this.platform && this.platform.expiresAt > t) return this.platform.id;
    const row = await this.prisma.organization.findFirst({
      where: { kind: 'platform' },
      orderBy: { id: 'asc' },
      select: { id: true },
    });
    this.platform = { id: row?.id ?? null, expiresAt: t + this.ttlMs };
    return this.platform.id;
  }

  private async load(organizationId: bigint): Promise<OrgContext> {
    const rows = await this.prisma.$queryRaw<
      Array<{
        id: bigint | number;
        status: string;
        kind: string;
        enabled: number | bigint | null;
        feature_updated_at: Date | null;
        mode: string | null;
        timezone: string | null;
        has_ato_rule: number | bigint | null;
      }>
    >`
      SELECT o.id, o.status, o.kind, f.enabled, f.updated_at AS feature_updated_at,
             JSON_UNQUOTE(JSON_EXTRACT(s.settings, '$.mode')) AS mode, os.timezone,
             (SELECT 1 FROM email_policies p
                JOIN policy_versions pv
                  ON pv.id = p.active_version_id AND pv.organization_id = p.organization_id
               WHERE p.organization_id = o.id AND p.status = 'active' AND p.deleted_at IS NULL
                 AND JSON_SEARCH(pv.definition, 'one', 'ato.%', NULL, '$**.field') IS NOT NULL
               LIMIT 1) AS has_ato_rule
      FROM organizations o
      LEFT JOIN organization_features f
        ON f.organization_id = o.id AND f.feature_key = ${ATO_FEATURE_KEY}
      LEFT JOIN ato_settings s ON s.organization_id = o.id
      LEFT JOIN organization_settings os ON os.organization_id = o.id
      WHERE o.id = ${organizationId}`;
    const row = rows[0];
    if (!row) {
      return {
        id: organizationId,
        exists: false,
        active: false,
        kind: 'customer',
        featureEnabled: false,
        featureEnabledAt: null,
        mode: 'monitor',
        timeZone: 'UTC',
        hasAtoPolicyRule: false,
      };
    }
    if (big(row.id) !== organizationId) throw new InconsistentReadError('organization');
    const enabled = Number(row.enabled ?? 0) === 1;
    const mode = (ATO_MODES as readonly string[]).includes(row.mode ?? '')
      ? (row.mode as AtoMode)
      : 'monitor';
    return {
      id: organizationId,
      exists: true,
      active: row.status === 'active',
      kind: row.kind,
      featureEnabled: enabled,
      featureEnabledAt: enabled ? (row.feature_updated_at ?? null) : null,
      mode,
      timeZone: row.timezone && row.timezone.length > 0 ? row.timezone : 'UTC',
      hasAtoPolicyRule: Number(row.has_ato_rule ?? 0) === 1,
    };
  }
}
