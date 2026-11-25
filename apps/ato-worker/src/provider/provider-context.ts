import {
  PROVIDER_STREAMS,
  type IdentityProviderAdapter,
  type ProviderCapabilities,
  type ProviderRegistry,
} from '@email-gateway/ato-detection';
import type { PrismaClient } from '@email-gateway/database';

/** The identity-provider facts of one organization (D15): adapter kind, streams and actions. */
export interface ProviderContext {
  /** Provider kind of the organization's active integration with a registered adapter. */
  kind: string | null;
  integrationId: bigint | null;
  /** The singleton adapter (8.4's fake); `null` for the per-integration 8.5 adapters. */
  adapter: IdentityProviderAdapter | null;
  /** Streams the adapter supports (rule capabilities `provider:<stream>`). */
  streams: string[];
  /** Action types the adapter supports (response recommendations). */
  actions: ReadonlySet<string>;
}

const NONE: ProviderContext = {
  kind: null,
  integrationId: null,
  adapter: null,
  streams: [],
  actions: new Set(),
};

/** Step 8.5 provider kinds whose capabilities are the probe's stored effective capabilities. */
export const IDP_KINDS: ReadonlySet<string> = new Set(['microsoft_entra', 'google_workspace']);

/** `ato_provider_integrations.capabilities` as the 8.5 probe writes it (D6), shape-checked. */
export function storedCapabilities(value: unknown): ProviderCapabilities {
  const out: ProviderCapabilities = { streams: {}, actions: {} };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  const v = value as { streams?: unknown; actions?: unknown };
  if (v.streams && typeof v.streams === 'object') {
    for (const [stream, cap] of Object.entries(v.streams as Record<string, unknown>)) {
      if (
        (PROVIDER_STREAMS as readonly string[]).includes(stream) &&
        cap &&
        typeof cap === 'object'
      ) {
        (out.streams as Record<string, { supported: boolean }>)[stream] = {
          supported: (cap as { supported?: unknown }).supported === true,
        };
      }
    }
  }
  if (v.actions && typeof v.actions === 'object') {
    for (const [action, cap] of Object.entries(v.actions as Record<string, unknown>)) {
      if (!cap || typeof cap !== 'object' || !/^[a-z_]{1,48}$/.test(action)) continue;
      const c = cap as { supported?: unknown; rollback?: unknown; confirmation?: unknown };
      (out.actions as Record<string, unknown>)[action] = {
        supported: c.supported === true,
        rollback: c.rollback === true,
        confirmation: c.confirmation === 'polling' ? 'polling' : 'synchronous',
      };
    }
  }
  return out;
}

/**
 * Per-organization provider context with a TTL. 8.4: the first active integration with a
 * registered (fake) adapter. Step 8.5: the Microsoft Entra ID / Google Workspace integrations
 * (status `active` or `error`) contribute the effective capabilities their last probe stored
 * (`capabilities`, D6) — the union over the organization's integrations — without building an
 * adapter, so the `detect` role (no credentials, R3) sees them too.
 */
export class ProviderContextCache {
  private readonly cache = new Map<string, { value: ProviderContext; expiresAt: number }>();

  constructor(
    private readonly prisma: PrismaClient,
    // The worker's registry is typed by its integration row (PX2); only `get`/`size` are used.
    readonly registry: Pick<ProviderRegistry, 'get' | 'size'>,
    private readonly ttlMs: number,
    private readonly now: () => Date = () => new Date(),
    /** Step 8.5: read the stored capabilities of the identity-provider integrations. */
    private readonly idpCapabilities = false,
  ) {}

  /**
   * Drops the cached context of one organization, or of every organization. The identity-provider
   * stream runner drops its organization's entry before each poll (step AI-5 D13): an entry cached
   * by another event shortly before the first probe stored the integration's capabilities would
   * otherwise hide every provider stream from the rules for up to the TTL, and the events of that
   * poll are remembered as processed, so their signals would never be raised.
   */
  invalidate(organizationId?: bigint): void {
    if (organizationId === undefined) this.cache.clear();
    else this.cache.delete(organizationId.toString());
  }

  async get(organizationId: bigint): Promise<ProviderContext> {
    if (this.registry.size === 0 && !this.idpCapabilities) return NONE;
    const key = organizationId.toString();
    const t = this.now().getTime();
    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > t) return hit.value;
    const rows = await this.prisma.atoProviderIntegration.findMany({
      where: { organizationId, status: { in: ['active', 'error'] } },
      orderBy: { id: 'asc' },
      select: { id: true, provider: true, organizationId: true, capabilities: true },
      take: 10,
    });
    let value = NONE;
    const streams = new Set<string>();
    const actions = new Set<string>();
    for (const row of rows) {
      if (row.organizationId !== organizationId) continue;
      if (IDP_KINDS.has(row.provider)) {
        if (!this.idpCapabilities) continue;
        const caps = storedCapabilities(row.capabilities);
        for (const s of PROVIDER_STREAMS) if (caps.streams[s]?.supported === true) streams.add(s);
        for (const [a, c] of Object.entries(caps.actions))
          if (c?.supported === true) actions.add(a);
        if (value === NONE) {
          value = {
            kind: row.provider,
            integrationId: row.id,
            adapter: null,
            streams: [],
            actions,
          };
        }
        continue;
      }
      if (value !== NONE) continue;
      const adapter = this.registry.get(row.provider);
      if (!adapter) continue;
      const caps = adapter.capabilities();
      value = {
        kind: adapter.kind,
        integrationId: row.id,
        adapter,
        streams: PROVIDER_STREAMS.filter((s) => caps.streams[s]?.supported === true),
        actions: new Set(
          Object.entries(caps.actions)
            .filter(([, v]) => v?.supported === true)
            .map(([k]) => k),
        ),
      };
    }
    if (value !== NONE && value.adapter === null) {
      value = { ...value, streams: PROVIDER_STREAMS.filter((s) => streams.has(s)), actions };
    }
    this.cache.set(key, { value, expiresAt: t + this.ttlMs });
    return value;
  }
}
