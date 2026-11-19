import {
  PROVIDER_STREAMS,
  type IdentityProviderAdapter,
  type ProviderRegistry,
} from '@email-gateway/ato-detection';
import type { PrismaClient } from '@email-gateway/database';

/** The identity-provider facts of one organization (D15): adapter kind, streams and actions. */
export interface ProviderContext {
  /** Provider kind of the organization's active integration with a registered adapter. */
  kind: string | null;
  integrationId: bigint | null;
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

/**
 * Per-organization provider context with a TTL. In 8.4 production the registry is empty, so every
 * organization has none (provider actions are `unsupported`, provider rules unavailable); 8.5
 * binds adapters to 8.2's connectors without changing this read.
 */
export class ProviderContextCache {
  private readonly cache = new Map<string, { value: ProviderContext; expiresAt: number }>();

  constructor(
    private readonly prisma: PrismaClient,
    readonly registry: ProviderRegistry,
    private readonly ttlMs: number,
    private readonly now: () => Date = () => new Date(),
  ) {}

  invalidate(): void {
    this.cache.clear();
  }

  async get(organizationId: bigint): Promise<ProviderContext> {
    if (this.registry.size === 0) return NONE;
    const key = organizationId.toString();
    const t = this.now().getTime();
    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > t) return hit.value;
    const rows = await this.prisma.atoProviderIntegration.findMany({
      where: { organizationId, status: { in: ['active', 'error'] } },
      orderBy: { id: 'asc' },
      select: { id: true, provider: true, organizationId: true },
      take: 10,
    });
    let value = NONE;
    for (const row of rows) {
      if (row.organizationId !== organizationId) continue;
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
      break;
    }
    this.cache.set(key, { value, expiresAt: t + this.ttlMs });
    return value;
  }
}
