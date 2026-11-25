import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { ProviderContextCache } from './provider-context';

const ORG_A = 920_001n;
const ORG_B = 920_002n;

/** A cache over a fake `ato_provider_integrations` read whose stored capabilities can change. */
function cacheOver(capabilities: Map<bigint, unknown>) {
  let reads = 0;
  const prisma = {
    atoProviderIntegration: {
      findMany: (args: { where: { organizationId: bigint } }) => {
        reads += 1;
        const caps = capabilities.get(args.where.organizationId);
        return Promise.resolve(
          caps === undefined
            ? []
            : [
                {
                  id: 1n,
                  provider: 'microsoft_entra',
                  organizationId: args.where.organizationId,
                  capabilities: caps,
                },
              ],
        );
      },
    },
  } as unknown as PrismaClient;
  const cache = new ProviderContextCache(
    prisma,
    { get: () => undefined, size: 0 },
    30_000,
    () => new Date('2026-11-25T12:00:00.000Z'),
    true,
  );
  return { cache, reads: () => reads };
}

const probed = { streams: { risk_events: { supported: true } }, actions: {} };

describe('ProviderContextCache (step AI-5 D13)', () => {
  it('serves a cached entry until it is dropped for its organization', async () => {
    const stored = new Map<bigint, unknown>([
      [ORG_A, {}],
      [ORG_B, {}],
    ]);
    const { cache, reads } = cacheOver(stored);
    expect((await cache.get(ORG_A)).streams).toEqual([]);
    expect((await cache.get(ORG_B)).streams).toEqual([]);
    // The first probe stores the capabilities: the cached entries still list no stream.
    stored.set(ORG_A, probed);
    stored.set(ORG_B, probed);
    expect((await cache.get(ORG_A)).streams).toEqual([]);
    expect(reads()).toBe(2);
    // Dropping one organization reads it again; the other entry stays cached.
    cache.invalidate(ORG_A);
    expect((await cache.get(ORG_A)).streams).toEqual(['risk_events']);
    expect((await cache.get(ORG_B)).streams).toEqual([]);
    expect(reads()).toBe(3);
    // Without an organization every entry is dropped.
    cache.invalidate();
    expect((await cache.get(ORG_B)).streams).toEqual(['risk_events']);
    expect(reads()).toBe(4);
  });
});
