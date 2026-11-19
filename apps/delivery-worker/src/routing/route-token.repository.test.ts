import type { PrismaClient } from '@email-gateway/database';
import { deriveRouteToken } from '@email-gateway/mail-routing';
import { describe, expect, it, vi } from 'vitest';
import {
  ROUTE_TOKEN_CACHE_SECONDS,
  RouteTokenRepository,
  type RouteTokenSubject,
  RouteTokenUnavailableError,
} from './route-token.repository';

// Obviously synthetic example key (tests only).
const KEY = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const CONNECTION = '0190a0a0-0000-7000-8000-000000000c05';

interface ConnectionOverrides {
  organizationId?: bigint;
  provider?: string;
  internalRouting?: boolean;
  outboundMode?: string;
  routeTokenVersion?: number;
}

function harness(connection: ConnectionOverrides | null = {}, key: string | null = KEY) {
  let now = 1_000_000;
  const findUnique = vi.fn(() =>
    Promise.resolve(
      connection === null
        ? null
        : {
            connection: {
              publicId: CONNECTION,
              organizationId: 7n,
              provider: 'microsoft_365',
              internalRouting: true,
              outboundMode: 'active',
              routeTokenVersion: 1,
              ...connection,
            },
          },
    ),
  );
  const repository = new RouteTokenRepository(
    { providerConnectionDomain: { findUnique } } as unknown as PrismaClient,
    key ?? undefined,
    { now: () => now },
  );
  return { repository, findUnique, advance: (ms: number) => (now += ms) };
}

const internal: RouteTokenSubject = {
  organizationId: 7n,
  direction: 'internal',
  destinationKey: 'tenant:42',
};

describe('RouteTokenRepository (D9)', () => {
  it('derives the header for an internal delivery to a qualifying Microsoft 365 domain', async () => {
    const { repository, findUnique } = harness();
    expect(await repository.headerFor(internal)).toBe(
      `X-EG-Route-Token: ${deriveRouteToken(KEY, CONNECTION, 1)}`,
    );
    expect(findUnique).toHaveBeenCalledWith(expect.objectContaining({ where: { domainId: 42n } }));
  });

  it('uses the current route_token_version', async () => {
    const { repository } = harness({ routeTokenVersion: 3 });
    expect(await repository.headerFor(internal)).toBe(
      `X-EG-Route-Token: ${deriveRouteToken(KEY, CONNECTION, 3)}`,
    );
  });

  it.each<[string, RouteTokenSubject]>([
    ['outbound deliveries', { ...internal, direction: 'outbound', destinationKey: 'mx:ext.test' }],
    ['inbound deliveries', { ...internal, direction: 'inbound' }],
    ['a non-tenant destination', { ...internal, destinationKey: 'mx:acme.test' }],
    ['another organization', { ...internal, organizationId: 8n }],
  ])('adds nothing for %s', async (_, subject) => {
    expect(await harness().repository.headerFor(subject)).toBeNull();
  });

  it.each<[string, ConnectionOverrides | null]>([
    ['an unlinked domain', null],
    ['a Google Workspace connection', { provider: 'google_workspace' }],
    ['internal routing off', { internalRouting: false }],
    ['outbound probe_only', { outboundMode: 'probe_only' }],
    ['outbound suspended', { outboundMode: 'suspended' }],
    ['outbound off', { outboundMode: 'off' }],
  ])('adds nothing for %s', async (_, connection) => {
    expect(await harness(connection).repository.headerFor(internal)).toBeNull();
  });

  it('caches per domain for 60 s (also misses)', async () => {
    const { repository, findUnique, advance } = harness(null);
    await repository.headerFor(internal);
    await repository.headerFor(internal);
    expect(findUnique).toHaveBeenCalledTimes(1);
    advance(ROUTE_TOKEN_CACHE_SECONDS * 1000 + 1);
    await repository.headerFor(internal);
    expect(findUnique).toHaveBeenCalledTimes(2);
  });

  it('never skips the header: a database error or a missing key throws (the row is retried)', async () => {
    const failing = harness();
    failing.findUnique.mockRejectedValueOnce(new Error('db down'));
    await expect(failing.repository.headerFor(internal)).rejects.toThrow('db down');
    await expect(harness({}, null).repository.headerFor(internal)).rejects.toBeInstanceOf(
      RouteTokenUnavailableError,
    );
    // Without a qualifying link the key is not needed.
    expect(await harness(null, null).repository.headerFor(internal)).toBeNull();
  });
});
