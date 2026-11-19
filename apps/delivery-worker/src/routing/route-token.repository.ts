import type { PrismaClient } from '@email-gateway/database';
import {
  deriveRouteToken,
  type RoutedDirection,
  routeTokenHeaderLine,
} from '@email-gateway/mail-routing';

/** Lookup cache TTL per recipient domain (D9). */
export const ROUTE_TOKEN_CACHE_SECONDS = 60;
/** Bound of the in-memory cache (cleared when full; it is only a cache). */
const MAX_CACHE_ENTRIES = 10_000;

const TENANT_DESTINATION = /^tenant:([1-9][0-9]{0,19})$/;

/** The reinjection fields the route token decision reads. */
export interface RouteTokenSubject {
  organizationId: bigint;
  /** `delivery_reinjections.direction` (the routed direction of the group). */
  direction: RoutedDirection;
  /** `tenant:<domainId>` for inbound and internal groups, `mx:<domain>` for outbound. */
  destinationKey: string;
}

/** The token is needed but PROVIDER_ROUTE_TOKEN_KEY is not configured: retry, never send. */
export class RouteTokenUnavailableError extends Error {
  constructor() {
    super('PROVIDER_ROUTE_TOKEN_KEY is not configured');
  }
}

interface Linked {
  organizationId: bigint;
  connectionPublicId: string;
  version: number;
}

type RouteTokenPrisma = Pick<PrismaClient, 'providerConnectionDomain'>;

/**
 * Which reinjections carry `X-EG-Route-Token` (step 8.2 D9, ADR-0081): only `internal`
 * deliveries whose recipient domain is linked to a connection of the same organization with
 * provider `microsoft_365`, `internal_routing = true` and `outbound_mode = active`. The token is
 * derived from the connection's current `route_token_version` (the pending version becomes
 * current only after the administrator's attestation, written by the api). Lookups are cached
 * 60 s per domain id in memory; a database error propagates so the reinjection is retried —
 * an internal message that needs the header is never sent without it.
 */
export class RouteTokenRepository {
  private readonly cache = new Map<string, { expiresAt: number; value: Linked | null }>();
  private readonly now: () => number;

  constructor(
    private readonly prisma: RouteTokenPrisma,
    private readonly keyHex: string | undefined,
    options: { now?: () => number } = {},
  ) {
    this.now = options.now ?? Date.now;
  }

  /** The header line (without CRLF), or null when the delivery does not carry one. */
  async headerFor(subject: RouteTokenSubject): Promise<string | null> {
    if (subject.direction !== 'internal') return null;
    const match = TENANT_DESTINATION.exec(subject.destinationKey);
    if (!match) return null;
    const linked = await this.lookup(match[1]!);
    if (linked === null || linked.organizationId !== subject.organizationId) return null;
    if (this.keyHex === undefined) throw new RouteTokenUnavailableError();
    return routeTokenHeaderLine(
      deriveRouteToken(this.keyHex, linked.connectionPublicId, linked.version),
    );
  }

  private async lookup(domainId: string): Promise<Linked | null> {
    const now = this.now();
    const cached = this.cache.get(domainId);
    if (cached && cached.expiresAt > now) return cached.value;
    const row = await this.prisma.providerConnectionDomain.findUnique({
      where: { domainId: BigInt(domainId) },
      select: {
        connection: {
          select: {
            publicId: true,
            organizationId: true,
            provider: true,
            internalRouting: true,
            outboundMode: true,
            routeTokenVersion: true,
          },
        },
      },
    });
    const connection = row?.connection;
    const value: Linked | null =
      connection &&
      connection.provider === 'microsoft_365' &&
      connection.internalRouting &&
      connection.outboundMode === 'active'
        ? {
            organizationId: connection.organizationId,
            connectionPublicId: connection.publicId,
            version: connection.routeTokenVersion,
          }
        : null;
    if (this.cache.size >= MAX_CACHE_ENTRIES) this.cache.clear();
    this.cache.set(domainId, { expiresAt: now + ROUTE_TOKEN_CACHE_SECONDS * 1000, value });
    return value;
  }
}
