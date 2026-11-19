import { Inject, Injectable } from '@nestjs/common';
import { RedisService } from '@email-gateway/common';
import { z } from 'zod';
import { ADAPTER_CONFIG } from '../config';
import type { ProviderRelayConfig } from './provider-relay.config';

/** Postfix queue ids as XFORWARD IDENT carries them (short and long formats). */
const QUEUE_ID = /^[A-Za-z0-9]{1,32}$/;

/**
 * Postfix's `maximal_queue_lifetime` on postfix-outbound (5 days): the least lifetime of a marker,
 * at its write and again when a delivery is tempfailed at ingestion. The marker must outlive every
 * delivery attempt of the queue file (also a first LMTP delivery that comes late because the
 * smtp-adapter was down or backlogged, and every later batch of a queue file split by the LMTP
 * recipient limit), or the message would be ingested without the proof (I7, review finding).
 */
export const RELAY_MARKER_RETRY_TTL_SECONDS = 432_000;

/** Redis key of the marker of one queue file (contracts §33). */
export const relayMarkerKey = (queueId: string): string => `sa:prelay:${queueId}`;

/**
 * Marker v1 (step 8.2 D8.1, contracts §33): written by the policy service at END-OF-MESSAGE of a
 * provider-relay session, read once by LMTP ingestion. Bounded strings only; no addresses beyond
 * the client IP.
 */
export const relayMarkerSchema = z
  .object({
    v: z.literal(1),
    organizationId: z.string().regex(/^\d{1,20}$/),
    connectionPublicId: z.string().min(1).max(36),
    provider: z.enum(['microsoft_365', 'google_workspace']),
    tenantId: z.string().max(64).nullable(),
    outboundMode: z.enum(['probe_only', 'active', 'suspended']),
    tlsProtocol: z.string().max(16).nullable(),
    tlsCipher: z.string().max(64).nullable(),
    clientAddress: z.string().max(45),
  })
  .strict();

export type RelayMarker = z.infer<typeof relayMarkerSchema>;

export class InvalidQueueIdError extends Error {}

/** The TTL a marker is written with (never below the Postfix queue lifetime). */
export const markerTtlSeconds = (configured: number): number =>
  Math.max(configured, RELAY_MARKER_RETRY_TTL_SECONDS);

/**
 * `sa:prelay:{queueId}` in Redis with TTL max(PROVIDER_RELAY_MARKER_TTL_SECONDS,
 * RELAY_MARKER_RETRY_TTL_SECONDS). Markers are not deleted after ingestion: a queue file may be
 * delivered in several LMTP transactions (recipient batches, per-recipient retries). Every Redis
 * error propagates: the writer answers `DEFER_IF_PERMIT 4.3.5`, the reader `451 4.3.0` (I7). A stored
 * value that does not parse is treated like a Redis failure (never as "no marker", which would
 * relay the message without proof).
 */
@Injectable()
export class RelayMarkerStore {
  constructor(
    private readonly redis: RedisService,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<ProviderRelayConfig, 'PROVIDER_RELAY_MARKER_TTL_SECONDS'>,
  ) {}

  async write(queueId: string, marker: RelayMarker): Promise<void> {
    if (!QUEUE_ID.test(queueId)) throw new InvalidQueueIdError('invalid queue id');
    const value = JSON.stringify(relayMarkerSchema.parse(marker));
    await this.redis.client.set(
      relayMarkerKey(queueId),
      value,
      'EX',
      markerTtlSeconds(this.config.PROVIDER_RELAY_MARKER_TTL_SECONDS),
    );
  }

  /** Keeps the marker of a tempfailed delivery for the whole Postfix retry period. */
  async extend(queueId: string): Promise<void> {
    if (!QUEUE_ID.test(queueId)) return;
    await this.redis.client.expire(relayMarkerKey(queueId), RELAY_MARKER_RETRY_TTL_SECONDS);
  }

  /** The marker of a queue file, or null when there is none. */
  async read(queueId: string): Promise<RelayMarker | null> {
    if (!QUEUE_ID.test(queueId)) return null;
    const raw = await this.redis.client.get(relayMarkerKey(queueId));
    if (raw === null) return null;
    return relayMarkerSchema.parse(JSON.parse(raw));
  }
}
