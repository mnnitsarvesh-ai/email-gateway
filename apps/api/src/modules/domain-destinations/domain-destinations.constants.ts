import { DESTINATION_HOST_REFUSALS } from '@email-gateway/mail-routing';

/** Constants of the domain destinations module (step 2.3 R2, R3, R13). */

/** Permissions (seeded by step 2.3 WP1): destinations are readable with `domain:read`. */
export const DOMAIN_ROUTING_MANAGE = 'domain:routing_manage';

/** Audit actions (resource type `domain`). Metadata names hosts and counts, never secrets. */
export const DestinationAuditAction = {
  Replaced: 'domain.destinations_replaced',
  Removed: 'domain.destinations_removed',
} as const;
export type DestinationAuditAction =
  (typeof DestinationAuditAction)[keyof typeof DestinationAuditAction];

/**
 * Stable `reason` values of a `422` destination refusal: the host rules of
 * validateDestinationHost (R3) plus two request-level reasons.
 */
export const DESTINATION_REFUSAL_REASONS = [
  ...DESTINATION_HOST_REFUSALS,
  /** The same host:port appears twice (after normalization). */
  'duplicate_server',
  /** The preset is missing, disabled or has no default servers. */
  'provider_unavailable',
  /** A custom server on a provider preset's host (use that provider; its TLS policy is fixed). */
  'host_reserved_for_provider',
  /**
   * The host:port is already a destination of another organization with a different TLS mode or
   * verify-name list. Postfix's TLS policy is looked up per next hop, not per tenant, so a
   * shared server must have one policy (review fix: no tenant changes another's TLS policy).
   */
  'destination_tls_conflict',
] as const;
export type DestinationRefusalReason = (typeof DESTINATION_REFUSAL_REASONS)[number];

/** Default custom server values (R13). */
export const CUSTOM_DEFAULTS = { port: 25, priority: 10, tlsMode: 'opportunistic' } as const;
/** Priority of the single Microsoft 365 server. */
export const PRESET_SINGLE_SERVER_PRIORITY = 10;

/** PUT / DELETE: per principal per minute (R13). */
export const DESTINATIONS_WRITE_LIMIT = { limit: 30, windowSeconds: 60 } as const;

/**
 * `domain.routing.changed.v1` names at most 2 × ROUTING_MAX_DESTINATIONS_PER_DOMAIN hosts
 * (the event schema's bound).
 */
export const MAX_EVENT_HOSTS = 20;
