import { countGatewayPasses } from '@email-gateway/common';

/**
 * Hop enforcement at reinjection (step 2.3 R10), before the worker connects to postfix-outbound.
 * The per-direction trace count at ingestion (step 2.2 D14) stays the primary loop stop; this
 * all-direction count stops loops that alternate directions (internal mail the tenant's server
 * sends back through submission, for example).
 */
export interface EvaluateHopsInput {
  /** Number of `Received:` header fields in the stored EML. */
  receivedHeaderCount: number;
  /** Every `X-Gateway-Trace` header value of the stored EML. */
  traceValues: readonly string[];
  /** The message's organization (trusted context). */
  organizationId: bigint | string;
  /** `GATEWAY_TRACE_SECRET`. */
  secret: string;
  /** `GATEWAY_TRACE_ID`. */
  gatewayId: string;
  /** `ROUTING_MAX_RECEIVED_HEADERS` (25, below Postfix's hopcount_limit of 30). */
  maxReceived: number;
  /** `ROUTING_MAX_GATEWAY_PASSES` (4). */
  maxPasses: number;
}

export type HopsResult =
  | { ok: true; passes: number }
  | { ok: false; reason: 'received_limit' | 'gateway_passes'; passes: number };

/**
 * `received_limit` when `Received:` count ≥ maxReceived; `gateway_passes` when the valid traces
 * of this gateway for the organization, in both directions, are ≥ maxPasses. Forged traces and
 * other organizations' traces never count (HMAC, step 2.2 D14).
 */
export function evaluateHops(input: EvaluateHopsInput): HopsResult {
  const key = {
    secret: input.secret,
    gatewayId: input.gatewayId,
    organizationId: input.organizationId,
  };
  const passes =
    countGatewayPasses(input.traceValues, { ...key, direction: 'in' }) +
    countGatewayPasses(input.traceValues, { ...key, direction: 'out' });
  if (input.receivedHeaderCount >= input.maxReceived) {
    return { ok: false, reason: 'received_limit', passes };
  }
  if (passes >= input.maxPasses) return { ok: false, reason: 'gateway_passes', passes };
  return { ok: true, passes };
}
