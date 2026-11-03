import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Gateway trace header (step 2.2 D14, ADR-0019): loop prevention for mail that passes the
 * gateway more than once for the same tenant and direction.
 *
 * Whatever reinjects mail (the delivery-worker) prepends one header per pass:
 *
 *   X-Gateway-Trace: v=1; g=<gatewayId>; d=<in|out>; t=<unix seconds>; s=<sig>
 *
 * `sig` = base64url (no padding) of the first 16 bytes of
 * HMAC-SHA256(secret, `v1|<g>|<d>|<t>|<organizationId>`). The header names neither the tenant
 * nor an internal host; the organization is bound only through the signature, so a trace of
 * another tenant (or a forged one) never counts. Traces do not expire: a loop may take hours of
 * queueing, and the HMAC already prevents forgery.
 */
export const GATEWAY_TRACE_HEADER = 'X-Gateway-Trace';

export type GatewayTraceDirection = 'in' | 'out';

export interface GatewayTraceKey {
  /** `GATEWAY_TRACE_SECRET`, at least 32 characters. */
  secret: string;
  /** `GATEWAY_TRACE_ID`: [A-Za-z0-9._-]{1,64}. */
  gatewayId: string;
  /** Decimal organization id (`organizations.id`). */
  organizationId: bigint | string;
  direction: GatewayTraceDirection;
}

export interface BuildGatewayTraceOptions extends GatewayTraceKey {
  /** Defaults to the current time. */
  now?: Date;
}

const GATEWAY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;
const TIMESTAMP = /^(0|[1-9][0-9]{0,11})$/;
/** 16 bytes in base64url without padding. */
const SIGNATURE = /^[A-Za-z0-9_-]{22}$/;
const MIN_SECRET_LENGTH = 32;
const SIGNATURE_BYTES = 16;

interface ValidKey {
  secret: string;
  gatewayId: string;
  organizationId: string;
  direction: GatewayTraceDirection;
}

function validateKey(key: GatewayTraceKey): ValidKey {
  if (typeof key.secret !== 'string' || key.secret.length < MIN_SECRET_LENGTH) {
    throw new Error(`Gateway trace secret must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  if (!GATEWAY_ID.test(key.gatewayId)) {
    throw new Error('Gateway trace id must match [A-Za-z0-9._-]{1,64}');
  }
  const organizationId = key.organizationId.toString();
  if (!DECIMAL_ID.test(organizationId)) {
    throw new Error('Gateway trace organization id must be a positive decimal id');
  }
  if (key.direction !== 'in' && key.direction !== 'out') {
    throw new Error('Gateway trace direction must be in or out');
  }
  return { secret: key.secret, gatewayId: key.gatewayId, organizationId, direction: key.direction };
}

function signature(key: ValidKey, timestamp: string): Buffer {
  return createHmac('sha256', key.secret)
    .update(`v1|${key.gatewayId}|${key.direction}|${timestamp}|${key.organizationId}`)
    .digest()
    .subarray(0, SIGNATURE_BYTES);
}

/** The header VALUE (without the name) for one pass through the gateway. */
export function buildGatewayTrace(options: BuildGatewayTraceOptions): string {
  const key = validateKey(options);
  const now = options.now ?? new Date();
  const seconds = Math.floor(now.getTime() / 1000);
  if (!Number.isSafeInteger(seconds) || seconds < 0) {
    throw new Error('Gateway trace time must be a valid date after the epoch');
  }
  const timestamp = String(seconds);
  const sig = signature(key, timestamp).toString('base64url');
  return `v=1; g=${key.gatewayId}; d=${key.direction}; t=${timestamp}; s=${sig}`;
}

/** Parsed fields of a well-formed trace value, or null. Unknown or repeated fields → null. */
function parseTrace(value: string): Record<'v' | 'g' | 'd' | 't' | 's', string> | null {
  // Unfold (RFC 5322 folding: CRLF or LF followed by whitespace) and trim.
  const unfolded = value.replace(/\r?\n(?=[ \t])/g, '').trim();
  if (unfolded.length === 0 || unfolded.length > 512) return null;
  const fields = new Map<string, string>();
  for (const part of unfolded.split(';')) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) return null;
    const name = trimmed.slice(0, eq).trim();
    const fieldValue = trimmed.slice(eq + 1).trim();
    if (!['v', 'g', 'd', 't', 's'].includes(name) || fields.has(name)) return null;
    fields.set(name, fieldValue);
  }
  const v = fields.get('v');
  const g = fields.get('g');
  const d = fields.get('d');
  const t = fields.get('t');
  const s = fields.get('s');
  if (v === undefined || g === undefined || d === undefined || t === undefined || s === undefined) {
    return null;
  }
  return { v, g, d, t, s };
}

/**
 * Counts the valid passes in a message's `X-Gateway-Trace` header values for one organization
 * and direction of this gateway: same `g`, same `d`, and a signature that verifies for that
 * organization (constant-time compare). Malformed values, forged signatures, other gateways,
 * other directions and other organizations' traces are ignored, never thrown on.
 */
export function countGatewayPasses(values: readonly string[], options: GatewayTraceKey): number {
  const key = validateKey(options);
  let passes = 0;
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const trace = parseTrace(value);
    if (!trace) continue;
    if (trace.v !== '1' || trace.g !== key.gatewayId || trace.d !== key.direction) continue;
    if (!TIMESTAMP.test(trace.t) || !SIGNATURE.test(trace.s)) continue;
    const presented = Buffer.from(trace.s, 'base64url');
    const expected = signature(key, trace.t);
    if (presented.length === expected.length && timingSafeEqual(presented, expected)) passes += 1;
  }
  return passes;
}
