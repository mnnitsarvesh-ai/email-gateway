import { createHmac, timingSafeEqual } from 'node:crypto';
import { HttpStatus, Inject, Injectable, Optional } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import type { ApiConfig } from '../../config';
import { ApiConventionMetrics } from '../api-metrics';
import { CodedHttpException } from '../coded-exception';

/**
 * Cursor v1 (step 6.1 D3, ADR-0051): opaque, signed and tenant-bound list cursors.
 *
 *   cursor = base64url(JSON payload) + "." + base64url(HMAC-SHA256(API_CURSOR_KEY,
 *            "eg-cursor/v1\0" + resource + "\0" + organizationPublicId + "\0" + payloadB64)[0..16])
 *   payload = { v: 1, r: resource, k: [key values as strings], f: filterHash (16 hex),
 *               d: "desc" | "asc", w?: [fromMs, toMs], t: issuedAtEpochSeconds }
 *
 * The organization is bound through the MAC only (it is not in the payload), so a cursor of one
 * tenant presented by another fails verification. Every failure is the same
 * `400 cursor_invalid` with no detail on which check failed. A cursor never widens access: the
 * repository re-applies the tenant scope regardless.
 */

export const CURSOR_INVALID = 'cursor_invalid';
export const CURSOR_VERSION = 1;
export const CURSOR_MAX_LENGTH = 512;
const MAC_BYTES = 16;
const MAC_DOMAIN = 'eg-cursor/v1';
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const FILTER_HASH = /^[0-9a-f]{16}$/;
const RESOURCE = /^[a-z][a-z0-9_.-]{0,63}$/;
/** A key value: a decimal id, an ISO timestamp, a public id, a short code. */
const MAX_KEY_LENGTH = 64;
const MAX_KEYS = 4;

export type CursorDirection = 'desc' | 'asc';

export interface CursorPosition {
  /** The list's resource name, e.g. `messages` (bound into the MAC and the payload). */
  resource: string;
  /** Public id of the caller's organization (scope), bound into the MAC only. */
  organizationPublicId: string;
  /** Keyset values of the last row (or the scan boundary), as strings. */
  keys: readonly string[];
  /** `filterHash({ resource, filters, sort })` of the request that produced the page. */
  filterHash: string;
  direction: CursorDirection;
  /** The resolved `[fromMs, toMs]` window of the first page, when the list has a range. */
  window?: readonly [number, number];
}

export interface DecodedCursor {
  keys: string[];
  direction: CursorDirection;
  window?: [number, number];
  issuedAt: number;
}

interface CursorPayload {
  v: number;
  r: string;
  k: string[];
  f: string;
  d: CursorDirection;
  w?: [number, number];
  t: number;
}

export const cursorInvalid = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.BAD_REQUEST, CURSOR_INVALID, 'Invalid cursor');

type CursorKeys = Pick<
  ApiConfig,
  'API_CURSOR_KEY' | 'API_CURSOR_KEY_PREVIOUS' | 'API_CURSOR_TTL_SECONDS'
>;

function isPayload(value: unknown): value is CursorPayload {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const p = value as Record<string, unknown>;
  const allowed = new Set(['v', 'r', 'k', 'f', 'd', 'w', 't']);
  if (Object.keys(p).some((key) => !allowed.has(key))) return false;
  if (p.v !== CURSOR_VERSION) return false;
  if (typeof p.r !== 'string' || !RESOURCE.test(p.r)) return false;
  if (
    !Array.isArray(p.k) ||
    p.k.length === 0 ||
    p.k.length > MAX_KEYS ||
    p.k.some((k) => typeof k !== 'string' || k.length === 0 || k.length > MAX_KEY_LENGTH)
  ) {
    return false;
  }
  if (typeof p.f !== 'string' || !FILTER_HASH.test(p.f)) return false;
  if (p.d !== 'desc' && p.d !== 'asc') return false;
  if (!Number.isSafeInteger(p.t) || (p.t as number) < 0) return false;
  if (p.w !== undefined) {
    if (
      !Array.isArray(p.w) ||
      p.w.length !== 2 ||
      !p.w.every((n) => Number.isSafeInteger(n) && (n as number) >= 0) ||
      (p.w[0] as number) > (p.w[1] as number)
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Encodes and verifies v1 cursors with `API_CURSOR_KEY` (verification also accepts
 * `API_CURSOR_KEY_PREVIOUS` while rotating) and `API_CURSOR_TTL_SECONDS`.
 */
@Injectable()
export class CursorCodec {
  private readonly key: Buffer;
  private readonly previousKey: Buffer | undefined;
  private readonly ttlSeconds: number;

  constructor(
    @Inject(API_CONFIG) config: CursorKeys,
    @Optional() private readonly metrics?: ApiConventionMetrics,
  ) {
    this.key = Buffer.from(config.API_CURSOR_KEY, 'hex');
    this.previousKey =
      config.API_CURSOR_KEY_PREVIOUS === undefined
        ? undefined
        : Buffer.from(config.API_CURSOR_KEY_PREVIOUS, 'hex');
    this.ttlSeconds = config.API_CURSOR_TTL_SECONDS;
  }

  /** Overridable clock (tests). */
  now(): number {
    return Date.now();
  }

  encode(position: CursorPosition): string {
    if (!RESOURCE.test(position.resource)) throw new Error('CursorCodec: invalid resource name');
    if (!FILTER_HASH.test(position.filterHash)) throw new Error('CursorCodec: invalid filter hash');
    if (position.organizationPublicId === '') throw new Error('CursorCodec: organization required');
    const payload: CursorPayload = {
      v: CURSOR_VERSION,
      r: position.resource,
      k: [...position.keys],
      f: position.filterHash,
      d: position.direction,
      ...(position.window && { w: [position.window[0], position.window[1]] }),
      t: Math.floor(this.now() / 1000),
    };
    if (!isPayload(payload)) throw new Error('CursorCodec: invalid cursor position');
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const mac = this.mac(this.key, position.resource, position.organizationPublicId, payloadB64);
    const cursor = `${payloadB64}.${mac.toString('base64url')}`;
    if (cursor.length > CURSOR_MAX_LENGTH) throw new Error('CursorCodec: cursor too long');
    return cursor;
  }

  /**
   * Verifies a cursor for this resource, organization and filter hash. Any failure (format,
   * MAC with either key, version, resource, filter hash, age, length) → `400 cursor_invalid`.
   */
  decode(
    cursor: string,
    expected: { resource: string; organizationPublicId: string; filterHash: string },
  ): DecodedCursor {
    const decoded = this.verify(cursor, expected);
    if (decoded === null) {
      this.metrics?.cursorRejected.inc();
      throw cursorInvalid();
    }
    return decoded;
  }

  private verify(
    cursor: unknown,
    expected: { resource: string; organizationPublicId: string; filterHash: string },
  ): DecodedCursor | null {
    if (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > CURSOR_MAX_LENGTH) {
      return null;
    }
    const parts = cursor.split('.');
    if (parts.length !== 2) return null;
    const [payloadB64, macB64] = parts as [string, string];
    if (!BASE64URL.test(payloadB64) || !BASE64URL.test(macB64)) return null;
    const mac = Buffer.from(macB64, 'base64url');
    // Canonical encoding only: a re-encoded MAC must give back exactly the same text.
    if (mac.length !== MAC_BYTES || mac.toString('base64url') !== macB64) return null;
    const keys = this.previousKey ? [this.key, this.previousKey] : [this.key];
    const authentic = keys.some((key) =>
      timingSafeEqual(
        mac,
        this.mac(key, expected.resource, expected.organizationPublicId, payloadB64),
      ),
    );
    if (!authentic) return null;
    let payload: unknown;
    try {
      const json = Buffer.from(payloadB64, 'base64url');
      if (json.toString('base64url') !== payloadB64) return null;
      payload = JSON.parse(json.toString('utf8'));
    } catch {
      return null;
    }
    if (!isPayload(payload)) return null;
    if (payload.r !== expected.resource || payload.f !== expected.filterHash) return null;
    const ageSeconds = Math.floor(this.now() / 1000) - payload.t;
    // A cursor from the future (clock skew beyond a minute) is as suspicious as an old one.
    if (ageSeconds > this.ttlSeconds || ageSeconds < -60) return null;
    return {
      keys: [...payload.k],
      direction: payload.d,
      ...(payload.w && { window: [payload.w[0], payload.w[1]] as [number, number] }),
      issuedAt: payload.t,
    };
  }

  private mac(
    key: Buffer,
    resource: string,
    organizationPublicId: string,
    payloadB64: string,
  ): Buffer {
    return createHmac('sha256', key)
      .update(`${MAC_DOMAIN}\0${resource}\0${organizationPublicId}\0${payloadB64}`, 'utf8')
      .digest()
      .subarray(0, MAC_BYTES);
  }
}
