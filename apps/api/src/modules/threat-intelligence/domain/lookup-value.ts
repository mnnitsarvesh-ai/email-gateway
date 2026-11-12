import type { IndicatorType } from '@email-gateway/database';
import { feedValues, normalizeIndicator, sha256Hex } from '@email-gateway/url-security';

/** `type` of `GET /threat-intelligence/lookup` (step 6.1 §3.3). */
export const LOOKUP_TYPES = ['sha256', 'url', 'domain', 'ip'] as const;
export type LookupType = (typeof LOOKUP_TYPES)[number];

/** Longest accepted `value` per type (a URL like the engine's 2048, a DNS name, an IPv6 text). */
export const LOOKUP_MAX_LENGTH: Readonly<Record<LookupType, number>> = Object.freeze({
  sha256: 64,
  url: 2048,
  domain: 253,
  ip: 45,
});

/** `threat_indicators.indicator_type` matched per lookup type. */
export const INDICATOR_TYPE: Readonly<Record<LookupType, IndicatorType>> = Object.freeze({
  sha256: 'file_sha256',
  url: 'url',
  domain: 'domain',
  ip: 'ip',
});

const SHA256_HEX = /^[0-9a-f]{64}$/;

export interface NormalizedLookup {
  type: LookupType;
  /** The normalized value (never returned or logged in the clear). */
  value: string;
  /** SHA-256 (hex) of the normalized value: `threat_indicators.value_sha256` of the value itself. */
  valueSha256: string;
  /**
   * `value_sha256` keys the engines match for this value: the URL identity form, the canonical
   * IP, or the domain and its parents down to the registrable domain (`feedValues` of the URL
   * engine's local feed), or the file hash's own key.
   */
  matchHashes: string[];
  indicatorType: IndicatorType;
}

export type LookupResult = { ok: true; lookup: NormalizedLookup } | { ok: false; reason: string };

/**
 * Normalizes a lookup value with the engines' own functions (`@email-gateway/url-security`):
 * `normalizeIndicator` is how platform indicators were stored (U16) and `feedValues` +
 * `sha256Hex` is how the URL engine's `local_feed` provider and the click-service compute the
 * `value_sha256` keys they look up, so a lookup matches exactly the rows the engines would.
 * `sha256` values are lower-case hex (the attachment engine's `malware_signatures.sha256`).
 */
export function normalizeLookup(type: LookupType, raw: string): LookupResult {
  const text = raw.trim();
  if (text.length > LOOKUP_MAX_LENGTH[type]) return { ok: false, reason: 'too long' };
  if (type === 'sha256') {
    const value = text.toLowerCase();
    if (!SHA256_HEX.test(value)) return { ok: false, reason: 'must be 64 hexadecimal characters' };
    const valueSha256 = sha256Hex(value);
    return {
      ok: true,
      lookup: {
        type,
        value,
        valueSha256,
        matchHashes: [valueSha256],
        indicatorType: 'file_sha256',
      },
    };
  }
  const normalized = normalizeIndicator(type, text);
  if (!normalized.ok) return { ok: false, reason: normalized.code.replace(/_/g, ' ') };
  const matchHashes = [
    ...new Set(feedValues({ kind: type, value: normalized.value }).map((v) => sha256Hex(v))),
  ];
  if (!matchHashes.includes(normalized.valueSha256)) matchHashes.unshift(normalized.valueSha256);
  return {
    ok: true,
    lookup: {
      type,
      value: normalized.value,
      valueSha256: normalized.valueSha256,
      matchHashes,
      indicatorType: INDICATOR_TYPE[type],
    },
  };
}
