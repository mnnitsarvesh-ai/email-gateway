/**
 * Field normalization shared by the mappers (design note §3.1): canonical IPs, ISO timestamps,
 * bounded display strings, provider locations and the final event check against the strict 8.4 schema.
 */
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { providerEventSchema, SECRET_SHAPED, type ProviderEvent } from '../port/ato-port';

/** Canonical IP (IPv4 dotted, IPv6 compressed lower case) or `undefined`. */
export function canonicalIp(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  let text = value.trim();
  // `[v6]:port`, `v4:port`
  const bracketed = /^\[([0-9a-fA-F:.]+)\](?::\d+)?$/.exec(text);
  if (bracketed) text = bracketed[1] as string;
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(text)) text = text.slice(0, text.lastIndexOf(':'));
  const version = isIP(text);
  if (version === 4)
    return text
      .split('.')
      .map((part) => String(Number(part)))
      .join('.');
  if (version === 6) {
    try {
      return new URL(`http://[${text}]/`).hostname.slice(1, -1);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** ISO 8601 UTC with milliseconds; a timestamp without zone is UTC (Office 365 audit records). */
export function isoUtc(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const text = /[zZ]|[+-]\d{2}:?\d{2}$/.test(value) ? value : `${value}Z`;
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
}

/** Printable, single-line, trimmed and truncated display text; `undefined` when empty. */
export function boundedText(value: string | null | undefined, max: number): string | undefined {
  if (!value) return undefined;
  const cleaned = value
    .replace(/\p{Cc}+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return undefined;
  return cleaned.length > max ? cleaned.slice(0, max).trimEnd() : cleaned;
}

/** Lower-cased address when it looks like one. */
export function normalizedAddress(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const text = value.trim().toLowerCase();
  return /^[^\s@]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/.test(text) && text.length <= 256
    ? text
    : undefined;
}

export function providerLocation(
  geo:
    | {
        countryOrRegion?: string | null;
        city?: string | null;
        geoCoordinates?: { latitude?: number | null; longitude?: number | null } | null;
      }
    | null
    | undefined,
): ProviderEvent['providerLocation'] | undefined {
  if (!geo) return undefined;
  const location: NonNullable<ProviderEvent['providerLocation']> = {};
  const country = geo.countryOrRegion?.trim().toUpperCase();
  if (country && /^[A-Z]{2}$/.test(country)) location.countryCode = country;
  // 8.4 bounds the city at 64 characters and refuses token-shaped values.
  const city = boundedText(geo.city, 64);
  if (city && !SECRET_SHAPED.test(city)) location.city = city;
  const lat = geo.geoCoordinates?.latitude;
  const lon = geo.geoCoordinates?.longitude;
  if (
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    Math.abs(lat) <= 90 &&
    Math.abs(lon) <= 180
  ) {
    if (!(lat === 0 && lon === 0)) {
      location.lat = lat;
      location.lon = lon;
    }
  }
  return Object.keys(location).length > 0 ? location : undefined;
}

export function riskLevel(
  value: string | null | undefined,
): ProviderEvent['riskLevel'] | undefined {
  return value === 'low' || value === 'medium' || value === 'high' ? value : undefined;
}

/** Bounded code (`[a-z0-9_]`, ≤ 64) from a provider value. */
export function code64(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 64);
}

/** Final check of every emitted event against the strict 8.4 schema (invariant 6). */
export function isValidEvent(event: ProviderEvent): boolean {
  return providerEventSchema.safeParse(event).success;
}

/**
 * A provider id as part of an event id (merge note M1, deviation WP3-2): 8.4's
 * `providerEventSchema` refuses runs of 40 or more base64-like characters as token-shaped, and
 * some provider ids are such runs (Entra risk detection ids are 64 hex characters). Those ids are
 * replaced by the first 32 hex characters of their SHA-256 (stable, so dedupe still works);
 * shorter ids (GUIDs, Google qualifiers) are kept as they are.
 */
export function eventIdPart(raw: string): string {
  return SECRET_SHAPED.test(raw)
    ? `h${createHash('sha256').update(raw, 'utf8').digest('hex').slice(0, 32)}`
    : raw;
}

/** Display text that is also not token-shaped (8.4 `safe` strings). */
export function safeDisplayText(value: string | null | undefined, max: number): string | undefined {
  const text = boundedText(value, max);
  return text && !SECRET_SHAPED.test(text) ? text : undefined;
}
