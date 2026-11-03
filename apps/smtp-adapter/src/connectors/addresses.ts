import { normalizeClientAddress } from '../shared/internal-networks';

/** A client IP in the form used for range lookups (step 2.2 §3). */
export interface IpKey {
  /** Canonical text (IPv4 dotted quad, IPv6 compressed lower-case; mapped IPv4 → IPv4). */
  text: string;
  /** 4 or 6 (`smtp_connector_networks.ip_version`). */
  version: 4 | 6;
  /** 4 or 16 bytes, big-endian (`range_start` / `range_end`). */
  bytes: Buffer;
}

/**
 * Parses a full client address (as Postfix sends `client_address` or a socketmap
 * `check_client_access` key). Returns null for anything that is not a complete IPv4/IPv6
 * address, which includes the truncated keys Postfix probes (`10.1.2`, `10.1`).
 */
export function parseIpKey(raw: string | undefined): IpKey | null {
  const normalized = normalizeClientAddress(raw);
  if (!normalized) return null;
  if (normalized.family === 'ipv4') {
    const bytes = Buffer.from(normalized.address.split('.').map((octet) => Number(octet)));
    return { text: normalized.address, version: 4, bytes };
  }
  const bytes = ipv6Bytes(normalized.address);
  if (!bytes) return null;
  return { text: formatIpv6(bytes), version: 6, bytes };
}

function ipv6Bytes(address: string): Buffer | null {
  // Expand an embedded IPv4 tail (`::ffff:1.2.3.4` forms other than mapped, e.g. `64:ff9b::1.2.3.4`).
  let text = address.toLowerCase();
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const octets = tail.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
      return null;
    }
    const high = ((octets[0]! << 8) | octets[1]!).toString(16);
    const low = ((octets[2]! << 8) | octets[3]!).toString(16);
    text = `${text.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  const bytes = Buffer.alloc(16);
  for (const [i, group] of groups.entries()) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    bytes.writeUInt16BE(parseInt(group, 16), i * 2);
  }
  return bytes;
}

/** Canonical compressed IPv6 text (RFC 5952: lower-case, longest zero run ≥ 2 as `::`). */
function formatIpv6(bytes: Buffer): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i));
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

/** True when `ip` lies in [start, end] (same length buffers, big-endian). */
export function ipInRange(ip: Buffer, start: Buffer, end: Buffer): boolean {
  return (
    ip.length === start.length &&
    ip.length === end.length &&
    Buffer.compare(start, ip) <= 0 &&
    Buffer.compare(ip, end) <= 0
  );
}

/**
 * Normalizes a certificate or public-key SHA-256 fingerprint. Postfix sends (policy
 * `ccert_fingerprint`) and looks up (`check_ccert_access`) colon-separated upper-case hex
 * (`AB:CD:…`); `smtp_connectors.cert_fingerprint_sha256` stores 64 lower-case hex digits.
 * Returns null for anything else (other digests, truncated values).
 */
export function normalizeFingerprint(raw: string | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const hex = raw.trim().replaceAll(':', '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}
