import { isIP, isIPv4, isIPv6 } from 'node:net';

/**
 * IP helpers shared by normalization, the SSRF guard and the DNSBL provider. Only syntactically
 * valid literals (node:net isIP) are accepted; nothing here resolves names.
 */

/** 16 bytes of an IPv6 literal (with an optional embedded IPv4 tail), or null when invalid. */
export function ipv6ToBytes(address: string): Uint8Array | null {
  if (!isIPv6(address)) return null;
  let text = address;
  const bytes = new Uint8Array(16);
  // An embedded dotted IPv4 tail (::ffff:1.2.3.4) becomes two hextets.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToNumber(tail);
    if (v4 === null) return null;
    text = `${text.slice(0, lastColon + 1)}${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (missing < 0) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  if (groups.length !== 8) return null;
  groups.forEach((group, index) => {
    const value = Number.parseInt(group, 16);
    bytes[index * 2] = (value >>> 8) & 0xff;
    bytes[index * 2 + 1] = value & 0xff;
  });
  return bytes;
}

/** RFC 5952 text of 16 bytes (lower case, longest zero run compressed). */
export function bytesToIpv6(bytes: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0));
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLength && j - i >= 2) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestStart < 0) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

/** Strict dotted-decimal IPv4 → uint32, or null. */
export function ipv4ToNumber(address: string): number | null {
  if (!isIPv4(address)) return null;
  const parts = address.split('.').map(Number);
  return (
    (((parts[0] ?? 0) << 24) |
      ((parts[1] ?? 0) << 16) |
      ((parts[2] ?? 0) << 8) |
      (parts[3] ?? 0)) >>>
    0
  );
}

export function numberToIpv4(value: number): string {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join(
    '.',
  );
}

/** Canonical text of an IP literal (IPv4 dotted decimal, IPv6 RFC 5952), or null. Brackets allowed. */
export function canonicalIp(value: string): string | null {
  const text = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
  if (isIPv4(text)) return numberToIpv4(ipv4ToNumber(text) ?? 0);
  if (isIPv6(text)) {
    const bytes = ipv6ToBytes(text);
    return bytes ? bytesToIpv6(bytes) : null;
  }
  return null;
}

export function ipFamily(value: string): 4 | 6 | 0 {
  return isIP(value) as 4 | 6 | 0;
}

/** DNSBL query label of an IP: reversed octets (IPv4) or reversed nibbles (IPv6). */
export function reverseIpLabel(address: string): string | null {
  if (isIPv4(address)) return address.split('.').reverse().join('.');
  const bytes = ipv6ToBytes(address);
  if (!bytes) return null;
  const nibbles: string[] = [];
  for (const byte of bytes) nibbles.push((byte >>> 4).toString(16), (byte & 0x0f).toString(16));
  return nibbles.reverse().join('.');
}
