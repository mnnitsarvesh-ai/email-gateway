import { isIP } from 'node:net';

/** Host-name label: letters, digits and hyphens, not starting or ending with a hyphen. */
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** Service label (`_spf`, `_dmarc`, `_emailgateway-verify`): a leading underscore is allowed. */
const SERVICE_LABEL = /^_[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$/;

/** Lower-cases, trims and strips one trailing dot. Does not validate. */
export function normalizeDnsName(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * True for an absolute DNS name in normalized form (lower-case ASCII, no trailing dot) with at
 * least two labels, at most 253 characters and a non-numeric last label (so IPv4 literals are
 * rejected). `allowUnderscore` accepts service labels such as `_spf.example.com`.
 */
export function isDnsName(name: string, options: { allowUnderscore?: boolean } = {}): boolean {
  if (name.length === 0 || name.length > 253) return false;
  const labels = name.split('.');
  if (labels.length < 2) return false;
  if (/^[0-9]+$/.test(labels[labels.length - 1]!)) return false;
  return labels.every(
    (label) => LABEL.test(label) || (options.allowUnderscore === true && SERVICE_LABEL.test(label)),
  );
}

/** True when `name` equals `suffix` or is a subdomain of it (both normalized). */
export function isNameAtOrUnder(name: string, suffix: string): boolean {
  return name === suffix || name.endsWith(`.${suffix}`);
}

const BRACKETED_V6 = /^\[([^\]]+)\]:(\d{1,5})$/;
const V4_WITH_PORT = /^([0-9.]+):(\d{1,5})$/;

function validPort(raw: string): number | null {
  const port = Number(raw);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

/**
 * Parses one `DNS_SERVERS` / system-mode `DNS_PROPAGATION_UPSTREAMS` entry (`ip`, `ip:port`,
 * `[ipv6]:port`, or a bare IPv6 address) into the canonical `ip:port` / `[ipv6]:port` form that
 * `node:dns` `setServers` accepts. Returns null when the entry is not one of those forms.
 */
export function parseDnsServer(entry: string): string | null {
  const value = entry.trim();
  const ipVersion = isIP(value);
  if (ipVersion === 4) return `${value}:53`;
  if (ipVersion === 6) return `[${value}]:53`;
  const v6 = BRACKETED_V6.exec(value);
  if (v6) {
    const port = validPort(v6[2]!);
    return isIP(v6[1]!) === 6 && port !== null ? `[${v6[1]!}]:${port}` : null;
  }
  const v4 = V4_WITH_PORT.exec(value);
  if (v4) {
    const port = validPort(v4[2]!);
    return isIP(v4[1]!) === 4 && port !== null ? `${v4[1]!}:${port}` : null;
  }
  return null;
}

export type DohUrlProblem = 'invalid' | 'insecure' | 'credentials';

/**
 * Validates a DNS-over-HTTPS endpoint (RFC 8484). `https:` always; `http:` only when
 * `allowHttp` (APP_ENV local/ci, for the in-process test server). URLs with userinfo are
 * rejected so upstream ids (logged, stored in evidence) never carry credentials.
 */
export function checkDohUrl(raw: string, allowHttp: boolean): DohUrlProblem | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'invalid';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return 'invalid';
  if (url.protocol === 'http:' && !allowHttp) return 'insecure';
  if (url.username !== '' || url.password !== '') return 'credentials';
  if (url.hash !== '') return 'invalid';
  return null;
}

/** Splits a comma-separated configuration list, dropping empty entries. */
export function splitList(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}
