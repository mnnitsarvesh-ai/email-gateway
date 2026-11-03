import { domainToASCII } from 'node:url';
import { matchesProviderHost, type MailDestinationPresetView } from './providers';
import {
  formatIpAddress,
  isMetadataAddress,
  isPublicIpAddress,
  parseIpAddress,
} from './special-addresses';

/**
 * Destination host safety (step 2.3 R3). Used by the api when destinations are written and by
 * the smtp-adapter on every transport / tls_policy answer, so a row written directly to the
 * database is re-checked before Postfix ever connects to it.
 */

/** Stable refusal reasons; the api answers `422` with one of them. */
export const DESTINATION_HOST_REFUSALS = [
  'ip_not_public',
  'metadata_address',
  'single_label',
  'internal_suffix',
  'gateway_host',
  'invalid_host',
  'port_not_allowed',
  'host_not_allowed_for_provider',
] as const;
export type DestinationHostRefusal = (typeof DESTINATION_HOST_REFUSALS)[number];

/**
 * Built-in refused suffixes: mDNS, loopback, private-use and orchestration names (a name equal
 * to the suffix or under it). `ROUTING_DENIED_DESTINATION_SUFFIXES` adds to this list.
 */
export const BUILT_IN_DENIED_SUFFIXES: readonly string[] = Object.freeze([
  'local',
  'localhost',
  'localdomain',
  'internal',
  'intranet',
  'lan',
  'home.arpa',
  'svc',
  'cluster.local',
  'consul',
]);

/** Cloud metadata service names, refused as `metadata_address` (with or without a suffix). */
const METADATA_NAMES: readonly string[] = Object.freeze([
  'metadata.google.internal',
  'instance-data',
]);

/** Refused exactly (a single label, but listed for clarity and future multi-label entries). */
const DENIED_NAMES: readonly string[] = Object.freeze(['localhost']);

/**
 * Default `ROUTING_ALLOWED_DESTINATION_PORTS`: SMTP relay (25), submission (587) and the common
 * alternative relay port (2525). Implicit-TLS 465 is not listed: postfix-outbound's `smtp`
 * transport speaks STARTTLS only.
 */
export const DEFAULT_ALLOWED_DESTINATION_PORTS: readonly number[] = Object.freeze([25, 587, 2525]);

/**
 * Ports of the gateway's own internal listeners and data services (Postfix reinjection and
 * content-filter listeners, the smtp-adapter LMTP/policy/socketmap listeners, Rspamd, ClamAV,
 * DNS, MySQL, Redis, RabbitMQ, MinIO). A destination on one of them is refused even when an
 * operator lists it in `ROUTING_ALLOWED_DESTINATION_PORTS` (review fix: a tenant-controlled name
 * resolving to a VPC address must never turn postfix-outbound into a client of an internal
 * listener; the network control in docs/deployment/mail-routing.md is the second layer).
 */
export const DENIED_DESTINATION_PORTS: readonly number[] = Object.freeze([
  53, 3306, 3310, 5672, 6379, 9000, 9001, 10024, 10025, 10026, 10027, 10040, 10041, 10042, 10050,
  10051, 10052, 11332, 11333, 11334, 15672,
]);

/**
 * Parses `ROUTING_ALLOWED_DESTINATION_PORTS` (comma list; empty → the default list). Throws on a
 * non-numeric entry, a port outside 1–65535 or one of DENIED_DESTINATION_PORTS, so a
 * configuration can never allow an internal listener.
 */
export function parseAllowedDestinationPorts(value: string | undefined): number[] {
  if (value === undefined || value.trim() === '') return [...DEFAULT_ALLOWED_DESTINATION_PORTS];
  const ports = value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      if (!/^\d{1,5}$/.test(entry)) throw new Error(`invalid port "${entry.slice(0, 16)}"`);
      const port = Number(entry);
      if (port < 1 || port > 65535) throw new Error(`port ${port} is out of range`);
      if (DENIED_DESTINATION_PORTS.includes(port)) {
        throw new Error(`port ${port} is an internal gateway port and cannot be allowed`);
      }
      return port;
    });
  if (ports.length === 0) return [...DEFAULT_ALLOWED_DESTINATION_PORTS];
  return [...new Set(ports)];
}

export interface ValidateDestinationHostOptions {
  /** `ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS`: accept non-public IP literals (never metadata). */
  allowNonPublic: boolean;
  /** `ROUTING_DENIED_DESTINATION_SUFFIXES`, in addition to the built-in list. */
  deniedSuffixes: readonly string[];
  /** `GATEWAY_MX_HOSTS`, `POSTFIX_MYHOSTNAME`, `POSTFIX_OUTBOUND_MYHOSTNAME` (any case). */
  gatewayHosts: ReadonlySet<string>;
  /** The gateway's bounce domain; the name and every name under it are refused. */
  bounceDomain?: string;
  /** Preset the host must belong to: its patterns and its port only. */
  provider?: MailDestinationPresetView | null;
  /**
   * `ROUTING_ALLOWED_DESTINATION_PORTS` for custom servers (default
   * DEFAULT_ALLOWED_DESTINATION_PORTS). A preset's own port is always allowed for that preset.
   * DENIED_DESTINATION_PORTS are refused in every case.
   */
  allowedPorts?: readonly number[];
}

export type DestinationHostResult =
  { ok: true; host: string; port: number } | { ok: false; reason: DestinationHostRefusal };

const MAX_INPUT_LENGTH = 1024;
const MAX_NAME_LENGTH = 253;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const NUMERIC_LABEL = /^[0-9]+$/;
/** Characters a host name may contain before IDNA (letters of any script, digits, dot, hyphen). */
const NAME_INPUT = /^[\p{L}\p{M}\p{N}.\-。．｡]+$/u;

/** Lower case, no leading or trailing dot. Empty for unusable input. */
function normalizeSuffix(suffix: string): string {
  return suffix.trim().toLowerCase().replace(/^\.+/, '').replace(/\.$/, '');
}

const isAtOrUnder = (name: string, suffix: string): boolean =>
  suffix.length > 0 && (name === suffix || name.endsWith(`.${suffix}`));

/** Lower case, one trailing dot stripped: the comparable form of a configured gateway host. */
export function normalizeHostForComparison(host: string): string {
  const lower = host.trim().toLowerCase();
  const unbracketed = lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;
  const ip = parseIpAddress(unbracketed);
  if (ip) return formatIpAddress(ip);
  return unbracketed.endsWith('.') ? unbracketed.slice(0, -1) : unbracketed;
}

const refuse = (reason: DestinationHostRefusal): DestinationHostResult => ({ ok: false, reason });

function isGatewayHost(host: string, options: ValidateDestinationHostOptions): boolean {
  for (const gateway of options.gatewayHosts) {
    if (normalizeHostForComparison(gateway) === host) return true;
  }
  if (options.bounceDomain !== undefined) {
    const bounce = normalizeSuffix(options.bounceDomain);
    if (isAtOrUnder(host, bounce)) return true;
  }
  return false;
}

function validatePort(port: number, options: ValidateDestinationHostOptions): boolean {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  if (DENIED_DESTINATION_PORTS.includes(port)) return false;
  if (options.provider) return port === options.provider.port;
  return (options.allowedPorts ?? DEFAULT_ALLOWED_DESTINATION_PORTS).includes(port);
}

/**
 * Validates and normalizes one destination server (R3):
 *
 * 1. Normalize: trim, lower case, strip one trailing dot, IDNA to ASCII (`domainToASCII`); LDH
 *    labels of 1–63 characters, total ≤ 253, last label not all-numeric (`invalid_host`). Port:
 *    the preset's port when a provider is given, else one of `allowedPorts` (default 25, 587,
 *    2525); never one of DENIED_DESTINATION_PORTS (`port_not_allowed`).
 * 2. IP literals (`1.2.3.4`, `[1.2.3.4]`, IPv6 with or without brackets): metadata addresses are
 *    always refused (`metadata_address`); other addresses must be globally reachable unless
 *    `allowNonPublic` (`ip_not_public`).
 * 3. Names: metadata service names (`metadata_address`), single labels (`single_label`), the
 *    built-in and configured suffixes (`internal_suffix`), gateway hosts and the bounce domain
 *    (`gateway_host`).
 * 4. With a provider preset: the host must match one of its patterns
 *    (`host_not_allowed_for_provider`).
 *
 * Resolved addresses are deliberately not checked (R3.4).
 */
export function validateDestinationHost(
  host: string,
  port: number,
  options: ValidateDestinationHostOptions,
): DestinationHostResult {
  if (typeof host !== 'string' || host.length === 0 || host.length > MAX_INPUT_LENGTH) {
    return refuse('invalid_host');
  }
  let text = host.trim();
  const bracketed = text.startsWith('[') && text.endsWith(']');
  if (bracketed) text = text.slice(1, -1);
  if (text.length === 0) return refuse('invalid_host');

  const ip = parseIpAddress(text);
  if (bracketed && !ip) return refuse('invalid_host');
  if (!validatePort(port, options)) return refuse('port_not_allowed');

  if (ip) {
    const canonical = formatIpAddress(ip);
    if (isMetadataAddress(canonical)) return refuse('metadata_address');
    if (!options.allowNonPublic && !isPublicIpAddress(canonical)) return refuse('ip_not_public');
    if (isGatewayHost(canonical, options)) return refuse('gateway_host');
    if (options.provider) return refuse('host_not_allowed_for_provider');
    return { ok: true, host: canonical, port };
  }

  if (!NAME_INPUT.test(text)) return refuse('invalid_host');
  const withoutDot = text.endsWith('.') ? text.slice(0, -1) : text;
  if (withoutDot.length === 0 || withoutDot.endsWith('.')) return refuse('invalid_host');
  const ascii = domainToASCII(withoutDot.toLowerCase()).toLowerCase();
  if (ascii.length === 0 || ascii.length > MAX_NAME_LENGTH) return refuse('invalid_host');
  const labels = ascii.split('.');
  if (labels.some((label) => !LABEL.test(label))) return refuse('invalid_host');
  if (NUMERIC_LABEL.test(labels.at(-1)!)) return refuse('invalid_host');

  if (METADATA_NAMES.some((name) => isAtOrUnder(ascii, name))) {
    return refuse('metadata_address');
  }
  if (labels.length < 2 || DENIED_NAMES.includes(ascii)) return refuse('single_label');
  const suffixes = [...BUILT_IN_DENIED_SUFFIXES, ...options.deniedSuffixes.map(normalizeSuffix)];
  if (suffixes.some((suffix) => isAtOrUnder(ascii, suffix))) return refuse('internal_suffix');
  if (isGatewayHost(ascii, options)) return refuse('gateway_host');
  if (options.provider && !matchesProviderHost(options.provider, ascii)) {
    return refuse('host_not_allowed_for_provider');
  }
  return { ok: true, host: ascii, port };
}
