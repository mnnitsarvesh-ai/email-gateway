/**
 * Delivery error classes (step 2.3 R9.2), stored in `email_deliveries.last_error_class`,
 * `delivery_reinjections.last_error_class` and every audit row.
 *
 * `classifyDeliveryError` derives the class of a Postfix delivery text. The `gateway_*` and
 * `reinjection_*` classes describe the worker's own hop and are set by the worker directly.
 */
export const DELIVERY_ERROR_CLASSES = [
  'connect',
  'dns',
  'tls',
  'timeout',
  'remote_4xx',
  'remote_5xx',
  'no_destination',
  'loop',
  'gateway_rate_limited',
  'gateway_rate_limit_unavailable',
  'gateway_hold',
  'reinjection_4xx',
  'reinjection_error',
  'other',
] as const;
export type DeliveryErrorClass = (typeof DELIVERY_ERROR_CLASSES)[number];

const RULES: readonly (readonly [RegExp, DeliveryErrorClass])[] = [
  // Postfix's own loop detection (the next hop is this MTA).
  [/\bloops back to myself\b/i, 'loop'],
  // The smtp-adapter's transport answer for a tenant domain without a usable destination.
  [/\bDestination not configured\b/i, 'no_destination'],
  // A reply of the remote server: `host h[ip] said: 451 4.3.0 …` / `refused to talk to me: 554 …`.
  [/\b(?:said|refused to talk to me):\s*4\d\d\b/i, 'remote_4xx'],
  [/\b(?:said|refused to talk to me):\s*5\d\d\b/i, 'remote_5xx'],
  // TLS policy and certificate failures of the smtp client.
  [
    /\bTLS is required, but\b|\bServer certificate not (?:verified|trusted)\b|\bcertificate verification failed\b|\bCannot start TLS\b|\bTLS handshake failed\b|\bserver certificate.*\bnot match\b/i,
    'tls',
  ],
  // Resolution failures.
  [
    /\bHost or domain name not found\b|\bName service error\b|\bHost not found\b|\bno MX host\b|\bDomain not found\b|\bhas invalid address\b/i,
    'dns',
  ],
  // TCP connection failures (before the greeting), including "Connection timed out".
  [
    /\bconnect to \S+: (?:Connection refused|Connection timed out|No route to host|Network is unreachable|Host is unreachable|Connection reset by peer|Operation timed out)\b/i,
    'connect',
  ],
  // Session-level timeouts and dropped connections after the TCP connect.
  [
    /\bconversation with \S+ timed out\b|\blost connection with \S+\b|\btimed out while\b/i,
    'timeout',
  ],
];

/**
 * Class of a Postfix delivery text (the parenthesized `status=… (text)` part, a DSN diagnostic
 * or a reply): `loop`, `no_destination`, `remote_4xx`, `remote_5xx`, `tls`, `dns`, `connect`,
 * `timeout`, else `other`. A remote reply wins over the generic patterns (a `530 Must issue a
 * STARTTLS command` is a remote 5xx). An unmatched text that starts with a reply code is a
 * remote reply; otherwise the DSN's network/routing subject (`x.4.1` connect, `x.4.2` timeout,
 * `x.4.3`/`x.4.4` dns, `x.4.6` loop) decides, else `other`.
 */
export function classifyDeliveryError(text: string, dsn: string | null): DeliveryErrorClass {
  const value = typeof text === 'string' ? text : '';
  for (const [pattern, errorClass] of RULES) {
    if (pattern.test(value)) return errorClass;
  }
  const bare = /^\s*([45])\d\d\b/.exec(value);
  if (bare) return bare[1] === '4' ? 'remote_4xx' : 'remote_5xx';
  // RFC 3463 network and routing subjects, when the text says nothing more specific.
  const subject = dsn !== null ? /^[45]\.4\.(\d{1,3})$/.exec(dsn)?.[1] : undefined;
  if (subject !== undefined) {
    const bySubject: Readonly<Record<string, DeliveryErrorClass>> = {
      '1': 'connect', // no answer from host
      '2': 'timeout', // bad connection
      '3': 'dns', // directory server failure
      '4': 'dns', // unable to route
      '6': 'loop', // routing loop detected
    };
    const fromDsn = bySubject[subject];
    if (fromDsn) return fromDsn;
  }
  return 'other';
}
