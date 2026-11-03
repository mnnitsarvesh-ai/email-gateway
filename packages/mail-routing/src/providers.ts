import type { TlsMode } from '@email-gateway/database';
import { z } from 'zod';

/**
 * Destination provider presets (step 2.3 R2) and the Postfix answers rendered from destination
 * rows (transport next-hop lists, TLS policies). Presets are configuration data
 * (`mail_destination_presets`), parsed here into a typed view; no provider is special-cased in
 * code.
 */

export const TLS_MODES = [
  'none',
  'opportunistic',
  'required',
  'verify',
] as const satisfies readonly TlsMode[];

/** Postfix `match=` list: host names, `.suffix` entries, `nexthop`/`dot-nexthop`, `:`-separated. */
const TLS_VERIFY_NAMES = /^[A-Za-z0-9.:-]{1,512}$/;
/** A next-hop host inside `[...]`: a normalized name or an IP literal (validated by R3 first). */
const NEXTHOP_HOST = /^[a-z0-9.:-]{1,253}$/;

const hostPattern = z
  .string()
  .min(3)
  .max(512)
  .refine((pattern) => pattern.startsWith('^') && pattern.endsWith('$'), {
    message: 'Host patterns must be anchored (^…$)',
  })
  .transform((pattern, ctx) => {
    try {
      return new RegExp(pattern);
    } catch {
      ctx.addIssue({ code: 'custom', message: `Invalid host pattern ${pattern}` });
      return z.NEVER;
    }
  });

const presetServer = z.object({
  host: z.string().min(1).max(253),
  priority: z.number().int().min(0).max(65_535),
});

/**
 * A `mail_destination_presets` row (Prisma model shape, JSON columns as stored) → the typed view.
 * Throws a ZodError for malformed configuration data.
 */
export const mailDestinationPresetSchema = z
  .object({
    provider: z.enum(['custom', 'microsoft_365', 'google_workspace']),
    displayName: z.string().min(1).max(128),
    hostPatterns: z.array(hostPattern).min(1).max(16),
    hostHint: z.string().max(255).nullable(),
    defaultServers: z.array(presetServer).min(1).max(10).nullable(),
    port: z.number().int().min(1).max(65_535),
    tlsMode: z.enum(TLS_MODES),
    tlsVerifyNames: z.string().regex(TLS_VERIFY_NAMES),
    maxServers: z.number().int().min(1).max(10),
    documentationUrl: z.string().max(512).nullable(),
  })
  .refine((preset) => (preset.defaultServers?.length ?? 1) <= preset.maxServers, {
    message: 'defaultServers exceeds maxServers',
  });

export type MailDestinationPresetView = z.output<typeof mailDestinationPresetSchema>;
export type MailDestinationProviderName = MailDestinationPresetView['provider'];

/** True when the (normalized, lower-case) host matches one of the preset's patterns. */
export function matchesProviderHost(preset: MailDestinationPresetView, host: string): boolean {
  return preset.hostPatterns.some((pattern) => pattern.test(host));
}

/**
 * Postfix 3.5+ next-hop list for the `transport` answer: `smtp:[h1]:p1,[h2]:p2`, in the order
 * given (callers pass rows ordered by priority, id; Postfix tries them in order). Hosts must be
 * validated with validateDestinationHost first; anything else throws.
 */
export function renderTransportNexthops(
  servers: readonly { host: string; port: number }[],
): string {
  if (servers.length === 0) throw new Error('At least one destination server is required');
  const hops = servers.map(({ host, port }) => {
    if (!NEXTHOP_HOST.test(host)) throw new Error('Destination host is not a normalized host');
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new Error('Destination port must be 1-65535');
    }
    return `[${host}]:${port}`;
  });
  return `smtp:${hops.join(',')}`;
}

/**
 * Postfix `smtp_tls_policy_maps` value for a TLS mode: none → `none`; opportunistic → `may`;
 * required → `encrypt protocols=>=TLSv1.2`; verify → `secure match=<verifyNames ?? nexthop>
 * protocols=>=TLSv1.2`. Verify names must match `^[A-Za-z0-9.:-]{1,512}$` (no spaces or `=`, so
 * they can never inject another policy attribute); anything else throws.
 */
export function renderTlsPolicy(mode: TlsMode, verifyNames: string | null): string {
  if (verifyNames !== null && !TLS_VERIFY_NAMES.test(verifyNames)) {
    throw new Error('TLS verify names must match [A-Za-z0-9.:-]{1,512}');
  }
  switch (mode) {
    case 'none':
      return 'none';
    case 'opportunistic':
      return 'may';
    case 'required':
      return 'encrypt protocols=>=TLSv1.2';
    case 'verify':
      return `secure match=${verifyNames ?? 'nexthop'} protocols=>=TLSv1.2`;
    default:
      throw new Error(`Unknown TLS mode ${String(mode)}`);
  }
}

/** The strictest of several TLS modes (none < opportunistic < required < verify); null if none. */
export function strictestTlsMode(modes: readonly TlsMode[]): TlsMode | null {
  let strictest: TlsMode | null = null;
  for (const mode of modes) {
    const rank = TLS_MODES.indexOf(mode);
    if (rank === -1) throw new Error(`Unknown TLS mode ${String(mode)}`);
    if (strictest === null || rank > TLS_MODES.indexOf(strictest)) strictest = mode;
  }
  return strictest;
}
