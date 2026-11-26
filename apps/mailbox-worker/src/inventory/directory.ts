import type { GoogleDirectoryUser, GraphMailUser } from '@email-gateway/mailbox-api';

/** One provider user as the inventory stores it (lower-case addresses, D11.1). */
export interface DirectoryUser {
  providerUserId: string;
  primary: string;
  /** Other addresses of the mailbox (never the primary), de-duplicated. */
  aliases: string[];
  /** `accountEnabled = false` / suspended / archived → false (mailbox `disabled`). */
  enabled: boolean;
}

const ADDRESS = /^[^@\s<>()"]{1,256}@[a-z0-9.-]{1,253}$/;

/** A lower-case addr-spec, or null when it is not one. */
export function normalizeAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  const address = value.trim().toLowerCase().replace(/\.$/, '');
  return address.length <= 320 && ADDRESS.test(address) ? address : null;
}

function unique(primary: string, values: Iterable<string | null>): string[] {
  const out: string[] = [];
  for (const value of values) {
    if (value !== null && value !== primary && !out.includes(value)) out.push(value);
  }
  return out;
}

/**
 * A Graph user: primary = the `SMTP:` proxy address, else `mail`, else the UPN; aliases = the other
 * `smtp:` proxy addresses and `mail` (X500, SIP and other proxy types are ignored).
 */
export function fromGraphUser(user: GraphMailUser): DirectoryUser | null {
  const smtp = user.proxyAddresses.filter((p) => /^smtp:/i.test(p));
  const primaryProxy = smtp.find((p) => p.startsWith('SMTP:'));
  const primary =
    normalizeAddress(primaryProxy?.slice(5)) ??
    normalizeAddress(user.mail) ??
    normalizeAddress(user.userPrincipalName);
  if (!primary) return null;
  return {
    providerUserId: user.id,
    primary,
    aliases: unique(primary, [
      ...smtp.map((p) => normalizeAddress(p.slice(5))),
      normalizeAddress(user.mail),
    ]),
    enabled: user.accountEnabled !== false,
  };
}

/** A Google Directory user: `primaryEmail` and `aliases`; suspended or archived = disabled. */
export function fromGoogleUser(user: GoogleDirectoryUser): DirectoryUser | null {
  const primary = normalizeAddress(user.primaryEmail);
  if (!primary) return null;
  return {
    providerUserId: user.id,
    primary,
    aliases: unique(
      primary,
      user.aliases.map((a) => normalizeAddress(a)),
    ),
    enabled: !user.suspended && !user.archived,
  };
}

/** D11.1: kept when the primary or an alias is in a domain linked to the connection. */
export function inScope(user: DirectoryUser, linkedDomains: ReadonlySet<string>): boolean {
  return [user.primary, ...user.aliases].some((a) =>
    linkedDomains.has(a.slice(a.indexOf('@') + 1)),
  );
}
