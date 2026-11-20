/**
 * Identity scope of an integration (invariant 4, WP2-10): only identities whose primary address or
 * UPN is in one of the integration's provider-verified linked domains are observed. The adapters
 * apply it before any mailbox impersonation, rules read or `mailboxState.write`, so nothing is read
 * or stored for users of domains the organization never linked (data minimisation); the ato-worker
 * runner applies the same rule again to the emitted events (`foreign_domain`).
 */
import type { ProviderIdentityRef } from '../port/ato-port';
import type { ProviderSession } from './session';
import { domainOf } from './hash';

const GUEST = /#ext#/i;

/**
 * The scope domains: the integration's `directory_domains` (provider-verified, written by the
 * probe loop), else the connection's provider-verified linked domains.
 */
export function scopeDomains(
  integrationDomains: readonly string[] | undefined,
  session: ProviderSession,
): ReadonlySet<string> {
  const names =
    integrationDomains && integrationDomains.length > 0
      ? integrationDomains
      : session.view.linkedDomains.filter((d) => d.providerVerified).map((d) => d.name);
  return new Set(names.map((name) => name.toLowerCase()));
}

/** Whether an identity is a member (not a guest) of one of the scope domains. */
export function inScope(identity: ProviderIdentityRef, domains: ReadonlySet<string>): boolean {
  const address = identity.primaryEmail ?? identity.userPrincipalName ?? '';
  if (GUEST.test(address) || GUEST.test(identity.userPrincipalName ?? '')) return false;
  const domain = domainOf(address);
  return domain !== null && domains.has(domain);
}
