import type { DomainStatus } from '@email-gateway/database';

/**
 * Gateway domain statuses a provider connection may link (step 8.2 D4 as amended by step API-4
 * B4, ADR-0107; docs/plan/steps/38-api-mode-parity-onboarding.md): ownership proven (`verified`)
 * or activated (`active`). `pending_verification`, `failed`, `suspended` and `deleted` domains are
 * refused (`422 domain_not_verified`). The provider relay still needs `active` + outbound (8.2
 * D7), and the integration-worker's tenant binding counts only DNS-TXT-proven domains.
 */
export const LINKABLE_DOMAIN_STATUSES: ReadonlySet<DomainStatus> = new Set<DomainStatus>([
  'verified',
  'active',
]);

/** B4: a domain in this gateway status can be linked to a provider connection. */
export function isLinkableDomainStatus(status: string): boolean {
  return (LINKABLE_DOMAIN_STATUSES as ReadonlySet<string>).has(status);
}
