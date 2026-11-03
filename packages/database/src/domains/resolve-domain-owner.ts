import type { PrismaClient } from '@prisma/client';
import { DomainNameError, normalizeDomainName } from './domain-name';
import type { ActiveDomain } from './resolve-active-domain';

/** Domain statuses whose mail is still ingested for the verified owner (step 2.2 D7). */
export type OwnedDomainStatus = 'active' | 'suspended';
/** Organization statuses whose mail is still ingested (step 2.2 D7). */
export type OwnerOrganizationStatus = 'active' | 'suspended';

/** The verified owner of a domain, for mail that was already accepted in-session. */
export interface DomainOwner extends ActiveDomain {
  status: OwnedDomainStatus;
  organizationStatus: OwnerOrganizationStatus;
}

const isOwnedDomainStatus = (status: string): status is OwnedDomainStatus =>
  status === 'active' || status === 'suspended';

const isOwnerOrganizationStatus = (status: string): status is OwnerOrganizationStatus =>
  status === 'active' || status === 'suspended';

/**
 * Post-queue tenant resolution (step 2.2 D7, D13): who owns the mail for this domain name.
 *
 * Used by LMTP ingestion and the bounce handler, after Postfix already accepted the message
 * in-session (where `resolveActiveDomain` decided). A suspension between acceptance and
 * ingestion must not lose the message, so this also resolves `suspended` domains and
 * `suspended` organizations; the post-queue pipeline decides what happens to the mail.
 *
 * **Writer client only** (data plane, ADR-0014): a replica may lag behind a status change or an
 * ownership transfer. Returns the owner when the name is verified-owned (`domains.verified_name`),
 * the domain is `active` or `suspended`, and the organization is `active` or `suspended`;
 * `null` otherwise: pending claims, `verified` (not yet activated), `failed`, deprecated
 * `disabled` and `deleted` domains, and organizations in any other status (`pending_deletion`,
 * `deleted`).
 *
 * Normalization is the same as `resolveActiveDomain` (case, trailing dot, IDN, test names
 * allowed); an input that is not a valid domain name resolves to `null` without a query.
 * One indexed lookup by the unique `verified_name`.
 */
export async function resolveDomainOwner(
  db: Pick<PrismaClient, 'domain'>,
  rawName: string,
): Promise<DomainOwner | null> {
  let name: string;
  try {
    name = normalizeDomainName(rawName, { allowTestNames: true }).ascii;
  } catch (error) {
    if (error instanceof DomainNameError) return null;
    throw error;
  }

  const domain = await db.domain.findUnique({
    where: { verifiedName: name },
    select: {
      id: true,
      publicId: true,
      organizationId: true,
      name: true,
      status: true,
      inboundEnabled: true,
      outboundEnabled: true,
      organization: { select: { status: true } },
    },
  });
  if (!domain) return null;
  const { status } = domain;
  const organizationStatus = domain.organization.status;
  if (!isOwnedDomainStatus(status) || !isOwnerOrganizationStatus(organizationStatus)) {
    return null;
  }
  return {
    domainId: domain.id,
    domainPublicId: domain.publicId,
    organizationId: domain.organizationId,
    name: domain.name,
    inboundEnabled: domain.inboundEnabled,
    outboundEnabled: domain.outboundEnabled,
    status,
    organizationStatus,
  };
}
