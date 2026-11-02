import type { PrismaClient } from '@prisma/client';
import { DomainNameError, normalizeDomainName } from './domain-name';

/** The owning tenant of a domain that may receive and send mail through the gateway. */
export interface ActiveDomain {
  domainId: bigint;
  domainPublicId: string;
  organizationId: bigint;
  /** Normalized ASCII name as stored (`domains.name`). */
  name: string;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
}

/**
 * Mail-path tenant resolution (step 2.1 D13; used by the step 2.2 policy server).
 *
 * **Writer client only** (data plane, ADR-0014): a replica may lag behind a suspension or a
 * deletion. Returns `null` unless the name is owned (`domains.verified_name`), the domain is
 * `active` and the owning organization is `active`. Never resolves pending claims, `verified`
 * (not yet activated), `suspended`, deprecated `disabled`, `failed` or `deleted` domains.
 *
 * The input is normalized like the api normalizes stored names (case, trailing dot, IDN);
 * an input that is not a valid domain name resolves to `null`. One indexed lookup by the
 * unique `verified_name`, never by `name` (a name may have several pending claims).
 */
export async function resolveActiveDomain(
  db: Pick<PrismaClient, 'domain'>,
  rawName: string,
): Promise<ActiveDomain | null> {
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
  if (!domain || domain.status !== 'active' || domain.organization.status !== 'active') {
    return null;
  }
  return {
    domainId: domain.id,
    domainPublicId: domain.publicId,
    organizationId: domain.organizationId,
    name: domain.name,
    inboundEnabled: domain.inboundEnabled,
    outboundEnabled: domain.outboundEnabled,
  };
}
