import {
  resolveDomainOwner,
  type MailDestinationProvider,
  type PrismaClient,
  type TlsMode,
} from '@email-gateway/database';
import { mailDestinationPresetSchema, type MailDestinationPresetView } from './providers';
import type { DomainView } from './route-plan';

/**
 * Writer-side loaders for routing decisions (ADR-0014: a replica may lag behind a suspension,
 * an ownership transfer or a destination change, so mail decisions read the writer). Every
 * loader accepts the PrismaClient or an interactive transaction client.
 */

/**
 * Ownership of each recipient domain, keyed by the input string (pass recipientDomain(address)):
 * resolveDomainOwner semantics (verified owner; `active` or `suspended` domain and organization),
 * `ownerStatus = active` only when both are active (exactly what resolveActiveDomain would
 * return), `suspended` when either is suspended, `none` without an owner.
 */
export async function loadDomainViews(
  prisma: Pick<PrismaClient, 'domain'>,
  domains: readonly string[],
): Promise<Map<string, DomainView>> {
  const views = new Map<string, DomainView>();
  for (const domain of new Set(domains)) {
    const owner = await resolveDomainOwner(prisma, domain);
    views.set(
      domain,
      owner === null
        ? { domainId: null, ownerOrganizationId: null, ownerStatus: 'none' }
        : {
            domainId: owner.domainId,
            ownerOrganizationId: owner.organizationId,
            ownerStatus:
              owner.status === 'active' && owner.organizationStatus === 'active'
                ? 'active'
                : 'suspended',
          },
    );
  }
  return views;
}

const SUPPRESSION_CHUNK = 500;

/**
 * The organization's active suppressions (no expiry, or expiring in the future) among
 * `addresses`, as lower-cased addresses. Matching is exact after lower-casing (the column's
 * accent-insensitive collation only pre-filters).
 */
export async function loadActiveSuppressions(
  prisma: Pick<PrismaClient, 'deliverySuppression'>,
  organizationId: bigint,
  addresses: readonly string[],
  now: Date = new Date(),
): Promise<Set<string>> {
  const wanted = [...new Set(addresses.map((address) => address.toLowerCase()))];
  const suppressed = new Set<string>();
  for (let i = 0; i < wanted.length; i += SUPPRESSION_CHUNK) {
    const chunk = wanted.slice(i, i + SUPPRESSION_CHUNK);
    const rows = await prisma.deliverySuppression.findMany({
      where: {
        organizationId,
        address: { in: chunk },
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: { address: true },
    });
    const inChunk = new Set(chunk);
    for (const row of rows) {
      const address = row.address.toLowerCase();
      if (inChunk.has(address)) suppressed.add(address);
    }
  }
  return suppressed;
}

export interface InboundDestination {
  publicId: string;
  host: string;
  port: number;
  priority: number;
  tlsMode: TlsMode;
  /** Postfix match= list; null = nexthop. */
  tlsVerifyNames: string | null;
  provider: MailDestinationProvider;
}

/** Upper bound of rows read per domain (the api allows ROUTING_MAX_DESTINATIONS_PER_DOMAIN). */
const MAX_DESTINATION_ROWS = 100;

/**
 * The domain's enabled `inbound_destination` servers with a host, ordered by (priority, id):
 * the next-hop order Postfix tries. Hosts are returned as stored; callers re-validate them with
 * validateDestinationHost before answering Postfix.
 */
export async function loadInboundDestinations(
  prisma: Pick<PrismaClient, 'domainMailServer'>,
  domainId: bigint,
): Promise<InboundDestination[]> {
  const rows = await prisma.domainMailServer.findMany({
    where: { domainId, role: 'inbound_destination', enabled: true, host: { not: null } },
    orderBy: [{ priority: 'asc' }, { id: 'asc' }],
    select: {
      publicId: true,
      host: true,
      port: true,
      priority: true,
      tlsMode: true,
      tlsVerifyNames: true,
      provider: true,
    },
    take: MAX_DESTINATION_ROWS,
  });
  return rows.map((row) => ({ ...row, host: row.host! }));
}

/**
 * The enabled provider presets, parsed (patterns compiled). A malformed preset row throws: it
 * is reviewed configuration data, and answering with a half-understood preset is worse than
 * failing closed.
 */
export async function loadDestinationPresets(
  prisma: Pick<PrismaClient, 'mailDestinationPreset'>,
): Promise<MailDestinationPresetView[]> {
  const rows = await prisma.mailDestinationPreset.findMany({
    where: { enabled: true },
    orderBy: { provider: 'asc' },
  });
  return rows.map((row) => mailDestinationPresetSchema.parse(row));
}
