/**
 * Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md §10.5): the onboarding tenant
 * `eta` of the portal end-to-end run (enterprise plan: `api_mode_protection` and
 * `journal_intake` are on). Synthetic rows only, written on the writer with the columns the api
 * and the workers write (never organizations 1, 2, 16946 or user 21416):
 *
 * - `bound.` — an active domain proven by DNS TXT (`ownership_method = dns_txt`) in API mode,
 *   linked to the Microsoft 365 connection: the binding proof of the tenant (B3.5);
 * - `inline.` — an active inline domain (inherits the organization mode `inline`), the domain
 *   page's inline case;
 * - a bound Microsoft 365 connection with the read-only mail-flow grant and the mailbox-access
 *   grant (`m365.mailbox_remediation`), both active: `ownership.providerCheckAvailable` is true
 *   for a pending domain of the organization (B3.1) and the wizard's connect step is done once a
 *   domain is linked;
 * - a verified, healthy journal source of that connection (the intake step is done) and its
 *   API-mode connection row (the spec seeds a mailbox and a copy of a new domain on it).
 *
 * The spec creates its own domains through the wizard and uses two test seams on the writer,
 * each documented where it is used: the integration-worker's answer to a provider ownership
 * check (`domain_verifications.provider_result`, applied by the api's DomainCheckScheduler) and
 * the mailbox-worker's rows of a first copy (mailbox, copy). Nothing is sent and no provider is
 * contacted.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';

export const ETA = { slug: 'e2e-portal-eta', name: 'E2E Portal Eta onboarding' } as const;
export const ETA_DOMAINS = {
  bound: 'bound.eta.e2e-portal.test',
  inline: 'inline.eta.e2e-portal.test',
} as const;
/** The zone the spec's own domains are created under (`<label>.eta-new.e2e-portal.test`). */
export const ETA_NEW_ZONE = 'eta-new.e2e-portal.test';
export const ETA_M365_NAME = 'Eta Contoso (e2e)';

export interface EtaState {
  domains: Record<keyof typeof ETA_DOMAINS, string>;
  domainNames: Record<keyof typeof ETA_DOMAINS, string>;
  m365ConnectionId: string;
  m365Name: string;
  journalSourceId: string;
}

const MIN = 60_000;
const HOUR = 60 * MIN;

export async function seedOnboarding(
  p: PrismaClient,
  org: { id: bigint; publicId: string },
): Promise<EtaState> {
  const now = Date.now();
  const at = (ms: number) => new Date(now - ms);
  const domain = (name: string, mode: 'api' | null) =>
    p.domain.create({
      data: {
        organizationId: org.id,
        name,
        status: 'active',
        statusChangedAt: at(2 * HOUR),
        verifiedAt: at(3 * HOUR),
        activatedAt: at(2 * HOUR),
        ownershipMethod: 'dns_txt',
        inboundEnabled: mode !== 'api',
        outboundEnabled: false,
        protectionMode: mode,
        protectionModeChangedAt: mode ? at(HOUR) : null,
      },
      select: { id: true, publicId: true },
    });
  const bound = await domain(ETA_DOMAINS.bound, 'api');
  const inline = await domain(ETA_DOMAINS.inline, null);
  await p.domainMxRecord.create({
    data: {
      organizationId: org.id,
      domainId: inline.id,
      priority: 10,
      host: 'mx1.gateway.e2e-portal.test',
      pointsToGateway: true,
      lastSeenAt: at(10 * MIN),
    },
  });

  const tenantId = randomUUID();
  const m365 = await p.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: ETA_M365_NAME,
      status: 'active',
      externalTenantId: tenantId,
      externalTenantName: `${ETA_M365_NAME} tenant`,
      tenantVerifiedAt: at(5 * HOUR),
      activeTenantKey: `microsoft_365:${tenantId}`,
      healthStatus: 'healthy',
      healthCheckedAt: at(5 * MIN),
      healthChangedAt: at(4 * HOUR),
    },
    select: { id: true, publicId: true },
  });
  await p.providerConnectionDomain.create({
    data: {
      organizationId: org.id,
      connectionId: m365.id,
      domainId: bound.id,
      providerVerification: 'verified',
      providerCheckedAt: at(4 * HOUR),
    },
  });
  for (const [profile, permissions] of [
    ['m365.mail_flow', ['Organization.Read.All', 'Domain.Read.All']],
    ['m365.mailbox_remediation', ['Mail.ReadWrite', 'User.Read.All']],
  ] as const) {
    await p.providerConnectionGrant.create({
      data: {
        organizationId: org.id,
        connectionId: m365.id,
        profile,
        profileVersion: 1,
        authMethod: 'platform_app',
        status: 'active',
        clientId: '00000000-0000-4000-8000-00000000e2e1',
        requestedPermissions: [...permissions],
        observedPermissions: [...permissions],
        missingPermissions: [],
        excessPermissions: [],
        consentedAt: at(5 * HOUR),
        verifyRequestedAt: at(5 * HOUR),
        verifiedAt: at(5 * HOUR),
      },
    });
  }
  const source = await p.journalIntakeSource.create({
    data: {
      organizationId: org.id,
      kind: 'microsoft_365_journal',
      displayName: `${ETA_M365_NAME} journal`,
      status: 'active',
      providerConnectionId: m365.id,
      addressHash: randomBytes(32).toString('hex'),
      verifiedAt: at(4 * HOUR),
      lastAcceptedAt: at(20 * MIN),
      healthStatus: 'healthy',
      healthChangedAt: at(4 * HOUR),
    },
    select: { publicId: true },
  });
  await p.apiModeConnection.create({
    data: {
      organizationId: org.id,
      providerConnectionId: m365.id,
      provider: 'microsoft_365',
      inventoryStatus: 'ok',
      inventorySyncedAt: at(2 * HOUR),
      nextInventoryAt: at(-4 * HOUR),
      mailboxesTotal: 0,
      healthStatus: 'unknown',
    },
  });
  return {
    domains: { bound: bound.publicId, inline: inline.publicId },
    domainNames: { ...ETA_DOMAINS },
    m365ConnectionId: m365.publicId,
    m365Name: ETA_M365_NAME,
    journalSourceId: source.publicId,
  };
}

/**
 * Test seam (mailbox-worker): a mailbox of a domain created by the spec on eta's API-mode
 * connection, and optionally its first scanned copy (the onboarding read's first copy, B8).
 */
export async function seedEtaMailbox(
  p: PrismaClient,
  input: { organizationId: bigint; domainId: bigint; address: string },
): Promise<{ mailboxId: bigint; apiConnectionId: bigint }> {
  const connection = await p.apiModeConnection.findFirstOrThrow({
    where: { organizationId: input.organizationId },
    select: { id: true },
  });
  const mailbox = await p.apiMailbox.create({
    data: {
      organizationId: input.organizationId,
      apiConnectionId: connection.id,
      providerUserId: `e2e-eta-${randomUUID()}`,
      primaryAddress: input.address,
      domainId: input.domainId,
      status: 'active',
      coverageState: 'gap',
      coverageChangedAt: new Date(),
      feedStatus: 'off',
    },
    select: { id: true },
  });
  await p.apiMailboxAddress.create({
    data: {
      organizationId: input.organizationId,
      mailboxId: mailbox.id,
      address: input.address,
      kind: 'primary',
    },
  });
  return { mailboxId: mailbox.id, apiConnectionId: connection.id };
}

/** Test seam (mailbox-worker): the first scanned journal copy of a mailbox (no content). */
export async function seedEtaFirstCopy(
  p: PrismaClient,
  input: { organizationId: bigint; mailboxId: bigint; apiConnectionId: bigint },
): Promise<string> {
  const now = Date.now();
  const publicId = randomUUID();
  await p.apiMessageCopy.create({
    data: {
      receivedAt: new Date(now - 30_000),
      publicId,
      organizationId: input.organizationId,
      apiConnectionId: input.apiConnectionId,
      mailboxId: input.mailboxId,
      // A registry id no message row uses: the copy has no content in this run.
      messageId: BigInt(9_100_000_000_000 + now),
      source: 'journal',
      seenJournal: true,
      status: 'scanned',
      verdict: 'clean',
      riskScore: 30,
      verdictAt: new Date(now - 10_000),
      providerDeliveredAt: new Date(now - 50_000),
      deliveredBasis: 'received_header',
      lagMs: 40_000,
      policyState: 'evaluated',
      policyDisposition: 'allow',
    },
  });
  return publicId;
}
