/**
 * Step API-1 (docs/plan/steps/35-api-mode-protection.md §9.5): the API-mode tenant `zeta` of the
 * portal end-to-end run. Synthetic rows only, written on the writer with the columns the api and
 * the mailbox-worker write (never organizations 1, 2, 16946 or user 21416):
 *
 * - four domains: `api.` (own mode `api`, inbound off), `hybrid.` (own mode `hybrid`), `inline.`
 *   (inherits the organization mode `inline`; its MX record points to the gateway, the MX-conflict
 *   target) and `switch.` (inherits, no MX observation: the domain the spec changes);
 * - a bound Microsoft 365 connection with the mail-flow grant and the mailbox-access grant
 *   (`m365.mailbox_remediation`, active) linked to the API and Hybrid domains, and a bound Google
 *   Workspace connection without mailbox access;
 * - a verified, healthy Microsoft 365 journal source of that connection (the intake of the API
 *   connection; no address or token is ever used: nothing is sent);
 * - the API-mode row of the Microsoft 365 connection, four mailboxes, six detections (copies
 *   without content: no message row, no S3 object) and one hourly counter row (lag buckets, one
 *   throttle event).
 *
 * The rows are a state the running mailbox-worker computes again and keeps (the Compose `apps`
 * profile runs it during the portal suite): the inventory ran two hours ago and is next due after
 * `API_MODE_INVENTORY_INTERVAL_HOURS` (6), so the worker never calls a provider with the synthetic
 * grant; feeds are off and three of four in-scope mailboxes were seen in the journal within
 * `API_MODE_JOURNAL_COVERAGE_DAYS`, so its health role (every minute) evaluates exactly the seeded
 * health: `degraded` with the one warning check `coverage.percent` (75 % < 95 %).
 *
 * The run's cleanup (cleanup.ts) deletes the six API-mode tables before the provider connections.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';

export const ZETA = { slug: 'e2e-portal-zeta', name: 'E2E Portal Zeta API mode' } as const;
export const ZETA_DOMAINS = {
  api: 'api.zeta.e2e-portal.test',
  hybrid: 'hybrid.zeta.e2e-portal.test',
  inline: 'inline.zeta.e2e-portal.test',
  switch: 'switch.zeta.e2e-portal.test',
} as const;
export const ZETA_M365_NAME = 'Zeta Contoso (e2e)';
export const ZETA_GOOGLE_NAME = 'Zeta Workspace (e2e)';
export const ZETA_MAILBOXES = [
  { address: `ana@${ZETA_DOMAINS.api}`, domain: 'api', coverage: 'covered' },
  { address: `ben@${ZETA_DOMAINS.api}`, domain: 'api', coverage: 'covered' },
  { address: `cy@${ZETA_DOMAINS.hybrid}`, domain: 'hybrid', coverage: 'gap' },
  { address: `dee@${ZETA_DOMAINS.hybrid}`, domain: 'hybrid', coverage: 'covered' },
] as const;
export const ZETA_DETECTIONS = 6;

export interface ZetaState {
  domains: Record<keyof typeof ZETA_DOMAINS, string>;
  m365ConnectionId: string;
  googleConnectionId: string;
}

const MIN = 60_000;
const HOUR = 60 * MIN;

export async function seedApiMode(
  p: PrismaClient,
  org: { id: bigint; publicId: string },
): Promise<ZetaState> {
  const now = Date.now();
  const at = (ms: number) => new Date(now - ms);
  const domain = async (
    name: string,
    mode: 'api' | 'hybrid' | null,
  ): Promise<{ id: bigint; publicId: string }> =>
    p.domain.create({
      data: {
        organizationId: org.id,
        name,
        status: 'active',
        statusChangedAt: at(2 * HOUR),
        verifiedAt: at(3 * HOUR),
        activatedAt: at(2 * HOUR),
        inboundEnabled: mode !== 'api',
        outboundEnabled: false,
        protectionMode: mode,
        protectionModeChangedAt: mode ? at(HOUR) : null,
      },
      select: { id: true, publicId: true },
    });
  const api = await domain(ZETA_DOMAINS.api, 'api');
  const hybrid = await domain(ZETA_DOMAINS.hybrid, 'hybrid');
  const inline = await domain(ZETA_DOMAINS.inline, null);
  const switchable = await domain(ZETA_DOMAINS.switch, null);
  // The inline domain's MX points to the gateway (the latest definitive observation, D2).
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

  const connection = async (
    provider: 'microsoft_365' | 'google_workspace',
    displayName: string,
  ) => {
    const tenantId = provider === 'microsoft_365' ? randomUUID() : `C0${randomUUID().slice(0, 7)}`;
    return p.providerConnection.create({
      data: {
        organizationId: org.id,
        provider,
        displayName,
        status: 'active',
        externalTenantId: tenantId,
        externalTenantName: `${displayName} tenant`,
        tenantVerifiedAt: at(5 * HOUR),
        activeTenantKey: `${provider}:${tenantId}`,
        healthStatus: 'healthy',
        healthCheckedAt: at(5 * MIN),
        healthChangedAt: at(4 * HOUR),
      },
      select: { id: true, publicId: true },
    });
  };
  const m365 = await connection('microsoft_365', ZETA_M365_NAME);
  const google = await connection('google_workspace', ZETA_GOOGLE_NAME);
  for (const d of [api, hybrid]) {
    await p.providerConnectionDomain.create({
      data: {
        organizationId: org.id,
        connectionId: m365.id,
        domainId: d.id,
        providerVerification: 'verified',
        providerCheckedAt: at(4 * HOUR),
      },
    });
  }
  const grant = (
    connectionId: bigint,
    profile: string,
    authMethod: 'platform_app' | 'platform_service_account',
    permissions: string[],
  ) =>
    p.providerConnectionGrant.create({
      data: {
        organizationId: org.id,
        connectionId,
        profile,
        profileVersion: 1,
        authMethod,
        status: 'active',
        clientId: '00000000-0000-4000-8000-00000000e2e0',
        subjectEmail:
          authMethod === 'platform_service_account' ? `admin@${ZETA_DOMAINS.api}` : null,
        requestedPermissions: permissions,
        observedPermissions: permissions,
        missingPermissions: [],
        excessPermissions: [],
        consentedAt: at(5 * HOUR),
        verifyRequestedAt: at(5 * HOUR),
        verifiedAt: at(5 * HOUR),
      },
    });
  await grant(m365.id, 'm365.mail_flow', 'platform_app', [
    'Organization.Read.All',
    'Domain.Read.All',
  ]);
  await grant(m365.id, 'm365.mailbox_remediation', 'platform_app', [
    'Mail.ReadWrite',
    'User.Read.All',
  ]);
  await grant(google.id, 'google.mail_flow', 'platform_service_account', [
    'https://www.googleapis.com/auth/admin.directory.customer.readonly',
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
  ]);

  // The connection's verified provider journal source (D11.3 `intake.present`), live: its last
  // accepted report is as recent as the mailboxes' journal sightings.
  await p.journalIntakeSource.create({
    data: {
      organizationId: org.id,
      kind: 'microsoft_365_journal',
      displayName: `${ZETA_M365_NAME} journal`,
      status: 'active',
      providerConnectionId: m365.id,
      addressHash: randomBytes(32).toString('hex'),
      verifiedAt: at(4 * HOUR),
      lastAcceptedAt: at(20 * MIN),
      healthStatus: 'healthy',
      healthChangedAt: at(4 * HOUR),
    },
  });

  const apiConnection = await p.apiModeConnection.create({
    data: {
      organizationId: org.id,
      providerConnectionId: m365.id,
      provider: 'microsoft_365',
      inventoryStatus: 'ok',
      inventorySyncedAt: at(2 * HOUR),
      // As the inventory role schedules it after a run: synced + API_MODE_INVENTORY_INTERVAL_HOURS.
      nextInventoryAt: at(-4 * HOUR),
      mailboxesTotal: ZETA_MAILBOXES.length,
      // The document the health role writes for this state (evaluateApiModeHealth, D11.3).
      healthStatus: 'degraded',
      healthChecks: {
        v: 1,
        checks: [
          {
            code: 'connection.active',
            status: 'pass',
            evidence: 'connection active and tenant bound',
          },
          { code: 'intake.present', status: 'pass', evidence: 'verified provider journal source' },
          { code: 'intake.journal_health', status: 'pass', evidence: 'journal source healthy' },
          { code: 'mailbox_access.grant', status: 'pass', evidence: 'mailbox access granted' },
          { code: 'coverage.percent', status: 'warn', evidence: '75% covered (3 of 4)' },
          { code: 'lag.p95_1h', status: 'pass', evidence: 'p95 lag 300 s in the last hour' },
          { code: 'throttling.1h', status: 'pass', evidence: '1 throttle events in the last hour' },
          { code: 'feeds.errors', status: 'pass', evidence: 'feeds disabled' },
          {
            code: 'domains.api_mode_mx',
            status: 'pass',
            evidence: 'no API-mode domain points its MX to the gateway',
          },
        ],
      },
      healthChangedAt: at(HOUR),
    },
    select: { id: true },
  });
  const domainIdOf = { api: api.id, hybrid: hybrid.id } as const;
  const mailboxes: Array<{ id: bigint; address: string }> = [];
  for (const [index, m] of ZETA_MAILBOXES.entries()) {
    const row = await p.apiMailbox.create({
      data: {
        organizationId: org.id,
        apiConnectionId: apiConnection.id,
        providerUserId: `e2e-user-${index}`,
        primaryAddress: m.address,
        domainId: domainIdOf[m.domain],
        status: 'active',
        coverageState: m.coverage,
        coverageChangedAt: at(HOUR),
        journalLastSeenAt: m.coverage === 'covered' ? at(20 * MIN) : null,
        feedStatus: 'off',
      },
      select: { id: true },
    });
    await p.apiMailboxAddress.create({
      data: { organizationId: org.id, mailboxId: row.id, address: m.address, kind: 'primary' },
    });
    mailboxes.push({ id: row.id, address: m.address });
  }
  const verdicts = ['phishing', 'clean', 'malware', 'clean', 'spam', 'clean'] as const;
  for (let i = 0; i < ZETA_DETECTIONS; i++) {
    const receivedAt = at((i + 1) * 25 * MIN);
    const lagMs = 30_000 + i * 45_000;
    const verdict = verdicts[i % verdicts.length]!;
    await p.apiMessageCopy.create({
      data: {
        receivedAt,
        publicId: randomUUID(),
        organizationId: org.id,
        apiConnectionId: apiConnection.id,
        mailboxId: mailboxes[i % mailboxes.length]!.id,
        // A registry id that no message row uses: the copy has no content in this run.
        messageId: BigInt(9_000_000_000_000 + now + i),
        source: 'journal',
        seenJournal: true,
        status: 'scanned',
        verdict,
        riskScore: verdict === 'clean' ? 40 : 880,
        verdictAt: new Date(receivedAt.getTime() + lagMs / 2),
        providerDeliveredAt: new Date(receivedAt.getTime() - lagMs / 2),
        deliveredBasis: 'received_header',
        lagMs,
      },
    });
  }
  const hour = new Date(Math.floor(now / HOUR) * HOUR);
  await p.apiModeCounter.create({
    data: {
      organizationId: org.id,
      apiConnectionId: apiConnection.id,
      hour,
      journalCopies: ZETA_DETECTIONS,
      lagCount: ZETA_DETECTIONS,
      lagLe60s: 1,
      lagLe300s: 5,
      lagMaxMs: 255_000,
      lagSumMs: BigInt(6 * 142_500),
      throttled429: 1,
      providerRequests: 40,
    },
  });
  return {
    domains: {
      api: api.publicId,
      hybrid: hybrid.publicId,
      inline: inline.publicId,
      switch: switchable.publicId,
    },
    m365ConnectionId: m365.publicId,
    googleConnectionId: google.publicId,
  };
}
