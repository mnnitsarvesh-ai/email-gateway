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
 * Step API-2 (docs/plan/steps/36-api-mode-remediation.md §9.5) adds four scanned copies with their
 * registry message (`mailbox_api`, `journaled`) and recipient row, and the rows the mailbox-worker
 * leaves after its remediation decisions (no provider is contacted): a hard-blocked malware copy
 * moved to the quarantine folder with its mailbox-located quarantine entry (its release needs an
 * approver), a phishing copy whose quarantine-folder move failed (`provider_unavailable`, the
 * History tab's retry target), a suspicious copy tagged by the policy (the "Remove tag" target)
 * and a phishing copy without remediation (the "Remediate…" target). No policy row: the platform
 * default P1 applies until the spec saves one.
 *
 * The run's cleanup (cleanup.ts) deletes the API-mode tables (remediation actions and policies
 * first) before the provider connections.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
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
/** Step API-2: the copies with a registry message and remediation rows (seedRemediation). */
export const ZETA_REMEDIATION_COPIES = 4;

export interface ZetaRemediationState {
  /** The hard-blocked copy moved to the quarantine folder and its mailbox entry. */
  quarantinedDetectionId: string;
  entryId: string;
  /** The failed quarantine-folder move (History retry). */
  failedActionId: string;
  failedDetectionId: string;
  /** The copy tagged by the policy (Remove tag). */
  taggedDetectionId: string;
  /** The phishing copy without remediation (Remediate…). */
  remediableDetectionId: string;
}

export interface ZetaState {
  domains: Record<keyof typeof ZETA_DOMAINS, string>;
  m365ConnectionId: string;
  googleConnectionId: string;
  remediation: ZetaRemediationState;
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
  const remediation = await seedRemediation(p, org, {
    apiConnectionId: apiConnection.id,
    domainId: api.id,
    mailbox: mailboxes[0]!,
    now,
  });
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
    remediation,
  };
}

const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

/** `action_key` of `@email-gateway/mailbox-api` (`remediationActionKey`, R-I4). */
const actionKey = (copyPublicId: string, action: string, generation: number) =>
  sha256(`api-remediation/1\0${copyPublicId}\0${action}\0${generation}`);

/**
 * The step API-2 rows (§9.5): four copies with registry messages, the actions the mailbox-worker
 * leaves after its decisions and the mailbox-located entry of the quarantine-folder move, with the
 * columns the mailbox-worker writes (R4, R5, R9.1; apps/api/integration/api-mode-remediation).
 */
async function seedRemediation(
  p: PrismaClient,
  org: { id: bigint },
  ctx: {
    apiConnectionId: bigint;
    domainId: bigint;
    mailbox: { id: bigint; address: string };
    now: number;
  },
): Promise<ZetaRemediationState> {
  const sender = 'billing@fabrikam-e2e.example.test';
  const copy = async (
    index: number,
    verdict: 'malware' | 'phishing' | 'suspicious',
    remediation: {
      state: 'none' | 'remediated' | 'failed';
      action: 'move_quarantine' | 'tag' | null;
    },
  ) => {
    const receivedAt = new Date(ctx.now - (10 + index * 7) * MIN);
    const identity = await p.messageIdentity.create({
      data: {
        organizationId: org.id,
        ingestKey: `v2:mbx:${sha256(randomUUID())}`,
        receivedAt,
      },
      select: { id: true },
    });
    await p.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt,
        organizationId: org.id,
        domainId: ctx.domainId,
        direction: 'inbound',
        status: 'journaled',
        statusChangedAt: receivedAt,
        version: 2,
        ingestSource: 'mailbox_api',
        envelopeFrom: sender,
        headerFrom: sender,
        subject: `E2E API-mode copy ${index}`,
        internetMessageId: `<${randomUUID()}@fabrikam-e2e.example.test>`,
        sizeBytes: 2048,
        recipientCount: 1,
        attachmentCount: 0,
        emlObjectKey: `org/${org.id.toString()}/eml/e2e-api-mode/${identity.id.toString()}.eml`,
        emlSha256: sha256(`e2e-api-mode-${index}`),
      },
    });
    const recipient = await p.emailRecipient.create({
      data: {
        receivedAt,
        messageId: identity.id,
        organizationId: org.id,
        rcptSeq: 0,
        address: ctx.mailbox.address,
        status: 'journaled',
        direction: 'inbound',
      },
      select: { id: true },
    });
    const publicId = randomUUID();
    const row = await p.apiMessageCopy.create({
      data: {
        publicId,
        receivedAt,
        organizationId: org.id,
        apiConnectionId: ctx.apiConnectionId,
        mailboxId: ctx.mailbox.id,
        messageId: identity.id,
        source: 'journal',
        seenJournal: true,
        status: 'scanned',
        verdict,
        riskScore: verdict === 'suspicious' ? 610 : 930,
        verdictAt: new Date(receivedAt.getTime() + 20_000),
        providerDeliveredAt: new Date(receivedAt.getTime() - 20_000),
        deliveredBasis: 'received_header',
        lagMs: 40_000,
        remediationState: remediation.state,
        remediationAction: remediation.action,
      },
      select: { id: true },
    });
    return { id: row.id, publicId, receivedAt, messageId: identity.id, recipientId: recipient.id };
  };
  const action = async (
    c: Awaited<ReturnType<typeof copy>>,
    kind: 'move_quarantine' | 'tag',
    status: 'succeeded' | 'failed',
    ruleId: string,
    verdict: string,
  ) => {
    const verdictAt = new Date(c.receivedAt.getTime() + 20_000);
    const row = await p.apiRemediationAction.create({
      data: {
        publicId: randomUUID(),
        organizationId: org.id,
        apiConnectionId: ctx.apiConnectionId,
        mailboxId: ctx.mailbox.id,
        copyId: c.id,
        copyReceivedAt: c.receivedAt,
        messageId: c.messageId,
        action: kind,
        generation: 0,
        actionKey: actionKey(c.publicId, kind, 0),
        trigger: 'policy',
        status,
        reasonCode: status === 'failed' ? 'provider_unavailable' : null,
        requestedByType: 'system',
        attempts: status === 'failed' ? 8 : 1,
        locateAttempts: 1,
        lastErrorCode: status === 'failed' ? 'provider_unavailable' : null,
        lastHttpStatus: status === 'failed' ? 503 : null,
        decision: {
          v: 1,
          policy: {
            scope: 'platform_default',
            publicId: null,
            rowVersion: null,
            sha256: sha256('p1'),
          },
          mode: 'enforce',
          ruleId,
          inputs: {
            verdict,
            riskScore: verdict === 'suspicious' ? 610 : 930,
            level: verdict === 'suspicious' ? 'high' : 'critical',
            hardBlocks: verdict === 'malware' ? ['hb.malware_attachment'] : [],
            verdictAuthority: 'copy',
          },
          policyOutcome: null,
          notes: [],
        },
        providerRefs:
          status === 'succeeded'
            ? {
                before: [`e2e-provider-${randomUUID()}`],
                after: kind === 'tag' ? [] : [`e2e-provider-${randomUUID()}`],
                container: kind === 'tag' ? null : 'quarantine_folder',
              }
            : { before: [], after: [], container: null },
        verdictAt,
        startedAt: new Date(verdictAt.getTime() + 1_000),
        completedAt: new Date(verdictAt.getTime() + 4_000),
      },
      select: { id: true, publicId: true },
    });
    await p.apiMessageCopy.updateMany({
      where: { id: c.id, receivedAt: c.receivedAt },
      data: { lastActionId: row.id },
    });
    return row;
  };

  const quarantined = await copy(0, 'malware', { state: 'remediated', action: 'move_quarantine' });
  const moved = await action(
    quarantined,
    'move_quarantine',
    'succeeded',
    'p1-high-confidence-malware-phishing-hb',
    'malware',
  );
  const quarantinedAt = new Date(quarantined.receivedAt.getTime() + 25_000);
  const entry = await p.quarantineMessage.create({
    data: {
      organizationId: org.id,
      messageId: quarantined.messageId,
      messageReceivedAt: quarantined.receivedAt,
      lifecycleRound: 0,
      recipientId: quarantined.recipientId,
      rcptSeq: 0,
      recipientAddress: ctx.mailbox.address,
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'api_remediation',
      reason: 'malware',
      status: 'held',
      envelopeFrom: sender,
      headerFrom: sender,
      hasAttachments: false,
      attachmentCount: 0,
      sizeBytes: 2048,
      riskScore: 930,
      riskLevel: 'critical',
      riskVerdict: 'malware',
      hasHardBlock: true,
      hardBlocks: ['hb.malware_attachment'],
      reasonCodes: [],
      floorReasons: [],
      primaryEngine: 'attachment',
      explanationText:
        'Removed from the mailbox by the API-mode remediation policy (rule p1-high-confidence-malware-phishing-hb)',
      emlObjectKey: `org/${org.id.toString()}/eml/e2e-api-mode/${quarantined.messageId.toString()}.eml`,
      quarantinedAt,
      expiresAt: new Date(quarantinedAt.getTime() + 30 * 24 * HOUR),
      stateChangedAt: quarantinedAt,
      location: 'mailbox',
      mailboxContainer: 'quarantine_folder',
      apiCopyId: quarantined.id,
      apiCopyReceivedAt: quarantined.receivedAt,
      apiMailboxId: ctx.mailbox.id,
      apiRemediationActionId: moved.id,
    },
    select: { id: true, publicId: true },
  });
  await p.apiRemediationAction.update({
    where: { id: moved.id },
    data: { quarantineEntryId: entry.id },
  });
  await p.quarantineAction.create({
    data: {
      organizationId: org.id,
      quarantineMessageId: entry.id,
      action: 'mailbox_remediated',
      actorType: 'system',
      result: 'move_quarantine',
      details: { actionId: moved.publicId, container: 'quarantine_folder' },
      createdAt: quarantinedAt,
    },
  });

  const failing = await copy(1, 'phishing', { state: 'failed', action: 'move_quarantine' });
  const failed = await action(
    failing,
    'move_quarantine',
    'failed',
    'p1-high-confidence-malware-phishing',
    'phishing',
  );
  const tagged = await copy(2, 'suspicious', { state: 'remediated', action: 'tag' });
  await action(tagged, 'tag', 'succeeded', 'p1-suspicious', 'suspicious');
  const remediable = await copy(3, 'phishing', { state: 'none', action: null });
  return {
    quarantinedDetectionId: quarantined.publicId,
    entryId: entry.publicId,
    failedActionId: failed.publicId,
    failedDetectionId: failing.publicId,
    taggedDetectionId: tagged.publicId,
    remediableDetectionId: remediable.publicId,
  };
}
