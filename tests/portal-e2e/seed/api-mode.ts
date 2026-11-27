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
 * Step API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md §9.5) adds seedClawback: a
 * searchable campaign (Message-ID hash on its copies), two `ready` clawbacks with frozen targets
 * (approval and cancel), `dee` as the report mailbox with two pending reports of one original, and
 * the organization settings row (CAS target).
 *
 * The run's cleanup (cleanup.ts) deletes the API-mode tables (clawback targets, clawbacks, user
 * reports, remediation actions and policies, organization settings first) before the provider
 * connections.
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
/**
 * Step API-3: the copies of seedClawback — the search campaign (2 mailboxes), the approval
 * campaign (2), the cancel campaign (1) and two report copies in the report mailbox.
 */
export const ZETA_CLAWBACK_COPIES = 7;

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

/** Step API-3 (seedClawback). */
export interface ZetaClawbackState {
  /** The Internet Message-ID the spec searches for (two copies, below the threshold). */
  searchMessageId: string;
  /** A `ready` clawback over two mailboxes (the approval flow after the threshold is lowered). */
  approvalClawbackId: string;
  /** A `ready` clawback the spec cancels. */
  cancelClawbackId: string;
  /** Two pending reports of one original (a group). */
  reportIds: [string, string];
  reportMailbox: string;
}

export interface ZetaState {
  domains: Record<keyof typeof ZETA_DOMAINS, string>;
  m365ConnectionId: string;
  googleConnectionId: string;
  remediation: ZetaRemediationState;
  clawback: ZetaClawbackState;
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
  const clawback = await seedClawback(p, org, {
    apiConnectionId: apiConnection.id,
    domainId: api.id,
    mailboxes,
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
    clawback,
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

/** `copyMessageIdHash` of `@email-gateway/mailbox-api` (identifiers.ts; fixed vectors there). */
export function copyMessageIdHash(organizationId: bigint, messageId: string): string {
  let value = messageId.trim();
  if (value.startsWith('<') && value.endsWith('>')) value = value.slice(1, -1).trim();
  return sha256(`api-copy/1\0${organizationId.toString()}\0${value}`);
}

/**
 * The step API-3 rows (docs/plan/steps/37-api-mode-clawback-reporting.md §9.5), with the columns
 * the api and the mailbox-worker write (C4.1 criteria document, C5.2 targets, C9 report mailbox,
 * C10 report rows, C14 #18 settings):
 *
 * - the search campaign: one registry message with two recipient copies (ana, ben) carrying the
 *   Message-ID hash, no remediation — the spec searches it by Message-ID and purges it;
 * - two `ready` admin clawbacks as the `clawback` role leaves them after materialization (frozen
 *   `matched` targets and counts): one over two mailboxes (the approval flow once the threshold is
 *   lowered to 1), one over one mailbox (cancel);
 * - `dee` designated as the report mailbox, two report copies there and two `pending_triage`
 *   reports of the search campaign's original (one group; assessment from the scan);
 * - the organization settings row at the defaults (row version 1: the CAS target).
 *
 * Nothing here is due for the mailbox-worker: `ready` clawbacks wait for a submit, the reports
 * are past the `reports` role, and no clawback is queued or running.
 */
async function seedClawback(
  p: PrismaClient,
  org: { id: bigint },
  ctx: {
    apiConnectionId: bigint;
    domainId: bigint;
    mailboxes: Array<{ id: bigint; address: string }>;
    now: number;
  },
): Promise<ZetaClawbackState> {
  const [ana, ben, cy, dee] = ctx.mailboxes as [
    { id: bigint; address: string },
    { id: bigint; address: string },
    { id: bigint; address: string },
    { id: bigint; address: string },
  ];
  const sender = 'invoices@contoso-billing-e2e.example.test';
  type Copy = {
    id: bigint;
    publicId: string;
    receivedAt: Date;
    messageId: bigint;
    mailboxId: bigint;
  };
  /** One registry message with one copy per recipient mailbox (a journal copy, C4.2). */
  const message = async (
    key: string,
    minutesAgo: number,
    recipients: Array<{ id: bigint; address: string }>,
    subject: string,
  ): Promise<{ internetMessageId: string; copies: Copy[] }> => {
    const receivedAt = new Date(ctx.now - minutesAgo * MIN);
    const internetMessageId = `<${key}.${randomUUID()}@contoso-billing-e2e.example.test>`;
    const identity = await p.messageIdentity.create({
      data: { organizationId: org.id, ingestKey: `v2:mbx:${sha256(randomUUID())}`, receivedAt },
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
        subject,
        internetMessageId,
        sizeBytes: 3072,
        recipientCount: recipients.length,
        attachmentCount: 0,
        emlObjectKey: `org/${org.id.toString()}/eml/e2e-api-mode/${identity.id.toString()}.eml`,
        emlSha256: sha256(`e2e-clawback-${key}`),
      },
    });
    const copies: Copy[] = [];
    for (const [rcptSeq, mailbox] of recipients.entries()) {
      await p.emailRecipient.create({
        data: {
          receivedAt,
          messageId: identity.id,
          organizationId: org.id,
          rcptSeq,
          address: mailbox.address,
          status: 'journaled',
          direction: 'inbound',
        },
      });
      const publicId = randomUUID();
      const row = await p.apiMessageCopy.create({
        data: {
          publicId,
          receivedAt,
          organizationId: org.id,
          apiConnectionId: ctx.apiConnectionId,
          mailboxId: mailbox.id,
          messageId: identity.id,
          source: 'journal',
          seenJournal: true,
          direction: 'inbound',
          messageIdHash: copyMessageIdHash(org.id, internetMessageId),
          status: 'scanned',
          verdict: 'phishing',
          riskScore: 720,
          verdictAt: new Date(receivedAt.getTime() + 20_000),
          providerDeliveredAt: new Date(receivedAt.getTime() - 20_000),
          deliveredBasis: 'received_header',
          lagMs: 40_000,
        },
        select: { id: true },
      });
      copies.push({
        id: row.id,
        publicId,
        receivedAt,
        messageId: identity.id,
        mailboxId: mailbox.id,
      });
    }
    return { internetMessageId, copies };
  };

  const search = await message('search', 50, [ana, ben], 'E2E clawback: your invoice is overdue');
  const approval = await message('approval', 70, [ben, cy], 'E2E clawback: payroll update');
  const cancel = await message('cancel', 90, [ana], 'E2E clawback: shared document');

  /** A `ready` admin clawback as the `clawback` role leaves it after materialization. */
  const readyClawback = async (
    m: { internetMessageId: string; copies: Copy[] },
    reason: string,
  ): Promise<string> => {
    const createdAt = new Date(ctx.now - 20 * MIN);
    const criteria = {
      v: 1,
      window: {
        from: new Date(ctx.now - 2 * 24 * HOUR).toISOString(),
        to: new Date(ctx.now - 15 * MIN).toISOString(),
      },
      keys: { messageIdHashes: [copyMessageIdHash(org.id, m.internetMessageId)] },
      directions: ['inbound', 'internal'],
      includeReportMailboxes: false,
    };
    const mailboxes = new Set(m.copies.map((c) => c.mailboxId)).size;
    const row = await p.apiClawback.create({
      data: {
        publicId: randomUUID(),
        organizationId: org.id,
        trigger: 'admin',
        signal: { v: 1, kind: 'admin', refs: {}, facts: null, signalAt: createdAt.toISOString() },
        criteria,
        criteriaSha256: sha256(JSON.stringify(criteria)),
        status: 'ready',
        targetsTotal: m.copies.length,
        mailboxesTotal: mailboxes,
        targetsEligible: m.copies.length,
        mailboxesEligible: mailboxes,
        requestedByType: 'user',
        requestReason: reason,
        signalAt: createdAt,
        rowVersion: 3,
        createdAt,
      },
      select: { id: true, publicId: true },
    });
    for (const c of m.copies) {
      await p.apiClawbackTarget.create({
        data: {
          clawbackId: row.id,
          organizationId: org.id,
          apiConnectionId: ctx.apiConnectionId,
          mailboxId: c.mailboxId,
          copyId: c.id,
          copyReceivedAt: c.receivedAt,
          messageId: c.messageId,
          matchKeys: ['message_id'],
          status: 'matched',
        },
      });
    }
    return row.publicId;
  };
  const approvalClawbackId = await readyClawback(approval, 'E2E payroll phishing (two mailboxes)');
  const cancelClawbackId = await readyClawback(cancel, 'E2E search to cancel');

  // The report mailbox (C9.1) and two reports of the search campaign's original (C10, C11).
  const designatedAt = new Date(ctx.now - 3 * 24 * HOUR);
  await p.apiMailbox.update({
    where: { id: dee.id },
    data: { reportMailbox: true, reportMailboxAt: designatedAt },
  });
  // One forwarded message per reporter, each a copy in the report mailbox (C9.2).
  const reportCopies = [
    (await message('report-0', 30, [dee], 'FW: E2E clawback: your invoice is overdue')).copies[0]!,
    (await message('report-1', 25, [dee], 'FW: E2E clawback: your invoice is overdue')).copies[0]!,
  ];
  const original = search.copies[0]!;
  const messageIdHash = copyMessageIdHash(org.id, search.internetMessageId);
  const reportIds: string[] = [];
  for (const [i, reporter] of [ana, ben].entries()) {
    const reportCopy = reportCopies[i]!;
    const reportedAt = new Date(ctx.now - (30 - i * 5) * MIN);
    const row = await p.apiUserReport.create({
      data: {
        publicId: randomUUID(),
        organizationId: org.id,
        apiConnectionId: ctx.apiConnectionId,
        reportMailboxId: dee.id,
        reportCopyId: reportCopy.id,
        reportCopyReceivedAt: reportCopy.receivedAt,
        reportMessageId: reportCopy.messageId,
        reporterAddress: reporter.address,
        reporterMailboxId: reporter.id,
        status: 'pending_triage',
        identification: 'attachment',
        original: {
          v: 1,
          messageIdHash,
          sender,
          subjectKey: 'e2e clawback: your invoice is overdue',
          date: original.receivedAt.toISOString(),
          attachmentSha256: [],
          urlSha256: [],
          extraOriginals: 0,
        },
        originalMessageIdHash: messageIdHash,
        groupKey: messageIdHash,
        originalCopyId: original.id,
        originalCopyReceivedAt: original.receivedAt,
        originalMessageId: original.messageId,
        originalReceivedAt: original.receivedAt,
        scanVerdict: 'phishing',
        scanRiskScore: 720,
        scanLevel: 'high',
        assessment: 'suspicious',
        ackFeedback: 'queued',
        reportedAt,
        rowVersion: 3,
      },
      select: { publicId: true },
    });
    reportIds.push(row.publicId);
  }
  // The organization settings at the defaults (C14 #18; row version 1).
  await p.apiModeOrgSetting.create({ data: { organizationId: org.id } });
  return {
    searchMessageId: search.internetMessageId,
    approvalClawbackId,
    cancelClawbackId,
    reportIds: [reportIds[0]!, reportIds[1]!],
    reportMailbox: dee.address,
  };
}
