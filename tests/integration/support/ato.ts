import type { PrismaClient } from '@email-gateway/database';
import { idempotencyKey, type ApiSession } from './api-client';
import type { ManagementApi } from './broker';
import { waitFor } from './compose';
import type { SmtpFixtures } from './smtp-fixtures';

/**
 * Account takeover helpers of the step 8.4 stack suites (docs/plan/steps/24-account-takeover-core.md
 * §10.5): synthetic `it-ato-*` organizations with the feature `ato_detection` enabled (D21: never
 * a pre-existing organization), settings through the api (CAS), waits for the rows the ato-worker
 * writes, and the removal of every ATO and incident row of the suite's organizations (before the
 * fixture cleanup removes the organizations) and of the ATO queues it filled.
 */

/** The three ATO queues of topology v13 (D3). */
export const ATO_QUEUES = ['ato.events', 'ato.mail', 'ato.responses'] as const;

/** A fixture organization renamed `it-ato-<suffix>-<label>` with ATO enabled (or not). */
export async function atoOrganization(
  fx: SmtpFixtures,
  label: string,
  enabled = true,
): Promise<{ id: bigint; slug: string }> {
  const id = await fx.organization(label);
  const slug = `it-ato-${fx.suffix}-${label}`;
  await fx.prisma.organization.update({ where: { id }, data: { slug } });
  if (enabled) await fx.feature(id, 'ato_detection', true);
  return { id, slug };
}

/** Deletes every ATO and security-incident row of the organizations (store tables, outbox, audit). */
export async function deleteAtoRows(prisma: PrismaClient, ids: readonly bigint[]): Promise<void> {
  if (ids.length === 0) return;
  const where = { organizationId: { in: [...ids] } };
  await prisma.atoResponseActionLog.deleteMany({ where });
  await prisma.atoResponseAction.deleteMany({ where });
  await prisma.atoSmtpRestriction.deleteMany({ where });
  await prisma.atoIncidentDetail.deleteMany({ where });
  await prisma.securityIncidentLink.deleteMany({ where });
  await prisma.securityIncidentEvent.deleteMany({ where });
  await prisma.securityIncident.deleteMany({ where });
  await prisma.atoTrustedContext.deleteMany({ where });
  await prisma.atoRiskOverride.deleteMany({ where });
  await prisma.atoRiskSignal.deleteMany({ where });
  await prisma.atoRiskScore.deleteMany({ where });
  await prisma.atoAuthEvent.deleteMany({ where });
  await prisma.atoAccountActivityDaily.deleteMany({ where });
  await prisma.atoAccountBaseline.deleteMany({ where });
  await prisma.atoAccountIdentity.deleteMany({ where });
  await prisma.atoProviderIntegration.deleteMany({ where });
  await prisma.atoAccount.deleteMany({ where });
  await prisma.atoSettingsVersion.deleteMany({ where });
  await prisma.atoSetting.deleteMany({ where });
}

/** Purges the ATO queues by name (the suites' own events; nothing else is queued there). */
export async function purgeAtoQueues(mgmt: ManagementApi, vhost: string): Promise<void> {
  for (const queue of ATO_QUEUES) {
    try {
      await mgmt.purge(vhost, queue);
    } catch {
      // A queue that does not exist yet (pre-v13 broker) has nothing to purge.
    }
  }
}

/** Saves settings through the api (`GET` for the row version, `PUT` with the merged document). */
export async function saveAtoSettings(
  admin: ApiSession,
  settings: Record<string, unknown>,
): Promise<{ version: number; rowVersion: number }> {
  const current = await admin.get('/ato/settings');
  if (current.status !== 200) throw new Error(`GET /ato/settings answered ${current.status}`);
  const body = current.body as { rowVersion: number; stored: Record<string, unknown> };
  const put = await admin.put(
    '/ato/settings',
    { expectedRowVersion: body.rowVersion, settings: { ...body.stored, ...settings } },
    idempotencyKey(),
  );
  if (put.status !== 200) {
    throw new Error(`PUT /ato/settings answered ${put.status}: ${JSON.stringify(put.body)}`);
  }
  return put.body as { version: number; rowVersion: number };
}

/**
 * Waits until the ato-worker's per-organization settings cache (`ATO_SETTINGS_CACHE_SECONDS`,
 * default 30) can no longer hold the settings read before a change: the fixture users' own api
 * logins are ATO events, so the worker may have cached the defaults before `saveAtoSettings`.
 */
export async function settleSettingsCache(): Promise<void> {
  const seconds = Number(process.env.ATO_SETTINGS_CACHE_SECONDS ?? 30);
  await new Promise((r) => setTimeout(r, (seconds + 2) * 1000));
}

/** Waits for the ATO account of a mailbox address (written by the ato-worker's detect role). */
export function waitForMailboxAccount(
  prisma: PrismaClient,
  organizationId: bigint,
  address: string,
  timeoutMs = 120_000,
) {
  return waitFor(
    `ATO mailbox account ${address}`,
    () =>
      prisma.atoAccount
        .findFirst({ where: { organizationId, kind: 'mailbox', address: address.toLowerCase() } })
        .then((row) => row ?? undefined),
    { timeoutMs, intervalMs: 500 },
  );
}

/** Waits for the ATO account of an SMTP connector. */
export async function waitForConnectorAccount(
  prisma: PrismaClient,
  organizationId: bigint,
  saslUsername: string,
  timeoutMs = 120_000,
) {
  const connector = await prisma.smtpConnector.findFirstOrThrow({
    where: { organizationId, saslUsername },
    select: { id: true, publicId: true },
  });
  const account = await waitFor(
    `ATO connector account ${connector.publicId}`,
    () =>
      prisma.atoAccount
        .findFirst({ where: { organizationId, kind: 'smtp_connector', connectorId: connector.id } })
        .then((row) => row ?? undefined),
    { timeoutMs, intervalMs: 500 },
  );
  return { account, connector };
}

/** Waits until every rule code has an active signal on the account. */
export function waitForSignals(
  prisma: PrismaClient,
  organizationId: bigint,
  accountId: bigint,
  codes: readonly string[],
  timeoutMs = 120_000,
) {
  return waitFor(
    `signals ${codes.join(', ')} on account ${accountId}`,
    async () => {
      const rows = await prisma.atoRiskSignal.findMany({
        where: { organizationId, accountId, ruleCode: { in: [...codes] } },
        select: { id: true, ruleCode: true, strength: true, status: true, weight: true },
      });
      return codes.every((c) => rows.some((r) => r.ruleCode === c)) ? rows : undefined;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

/** Waits for the active ATO incident of an account (opened by the store's incident policy). */
export function waitForIncident(
  prisma: PrismaClient,
  organizationId: bigint,
  accountId: bigint,
  timeoutMs = 120_000,
) {
  return waitFor(
    `active ATO incident of account ${accountId}`,
    () =>
      prisma.securityIncident
        .findFirst({
          where: {
            organizationId,
            category: 'account_takeover',
            subjectRefId: accountId,
            activeMarker: 1,
          },
        })
        .then((row) => row ?? undefined),
    { timeoutMs, intervalMs: 500 },
  );
}

/** Requests a response as one analyst and approves it as another (MFA); returns the action. */
export async function requestAndApprove(
  requester: ApiSession,
  approver: ApiSession,
  incidentPublicId: string,
  body: Record<string, unknown>,
): Promise<{ id: string; status: string }> {
  const requested = await requester.post(
    `/ato/incidents/${incidentPublicId}/responses`,
    body,
    idempotencyKey(),
  );
  if (requested.status !== 201) {
    throw new Error(`request answered ${requested.status}: ${JSON.stringify(requested.body)}`);
  }
  const action = requested.body as { id: string; status: string };
  if (action.status !== 'pending_approval') return action;
  const self = await requester.post(`/ato/responses/${action.id}/approve`, {}, idempotencyKey());
  if (self.status !== 403) throw new Error(`self-approval answered ${self.status}`);
  const approved = await approver.post(`/ato/responses/${action.id}/approve`, {}, idempotencyKey());
  if (approved.status !== 200) {
    throw new Error(`approve answered ${approved.status}: ${JSON.stringify(approved.body)}`);
  }
  return approved.body as { id: string; status: string };
}

/** Rolls a response back (MFA user, reason). */
export async function rollback(approver: ApiSession, responseId: string): Promise<void> {
  const res = await approver.post(
    `/ato/responses/${responseId}/rollback`,
    { reason: 'stack test: lift the restriction again' },
    idempotencyKey(),
  );
  if (res.status !== 200)
    throw new Error(`rollback answered ${res.status}: ${JSON.stringify(res.body)}`);
}
