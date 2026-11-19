/**
 * Helpers of the step 8.4 specs (account takeover and incidents): the seeded accounts by plan
 * key, KPI tiles by label, and reads of the rows the api wrote (on the writer, for figures the
 * specs compare with the portal independently of the api).
 */
import type { Page } from '@playwright/test';
import { writerDb } from './messages';
import { readState } from './state';

export function atoAccount(key: string, tenant: 'alpha' | 'beta' = 'alpha') {
  const account = readState().ato[tenant].find((a) => a.key === key);
  if (!account) throw new Error(`no seeded ATO account ${tenant}/${key}`);
  return account;
}

/** A KPI tile of the ATO dashboard by its label (the card around the level-3 heading). */
export function atoTile(page: Page, label: string) {
  return page
    .getByRole('heading', { level: 3, name: label, exact: true })
    .locator('xpath=ancestor::*[@data-slot="card"][1]');
}

async function orgId(tenant: 'alpha' | 'beta'): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs[tenant].id },
    select: { id: true },
  });
  return org.id;
}

/** Responses waiting for approval in the tenant (writer count, independent of the api). */
export async function pendingApprovals(tenant: 'alpha' | 'beta' = 'alpha'): Promise<number> {
  return writerDb().atoResponseAction.count({
    where: { organizationId: await orgId(tenant), status: 'pending_approval' },
  });
}

/** The active SMTP restrictions of the tenant (writer). */
export async function activeRestrictions(tenant: 'alpha' | 'beta' = 'alpha') {
  return writerDb().atoSmtpRestriction.findMany({
    where: { organizationId: await orgId(tenant), status: 'active' },
    select: { kind: true, scope: true, status: true },
  });
}

/** Audit actions written for the tenant since `since` (writer). */
export async function auditActions(since: Date, tenant: 'alpha' | 'beta' = 'alpha') {
  const rows = await writerDb().auditLog.findMany({
    where: { organizationId: await orgId(tenant), createdAt: { gte: since } },
    select: { action: true },
  });
  return rows.map((r) => r.action);
}

const LOGIN_CATEGORIES = ['authentication', 'access_context', 'geography', 'threat_intel'];

/**
 * Figures of the alpha `gateway_user` accounts (writer): the suite's own portal sign-ins are real
 * ATO events of the e2e tenant (ato-worker running), so the dashboard counts them next to the
 * seeded mailboxes. Read independently of the api and added to the seed plan's figures.
 */
export async function gatewayUserFigures(since: Date) {
  const organizationId = await orgId('alpha');
  const accounts = await writerDb().atoAccount.findMany({
    where: { organizationId, kind: 'gateway_user', status: 'active' },
    select: { id: true, riskScore: true },
  });
  const ids = accounts.map((a) => a.id);
  const [signals, failures] = await Promise.all([
    writerDb().atoRiskSignal.count({
      where: {
        organizationId,
        accountId: { in: ids },
        category: { in: LOGIN_CATEGORIES as never },
        detectedAt: { gte: since },
      },
    }),
    writerDb().atoAuthEvent.count({
      where: {
        organizationId,
        accountId: { in: ids },
        outcome: 'failure',
        occurredAt: { gte: since },
      },
    }),
  ]);
  return {
    accounts: accounts.length,
    highRisk: accounts.filter((a) => a.riskScore >= 50).length,
    criticalRisk: accounts.filter((a) => a.riskScore >= 75).length,
    suspiciousLogins: signals,
    failedLogins: failures,
  };
}

/**
 * Whether the ato-worker reports a loaded GeoIP City database (the `system_settings` capabilities
 * row, fresh within 15 minutes, D17). Locally the Compose worker mounts the synthetic databases,
 * so geography is available once the worker has reported; a fresh worker reports nothing yet.
 */
export async function geographyAvailable(): Promise<boolean> {
  const row = await writerDb().systemSetting.findUnique({
    where: { key: 'ato.worker.capabilities' },
  });
  if (!row) return false;
  const value = row.value as { geoipCity?: { loaded?: boolean }; updatedAt?: string };
  const updated = Date.parse(value.updatedAt ?? '');
  return value.geoipCity?.loaded === true && Date.now() - updated < 15 * 60_000;
}

/** Active ATO incidents of the alpha `gateway_user` accounts by severity (writer). */
export async function gatewayUserIncidents() {
  const organizationId = await orgId('alpha');
  const accounts = await writerDb().atoAccount.findMany({
    where: { organizationId, kind: 'gateway_user' },
    select: { id: true },
  });
  const rows = await writerDb().securityIncident.findMany({
    where: {
      organizationId,
      category: 'account_takeover',
      subjectRefId: { in: accounts.map((a) => a.id) },
      status: { in: ['open', 'investigating', 'confirmed', 'mitigated'] },
    },
    select: { severity: true },
  });
  return { active: rows.length, critical: rows.filter((r) => r.severity === 'critical').length };
}
