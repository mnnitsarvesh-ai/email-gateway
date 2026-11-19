import { createHash } from 'node:crypto';
import { atoSubjectHash } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { AtoPolicyFactsRepository } from '../src/modules/policies/repositories/ato-policy-facts.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';

/**
 * Step 8.4 D23 / §5.3 (WP3): the **current** ATO facts a policy dry-run reads for a round without
 * a stored evaluation, against the real MySQL writer (fixtures) and replica (the repository).
 * The same rules as the policy-engine reader: feature `ato_detection` enabled and ATO mode not
 * `off`; the `mailbox` account by its unique key with its active `account_takeover` incident of
 * the same organization; no account → `accountKnown: false`, score 0, level `low`.
 *
 * Synthetic organizations only (pre-existing organizations keep ATO off, D21).
 */
const POLL = { timeout: 15_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let enabled: FixtureOrganization;
let other: FixtureOrganization;
let off: FixtureOrganization;
let disabled: FixtureOrganization;
let repo: AtoPolicyFactsRepository;

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

async function enableAto(org: FixtureOrganization, mode?: 'off' | 'monitor') {
  await ctx.prisma.organizationFeature.upsert({
    where: {
      organizationId_featureKey: { organizationId: org.id, featureKey: 'ato_detection' },
    },
    create: {
      organizationId: org.id,
      featureKey: 'ato_detection',
      enabled: true,
      source: 'override',
    },
    update: { enabled: true },
  });
  if (mode !== undefined) {
    await ctx.prisma.atoSetting.create({
      data: {
        organizationId: org.id,
        settings: { mode },
        settingsSha256: sha256(JSON.stringify({ mode })),
        learningStartedAt: new Date(),
      },
    });
  }
}

async function atoAccount(
  org: FixtureOrganization,
  address: string,
  risk: { score: number; level: 'low' | 'medium' | 'high' | 'critical' },
  incident?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    status: 'open' | 'confirmed';
    category?: 'account_takeover';
    organization?: FixtureOrganization;
  },
): Promise<bigint> {
  const now = new Date();
  const account = await ctx.prisma.atoAccount.create({
    data: {
      organizationId: org.id,
      kind: 'mailbox',
      subjectHash: atoSubjectHash('mailbox', address),
      address: address.toLowerCase(),
      riskScore: risk.score,
      riskLevel: risk.level,
      firstSeenAt: now,
      lastSeenAt: now,
    },
    select: { id: true, publicId: true },
  });
  if (incident) {
    const owner = incident.organization ?? org;
    const row = await ctx.prisma.securityIncident.create({
      data: {
        organizationId: owner.id,
        category: incident.category ?? 'account_takeover',
        subjectType: 'ato_account',
        subjectRefId: account.id,
        subjectPublicId: account.publicId,
        origin: 'detection',
        severity: incident.severity,
        status: incident.status,
        reasonCodes: [],
        detectedAt: now,
        createdByType: 'system',
      },
      select: { id: true },
    });
    await ctx.prisma.atoAccount.update({
      where: { id: account.id },
      data: { activeIncidentId: row.id },
    });
  }
  return account.id;
}

/** Polls the replica until the repository sees the expected facts. */
async function expectCurrent(org: FixtureOrganization, sender: string, expected: unknown) {
  await expect.poll(() => repo.current(systemScope(org.id), sender), POLL).toEqual(expected);
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  repo = ctx.get(AtoPolicyFactsRepository);
  enabled = await fx.createOrganization();
  other = await fx.createOrganization();
  off = await fx.createOrganization();
  disabled = await fx.createOrganization();
  await enableAto(enabled);
  await enableAto(other, 'monitor');
  await enableAto(off, 'off');
  // `disabled` starts without an ato_detection row (the plan default is false for every plan).
});

afterAll(async () => {
  const ids = [enabled, other, off, disabled].filter(Boolean).map((org) => org.id);
  if (ids.length > 0) {
    const where = { organizationId: { in: ids } };
    await ctx.prisma.atoAccount.deleteMany({ where });
    await ctx.prisma.securityIncident.deleteMany({ where });
    await ctx.prisma.atoSetting.deleteMany({ where });
  }
  await fx?.cleanup();
  await ctx?.close();
});

describe('current ATO policy facts on the replica (step 8.4 D23, §5.3)', () => {
  it('a high-risk account with an active incident: score, level and the incident', async () => {
    await atoAccount(
      enabled,
      'ceo@ato-high.example',
      { score: 82, level: 'high' },
      {
        severity: 'critical',
        status: 'confirmed',
      },
    );
    // The address is normalized like the policy-engine does (lower-cased full address).
    await expectCurrent(enabled, 'CEO@ATO-High.example', {
      accountKnown: true,
      riskScore: 82,
      riskLevel: 'high',
      incidentSeverity: 'critical',
      incidentStatus: 'confirmed',
    });
  });

  it('an unmonitored sender of an ATO-enabled organization is unknown: score 0, low, no incident', async () => {
    await expectCurrent(enabled, 'nobody@ato-high.example', {
      accountKnown: false,
      riskScore: 0,
      riskLevel: 'low',
      incidentSeverity: null,
      incidentStatus: null,
    });
  });

  it('an incident row of another organization is never this account’s', async () => {
    await atoAccount(
      other,
      'cfo@ato-other.example',
      { score: 40, level: 'medium' },
      {
        severity: 'high',
        status: 'open',
        organization: enabled,
      },
    );
    await expectCurrent(other, 'cfo@ato-other.example', {
      accountKnown: true,
      riskScore: 40,
      riskLevel: 'medium',
      incidentSeverity: null,
      incidentStatus: null,
    });
  });

  it('organizations are isolated: the same address in another organization is not known there', async () => {
    await expectCurrent(other, 'ceo@ato-high.example', {
      accountKnown: false,
      riskScore: 0,
      riskLevel: 'low',
      incidentSeverity: null,
      incidentStatus: null,
    });
  });

  it('no facts with ATO mode off or with the feature disabled', async () => {
    await atoAccount(off, 'ceo@ato-off.example', { score: 95, level: 'critical' });
    await atoAccount(disabled, 'ceo@ato-disabled.example', { score: 95, level: 'critical' });
    // The accounts reached the replica (the same high-risk row would be facts if ATO were on).
    await enableAto(disabled);
    await expectCurrent(disabled, 'ceo@ato-disabled.example', {
      accountKnown: true,
      riskScore: 95,
      riskLevel: 'critical',
      incidentSeverity: null,
      incidentStatus: null,
    });
    await ctx.prisma.organizationFeature.update({
      where: {
        organizationId_featureKey: { organizationId: disabled.id, featureKey: 'ato_detection' },
      },
      data: { enabled: false },
    });
    await expect
      .poll(() => repo.current(systemScope(disabled.id), 'ceo@ato-disabled.example'), POLL)
      .toBeNull();
    expect(await repo.current(systemScope(off.id), 'ceo@ato-off.example')).toBeNull();
    expect(await repo.current(systemScope(disabled.id), 'ceo@ato-disabled.example')).toBeNull();
  });

  it('an address that cannot be an account yields no facts', async () => {
    expect(await repo.current(systemScope(enabled.id), 'not-an-address')).toBeNull();
  });
});
