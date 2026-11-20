import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Prisma } from '@email-gateway/database';
import { sha256Hex } from '@email-gateway/ato-detection';
import { directoryRefHash } from '@email-gateway/idp-adapters';
import { Fixtures } from './support/fixtures';
import { Clock } from './support/harness';
import { IdpWorld, MIN, msDirectoryAs } from './support/idp';
import { configure } from './support/scenario';

/**
 * Step 8.5 §11.3 tenant isolation: two organizations, two directories, identical user names
 * (`alex`, `blake`, … in each). Every account, identity, auth event, signal, mailbox item and
 * stream counter stays with its own organization; a directory binds to at most one non-disabled
 * integration platform-wide (the generated `active_marker` unique key; the probe pauses a second
 * binding `directory_in_use`).
 */
const fx = new Fixtures();
const clock = new Clock(new Date(Math.floor(Date.now() / MIN) * MIN));
const w = new IdpWorld(fx, clock);
const TA = '66666666-0000-4000-8000-00000000000a';
const TB = '66666666-0000-4000-8000-00000000000b';
const DA = 'iso-a.example';
const DB = 'iso-b.example';

beforeAll(async () => {
  const now = clock.now();
  await w.start({ microsoft: [msDirectoryAs(now, TA, DA), msDirectoryAs(now, TB, DB)] });
});

afterAll(async () => {
  await w.stop();
  await fx.cleanup();
});

describe('tenant isolation (inv. 3)', () => {
  it('two organizations with identical user names never see each other', async () => {
    const a = await fx.organization('isoa');
    const b = await fx.organization('isob');
    await configure(w.h, a.id);
    await configure(w.h, b.id);
    const ia = await w.bind(w.connect(a.id, 'microsoft_entra', { tenantId: TA, domain: DA }));
    const ib = await w.bind(w.connect(b.id, 'microsoft_entra', { tenantId: TB, domain: DB }));
    await w.probe();
    await w.due();
    await w.poll();
    for (const [org, domain, integration, other] of [
      [a, DA, ia, DB],
      [b, DB, ib, DA],
    ] as const) {
      const accounts = await fx.prisma.atoAccount.findMany({ where: { organizationId: org.id } });
      expect(accounts.length).toBeGreaterThan(0);
      expect(accounts.every((x) => x.address === null || x.address.endsWith(`@${domain}`))).toBe(
        true,
      );
      expect(accounts.some((x) => x.address?.endsWith(`@${other}`))).toBe(false);
      const identities = await fx.prisma.atoAccountIdentity.findMany({
        where: { organizationId: org.id },
      });
      expect(identities.every((i) => i.integrationId === integration.id)).toBe(true);
      const items = await fx.prisma.atoProviderMailboxItem.findMany({
        where: { organizationId: org.id },
      });
      expect(items.every((i) => i.integrationId === integration.id)).toBe(true);
      const accountIds = new Set(accounts.map((x) => x.id));
      const signals = await fx.prisma.atoRiskSignal.findMany({ where: { organizationId: org.id } });
      expect(signals.every((s) => accountIds.has(s.accountId))).toBe(true);
    }
    // Identical external ids in both directories map to separate accounts per organization.
    const alexA = await fx.prisma.atoAccountIdentity.findFirst({
      where: { organizationId: a.id, userPrincipalName: `alex@${DA}` },
    });
    const alexB = await fx.prisma.atoAccountIdentity.findFirst({
      where: { organizationId: b.id, userPrincipalName: `alex@${DB}` },
    });
    expect(alexA!.externalIdHash).toBe(alexB!.externalIdHash);
    expect(alexA!.accountId).not.toBe(alexB!.accountId);
  });

  it('a directory binds to one non-disabled integration platform-wide', async () => {
    const c = await fx.organization('isoc');
    await configure(w.h, c.id);
    // Same directory as organization A: the unique (provider, directory_ref_hash, active_marker).
    await expect(
      fx.prisma.atoProviderIntegration.create({
        data: {
          organizationId: c.id,
          provider: 'microsoft_entra',
          connectorRef: crypto.randomUUID(),
          bindingKey: sha256Hex(`microsoft_entra|${crypto.randomUUID()}`),
          status: 'active',
          capabilities: {},
          cursors: {},
          nextPollAt: clock.now(),
          directoryRefHash: directoryRefHash('microsoft_entra', TA),
        },
      }),
    ).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
    // A binding whose directory is only learnt by the probe is paused `directory_in_use`.
    const connection = w.connect(c.id, 'microsoft_entra', { tenantId: TA, domain: DA });
    const unbound = await w.bind(connection, { unknownDirectory: true });
    await w.probe();
    const row = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: unbound.id },
    });
    expect(row).toMatchObject({ status: 'paused', pausedReason: 'directory_in_use' });
    expect(row.directoryRefHash).toBeNull();
    // A disabled integration frees the directory: the paused binding then takes it on a probe.
    await fx.prisma.atoProviderIntegration.updateMany({
      where: {
        organizationId: { in: fx.organizationIds },
        directoryRefHash: directoryRefHash('microsoft_entra', TA),
      },
      data: { status: 'disabled', disabledAt: clock.now(), disabledReason: 'test' },
    });
    await w.healthDue(unbound.id);
    await w.probe();
    expect(
      await fx.prisma.atoProviderIntegration.findUniqueOrThrow({ where: { id: unbound.id } }),
    ).toMatchObject({
      directoryRefHash: directoryRefHash('microsoft_entra', TA),
    });
  });
});
