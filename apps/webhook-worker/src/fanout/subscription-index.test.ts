import { NOTIFICATION_SETTINGS_DEFAULTS } from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';
import { InconsistentReadError } from '../shared/errors';
import { ORG_ID, ORG_PUBLIC_ID, silentLogger } from '../worker.test-support';
import {
  alertEnabled,
  matchingSubscriptions,
  type OrganizationIndex,
  SubscriptionIndex,
} from './subscription-index';

interface Rows {
  organization?: { id: bigint; publicId: string; status: string } | null;
  feature?: { organizationId: bigint; featureKey: string; enabled: boolean } | null;
  subscriptions?: Array<Record<string, unknown>>;
  settings?: { organizationId: bigint; settings: unknown } | null;
}

function fakePrisma(rows: Rows) {
  const loads = { organization: 0 };
  const prisma = {
    organization: {
      findUnique: () => {
        loads.organization += 1;
        return Promise.resolve(
          rows.organization === undefined
            ? { id: ORG_ID, publicId: ORG_PUBLIC_ID, status: 'active' }
            : rows.organization,
        );
      },
    },
    organizationFeature: {
      findUnique: () =>
        Promise.resolve(
          rows.feature === undefined
            ? { organizationId: ORG_ID, featureKey: 'webhooks', enabled: true }
            : rows.feature,
        ),
    },
    webhookSubscription: {
      findMany: () =>
        Promise.resolve(
          rows.subscriptions ?? [
            {
              id: 1n,
              publicId: 'sub-1',
              organizationId: ORG_ID,
              status: 'active',
              eventTypes: ['email.received', 'email.scanned'],
              filters: { directions: ['inbound'] },
              createdAt: new Date('2026-10-01T00:00:00.000Z'),
            },
          ],
        ),
    },
    notificationSettings: {
      findUnique: () => Promise.resolve(rows.settings === undefined ? null : rows.settings),
    },
  };
  return { prisma, loads };
}

const reads: string[] = [];
const sink = (read: string) => void reads.push(read);

describe('SubscriptionIndex (W5)', () => {
  it('loads active subscriptions, the feature, the public id and default settings', async () => {
    const { prisma } = fakePrisma({});
    const index = await new SubscriptionIndex(prisma as never, 5000, sink, silentLogger).get(
      ORG_ID,
    );
    expect(index).toMatchObject({
      organizationId: ORG_ID,
      publicId: ORG_PUBLIC_ID,
      organizationActive: true,
      webhooksEnabled: true,
      settingsInvalid: false,
      subscriptions: [
        {
          id: 1n,
          eventTypes: ['email.received', 'email.scanned'],
          filters: { directions: ['inbound'] },
        },
      ],
    });
    expect(index?.settings).toEqual(NOTIFICATION_SETTINGS_DEFAULTS);
  });

  it('caches per organization for the TTL, one load in flight', async () => {
    let now = 0;
    const { prisma, loads } = fakePrisma({});
    const index = new SubscriptionIndex(prisma as never, 5000, sink, silentLogger, () => now);
    await Promise.all([index.get(ORG_ID), index.get(ORG_ID)]);
    expect(loads.organization).toBe(1);
    now = 4999;
    await index.get(ORG_ID);
    expect(loads.organization).toBe(1);
    now = 5000;
    await index.get(ORG_ID);
    expect(loads.organization).toBe(2);
    index.invalidate(ORG_ID);
    await index.get(ORG_ID);
    expect(loads.organization).toBe(3);
  });

  it('a missing feature row means disabled; a suspended organization is inactive; a missing one null', async () => {
    const off = fakePrisma({ feature: null });
    expect(
      (await new SubscriptionIndex(off.prisma as never, 1, sink, silentLogger).get(ORG_ID))
        ?.webhooksEnabled,
    ).toBe(false);
    const suspended = fakePrisma({
      organization: { id: ORG_ID, publicId: ORG_PUBLIC_ID, status: 'suspended' },
    });
    expect(
      (await new SubscriptionIndex(suspended.prisma as never, 1, sink, silentLogger).get(ORG_ID))
        ?.organizationActive,
    ).toBe(false);
    const gone = fakePrisma({ organization: null });
    expect(
      await new SubscriptionIndex(gone.prisma as never, 1, sink, silentLogger).get(ORG_ID),
    ).toBeNull();
  });

  it('skips a stored subscription whose types or filters no longer validate', async () => {
    const { prisma } = fakePrisma({
      subscriptions: [
        {
          id: 1n,
          publicId: 'a',
          organizationId: ORG_ID,
          status: 'active',
          eventTypes: ['email.*'],
          filters: null,
          createdAt: new Date(),
        },
        {
          id: 2n,
          publicId: 'b',
          organizationId: ORG_ID,
          status: 'active',
          eventTypes: ['email.received'],
          filters: { extra: 1 },
          createdAt: new Date(),
        },
        {
          id: 3n,
          publicId: 'c',
          organizationId: ORG_ID,
          status: 'active',
          eventTypes: ['email.received'],
          filters: null,
          createdAt: new Date(),
        },
      ],
    });
    const index = await new SubscriptionIndex(prisma as never, 1, sink, silentLogger).get(ORG_ID);
    expect(index?.subscriptions.map((s) => s.id)).toEqual([3n]);
  });

  it('refuses rows of another organization (echo check) and does not cache the failure', async () => {
    const { prisma, loads } = fakePrisma({
      subscriptions: [
        {
          id: 1n,
          publicId: 'x',
          organizationId: 7n,
          status: 'active',
          eventTypes: ['email.received'],
          filters: null,
          createdAt: new Date(),
        },
      ],
    });
    const index = new SubscriptionIndex(prisma as never, 60_000, sink, silentLogger);
    await expect(index.get(ORG_ID)).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(index.get(ORG_ID)).rejects.toBeInstanceOf(InconsistentReadError);
    expect(loads.organization).toBe(2);
    expect(reads).toContain('subscriptions');
  });

  it('applies stored notification settings; invalid ones fall back to defaults', async () => {
    const valid = fakePrisma({
      settings: {
        organizationId: ORG_ID,
        settings: { alerts: { threatDetected: { minSeverity: 'medium' } } },
      },
    });
    const v = await new SubscriptionIndex(valid.prisma as never, 1, sink, silentLogger).get(ORG_ID);
    expect(v?.settings.alerts.threatDetected.minSeverity).toBe('medium');
    const invalid = fakePrisma({
      settings: { organizationId: ORG_ID, settings: { alerts: { nope: 1 } } },
    });
    const i = await new SubscriptionIndex(invalid.prisma as never, 1, sink, silentLogger).get(
      ORG_ID,
    );
    expect(i?.settingsInvalid).toBe(true);
    expect(i?.settings).toEqual(NOTIFICATION_SETTINGS_DEFAULTS);
  });
});

describe('matching and alert settings', () => {
  const index: OrganizationIndex = {
    organizationId: ORG_ID,
    publicId: ORG_PUBLIC_ID,
    organizationActive: true,
    webhooksEnabled: true,
    settings: structuredClone(NOTIFICATION_SETTINGS_DEFAULTS),
    settingsInvalid: false,
    subscriptions: [
      {
        id: 1n,
        publicId: 'a',
        eventTypes: ['email.received'],
        filters: null,
        createdAt: new Date('2026-11-01T00:00:00Z'),
      },
      {
        id: 2n,
        publicId: 'b',
        eventTypes: ['email.received'],
        filters: { directions: ['outbound'] },
        createdAt: new Date('2026-01-01T00:00:00Z'),
      },
      {
        id: 3n,
        publicId: 'c',
        eventTypes: ['email.scanned'],
        filters: { minSeverity: 'high' },
        createdAt: new Date('2026-01-01T00:00:00Z'),
      },
    ],
  };

  it('matches type, filters and created_at ≤ occurredAt', () => {
    const ids = (event: Parameters<typeof matchingSubscriptions>[1], at: string) =>
      matchingSubscriptions(index, event, new Date(at)).map((s) => s.id);
    expect(
      ids(
        { type: 'email.received', severity: 'info', direction: 'inbound' },
        '2026-11-02T00:00:00Z',
      ),
    ).toEqual([1n]);
    expect(
      ids(
        { type: 'email.received', severity: 'info', direction: 'outbound' },
        '2026-11-02T00:00:00Z',
      ),
    ).toEqual([1n, 2n]);
    expect(
      ids(
        { type: 'email.received', severity: 'info', direction: 'outbound' },
        '2026-10-31T00:00:00Z',
      ),
    ).toEqual([2n]);
    expect(ids({ type: 'email.scanned', severity: 'medium' }, '2026-11-02T00:00:00Z')).toEqual([]);
    expect(ids({ type: 'email.scanned', severity: 'high' }, '2026-11-02T00:00:00Z')).toEqual([3n]);
    expect(
      matchingSubscriptions(
        { ...index, webhooksEnabled: false },
        { type: 'email.received', severity: 'info' },
        new Date(),
      ),
    ).toEqual([]);
    // A suspended / pending-deletion / deleted organization gets no deliveries.
    expect(
      matchingSubscriptions(
        { ...index, organizationActive: false },
        { type: 'email.received', severity: 'info' },
        new Date(),
      ),
    ).toEqual([]);
  });

  it('alertEnabled follows the tenant settings (N2)', () => {
    const s = structuredClone(NOTIFICATION_SETTINGS_DEFAULTS) as OrganizationIndex['settings'];
    expect(alertEnabled(s, 'threat_detected', 'high')).toBe(true);
    expect(alertEnabled(s, 'threat_detected', 'medium')).toBe(false);
    s.alerts.threatDetected.minSeverity = 'medium';
    expect(alertEnabled(s, 'threat_detected', 'medium')).toBe(true);
    expect(alertEnabled(s, 'threat_detected', 'low')).toBe(false);
    s.alerts.threatDetected.enabled = false;
    expect(alertEnabled(s, 'threat_detected', 'high')).toBe(false);
    expect(alertEnabled(s, 'domain_dns_failed', 'medium')).toBe(true);
    s.alerts.webhookDisabled.enabled = false;
    expect(alertEnabled(s, 'webhook_disabled', 'high')).toBe(false);
  });
});
