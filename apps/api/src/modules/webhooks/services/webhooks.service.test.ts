import { randomUUID } from 'node:crypto';
import { isWebhookSecret, secretAad, WebhookSecretCipher } from '@email-gateway/webhooks';
import { beforeEach, describe, expect, it } from 'vitest';
import { InMemoryIdempotencyStore, immediateRunner } from '../../../../test/support/api-test-app';
import { RecordingAuditService, WebhooksWorld } from '../../../../test/support/webhooks-fixtures';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { IdempotencyService } from '../../../http/idempotency/idempotency.service';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import type { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import { checkReplayRange } from './webhook-deliveries.service';
import { WebhookSecrets } from './webhook-secrets';
import { changedFields, WebhooksService, withSecret } from './webhooks.service';

const KEY = 'a'.repeat(64);
const ORG = 7n;
const scope = systemScope(ORG);
const principal: UserPrincipal = {
  kind: 'user',
  userId: 3n,
  userPublicId: randomUUID(),
  organizationId: ORG,
  organizationPublicId: randomUUID(),
  organizationKind: 'customer',
  sessionId: randomUUID(),
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['webhook:manage']),
};

function bed(config: Record<string, unknown> = {}) {
  const world = new WebhooksWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  const runner = immediateRunner as unknown as TransactionRunner;
  const idempotency = new IdempotencyService(runner, store.records);
  const features = {
    isEnabled: (org: bigint) => Promise.resolve(!world.featureDisabled.has(org)),
  } as unknown as OrganizationFeaturesService;
  const limits = {
    lockOrganization: () => Promise.resolve(),
  } as unknown as OrganizationLimitsService;
  const cfg = {
    WEBHOOK_ALLOWED_PORTS: [443],
    WEBHOOK_ALLOW_HTTP: false,
    WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG: 2,
    WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT: 24,
    URL_CLICK_BASE_URL: undefined,
    PORTAL_PUBLIC_URL: 'https://portal.gateway.example',
    WEBHOOK_SECRET_ENCRYPTION_KEY: KEY,
    ...config,
  };
  const service = new WebhooksService(
    cfg,
    world.subscriptionsDouble(),
    world.deliveriesDouble(),
    new WebhookSecrets(cfg),
    idempotency,
    runner,
    features,
    limits,
    audit,
    new CursorCodec({ API_CURSOR_KEY: KEY, API_CURSOR_TTL_SECONDS: 3600 }),
  );
  return { world, audit, store, service };
}

const body = (patch: Record<string, unknown> = {}) => ({
  name: ' Hook\u0007 ',
  url: 'https://hooks.example.com/in',
  eventTypes: ['email.received'],
  ...patch,
});

describe('WebhooksService (step 6.2 W5–W7)', () => {
  let t: ReturnType<typeof bed>;
  beforeEach(() => {
    t = bed();
  });

  it('create: encrypts with the AAD of (organization, subscription, 1); stores the redacted body', async () => {
    const res = await t.service.create(
      principal,
      scope,
      { idempotencyKey: 'k1', body: body(), requestHost: null },
      '10.0.0.1',
    );
    expect(res.replayed).toBe(false);
    expect(res.statusCode).toBe(201);
    expect(isWebhookSecret(res.body.secret!)).toBe(true);
    expect(res.body.name).toBe('Hook');
    const row = t.world.subscriptions[0]!;
    const cipher = new WebhookSecretCipher({ key: KEY });
    expect(cipher.decrypt(row.secretCiphertext, secretAad(ORG, res.body.id, 1)).plaintext).toBe(
      res.body.secret,
    );
    const stored = [...t.store.rows.values()][0]!;
    expect((stored.response as { secret: unknown }).secret).toBeNull();
    const replay = await t.service.create(
      principal,
      scope,
      { idempotencyKey: 'k1', body: body(), requestHost: null },
      null,
    );
    expect(replay).toMatchObject({ replayed: true, body: { secret: null, id: res.body.id } });
    expect(t.audit.entries).toHaveLength(1);
    expect(t.audit.entries[0]!.metadata).toMatchObject({ urlHost: 'hooks.example.com' });
    expect(JSON.stringify(t.audit.entries[0]!.metadata)).not.toMatch(/https:|whsec_/);
  });

  it('create: refuses the cap (409), the feature (403) and bad URLs (422) without storing', async () => {
    t.world.featureDisabled.add(ORG);
    await expect(
      t.service.create(
        principal,
        scope,
        { idempotencyKey: 'f', body: body(), requestHost: null },
        null,
      ),
    ).rejects.toMatchObject({ code: 'webhooks_not_enabled' });
    t.world.featureDisabled.clear();
    t.world.addSubscription(ORG, { publicId: randomUUID() });
    t.world.addSubscription(ORG, { publicId: randomUUID() });
    await expect(
      t.service.create(
        principal,
        scope,
        { idempotencyKey: 'c', body: body(), requestHost: null },
        null,
      ),
    ).rejects.toMatchObject({ code: 'webhook_limit_reached' });
    await expect(
      t.service.create(
        principal,
        scope,
        {
          idempotencyKey: 'u',
          body: body({ url: 'https://portal.gateway.example/x' }),
          requestHost: null,
        },
        null,
      ),
    ).rejects.toMatchObject({ code: 'webhook_url_not_allowed', details: { reason: 'deny_list' } });
    expect(t.store.rows.size).toBe(0);
  });

  it('rotate: overlap moves the current ciphertext to previous; 0 clears it; the replay is redacted', async () => {
    const sub = t.world.addSubscription(ORG, {
      publicId: randomUUID(),
      secretCiphertext: 'v1.k1.cur',
    });
    const res = await t.service.rotate(
      principal,
      scope,
      { webhookId: sub.publicId, idempotencyKey: 'r1', body: { overlapHours: 3 } },
      null,
    );
    expect(res.body.secretVersion).toBe(2);
    expect(sub).toMatchObject({ secretVersion: 2, previousSecretCiphertext: 'v1.k1.cur' });
    expect(sub.previousSecretExpiresAt!.getTime() - sub.secretRotatedAt!.getTime()).toBe(
      3 * 3_600_000,
    );
    const replay = await t.service.rotate(
      principal,
      scope,
      { webhookId: sub.publicId, idempotencyKey: 'r1', body: { overlapHours: 3 } },
      null,
    );
    expect(replay.body.secret).toBeNull();
    await t.service.rotate(
      principal,
      scope,
      { webhookId: sub.publicId, idempotencyKey: 'r2', body: { overlapHours: 0 } },
      null,
    );
    expect(sub).toMatchObject({
      secretVersion: 3,
      previousSecretCiphertext: null,
      previousSecretExpiresAt: null,
    });
  });

  it('update: CAS, no-op without audit, manual disable cancels pending deliveries', async () => {
    const sub = t.world.addSubscription(ORG, { publicId: randomUUID() });
    t.world.addDelivery(sub, {
      publicId: randomUUID(),
      eventId: randomUUID(),
      eventOccurredAt: new Date(),
      status: 'pending',
    });
    await expect(
      t.service.update(
        principal,
        scope,
        sub.publicId,
        { expectedRowVersion: 9, name: 'x' },
        null,
        null,
      ),
    ).rejects.toMatchObject({ code: 'webhook_version_conflict' });
    const same = await t.service.update(
      principal,
      scope,
      sub.publicId,
      { expectedRowVersion: 1, name: 'hook' },
      null,
      null,
    );
    expect(same.rowVersion).toBe(1);
    expect(t.audit.entries).toHaveLength(0);
    const disabled = await t.service.update(
      principal,
      scope,
      sub.publicId,
      { expectedRowVersion: 1, status: 'disabled' },
      null,
      null,
    );
    expect(disabled).toMatchObject({ status: 'disabled', disabledReason: 'manual', rowVersion: 2 });
    expect(t.world.deliveries[0]!.status).toBe('cancelled');
  });

  it('delete: soft delete, pending cancelled, then 404 for a new key', async () => {
    const sub = t.world.addSubscription(ORG, { publicId: randomUUID() });
    const res = await t.service.delete(
      principal,
      scope,
      { webhookId: sub.publicId, idempotencyKey: 'd1' },
      null,
    );
    expect(res).toMatchObject({ statusCode: 204, replayed: false });
    expect(sub.status).toBe('deleted');
    await expect(
      t.service.delete(principal, scope, { webhookId: sub.publicId, idempotencyKey: 'd2' }, null),
    ).rejects.toMatchObject({ code: 'webhook_not_found' });
  });

  it('never returns another organization’s subscription', async () => {
    const foreign = t.world.addSubscription(99n, { publicId: randomUUID() });
    await expect(t.service.get(scope, foreign.publicId)).rejects.toMatchObject({
      code: 'webhook_not_found',
    });
    await expect(t.service.test(principal, scope, foreign.publicId, null)).rejects.toMatchObject({
      code: 'webhook_not_found',
    });
  });
});

describe('helpers', () => {
  it('withSecret adds the secret to live responses only', () => {
    const stored = { statusCode: 201, body: { id: 'x', secret: null as string | null } };
    expect(withSecret({ ...stored, replayed: false }, 'whsec_x').body.secret).toBe('whsec_x');
    expect(withSecret({ ...stored, replayed: true }, 'whsec_x').body.secret).toBeNull();
    expect(withSecret({ ...stored, replayed: false }, null).body.secret).toBeNull();
  });

  it('changedFields lists the client-visible fields only', () => {
    expect(
      changedFields({ status: 'active', consecutiveFailures: 0, failingSince: null, url: 'u' }),
    ).toEqual(['status', 'url']);
  });

  it('checkReplayRange enforces order, length, retention and no future end', () => {
    const now = new Date('2026-11-13T12:00:00Z');
    const ok = checkReplayRange(
      { from: '2026-11-13T00:00:00Z', to: '2026-11-13T10:00:00Z' },
      { maxRangeHours: 72, now },
    );
    expect(ok.to.toISOString()).toBe('2026-11-13T10:00:00.000Z');
    for (const [from, to] of [
      ['2026-11-13T10:00:00Z', '2026-11-13T09:00:00Z'],
      ['2026-11-01T00:00:00Z', '2026-11-13T00:00:00Z'],
      ['2026-09-01T00:00:00Z', '2026-09-01T01:00:00Z'],
      ['2026-11-13T11:00:00Z', '2026-11-13T13:00:00Z'],
    ] as const) {
      expect(() => checkReplayRange({ from, to }, { maxRangeHours: 72, now }), from).toThrow();
    }
  });
});
