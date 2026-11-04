import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { waitFor } from './support/compose';
import { waitForAllDeliveries } from './support/deliveries';
import {
  expectConsistentHistory,
  expectStateChangedRows,
  historyOf,
  insertFixtureMessage,
  pathOf,
  waitForLifecycle,
  type FixtureMessage,
} from './support/lifecycle';
import { sinkFiles } from './support/mail-sink';
import { MessagingScenario } from './support/messaging-scenario';
import { messagingStackGate, record } from './support/messaging-stack';
import { organizationRef } from './support/routing';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Quarantine release through the LIVE api and the real delivery path (docs/plan/steps/
 * 08-message-lifecycle.md L10.3, §9 "Stack"). Test setup puts a stored message (EML in MinIO,
 * two recipients on a domain whose destination is mail-sink) into `quarantined` with a matching
 * history (direct SQL is a fixture, L8.6: no producer of `quarantined` exists before 5.2). An
 * organization administrator releases it with `POST /api/v1/messages/{id}/release` and an
 * Idempotency-Key: E14 (`quarantined → approved`, round 1), approvals with `deliverySeq` 1 in
 * the outbox; the relay publishes them, the planner plans them (E20, round 1), Postfix delivers,
 * the recorder derives `delivered`. A retry with the same key replays the stored response and
 * changes nothing.
 */
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('lifecycle-release', fx);
let session: ApiSession | undefined;

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('lc-release');
  session = await apiSession(
    fx.prisma,
    await organizationRef(fx, scenario.org),
    'organization_admin',
  );
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await session?.remove();
  await scenario.teardown();
}, 300_000);

describe.skipIf(gate.skip)('lifecycle stack: quarantine release', { timeout: 300_000 }, () => {
  it('releases a quarantined message through the api; it is planned and delivered once', async () => {
    const recipients = [`rel-a@${scenario.domain.name}`, `rel-b@${scenario.domain.name}`];
    const message: FixtureMessage = await insertFixtureMessage(fx, {
      organizationId: scenario.org,
      domainId: scenario.domain.id,
      state: 'quarantined',
      recipients,
      recipientStatus: 'quarantined',
      subject: 'Lifecycle release',
    });
    expect(message.version).toBe(2);
    const key = `it-release-${fx.suffix}`;
    const body = { expectedVersion: 2, reason: 'stack test: false positive, release to inbox' };
    const path = `/messages/${message.publicId}/release`;

    // Without the header: 400, nothing changes.
    const missing = await session!.post(path, body);
    expect(missing.status).toBe(400);
    expect(missing.body).toMatchObject({ code: 'idempotency_key_required' });

    const started = Date.now();
    const first = await session!.post(path, body, { 'Idempotency-Key': key });
    expect(first.status, JSON.stringify(first.body)).toBe(202);
    expect(first.body).toMatchObject({
      messageId: message.publicId,
      state: 'approved',
      version: 3,
      lifecycleRound: 1,
      deliverySeq: 1,
      recipientCount: 2,
    });
    const approvalEventIds = (first.body as { approvalEventIds: string[] }).approvalEventIds;
    expect(approvalEventIds).toHaveLength(1);

    // Same key, same request: the stored response, no second effect.
    const replay = await session!.post(path, body, { 'Idempotency-Key': key });
    expect(replay.status).toBe(202);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body).toEqual(first.body);
    // Same key, another body: refused.
    const reused = await session!.post(
      path,
      { ...body, reason: 'a different operator reason text' },
      { 'Idempotency-Key': key },
    );
    expect(reused.status).toBe(422);
    expect(reused.body).toMatchObject({ code: 'idempotency_key_reused' });

    // The real delivery path: relay → planner (E20) → reinjection → Postfix → mail-sink.
    const deliveries = await waitForAllDeliveries(
      fx.prisma,
      scenario.org,
      message.id,
      ['delivered'],
      2,
      180_000,
    );
    expect(deliveries.every((d) => d.deliverySeq === 1)).toBe(true);
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    const deliveredAfterMs = Date.now() - started;
    for (const rcpt of recipients) expect(await sinkFiles(rcpt)).toHaveLength(1);

    expect(await pathOf(fx.prisma, message)).toEqual([
      [null, 'received', 'smtp_accepted'],
      ['received', 'persisted', 'committed'],
      ['persisted', 'quarantined', 'policy_quarantine'],
      ['quarantined', 'approved', 'quarantine_release'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_complete'],
    ]);
    await expectConsistentHistory(fx.prisma, message);
    await expectStateChangedRows(fx.prisma, scenario.org, message);
    const history = await historyOf(fx.prisma, message);
    expect(history.slice(3).map((h) => h.lifecycleRound)).toEqual([1, 1, 1]);
    expect(history[3]).toMatchObject({
      actorRole: 'operator',
      actorService: 'api',
      actorType: 'user',
      actorId: session!.userPublicId,
    });
    const row = await fx.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: message.id, receivedAt: message.receivedAt } },
    });
    expect([row.version, row.lifecycleRound]).toEqual([5, 1]);

    // Exactly one approval outbox row, one planner ledger row, one audit row, one key record.
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: scenario.org, eventType: 'mail.delivery.approved.v1' },
      }),
    ).toBe(1);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: 'delivery-worker.planner', eventId: { in: approvalEventIds } },
      }),
    ).toBe(1);
    const audits = await fx.prisma.auditLog.findMany({
      where: { organizationId: scenario.org, action: 'message.quarantine_released' },
    });
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ resourceType: 'message', resourceId: message.publicId });
    expect(
      await fx.prisma.apiIdempotencyKey.count({ where: { organizationId: scenario.org } }),
    ).toBe(1);

    // The read API (replica, lag fallback) shows the final state.
    await waitFor(
      'the lifecycle read API to show delivered',
      async () => {
        const res = await session!.get(`/messages/${message.publicId}/lifecycle`);
        return res.status === 200 && (res.body as { state?: string }).state === 'delivered'
          ? res
          : undefined;
      },
      { timeoutMs: 30_000, intervalMs: 500 },
    ).then((res) =>
      expect(res.body).toMatchObject({
        statusReason: 'delivery_complete',
        version: 5,
        lifecycleRound: 1,
        deliverySeq: 1,
        recipients: { total: 2, byStatus: { delivered: 2 } },
        actions: { rescan: false, release: false },
      }),
    );
    // A second release is a state conflict now.
    const again = await session!.post(
      path,
      { ...body, expectedVersion: 5 },
      { 'Idempotency-Key': `${key}-2` },
    );
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({ code: 'message_state_conflict', currentState: 'delivered' });
    record('lifecycle-release', {
      recipients: 2,
      delivered_after_release_s: (deliveredAfterMs / 1000).toFixed(1),
      history_rows: history.length,
    });
  });

  it('a refused first recipient does not finish the release: the other is delivered, delivery_partial', async () => {
    // Regression (step 3.3 verification round 2): the release turns its quarantined recipients
    // into `pending`, so the planner's refusal of recipient 0 cannot derive `rejected` while
    // recipient 1 still reads as `quarantined` (settled).
    // Inbound: the planner refuses a recipient whose domain is not a domain of the organization
    // (`recipient_domain_inactive`, delivery `failed`); suppressions apply to outbound only.
    const refused = `rel-x@not-a-tenant-${fx.suffix}.test`;
    const kept = `rel-k@${scenario.domain.name}`;
    const message: FixtureMessage = await insertFixtureMessage(fx, {
      organizationId: scenario.org,
      domainId: scenario.domain.id,
      state: 'quarantined',
      recipients: [refused, kept],
      recipientStatus: 'quarantined',
      subject: 'Lifecycle release, one recipient refused',
    });
    const res = await session!.post(
      `/messages/${message.publicId}/release`,
      { expectedVersion: message.version, reason: 'stack test: release with a refused rcpt' },
      { 'Idempotency-Key': `it-release-partial-${fx.suffix}` },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({ state: 'approved', recipientCount: 2 });

    const deliveries = await waitForAllDeliveries(
      fx.prisma,
      scenario.org,
      message.id,
      ['delivered', 'failed'],
      2,
      180_000,
    );
    expect(deliveries.map((d) => d.status).sort()).toEqual(['delivered', 'failed']);
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_partial');
    expect(await sinkFiles(kept)).toHaveLength(1);
    expect(await pathOf(fx.prisma, message)).toEqual([
      [null, 'received', 'smtp_accepted'],
      ['received', 'persisted', 'committed'],
      ['persisted', 'quarantined', 'policy_quarantine'],
      ['quarantined', 'approved', 'quarantine_release'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_partial'],
    ]);
    await expectConsistentHistory(fx.prisma, message);
  });
});
