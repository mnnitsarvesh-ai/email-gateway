import { describe, expect, it } from 'vitest';
import { testUser } from '../../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../../auth-contracts/tenant-scope';
import { ownerOf } from '../conversation.service';
import { sha256Hex } from './report-object-store';
import { figuresOf, sectionsOf } from './reports.service';

/**
 * `GET /assistant/reports/{reportId}` (step AI-R §4.1) and the report retention (D7) at the
 * service level: the owner view with the HTML from the object store, the purge transitions with
 * the conversation content, the object deletion batches, the pending and queued sweeps and the
 * hard-delete guard. In-memory doubles; synthetic data only.
 */

const ORG = 7001n;
const HTML = '<!doctype html><html lang="en"><body><h1>Security report</h1></body></html>';
const ID = (n: number) => `0193d000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const DAY = 86_400_000;

function setup(user: UserPrincipal = testUser()) {
  const h = createAssistantHarness({}, undefined, user);
  h.world.enable(ORG);
  const scope = scopeFromPrincipal(user);
  const owner = ownerOf(user, scope);
  const conversation = h.world.addConversation(owner);
  const rw = h.world.reportWorld;
  const addReport = (n: number, overrides: Record<string, unknown> = {}) => {
    const publicId = ID(n);
    const key = `org/7001/assistant/report/2026/11/23/${publicId}.html`;
    const bytes = Buffer.from(HTML, 'utf8');
    rw.objects.set(key, bytes);
    const id = rw.id();
    rw.reports.push({
      id,
      publicId,
      organizationId: ORG,
      userId: user.userId,
      platformOverrideId: null,
      conversationId: conversation.id,
      conversationPublicId: conversation.publicId,
      executionId: null,
      status: 'available',
      title: 'Security report: Last 7 days',
      periodFrom: new Date('2026-11-16T09:00:00.000Z'),
      periodTo: new Date('2026-11-23T09:00:00.000Z'),
      granularity: 'day',
      sections: {
        included: ['summary', 'traffic'],
        omitted: [{ section: 'ato', reason: 'permission', code: 'ato:read' }],
        atoRange: '7d',
        label: 'Last 7 days',
      },
      figures: [{ label: 'Messages', value: '120' }],
      templateVersion: 'assistant-report/1',
      objectKey: key,
      sizeBytes: bytes.length,
      sha256: sha256Hex(bytes),
      errorCode: null,
      purgedAt: null,
      objectDeletedAt: null,
      createdAt: new Date('2026-11-23T09:00:31.000Z'),
      updatedAt: new Date('2026-11-23T09:00:31.000Z'),
      ...overrides,
    } as never);
    return rw.reports.at(-1)!;
  };
  const addDelivery = (reportId: bigint, n: number, overrides: Record<string, unknown> = {}) => {
    rw.deliveries.push({
      id: rw.id(),
      publicId: ID(100 + n),
      organizationId: ORG,
      userId: user.userId,
      conversationId: conversation.id,
      reportId,
      confirmationId: BigInt(n),
      recipientAddress: 'it-analyst@example.test',
      recipientSha256: 'ab'.repeat(32),
      recipientKind: 'self',
      status: 'queued',
      errorCode: null,
      sizeBytes: 100,
      correlationId: 'it-corr',
      requestedAt: new Date(Date.UTC(2026, 10, 23, 9, n)),
      sentAt: null,
      ...overrides,
    } as never);
    return rw.deliveries.at(-1)!;
  };
  return { h, rw, user, scope, owner, conversation, addReport, addDelivery };
}

const coded = async (promise: Promise<unknown>): Promise<{ status: number; code: string }> => {
  try {
    await promise;
  } catch (error) {
    const e = error as { getStatus(): number; code: string };
    return { status: e.getStatus(), code: e.code };
  }
  throw new Error('expected a coded error');
};

describe('GET /assistant/reports/{reportId} (step AI-R §4.1)', () => {
  it('maps the owner’s report with the HTML and its deliveries newest first', async () => {
    const t = setup();
    const report = t.addReport(1);
    t.addDelivery(report.id, 1, { status: 'sent', sentAt: new Date('2026-11-23T09:02:00.000Z') });
    t.addDelivery(report.id, 2, { status: 'failed', errorCode: 'relay_not_configured' });
    const view = await t.h.reports.get(t.user, t.scope, ID(1));
    expect(view.html).toBe(HTML);
    expect(view.report).toMatchObject({
      id: ID(1),
      conversationId: t.conversation.publicId,
      status: 'available',
      period: {
        from: '2026-11-16T09:00:00.000Z',
        to: '2026-11-23T09:00:00.000Z',
        granularity: 'day',
        atoRange: '7d',
      },
      sections: ['summary', 'traffic'],
      omitted: [{ section: 'ato', reason: 'permission', code: 'ato:read' }],
      figures: [{ label: 'Messages', value: '120' }],
      templateVersion: 'assistant-report/1',
    });
    expect(view.report.deliveries.map((d) => [d.id, d.status, d.errorCode])).toEqual([
      [ID(102), 'failed', 'relay_not_configured'],
      [ID(101), 'sent', null],
    ]);
  });

  it('answers 404 for another user, organization or override; html null unless available', async () => {
    const t = setup();
    t.addReport(1);
    const other = testUser({ userId: 502n, userPublicId: ID(502) });
    expect(await coded(t.h.reports.get(other, t.scope, ID(1)))).toEqual({
      status: 404,
      code: 'assistant_report_not_found',
    });
    expect(await coded(t.h.reports.get(t.user, t.scope, ID(9)))).toEqual({
      status: 404,
      code: 'assistant_report_not_found',
    });
    t.addReport(2, { status: 'purged', objectKey: null });
    expect((await t.h.reports.get(t.user, t.scope, ID(2))).html).toBeNull();
    // An object that no longer matches its SHA-256 is never served.
    const tampered = t.addReport(3);
    t.rw.objects.set(tampered.objectKey!, Buffer.from('<p>changed</p>'));
    expect((await t.h.reports.get(t.user, t.scope, ID(3))).html).toBeNull();
  });

  it('parses stored JSON defensively', () => {
    expect(sectionsOf({ included: ['summary', 'x'], omitted: [{ section: 'y' }] })).toEqual({
      included: ['summary'],
      omitted: [],
      atoRange: null,
    });
    expect(figuresOf([{ label: 'a', value: 'b' }, { label: 1 }])).toEqual([
      { label: 'a', value: 'b' },
    ]);
  });
});

describe('report retention (step AI-R D7)', () => {
  it('DELETE conversation: reports purged and their objects deleted inline; queued deliveries fail', async () => {
    const t = setup();
    const report = t.addReport(1);
    const delivery = t.addDelivery(report.id, 1);
    await t.h.conversations.remove(t.user, t.scope, t.conversation.publicId, null);
    expect(report).toMatchObject({ status: 'purged', objectKey: null });
    expect(report.objectDeletedAt).not.toBeNull();
    expect(t.rw.objects.size).toBe(0);
    expect(delivery).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_purged',
      recipientAddress: null,
    });
  });

  it('a failing inline delete leaves the object to the job, which deletes it in a batch', async () => {
    const t = setup();
    const report = t.addReport(1);
    t.rw.failNext.delete = true;
    await t.h.conversations.remove(t.user, t.scope, t.conversation.publicId, null);
    expect(report).toMatchObject({ status: 'purged', objectDeletedAt: null });
    expect(t.rw.objects.size).toBe(1);
    expect(await t.h.retention.deletePurgedReportObjects(new Date())).toBe(1);
    expect(report.objectKey).toBeNull();
    expect(t.rw.objects.size).toBe(0);
  });

  it('the content purge at purge_after purges the reports; the job deletes the objects', async () => {
    const t = setup();
    const report = t.addReport(1);
    t.conversation.purgeAfter = new Date(Date.now() - 1000);
    await t.h.retention.purgeContent(new Date());
    expect(report.status).toBe('purged');
    expect(await t.h.retention.deletePurgedReportObjects(new Date())).toBe(1);
    expect(t.rw.objects.size).toBe(0);
  });

  it('sweeps pending reports older than 1 hour and queued deliveries older than 25 hours', async () => {
    const t = setup();
    const now = new Date('2026-11-24T12:00:00.000Z');
    const old = t.addReport(1, {
      status: 'pending',
      createdAt: new Date(now.getTime() - 2 * 3600_000),
    });
    const fresh = t.addReport(2, {
      status: 'pending',
      createdAt: new Date(now.getTime() - 60_000),
    });
    expect(await t.h.retention.sweepPendingReports(now)).toBe(1);
    expect(old).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_abandoned',
      objectKey: null,
    });
    expect(fresh.status).toBe('pending');
    expect(t.rw.objects.has(`org/7001/assistant/report/2026/11/23/${ID(1)}.html`)).toBe(false);

    const report = t.addReport(3);
    const stale = t.addDelivery(report.id, 1, {
      requestedAt: new Date(now.getTime() - 26 * 3600_000),
    });
    const recent = t.addDelivery(report.id, 2, { requestedAt: new Date(now.getTime() - 3600_000) });
    expect(await t.h.retention.sweepQueuedDeliveries(now)).toBe(1);
    expect(stale).toMatchObject({ status: 'failed', errorCode: 'assistant_report_email_timeout' });
    expect(recent.status).toBe('queued');
  });

  it('the hard delete skips a conversation whose report still has an object', async () => {
    const t = setup();
    const report = t.addReport(1, { status: 'purged' });
    t.conversation.lastTurnAt = new Date(Date.now() - 400 * DAY);
    const result = await t.h.retention.runOnce(new Date());
    // The run deletes the purged object first; the next run's hard delete may then remove it.
    expect(result?.reportObjects).toBe(1);
    expect(report.objectKey).toBeNull();
    const kept = setup();
    kept.addReport(1, { status: 'purged' });
    kept.rw.failNext.delete = true;
    kept.conversation.lastTurnAt = new Date(Date.now() - 400 * DAY);
    await kept.h.retention.runOnce(new Date());
    expect(kept.h.world.conversations.some((c) => c.id === kept.conversation.id)).toBe(true);
  });
});
