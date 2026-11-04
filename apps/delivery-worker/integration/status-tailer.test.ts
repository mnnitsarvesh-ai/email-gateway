import { renameSync, writeFileSync } from 'node:fs';
import { AdvisoryLocks } from '@email-gateway/common';
import { reinjectionToken } from '@email-gateway/mail-routing';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { RECORDER_TX_TIMEOUT_MS } from '../src/delivery.module';
import { DeliveryReconciler } from '../src/reconciler/delivery-reconciler';
import { PostfixLogTailer } from '../src/status/postfix-log-tailer';
import { StatusSignalApplier } from '../src/status/status-signal-applier';
import { FakePostfix } from './support/fake-postfix';
import {
  Fixtures,
  type MessageFixture,
  newMetrics,
  requireEnv,
  silentLogger,
  workerConfig,
} from './support/fixtures';
import { lines, TempLog } from './support/postfix-log';
import { buildWorker, FAST, makeDue, type TestWorker } from './support/worker';

const fx = new Fixtures();
const postfix = new FakePostfix();
const logs: TempLog[] = [];
const lockConnections: AdvisoryLocks[] = [];
let worker: TestWorker;
let org: bigint;

beforeAll(async () => {
  await postfix.start();
  worker = buildWorker(
    fx,
    workerConfig({ ...FAST, ...postfix.configOverrides, DELIVERY_REINJECT_DATA_TIMEOUT_MS: '300' }),
  );
  org = await fx.organization('tail');
});
afterEach(() => postfix.reset());
afterAll(async () => {
  await worker.close();
  await postfix.stop();
  for (const locks of lockConnections) await locks.close();
  for (const log of logs) log.remove();
  await fx.cleanup();
});

function tailer(log: TempLog, sourceId: string) {
  return new PostfixLogTailer(tailerOptions(log, sourceId));
}

function tailerOptions(log: TempLog, sourceId: string) {
  const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  lockConnections.push(locks);
  const metrics = newMetrics();
  return {
    prisma: fx.prisma,
    locks,
    metrics,
    logger: silentLogger,
    path: log.path,
    sourceId,
    pollMs: 100,
    rotationGraceMs: 0,
    applier: new StatusSignalApplier({
      prisma: fx.prisma,
      metrics,
      logger: silentLogger,
      sourceId,
      unmatchedRetryMs: 1000,
      recorderTimeoutMs: RECORDER_TX_TIMEOUT_MS,
    }),
  };
}

const newLog = () => {
  const log = new TempLog();
  logs.push(log);
  return log;
};

async function delivered(
  addresses: string[],
): Promise<{ message: MessageFixture; token: string; queueId: string }> {
  const message = await fx.message(org, {
    envelopeFrom: 'alice@sender.example',
    recipients: addresses.map((address) => ({ address })),
  });
  await worker.plan(fx.approval(message));
  await worker.reinjectOnce();
  const [row] = await fx.reinjections(message);
  return { message, token: reinjectionToken(row!.publicId), queueId: row!.queueId! };
}

const byAddress = async (message: MessageFixture) => {
  const out: Record<
    string,
    { status: string; attempts: number; errorClass: string | null; dsnQueueId: string | null }
  > = {};
  for (const d of await fx.deliveries(message)) {
    const r = message.recipients.find((x) => x.id === d.recipientId)!;
    out[r.address] = {
      status: d.status,
      attempts: d.attemptCount,
      errorClass: d.lastErrorClass,
      dsnQueueId: d.dsnQueueId,
    };
  }
  return out;
};

describe('Postfix delivery-log tailer (R9) over a log file', () => {
  it('applies binding, results, DSN and removal lines; follows rotation; re-reading changes nothing', async () => {
    const { message, token, queueId } = await delivered([
      'd1@ext-t.test',
      'd2@ext-t.test',
      'b3@ext-t.test',
    ]);
    const log = newLog();
    const source = fx.logSource('main');
    const t0 = new Date(Date.now() + 1000);
    const at = (s: number) => new Date(t0.getTime() + s * 1000);
    log.append(
      lines.health(at(0)),
      lines.bind(at(0), queueId, token),
      lines.queueActive(at(0), queueId, 'alice@sender.example', 3),
      lines.deferred(at(1), queueId, 'd1@ext-t.test'),
      lines.sent(at(1), queueId, 'D2@ext-t.test'), // Postfix keeps the case: matched case-insensitively
      lines.sent(at(1), queueId, 'D2@ext-t.test'), // duplicated line
      lines.bounced(at(2), queueId, 'b3@ext-t.test'),
      lines.senderDsn(at(2), queueId, '4jJdnb5qBvzs5Z'),
    );
    const reader = tailer(log, source);
    await reader.pollOnce();
    let states = await byAddress(message);
    expect(states['d1@ext-t.test']).toMatchObject({
      status: 'deferred',
      attempts: 1,
      errorClass: 'remote_4xx',
    });
    expect(states['d2@ext-t.test']).toMatchObject({ status: 'delivered', attempts: 1 });
    expect(states['b3@ext-t.test']).toMatchObject({
      status: 'bounced',
      dsnQueueId: '4jJdnb5qBvzs5Z',
    });
    const audit = await fx.prisma.deliveryStatusEvent.findMany({
      where: { messageId: message.messageId, source: 'postfix_log' },
    });
    // The duplicated sent line produced no second audit row.
    expect(audit.filter((a) => a.toStatus === 'delivered')).toHaveLength(1);
    const cursor = await fx.prisma.streamCursor.findUniqueOrThrow({
      where: { name: `postfix-log:${source}` },
    });
    expect(cursor.fileId).toMatch(/^\d+:\d+$/);
    expect(Number(cursor.fileOffset)).toBeGreaterThan(0);
    expect(cursor.lastEventAt?.toISOString()).toBe(
      new Date(Math.floor(at(2).getTime() / 1000) * 1000).toISOString(),
    );

    // Rotation: rename, postlogd writes a last line to the old inode, then a new file appears.
    renameSync(log.path, `${log.path}.20261103-120000`);
    writeFileSync(`${log.path}.20261103-120000`, `${lines.health(at(3))}\n`, { flag: 'a' });
    // Out of order: an older deferred line for d1 after a newer one, then the final sent line.
    writeFileSync(
      log.path,
      [
        lines.deferred(at(0), queueId, 'd1@ext-t.test'),
        lines.sent(at(4), queueId, 'd1@ext-t.test'),
        lines.removed(at(5), queueId),
        '',
      ].join('\n'),
    );
    await reader.pollOnce(); // drains the old file, then switches
    await reader.pollOnce();
    states = await byAddress(message);
    expect(states['d1@ext-t.test']).toMatchObject({ status: 'delivered', attempts: 2 });
    const staleRow = await fx.prisma.deliveryStatusEvent.findMany({
      where: { messageId: message.messageId, applied: false },
    });
    expect(staleRow.length).toBeGreaterThanOrEqual(1);
    const msg = await fx.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
    });
    // The derived lifecycle state (step 3.3 L9): settled, one recipient delivered.
    expect(msg).toMatchObject({ status: 'delivered', statusReason: 'delivery_partial' });
    await reader.stop();

    // Reset the cursor and re-read the current file: no transition, no email_events/outbox row.
    const before = await fx.counts(message);
    await fx.prisma.streamCursor.delete({ where: { name: `postfix-log:${source}` } });
    const again = tailer(log, source);
    await again.pollOnce();
    await again.stop();
    expect(await fx.counts(message)).toEqual(before);
  });

  it('retries the lines of a bound queue id whose binding commits later; unrelated queue ids are ignored at once', async () => {
    const { message, token } = await delivered(['late@ext-t2.test']);
    const log = newLog();
    const source = fx.logSource('late');
    const now = new Date(Date.now() + 1000);
    // A different queue id than the 250 reply: the log binding is what matters.
    const [row] = await fx.reinjections(message);
    const where = { id_receivedAt: { id: row!.id, receivedAt: row!.receivedAt } };
    await fx.prisma.deliveryReinjection.update({ where, data: { queueId: null } });
    await fx.prisma.emailDelivery.updateMany({
      where: { messageId: message.messageId },
      data: { outboundQueueId: null },
    });
    // The token's row is not findable yet (its commit is late): park it under another public id.
    await fx.prisma.deliveryReinjection.update({
      where,
      data: { publicId: '00000000-0000-7000-8000-000000000000' },
    });
    log.append(
      lines.bind(now, '4jJlateQID01', token),
      lines.sent(now, '4jJlateQID01', 'late@ext-t2.test'),
      lines.sent(now, '4jJunknown01', 'nobody@ext-t2.test'),
    );
    const reader = tailer(log, source);
    await reader.pollOnce();
    expect((await byAddress(message))['late@ext-t2.test']!.status).toBe('queued');
    await fx.prisma.deliveryReinjection.update({ where, data: { publicId: row!.publicId } });
    await new Promise((r) => setTimeout(r, 2100));
    await reader.pollOnce();
    await reader.pollOnce();
    expect((await byAddress(message))['late@ext-t2.test']!.status).toBe('delivered');
    await reader.stop();
  });

  it('a missing log file is retried without failing', async () => {
    const log = newLog();
    const reader = tailer(log, fx.logSource('missing'));
    expect(await reader.pollOnce()).toBe(0);
    log.append(lines.health(new Date()));
    expect(await reader.pollOnce()).toBe(1);
    await reader.stop();
  });

  it('only one reader per source holds the lock', async () => {
    const log = newLog();
    const source = fx.logSource('lock');
    log.append(lines.health(new Date()));
    const a = tailer(log, source);
    const b = tailer(log, source);
    expect(await a.pollOnce()).toBe(1);
    expect(await b.pollOnce()).toBe(0);
    await a.stop();
    // b takes over at a's committed cursor: nothing is read twice.
    expect(await b.pollOnce()).toBe(0);
    log.append(lines.health(new Date()));
    expect(await b.pollOnce()).toBe(1);
    await b.stop();
  });
});

/** A reconciler that decides from this test's log source only (the minimum over sources). */
const reconcilerFor = (source: string, overrides: Partial<typeof worker.config> = {}) =>
  new DeliveryReconciler(
    fx.prisma,
    newMetrics(),
    { ...worker.config, ...overrides },
    silentLogger,
    RECORDER_TX_TIMEOUT_MS,
    undefined,
    { organizationIds: fx.organizationIds, logSourcePrefix: `postfix-log:${source}` },
  );

/** A session that hangs after the final dot (crash or timeout in the ambiguous window). */
async function ambiguous(address: string) {
  postfix.dataReply = () => 'hang';
  const message = await fx.message(org, { recipients: [{ address }] });
  await worker.plan(fx.approval(message));
  await worker.reinjectOnce();
  const [row] = await fx.reinjections(message);
  expect(row).toMatchObject({ status: 'in_progress', queueId: null });
  expect(postfix.transactions).toHaveLength(1);
  return { message, row: row! };
}

describe('crash in the ambiguous window (R8, R12)', () => {
  it('qmgr queue active for the bound queue id: queued, never re-sent', async () => {
    const { message, row } = await ambiguous('amb@ext-c.test');
    const log = newLog();
    const source = fx.logSource('amb');
    log.append(
      lines.bind(new Date(), '4jJambQID001', reinjectionToken(row.publicId)),
      lines.queueActive(new Date(), '4jJambQID001', 'alice@sender.example', 1),
    );
    const reader = tailer(log, source);
    await reader.pollOnce();
    expect((await fx.reinjections(message))[0]).toMatchObject({
      status: 'queued',
      queueId: '4jJambQID001',
    });
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'queued',
      outboundQueueId: '4jJambQID001',
    });
    await new Promise((r) => setTimeout(r, 1200)); // lease (1 s) expires: nothing left to do
    const report = await reconcilerFor(source).reconcileOnce();
    expect(report).toMatchObject({ leaseQueued: 0, leaseReleased: 0, leaseWaiting: 0 });
    expect(await worker.reinjectOnce()).toBe(0);
    expect(postfix.transactions).toHaveLength(1);

    log.append(lines.sent(new Date(Date.now() + 1000), '4jJambQID001', 'amb@ext-c.test'));
    await reader.pollOnce();
    await reader.stop();
    expect((await fx.deliveries(message))[0]).toMatchObject({ status: 'delivered' });
  });

  it('a binding alone is no proof: the uncommitted file is abandoned, re-sent and the new queue id tracked', async () => {
    // smtpd logged client= at the first accepted RCPT; the session then died before the dot
    // was accepted, so Postfix discarded 4jJdeadQID01 and never logs it again.
    const { message, row } = await ambiguous('dead@ext-c.test');
    const log = newLog();
    const source = fx.logSource('dead');
    log.append(lines.bind(new Date(), '4jJdeadQID01', reinjectionToken(row.publicId)));
    const reader = tailer(log, source);
    await reader.pollOnce();
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'pending',
      outboundQueueId: null,
    });
    await new Promise((r) => setTimeout(r, 1200));
    const reconciler = reconcilerFor(source);
    expect((await reconciler.reconcileOnce()).leaseWaiting).toBe(1);

    // The log moved past started_at + lease without queue active or a result: released.
    log.append(lines.health(new Date(row.startedAt!.getTime() + 2000)));
    await reader.pollOnce();
    expect((await reconciler.reconcileOnce()).leaseReleased).toBe(1);
    let [after] = await fx.reinjections(message);
    expect(after).toMatchObject({ status: 'pending', queueId: null });

    // Next attempt: queued under a new queue id; its lines are matched, the dead id's are not.
    postfix.reset();
    await makeDue(fx, [after!]);
    await worker.reinjectOnce();
    [after] = await fx.reinjections(message);
    const newQueueId = postfix.transactions[0]!.queueId!;
    expect(after).toMatchObject({ status: 'queued', attempts: 2, queueId: newQueueId });
    const t = new Date(Date.now() + 1000);
    log.append(
      lines.bind(t, newQueueId, reinjectionToken(row.publicId)),
      lines.queueActive(t, newQueueId, 'alice@sender.example', 1),
      lines.sent(t, newQueueId, 'dead@ext-c.test'),
    );
    await reader.pollOnce();
    await reader.stop();
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'delivered',
      outboundQueueId: newQueueId,
    });
  });

  it('a retry after a DATA 4xx rebinds the token: the second queue id is tracked to delivered', async () => {
    postfix.dataReply = () => ({ code: 451, message: '4.3.0 Error: queue file write error' });
    const message = await fx.message(org, { recipients: [{ address: 'r451@ext-c.test' }] });
    await worker.plan(fx.approval(message));
    await worker.reinjectOnce();
    let [row] = await fx.reinjections(message);
    expect(row).toMatchObject({ status: 'pending', queueId: null });
    const token = reinjectionToken(row!.publicId);
    const log = newLog();
    const source = fx.logSource('r451');
    // The first session's binding (discarded file) is read before the retry runs.
    log.append(lines.bind(new Date(), '4jJfirstQID1', token));
    const reader = tailer(log, source);
    await reader.pollOnce();
    expect((await fx.reinjections(message))[0]!.queueId).toBe('4jJfirstQID1');

    postfix.reset();
    await makeDue(fx, [row!]);
    await worker.reinjectOnce();
    [row] = await fx.reinjections(message);
    const second = postfix.transactions[0]!.queueId!;
    expect(row).toMatchObject({ status: 'queued', queueId: second });
    const t = new Date(Date.now() + 1000);
    log.append(lines.bind(t, second, token), lines.sent(t, second, 'r451@ext-c.test'));
    await reader.pollOnce();
    await reader.stop();
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'delivered',
      outboundQueueId: second,
    });
  });

  it('a quiet log still advances the horizon at the end of the file: the expired lease is released', async () => {
    const { message, row } = await ambiguous('quiet@ext-c.test');
    const log = newLog();
    const source = fx.logSource('quiet');
    log.append(lines.health(new Date(row.startedAt!.getTime() - 1000)));
    // The tailer's clock is ahead (the host stayed quiet for a minute after the session).
    const reader = new PostfixLogTailer({
      ...tailerOptions(log, source),
      now: () => new Date(Date.now() + 60_000),
    });
    await reader.pollOnce(); // reads the line
    await reader.pollOnce(); // at the end of the file: the horizon advances
    await reader.stop();
    const cursor = await fx.prisma.streamCursor.findUniqueOrThrow({
      where: { name: `postfix-log:${source}` },
    });
    expect(cursor.lastEventAt!.getTime()).toBeGreaterThan(row.startedAt!.getTime() + 1000);
    await new Promise((r) => setTimeout(r, 1200));
    expect((await reconcilerFor(source).reconcileOnce()).leaseReleased).toBe(1);
    const [released] = await fx.reinjections(message);
    expect(released).toMatchObject({ status: 'pending' });
    // Park the row so later claims of this suite do not send it.
    await fx.prisma.deliveryReinjection.update({
      where: { id_receivedAt: { id: released!.id, receivedAt: released!.receivedAt } },
      data: { status: 'failed' },
    });
  });

  it('an ambiguous session whose log never advances ends unknown at the max age, never re-sent', async () => {
    const { message, row } = await ambiguous('never@ext-c.test');
    const log = newLog();
    const source = fx.logSource('never');
    log.append(lines.health(new Date(row.startedAt!.getTime() - 1000)));
    const reader = tailer(log, source);
    await reader.pollOnce();
    await reader.stop();
    await new Promise((r) => setTimeout(r, 1200));
    const reconciler = reconcilerFor(source);
    expect((await reconciler.reconcileOnce()).leaseWaiting).toBe(1);
    await fx.prisma.deliveryReinjection.update({
      where: { id_receivedAt: { id: row.id, receivedAt: row.receivedAt } },
      data: { createdAt: new Date(Date.now() - 432_001_000) },
    });
    expect((await reconciler.reconcileOnce()).leaseUnknown).toBe(1);
    expect((await fx.reinjections(message))[0]).toMatchObject({ status: 'failed' });
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'unknown',
      failureReason: 'status_signal_missing',
    });
    expect(await worker.reinjectOnce()).toBe(0);
    expect(postfix.transactions).toHaveLength(1);
  });

  it('crash after the 250 with a partial RCPT: queue active queues nobody; the unconfirmed recipient is re-planned', async () => {
    // The worker crashed after DATA: Postfix accepted ok@ and refused soft@ (4xx) at RCPT.
    postfix.rcptReply = (address) =>
      address.startsWith('soft') ? { code: 450, message: '4.2.0 <soft>: try later' } : null;
    postfix.dataReply = () => 'hang';
    const message = await fx.message(org, {
      recipients: [{ address: 'ok@ext-u.test' }, { address: 'soft@ext-u.test' }],
    });
    await worker.plan(fx.approval(message));
    await worker.reinjectOnce();
    const [row] = await fx.reinjections(message);
    const token = reinjectionToken(row!.publicId);
    const log = newLog();
    const source = fx.logSource('partial');
    const t = new Date();
    log.append(
      lines.bind(t, '4jJpartQID01', token),
      lines.queueActive(t, '4jJpartQID01', 'alice@sender.example', 1),
    );
    const reader = tailer(log, source);
    await reader.pollOnce();
    // The file exists (row queued, never re-sent), but nrcpt=1 of 2: nobody is marked queued.
    expect((await fx.reinjections(message))[0]).toMatchObject({ status: 'queued' });
    let states = await byAddress(message);
    expect(states['ok@ext-u.test']!.status).toBe('pending');
    expect(states['soft@ext-u.test']!.status).toBe('pending');
    // The accepted recipient's own line ties it to the file.
    log.append(lines.sent(new Date(t.getTime() + 1000), '4jJpartQID01', 'ok@ext-u.test'));
    await reader.pollOnce();
    expect((await byAddress(message))['ok@ext-u.test']!.status).toBe('delivered');

    // After the unconfirmed window (and the log past it): soft@ moves to a new reinjection.
    await new Promise((r) => setTimeout(r, 1200));
    log.append(lines.health(new Date(Date.now() + 2000)));
    await reader.pollOnce();
    await reader.stop();
    const report = await reconcilerFor(source, {
      DELIVERY_RECONCILE_UNCONFIRMED_SECONDS: 1,
    }).reconcileOnce();
    expect(report.unconfirmedReplanned).toBe(1);
    states = await byAddress(message);
    expect(states['soft@ext-u.test']).toMatchObject({
      status: 'deferred',
      errorClass: 'reinjection_error',
    });
    const rows = await fx.reinjections(message);
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({ status: 'pending', recipientCount: 1 });

    postfix.reset();
    await worker.reinjectOnce();
    expect(postfix.transactions.map((tx) => tx.rcpts.map((r) => r.address))).toEqual([
      ['soft@ext-u.test'],
    ]);
    expect((await byAddress(message))['soft@ext-u.test']!.status).toBe('queued');
  });

  it('stale queued deliveries become unknown (status_signal_missing)', async () => {
    const message = await fx.message(org, { recipients: [{ address: 'stale@ext-s.test' }] });
    await worker.plan(fx.approval(message));
    await worker.reinjectOnce();
    const [delivery] = await fx.deliveries(message);
    await fx.prisma.emailDelivery.update({
      where: { id_receivedAt: { id: delivery!.id, receivedAt: delivery!.receivedAt } },
      data: { lastSignalAt: new Date(Date.now() - 518_401_000) },
    });
    expect((await worker.reconciler.reconcileOnce()).staleUnknown).toBe(1);
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'unknown',
      failureReason: 'status_signal_missing',
    });
  });
});
