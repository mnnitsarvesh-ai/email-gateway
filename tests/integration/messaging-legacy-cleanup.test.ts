import { QUEUE_NAMES } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestVhost, ManagementApi, runInit, type TestVhost } from './support/broker';
import { stack } from './support/env';

/**
 * `init.mjs --cleanup-legacy` (step 3.2 Q5, Q14) against the real broker: the ADR-0005 objects
 * (topic exchanges `mail.events` / `mail.dlx`, five QUORUM `<service>.<event>` queues and their
 * `.dlq`) are deleted only when empty; a queue with messages is kept with a warning and so is the
 * exchange it is still bound to. RabbitMQ 4.x refuses `DELETE …?if-empty=true` for quorum queues
 * (HTTP 400), which made the first version of the cleanup keep every legacy queue (WP5 fix).
 * The objects are created in a second throwaway vhost (`eg-it-<hex>-legacy`) and the cleanup
 * is pointed at it with the test-only `--legacy-vhost`; vhost "/" is never touched here.
 */
const LEGACY = [
  'email-worker.message-received',
  'policy-engine.message-scanned',
  'delivery-worker.policy-decided',
  'archive-worker.policy-decided',
  'notification-worker.events',
];
const KEPT = 'notification-worker.events';

let vhost: TestVhost;
let legacy = '';
const mgmt = new ManagementApi();

function admin(method: string, path: string, body?: unknown) {
  const base = new URL(stack.rabbitmqMgmtUrl());
  base.username = '';
  base.password = '';
  const { user, password } = stack.rabbitmqAdmin();
  return fetch(`${base.toString().replace(/\/+$/, '')}/api${path}`, {
    method,
    headers: {
      authorization: `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`,
      'content-type': 'application/json',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
}

async function ok(method: string, path: string, body?: unknown) {
  const res = await admin(method, path, body);
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status} ${await res.text()}`);
  return res;
}

beforeAll(async () => {
  vhost = await createTestVhost();
  legacy = `${vhost.vhost}-legacy`;
  const v = encodeURIComponent(legacy);
  await ok('PUT', `/vhosts/${v}`, { description: 'legacy cleanup test' });
  await ok('PUT', `/permissions/${v}/${encodeURIComponent(stack.rabbitmqAdmin().user)}`, {
    configure: '.*',
    write: '.*',
    read: '.*',
  });
  for (const name of ['mail.events', 'mail.dlx']) {
    await ok('PUT', `/exchanges/${v}/${name}`, { type: 'topic', durable: true });
  }
  // The ADR-0005 shape: quorum work queue + quorum `.dlq`, bound to the two exchanges.
  for (const name of LEGACY) {
    await ok('PUT', `/queues/${v}/${name}`, {
      durable: true,
      arguments: { 'x-queue-type': 'quorum', 'x-dead-letter-exchange': 'mail.dlx' },
    });
    await ok('PUT', `/queues/${v}/${name}.dlq`, {
      durable: true,
      arguments: { 'x-queue-type': 'quorum' },
    });
    await ok('POST', `/bindings/${v}/e/mail.events/q/${name}`, { routing_key: name });
    await ok('POST', `/bindings/${v}/e/mail.dlx/q/${name}.dlq`, { routing_key: name });
  }
  // One legacy queue still holds a message: it must survive the cleanup.
  await ok('POST', `/exchanges/${v}/mail.events/publish`, {
    properties: { delivery_mode: 2 },
    routing_key: KEPT,
    payload: '{}',
    payload_encoding: 'string',
  });
}, 60_000);

afterAll(async () => {
  if (legacy) await runInit(['--delete-vhost', legacy]).catch(() => undefined);
  await vhost?.cleanup();
}, 60_000);

describe('init.mjs --cleanup-legacy (quorum legacy queues)', () => {
  it('deletes the empty quorum queues, keeps a non-empty one and its bound exchange', async () => {
    const before = await mgmt.queues(legacy);
    expect(before.filter((q) => q.type === 'quorum').map((q) => q.name)).toEqual(
      expect.arrayContaining(LEGACY.flatMap((n) => [n, `${n}.dlq`])),
    );
    await expect
      .poll(async () => (await mgmt.queue(legacy, KEPT)).messages, { timeout: 15_000 })
      .toBe(1);

    const output = await runInit([
      '--vhost',
      vhost.vhost,
      '--cleanup-legacy',
      '--legacy-vhost',
      legacy,
    ]);
    expect(output).not.toContain(stack.rabbitmqAdmin().password);

    const names = new Set((await mgmt.queues(legacy)).map((q) => q.name));
    for (const name of LEGACY.filter((n) => n !== KEPT)) {
      expect(names.has(name), name).toBe(false);
      expect(names.has(`${name}.dlq`), `${name}.dlq`).toBe(false);
    }
    expect(names.has(KEPT)).toBe(true);
    expect(names.has(`${KEPT}.dlq`)).toBe(false);
    expect((await mgmt.queue(legacy, KEPT)).messages).toBe(1);
    expect(output).toMatch(
      new RegExp(`legacy queue ${KEPT.replace('.', '\\.')} on .* kept: 1 messages`),
    );

    expect(names.size).toBe(1);
    const exchanges = new Set((await mgmt.exchanges(legacy)).map((e) => e.name));
    expect(exchanges.has('mail.dlx')).toBe(false); // only the deleted .dlq queues were bound
    expect(exchanges.has('mail.events')).toBe(true); // still bound to the kept queue
    // The topology vhost is untouched (every queue of the current topology, 19 in v8).
    expect(QUEUE_NAMES).toHaveLength(19);
    expect((await mgmt.queues(vhost.vhost)).length).toBe(QUEUE_NAMES.length);

    // Idempotent: a second run changes nothing and still succeeds.
    await runInit(['--vhost', vhost.vhost, '--cleanup-legacy', '--legacy-vhost', legacy]);
    expect((await mgmt.queues(legacy)).map((q) => q.name)).toEqual([KEPT]);
  });
});
