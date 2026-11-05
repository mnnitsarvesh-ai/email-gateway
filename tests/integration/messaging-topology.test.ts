import {
  EXCHANGE_NAMES,
  policyFor,
  QUEUE_NAMES,
  queueDefinition,
  TOPOLOGY,
  TOPOLOGY_VERSION,
} from '@email-gateway/event-contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  ManagementApi,
  runInit,
  type RawBinding,
  type RawExchange,
  type RawPolicy,
} from './support/broker';
import { stack } from './support/env';

/**
 * The provisioned vhost `email-gateway` matches the topology exactly (step 3.2 Q1, Q4, §3; v2:
 * step 3.3 L7; v3: step 4.1 S2): checks through the management API. The prune case adds one
 * stray binding to the dormant `scan.auth` and lets `init.mjs` remove it again.
 */
const api = new ManagementApi();
const vhost = stack.rabbitmqVhost();

let exchanges: RawExchange[];
let queues: Awaited<ReturnType<ManagementApi['queues']>>;
let bindings: RawBinding[];
let policies: RawPolicy[];

beforeAll(async () => {
  [exchanges, queues, bindings, policies] = await Promise.all([
    api.exchanges(vhost),
    api.queues(vhost),
    api.bindings(vhost),
    api.policies(vhost),
  ]);
});

describe(`RabbitMQ topology v${TOPOLOGY_VERSION} on the real vhost`, () => {
  it('has exactly the six durable topic exchanges (besides the default and amq.*)', () => {
    const own = exchanges.filter((e) => e.name !== '' && !e.name.startsWith('amq.'));
    expect(own.map((e) => e.name).sort()).toEqual([...EXCHANGE_NAMES].sort());
    for (const exchange of own) {
      expect(exchange).toMatchObject({
        type: 'topic',
        durable: true,
        auto_delete: false,
        internal: false,
      });
    }
  });

  it('has exactly the fourteen durable quorum queues, each under its policy eg.<queue>', () => {
    expect(queues.map((q) => q.name).sort()).toEqual([...QUEUE_NAMES].sort());
    for (const queue of queues) {
      expect(queue.type, queue.name).toBe('quorum');
      expect(queue.durable, queue.name).toBe(true);
      expect(queue.policy, queue.name).toBe(`eg.${queue.name}`);
      // Only the queue type is an argument; everything mutable is a policy (Q4).
      expect(queue.arguments, queue.name).toEqual({ 'x-queue-type': 'quorum' });
    }
  });

  it('applies the Q4 policy of every queue role', () => {
    for (const definition of TOPOLOGY.queues) {
      const policy = policies.find((p) => p.name === `eg.${definition.name}`);
      expect(policy, definition.name).toBeDefined();
      expect(policy?.['apply-to']).toBe('queues');
      expect(policy?.priority).toBe(10);
      expect(new RegExp(policy?.pattern ?? '^$').test(definition.name)).toBe(true);
      for (const other of QUEUE_NAMES.filter((q) => q !== definition.name)) {
        expect(new RegExp(policy?.pattern ?? '^$').test(other), `${policy?.name} vs ${other}`).toBe(
          false,
        );
      }
      expect(policy?.definition).toEqual(policyFor(definition.role, definition.name));
      const queue = queues.find((q) => q.name === definition.name);
      expect(queue?.effective_policy_definition, definition.name).toEqual(
        policyFor(definition.role, definition.name),
      );
    }
    expect(policies.filter((p) => p.name.startsWith('eg.'))).toHaveLength(QUEUE_NAMES.length);
  });

  it('has every binding of TOPOLOGY (queue and exchange destinations) and nothing else', () => {
    const id = (b: {
      source: string;
      destination: string;
      destination_type: string;
      routing_key: string;
    }) => `${b.source} -> ${b.destination_type}:${b.destination} [${b.routing_key}]`;
    const expected = [
      ...TOPOLOGY.queues.flatMap((q) =>
        q.bindings.map((b) =>
          id({
            source: b.exchange,
            destination: q.name,
            destination_type: 'queue',
            routing_key: b.routingKey,
          }),
        ),
      ),
      ...TOPOLOGY.exchangeBindings.map((b) =>
        id({
          source: b.source,
          destination: b.destination,
          destination_type: 'exchange',
          routing_key: b.routingKey,
        }),
      ),
    ].sort();
    // The default exchange's implicit per-queue bindings are not part of the topology.
    const actual = bindings
      .filter((b) => b.source !== '')
      .map(id)
      .sort();
    expect(actual).toEqual(expected);
    expect(bindings.filter((b) => b.destination_type === 'exchange')).toHaveLength(5);
  });

  it('is topology v3: the vhost description and the rescan bindings (step 4.1 S2)', async () => {
    expect(TOPOLOGY_VERSION).toBe(3);
    const info = await api.get<{ description?: string }>(`/vhosts/${encodeURIComponent(vhost)}`);
    expect(info.description).toBe('email-gateway topology v3');
    const rescan = bindings
      .filter(
        (b) =>
          b.source === 'email.security' &&
          b.routing_key === 'org.*.mail.message.rescan_requested.v1',
      )
      .map((b) => `${b.destination_type}:${b.destination}`)
      .sort();
    // v2 bound five scan queues; v3 removed scan.auth's event bindings (authentication results
    // come from the rspamd engine on scan.spam, ADR-0026).
    expect(rescan).toEqual(
      ['scan.attachment', 'scan.dlp', 'scan.spam', 'scan.url'].map((q) => `queue:${q}`),
    );
    expect(bindings.filter((b) => b.source !== '')).toHaveLength(35);
  });

  it('scan.auth keeps only its retry binding (reserved, no event binding)', () => {
    const auth = bindings
      .filter((b) => b.source !== '' && b.destination === 'scan.auth')
      .map((b) => `${b.source} [${b.routing_key}]`);
    expect(auth).toEqual(['email.security [retry.scan.auth.#]']);
    expect(queueDefinition('scan.auth')).toMatchObject({ role: 'dormant' });
  });

  it('scan.spam is a work queue (work policy) consumed by the scanner role user eg-scanner', async () => {
    expect(queueDefinition('scan.spam')).toMatchObject({
      role: 'work',
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.rspamd', service: 'email-worker' },
    });
    const spam = bindings
      .filter((b) => b.source !== '' && b.destination === 'scan.spam')
      .map((b) => `${b.source} [${b.routing_key}]`)
      .sort();
    expect(spam).toEqual(
      [
        'email.ingestion [org.*.mail.message.parsed.v1]',
        'email.security [org.*.mail.message.rescan_requested.v1]',
        'email.security [retry.scan.spam.#]',
      ].sort(),
    );
    const details = await api.get<{
      consumer_details?: { channel_details?: { user?: string } }[];
    }>(`/queues/${encodeURIComponent(vhost)}/scan.spam`);
    const users = (details.consumer_details ?? []).map((c) => c.channel_details?.user);
    expect(users.length, 'consumers on scan.spam').toBeGreaterThanOrEqual(1);
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    expect(new Set(users)).toEqual(new Set([scanner]));
  });

  it('init.mjs prunes a binding on a topology queue that the definitions do not have', async () => {
    // The v2 binding scan.auth lost in v3, re-added by hand as on a broker upgraded from v2.
    const stray = {
      source: 'email.ingestion',
      destination: 'scan.auth',
      routing_key: 'org.*.mail.message.parsed.v1',
    };
    await api.bindQueue(vhost, stray.source, stray.destination, stray.routing_key);
    const has = async () =>
      (await api.bindings(vhost)).some(
        (b) =>
          b.source === stray.source &&
          b.destination === stray.destination &&
          b.routing_key === stray.routing_key,
      );
    expect(await has()).toBe(true);
    const dryRun = await runInit(['--prune-dry-run', '--vhost', vhost]);
    expect(dryRun).toMatch(/scan\.auth/);
    expect(await has()).toBe(true);
    const output = await runInit(['--vhost', vhost]);
    expect(output).toContain(`1 binding(s) on topology objects of ${vhost} were removed`);
    expect(await has()).toBe(false);
    expect((await api.bindings(vhost)).filter((b) => b.source !== '')).toHaveLength(35);
    await api.purge(vhost, 'scan.auth');
  });
});
