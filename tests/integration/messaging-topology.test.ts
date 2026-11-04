import {
  EXCHANGE_NAMES,
  policyFor,
  QUEUE_NAMES,
  TOPOLOGY,
  TOPOLOGY_VERSION,
} from '@email-gateway/event-contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import { ManagementApi, type RawBinding, type RawExchange, type RawPolicy } from './support/broker';
import { stack } from './support/env';

/**
 * The provisioned vhost `email-gateway` matches the topology exactly (step 3.2 Q1, Q4, §3; v2:
 * step 3.3 L7): read-only checks through the management API.
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

  it('is topology v2: the vhost description and the rescan bindings of step 3.3', async () => {
    expect(TOPOLOGY_VERSION).toBe(2);
    const info = await api.get<{ description?: string }>(`/vhosts/${encodeURIComponent(vhost)}`);
    expect(info.description).toBe('email-gateway topology v2');
    const rescan = bindings
      .filter(
        (b) =>
          b.source === 'email.security' &&
          b.routing_key === 'org.*.mail.message.rescan_requested.v1',
      )
      .map((b) => `${b.destination_type}:${b.destination}`)
      .sort();
    expect(rescan).toEqual(
      ['scan.attachment', 'scan.auth', 'scan.dlp', 'scan.spam', 'scan.url'].map(
        (q) => `queue:${q}`,
      ),
    );
    expect(bindings.filter((b) => b.source !== '')).toHaveLength(37);
  });
});
