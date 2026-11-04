import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { exactNamePattern, toRabbitDefinitions } from './definitions';
import { EVENT_REGISTRY, RESERVED_EVENT_TYPES } from './registry';
import {
  DEFAULT_VHOST,
  DELAY_EXPIRED_ROUTING_KEY,
  deadLetterRoutingKey,
  delayRoutingKey,
  EXCHANGE_NAMES,
  eventRoutingKey,
  eventTypesBoundTo,
  HOLD_MAX_DELAY_MS,
  parseRoutingKey,
  policyFor,
  QUEUE_NAMES,
  type QueueDefinition,
  queueDefinition,
  type QueueName,
  retryPolicyViolations,
  retryRoutingKey,
  routeMessage,
  TOPOLOGY,
  TOPOLOGY_VERSION,
  type Topology,
  topicMatches,
  validateTopology,
} from './topology';

const clone = (): { -readonly [K in keyof Topology]: Topology[K] } & {
  queues: QueueDefinition[];
} => structuredClone(TOPOLOGY) as never;

const mutableQueue = (topology: { queues: QueueDefinition[] }, name: QueueName) => {
  const queue = topology.queues.find((q) => q.name === name);
  if (!queue) throw new Error(name);
  return queue;
};

describe('TOPOLOGY v1', () => {
  it('satisfies every invariant of design §3', () => {
    expect(validateTopology(TOPOLOGY)).toEqual([]);
  });

  it('declares exactly the six exchanges and fourteen queues of the brief', () => {
    expect(TOPOLOGY_VERSION).toBe(1);
    expect(DEFAULT_VHOST).toBe('email-gateway');
    expect([...TOPOLOGY.exchanges]).toEqual([
      'email.ingestion',
      'email.security',
      'email.policy',
      'email.delivery',
      'email.archive',
      'email.events',
    ]);
    expect(EXCHANGE_NAMES).toHaveLength(6);
    expect(QUEUE_NAMES).toHaveLength(14);
    expect(TOPOLOGY.queues.map((q) => q.name)).toEqual([...QUEUE_NAMES]);
    expect(new Set(QUEUE_NAMES).size).toBe(14);
  });

  it('assigns roles: two work queues, one delay, one dead-letter, ten dormant', () => {
    const byRole = (role: string) =>
      TOPOLOGY.queues.filter((q) => q.role === role).map((q) => q.name);
    expect(byRole('work')).toEqual(['email.received', 'email.delivery.pending']);
    expect(byRole('delay')).toEqual(['email.delivery.retry']);
    expect(byRole('dead-letter')).toEqual(['email.dead-letter']);
    expect(byRole('dormant')).toHaveLength(10);
  });

  it('has the bindings and home exchanges of design §3', () => {
    const table = Object.fromEntries(
      TOPOLOGY.queues.map((q) => [
        q.name,
        [q.homeExchange, ...q.bindings.map((b) => `${b.exchange} ${b.routingKey}`)],
      ]),
    );
    expect(table).toEqual({
      'email.received': [
        'email.ingestion',
        'email.ingestion org.*.mail.message.received.v1',
        'email.ingestion retry.email.received.#',
      ],
      'scan.auth': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security retry.scan.auth.#',
      ],
      'scan.spam': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security retry.scan.spam.#',
      ],
      'scan.url': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security retry.scan.url.#',
      ],
      'scan.attachment': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security retry.scan.attachment.#',
      ],
      'scan.dlp': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security retry.scan.dlp.#',
      ],
      'scan.sandbox': [
        'email.security',
        'email.security org.*.mail.attachment.sandbox_requested.v1',
        'email.security retry.scan.sandbox.#',
      ],
      'email.policy.evaluate': [
        'email.policy',
        'email.security org.*.mail.message.scanned.v1',
        'email.ingestion org.*.mail.message.parse_failed.v1',
        'email.policy retry.email.policy.evaluate.#',
      ],
      'email.delivery.pending': [
        'email.delivery',
        'email.delivery org.*.mail.delivery.approved.v1',
        'email.delivery retry.email.delivery.pending.#',
      ],
      'email.delivery.retry': ['email.delivery', 'email.delivery delay.email.delivery.pending.#'],
      'email.quarantine': [
        'email.policy',
        'email.policy org.*.mail.policy.decided.v1',
        'email.policy retry.email.quarantine.#',
      ],
      'email.archive': [
        'email.archive',
        'email.policy org.*.mail.policy.decided.v1',
        'email.archive retry.email.archive.#',
      ],
      'email.analytics': [
        'email.events',
        'email.events org.#',
        'email.events retry.email.analytics.#',
      ],
      'email.dead-letter': ['email.events', 'email.events dead-letter.#'],
    });
    expect(TOPOLOGY.exchangeBindings).toEqual(
      ['email.ingestion', 'email.security', 'email.policy', 'email.delivery', 'email.archive'].map(
        (source) => ({ source, destination: 'email.events', routingKey: 'org.#' }),
      ),
    );
  });

  it('names the ledger consumers of this step and the planned stage of every dormant queue', () => {
    expect(queueDefinition('email.received').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.mime-parser',
      service: 'email-worker',
    });
    expect(queueDefinition('email.delivery.pending').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'delivery-worker.planner',
      service: 'delivery-worker',
    });
    const planned = Object.fromEntries(
      TOPOLOGY.queues
        .filter((q) => q.consumer.kind === 'planned')
        .map((q) => [q.name, q.consumer.kind === 'planned' ? q.consumer.plannedStep : '']),
    );
    expect(planned).toEqual({
      'scan.auth': '4.1',
      'scan.spam': '4.1',
      'scan.url': '4.3',
      'scan.attachment': '4.2',
      'scan.dlp': '4.5',
      'scan.sandbox': '4.6',
      'email.policy.evaluate': '5.1/5.2',
      'email.quarantine': '5.3',
      'email.archive': '8.1',
      'email.analytics': 'not scheduled (ADR-0009)',
    });
    expect(queueDefinition('email.delivery.retry').consumer.kind).toBe('none');
    expect(queueDefinition('email.dead-letter').consumer.kind).toBe('none');
  });

  it('throws for an unknown queue', () => {
    expect(() => queueDefinition('email.unknown')).toThrow('Unknown queue');
  });
});

describe('policies (Q4)', () => {
  it('applies the policy of each role', () => {
    for (const queue of TOPOLOGY.queues) {
      expect(queue.policy, queue.name).toEqual(policyFor(queue.role, queue.name));
    }
    expect(queueDefinition('email.received').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.email.received',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    expect(queueDefinition('scan.url').policy).toEqual({
      'delivery-limit': -1,
      'max-length': 10_000,
      overflow: 'drop-head',
    });
    expect(queueDefinition('email.delivery.retry').policy).toEqual({
      'delivery-limit': -1,
      'dead-letter-exchange': 'email.delivery',
      'dead-letter-routing-key': 'retry.email.delivery.pending.expired',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    expect(queueDefinition('email.dead-letter').policy).toEqual({
      'delivery-limit': -1,
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
  });

  it('limits deliveries only on consumed work queues (a basic.get scan never drops a message)', () => {
    for (const queue of TOPOLOGY.queues) {
      expect(queue.policy['delivery-limit'], queue.name).toBe(queue.role === 'work' ? 20 : -1);
    }
  });

  it('never dead-letters a dormant queue and bounds every queue', () => {
    for (const queue of TOPOLOGY.queues) {
      expect(queue.policy['max-length'], queue.name).toBeGreaterThan(0);
      if (queue.role === 'dormant') expect(queue.policy['dead-letter-exchange']).toBeUndefined();
      else expect(queue.policy.overflow).toBe('reject-publish');
    }
  });
});

describe('retry policies (Q8)', () => {
  it('uses the hold and delay-queue policies of the design', () => {
    expect(queueDefinition('email.received').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 8,
      baseDelayMs: 1000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 86_400_000,
    });
    expect(queueDefinition('email.delivery.pending').retry).toEqual({
      strategy: 'delay-queue',
      maxAttempts: 10,
      baseDelayMs: 5000,
      maxDelayMs: 900_000,
      maxRetryAgeMs: 172_800_000,
      delayQueue: 'email.delivery.retry',
    });
    for (const queue of TOPOLOGY.queues.filter((q) => q.role === 'dormant')) {
      expect(queue.retry, queue.name).toEqual({
        strategy: 'hold',
        maxAttempts: 5,
        baseDelayMs: 1000,
        maxDelayMs: 60_000,
        maxRetryAgeMs: 86_400_000,
      });
    }
    expect(queueDefinition('email.delivery.retry').retry).toBeUndefined();
    expect(queueDefinition('email.dead-letter').retry).toBeUndefined();
  });

  it('caps hold delays at 60 s and requires a delay queue of role delay for delay-queue', () => {
    for (const queue of TOPOLOGY.queues) {
      if (queue.retry?.strategy === 'hold') {
        expect(queue.retry.maxDelayMs).toBeLessThanOrEqual(HOLD_MAX_DELAY_MS);
      }
      if (queue.retry?.strategy === 'delay-queue') {
        const delay = queueDefinition(queue.retry.delayQueue ?? '');
        expect(delay.role).toBe('delay');
        expect(delay.policy['dead-letter-exchange']).toBe('email.delivery');
        expect(delay.policy['dead-letter-routing-key']).toBe(DELAY_EXPIRED_ROUTING_KEY);
      }
    }
  });

  it('routes the delay expiry key to exactly email.delivery.pending via its retry binding', () => {
    expect(routeMessage('email.delivery', DELAY_EXPIRED_ROUTING_KEY)).toEqual([
      'email.delivery.pending',
    ]);
    const matching = TOPOLOGY.queues.flatMap((q) =>
      q.bindings
        .filter((b) => topicMatches(b.routingKey, DELAY_EXPIRED_ROUTING_KEY))
        .map((b) => `${q.name} ${b.exchange} ${b.routingKey}`),
    );
    expect(matching).toEqual([
      'email.delivery.pending email.delivery retry.email.delivery.pending.#',
    ]);
  });

  it('reports bound violations of a retry policy', () => {
    const base = {
      strategy: 'hold',
      maxAttempts: 3,
      baseDelayMs: 10,
      maxDelayMs: 100,
      maxRetryAgeMs: 1000,
    } as const;
    expect(retryPolicyViolations(base)).toEqual([]);
    expect(retryPolicyViolations({ ...base, maxDelayMs: 60_001 })).toContain(
      'hold maxDelayMs exceeds 60000',
    );
    expect(retryPolicyViolations({ ...base, baseDelayMs: 1000 })).toContain(
      'baseDelayMs exceeds maxDelayMs',
    );
    expect(retryPolicyViolations({ ...base, maxAttempts: 0 })).toContain(
      'maxAttempts must be a positive integer',
    );
    expect(retryPolicyViolations({ ...base, maxRetryAgeMs: 1.5 })).toContain(
      'maxRetryAgeMs must be a positive integer',
    );
    expect(retryPolicyViolations({ ...base, delayQueue: 'email.delivery.retry' })).toContain(
      'hold has no delayQueue',
    );
    expect(retryPolicyViolations({ ...base, strategy: 'delay-queue' })).toContain(
      'delay-queue requires delayQueue',
    );
  });
});

describe('routing keys (Q2)', () => {
  it('builds event, retry, delay and dead-letter keys', () => {
    expect(eventRoutingKey('42', 'mail.message.received.v1')).toBe(
      'org.42.mail.message.received.v1',
    );
    expect(eventRoutingKey(42n, 'mail.message.received.v1')).toBe(
      'org.42.mail.message.received.v1',
    );
    expect(retryRoutingKey('email.received', 42, 'mail.message.received.v1')).toBe(
      'retry.email.received.org.42.mail.message.received.v1',
    );
    expect(delayRoutingKey('email.delivery.pending', '7', 'mail.delivery.approved.v1')).toBe(
      'delay.email.delivery.pending.org.7.mail.delivery.approved.v1',
    );
    expect(deadLetterRoutingKey('email.delivery.pending')).toBe(
      'dead-letter.email.delivery.pending',
    );
    expect(deadLetterRoutingKey('email.received', '9', 'mail.message.received.v1')).toBe(
      'dead-letter.email.received.org.9.mail.message.received.v1',
    );
  });

  it('refuses malformed organization ids, event types and queues', () => {
    for (const id of ['0', '042', '-1', 'abc', '', '1.5', 'a'.repeat(21)]) {
      expect(() => eventRoutingKey(id, 'mail.message.received.v1'), id).toThrow();
    }
    expect(() => eventRoutingKey('1', 'mail.received')).toThrow();
    expect(() => eventRoutingKey('1', 'org.#')).toThrow();
    expect(() =>
      retryRoutingKey('email.unknown' as QueueName, '1', 'mail.message.received.v1'),
    ).toThrow();
    expect(() => deadLetterRoutingKey('email.received', '1')).toThrow();
  });

  it('round-trips every key of every queue and event type through parseRoutingKey', () => {
    for (const queue of QUEUE_NAMES) {
      expect(parseRoutingKey(deadLetterRoutingKey(queue))).toEqual({ kind: 'dead-letter', queue });
      for (const eventType of [
        ...Object.keys(EVENT_REGISTRY),
        ...Object.keys(RESERVED_EVENT_TYPES),
      ]) {
        const org = { organizationId: '18446744073709551615', eventType };
        expect(parseRoutingKey(eventRoutingKey(org.organizationId, eventType))).toEqual({
          kind: 'event',
          ...org,
        });
        expect(parseRoutingKey(retryRoutingKey(queue, org.organizationId, eventType))).toEqual({
          kind: 'retry',
          queue,
          ...org,
        });
        expect(parseRoutingKey(delayRoutingKey(queue, org.organizationId, eventType))).toEqual({
          kind: 'delay',
          queue,
          ...org,
        });
        expect(parseRoutingKey(deadLetterRoutingKey(queue, org.organizationId, eventType))).toEqual(
          { kind: 'dead-letter', queue, ...org },
        );
      }
    }
  });

  it('parses the delay-expiry key as a retry of email.delivery.pending without organization', () => {
    expect(parseRoutingKey(DELAY_EXPIRED_ROUTING_KEY)).toEqual({
      kind: 'retry',
      queue: 'email.delivery.pending',
    });
  });

  it('resolves dotted queue names by longest match', () => {
    expect(parseRoutingKey('retry.email.policy.evaluate.org.1.mail.message.scanned.v1')).toEqual({
      kind: 'retry',
      queue: 'email.policy.evaluate',
      organizationId: '1',
      eventType: 'mail.message.scanned.v1',
    });
  });

  it('returns null for keys topology v1 never produces', () => {
    for (const key of [
      '',
      'org',
      'org.42',
      'org.042.mail.message.received.v1',
      'org.42.mail.received',
      'retry.email.received',
      'retry.unknown.org.1.mail.message.received.v1',
      'delay.email.delivery.pending',
      'delay.email.delivery.pending.expired',
      'dead-letter.email.received.org.1',
      'dead-letter.email',
      'other.email.received',
      'retry.email.receivedx.org.1.mail.message.received.v1',
    ]) {
      expect(parseRoutingKey(key), key).toBeNull();
    }
  });
});

describe('routing (topic semantics)', () => {
  it('matches * as one word and # as zero or more', () => {
    expect(topicMatches('org.*.a.b', 'org.1.a.b')).toBe(true);
    expect(topicMatches('org.*.a.b', 'org.1.2.a.b')).toBe(false);
    expect(topicMatches('org.#', 'org')).toBe(true);
    expect(topicMatches('org.#', 'org.1.x')).toBe(true);
    expect(topicMatches('org.#', 'retry.org.1')).toBe(false);
    expect(topicMatches('retry.email.received.#', 'retry.email.received')).toBe(true);
    expect(topicMatches('retry.email.received.#', 'retry.email.received.org.1.t.v1')).toBe(true);
    expect(topicMatches('a.#.b', 'a.b')).toBe(true);
    expect(topicMatches('a.#.b', 'a.x.y.b')).toBe(true);
    expect(topicMatches('a.#.b', 'a.x.y.c')).toBe(false);
  });

  it('routes each registered event to its queues and to the firehose', () => {
    const route = (type: keyof typeof EVENT_REGISTRY) =>
      routeMessage(EVENT_REGISTRY[type].exchange, eventRoutingKey('42', type));
    expect(route('mail.message.received.v1')).toEqual(['email.analytics', 'email.received']);
    expect(route('mail.message.parsed.v1')).toEqual(
      [
        'email.analytics',
        'scan.attachment',
        'scan.auth',
        'scan.dlp',
        'scan.spam',
        'scan.url',
      ].sort(),
    );
    expect(route('mail.message.parse_failed.v1')).toEqual([
      'email.analytics',
      'email.policy.evaluate',
    ]);
    expect(route('mail.message.scanned.v1')).toEqual(['email.analytics', 'email.policy.evaluate']);
    expect(route('mail.policy.decided.v1')).toEqual(
      ['email.analytics', 'email.archive', 'email.quarantine'].sort(),
    );
    expect(route('mail.delivery.approved.v1')).toEqual([
      'email.analytics',
      'email.delivery.pending',
    ]);
    expect(route('mail.delivery.status_changed.v1')).toEqual(['email.analytics']);
    expect(route('domain.status.changed.v1')).toEqual(['email.analytics']);
    expect(route('domain.routing.changed.v1')).toEqual(['email.analytics']);
  });

  it('keeps internal hops out of the firehose and out of other queues', () => {
    for (const queue of TOPOLOGY.queues) {
      for (const type of eventTypesBoundTo(queue.name)) {
        if (queue.role === 'work' || queue.role === 'dormant') {
          expect(routeMessage(queue.homeExchange, retryRoutingKey(queue.name, '1', type))).toEqual([
            queue.name,
          ]);
        }
        expect(routeMessage('email.events', deadLetterRoutingKey(queue.name, '1', type))).toEqual([
          'email.dead-letter',
        ]);
      }
      expect(routeMessage('email.events', deadLetterRoutingKey(queue.name))).toEqual([
        'email.dead-letter',
      ]);
    }
    expect(
      routeMessage(
        'email.delivery',
        delayRoutingKey('email.delivery.pending', '1', 'mail.delivery.approved.v1'),
      ),
    ).toEqual(['email.delivery.retry']);
    // No org.* / org.# binding matches an internal key.
    const orgBindings = TOPOLOGY.queues.flatMap((q) =>
      q.bindings.filter((b) => b.routingKey.startsWith('org.')),
    );
    for (const key of [
      retryRoutingKey('email.received', '1', 'mail.message.received.v1'),
      delayRoutingKey('email.delivery.pending', '1', 'mail.delivery.approved.v1'),
      deadLetterRoutingKey('email.received', '1', 'mail.message.received.v1'),
      deadLetterRoutingKey('email.received'),
      DELAY_EXPIRED_ROUTING_KEY,
    ]) {
      expect(
        orgBindings.some((b) => topicMatches(b.routingKey, key)),
        key,
      ).toBe(false);
    }
  });

  it('lists the event types bound to each queue, including the firehose', () => {
    expect(eventTypesBoundTo('email.received')).toEqual(['mail.message.received.v1']);
    expect(eventTypesBoundTo('email.delivery.pending')).toEqual(['mail.delivery.approved.v1']);
    expect(eventTypesBoundTo('email.policy.evaluate')).toEqual([
      'mail.message.parse_failed.v1',
      'mail.message.scanned.v1',
    ]);
    expect(eventTypesBoundTo('scan.sandbox')).toEqual(['mail.attachment.sandbox_requested.v1']);
    expect(eventTypesBoundTo('email.analytics')).toEqual(
      [...Object.keys(EVENT_REGISTRY), ...Object.keys(RESERVED_EVENT_TYPES)].sort(),
    );
    expect(eventTypesBoundTo('email.delivery.retry')).toEqual([]);
    expect(eventTypesBoundTo('email.dead-letter')).toEqual([]);
  });
});

describe('validateTopology (negative cases)', () => {
  it('detects a missing or extra queue and exchange', () => {
    const t = clone();
    t.queues = t.queues.filter((q) => q.name !== 'scan.dlp');
    expect(validateTopology(t).some((v) => v.startsWith('queues must be exactly'))).toBe(true);
    const e = clone();
    e.exchanges = [...EXCHANGE_NAMES, 'email.extra' as never];
    expect(validateTopology(e).some((v) => v.startsWith('exchanges must be exactly'))).toBe(true);
  });

  it('detects an event binding on the wrong exchange and an unknown event type', () => {
    const t = clone();
    mutableQueue(t, 'email.received').bindings[0] = {
      exchange: 'email.delivery',
      routingKey: 'org.*.mail.message.received.v1',
    };
    expect(validateTopology(t)).toContain(
      'email.received: mail.message.received.v1 is published to email.ingestion, bound on email.delivery',
    );
    const u = clone();
    mutableQueue(u, 'scan.url').bindings[0] = {
      exchange: 'email.ingestion',
      routingKey: 'org.*.mail.unknown.v1',
    };
    expect(validateTopology(u)).toContain(
      'scan.url: binding for unknown event type mail.unknown.v1',
    );
  });

  it('detects a dot-prefix queue name', () => {
    const t = clone();
    mutableQueue(t, 'scan.dlp').name = 'scan.auth.dlp' as QueueName;
    expect(validateTopology(t)).toContain('queue scan.auth is a dot-prefix of scan.auth.dlp');
  });

  it('detects missing, duplicate and foreign retry bindings', () => {
    const t = clone();
    const q = mutableQueue(t, 'scan.spam');
    q.bindings = q.bindings.filter((b) => !b.routingKey.startsWith('retry.'));
    expect(validateTopology(t)).toContain(
      'scan.spam: needs exactly one retry binding retry.scan.spam.# on its home exchange',
    );
    const u = clone();
    mutableQueue(u, 'scan.spam').bindings.push({
      exchange: 'email.security',
      routingKey: 'retry.scan.#',
    });
    expect(validateTopology(u)).toContain(
      'scan.spam: retry binding retry.scan.# names another queue',
    );
    const w = clone();
    mutableQueue(w, 'scan.spam').bindings[1] = {
      exchange: 'email.ingestion',
      routingKey: 'retry.scan.spam.#',
    };
    expect(validateTopology(w)).toContain(
      'scan.spam: needs exactly one retry binding retry.scan.spam.# on its home exchange',
    );
  });

  it('detects a delay queue that does not route back to exactly its work queue', () => {
    const t = clone();
    mutableQueue(t, 'email.delivery.retry').policy['dead-letter-routing-key'] =
      'retry.email.received.expired';
    const violations = validateTopology(t);
    expect(violations).toContain(
      'email.delivery.pending: its delay queue must dead-letter to exactly email.delivery.pending',
    );
  });

  it('detects a firehose binding that would see internal hops', () => {
    const t = clone();
    mutableQueue(t, 'email.analytics').bindings[0] = { exchange: 'email.events', routingKey: '#' };
    expect(validateTopology(t).length).toBeGreaterThan(0);
  });

  it('detects a hold policy above 60 s, wrong policies and wrong consumers', () => {
    const t = clone();
    const q = mutableQueue(t, 'email.received');
    q.retry = { ...q.retry!, maxDelayMs: 120_000 };
    q.policy = policyFor('dormant', 'email.received');
    q.consumer = { kind: 'none', reason: 'x' };
    const violations = validateTopology(t);
    expect(violations).toContain('email.received: hold maxDelayMs exceeds 60000');
    expect(violations).toContain('email.received: policy differs from the work policy');
    expect(violations).toContain('email.received: a work queue must have consumer kind ledger');
  });

  it('detects a missing exchange-to-exchange binding', () => {
    const t = clone();
    t.exchangeBindings = t.exchangeBindings.filter((b) => b.source !== 'email.archive');
    expect(validateTopology(t)).toContain(
      'exchange email.archive must be bound to email.events with org.# exactly once',
    );
  });

  it('detects an event type that reaches no queue', () => {
    const t = clone();
    const analytics = mutableQueue(t, 'email.analytics');
    analytics.bindings = analytics.bindings.filter((b) => b.routingKey !== 'org.#');
    expect(validateTopology(t)).toContain('event type domain.status.changed.v1 reaches no queue');
  });
});

describe('toRabbitDefinitions (Q5)', () => {
  const definitions = toRabbitDefinitions(TOPOLOGY, { vhost: DEFAULT_VHOST });

  it('declares topic exchanges and quorum queues with no other argument', () => {
    expect(definitions.topology_version).toBe(1);
    expect(definitions.exchanges).toHaveLength(6);
    for (const exchange of definitions.exchanges) {
      expect(exchange).toEqual({
        name: exchange.name,
        vhost: 'email-gateway',
        type: 'topic',
        durable: true,
        auto_delete: false,
        internal: false,
        arguments: {},
      });
    }
    expect(definitions.queues).toHaveLength(14);
    for (const queue of definitions.queues) {
      expect(queue).toEqual({
        name: queue.name,
        vhost: 'email-gateway',
        durable: true,
        auto_delete: false,
        arguments: { 'x-queue-type': 'quorum' },
      });
    }
    expect(definitions.exchanges.some((e) => e.name === '' || e.name.startsWith('amq.'))).toBe(
      false,
    );
  });

  it('declares every queue and exchange binding exactly once, sorted', () => {
    const expected =
      TOPOLOGY.exchangeBindings.length + TOPOLOGY.queues.reduce((n, q) => n + q.bindings.length, 0);
    expect(definitions.bindings).toHaveLength(expected);
    const keys = definitions.bindings.map(
      (b) => `${b.source}|${b.destination_type}|${b.destination}|${b.routing_key}`,
    );
    expect(new Set(keys).size).toBe(keys.length);
    expect([...keys].sort()).toEqual(keys);
    expect(definitions.bindings.filter((b) => b.destination_type === 'exchange')).toHaveLength(5);
    for (const binding of definitions.bindings) {
      expect(binding.arguments).toEqual({});
      expect(binding.vhost).toBe('email-gateway');
    }
  });

  it('generates one anchored policy per queue', () => {
    expect(definitions.policies).toHaveLength(14);
    for (const policy of definitions.policies) {
      const queue = policy.name.slice('eg.'.length);
      expect(policy).toEqual({
        vhost: 'email-gateway',
        name: `eg.${queue}`,
        pattern: exactNamePattern(queue),
        'apply-to': 'queues',
        priority: 10,
        definition: queueDefinition(queue).policy,
      });
      const regex = new RegExp(policy.pattern);
      expect(QUEUE_NAMES.filter((name) => regex.test(name))).toEqual([queue]);
    }
    expect(exactNamePattern('email.dead-letter')).toBe('^email\\.dead-letter$');
  });

  it('is deterministic and uses the given vhost', () => {
    expect(toRabbitDefinitions(TOPOLOGY, { vhost: DEFAULT_VHOST })).toEqual(definitions);
    const other = toRabbitDefinitions(TOPOLOGY, { vhost: 'eg-it-abc' });
    expect(
      new Set(
        [...other.queues, ...other.exchanges, ...other.bindings, ...other.policies].map(
          (o) => o.vhost,
        ),
      ),
    ).toEqual(new Set(['eg-it-abc']));
  });

  it('equals the committed infrastructure/rabbitmq/definitions.json', () => {
    const committed: unknown = JSON.parse(
      readFileSync(resolve(__dirname, '../../../infrastructure/rabbitmq/definitions.json'), 'utf8'),
    );
    expect(committed).toEqual(definitions);
  });
});
