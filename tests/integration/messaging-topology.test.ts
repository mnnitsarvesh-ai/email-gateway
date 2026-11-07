import {
  EXCHANGE_NAMES,
  policyFor,
  policyKindOf,
  QUEUE_NAMES,
  queueDefinition,
  TOPOLOGY,
  TOPOLOGY_VERSION,
  topicMatches,
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
 * step 3.3 L7; v3: step 4.1 S2; v4: step 4.2 A2; v5: step 4.3 U2; v6: step 4.4 B3; v7: step 4.5
 * D2): checks through the management API. The prune case adds one stray binding to the dormant
 * `scan.auth` and lets `init.mjs` remove it again.
 */
/**
 * Bindings of topology v7 (queue and exchange destinations), besides the default exchange's. v7
 * turned the dormant scan.dlp into a work queue with the same three bindings (it always had its
 * retry binding), so the count is v6's 41 (docs/plan/steps/13-dlp.md §12, WP1 deviation 1).
 */
const TOPOLOGY_BINDINGS = 41;
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

  it('has exactly the seventeen durable quorum queues, each under its policy eg.<queue>', () => {
    expect(QUEUE_NAMES).toHaveLength(17);
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
      expect(policy?.definition).toEqual(policyFor(policyKindOf(definition), definition.name));
      const queue = queues.find((q) => q.name === definition.name);
      expect(queue?.effective_policy_definition, definition.name).toEqual(
        policyFor(policyKindOf(definition), definition.name),
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

  it('is topology v7: the vhost description and the rescan bindings (steps 4.1 S2, 4.2 A2, 4.3 U2, 4.4 B3, 4.5 D2)', async () => {
    expect(TOPOLOGY_VERSION).toBe(7);
    const info = await api.get<{ description?: string }>(`/vhosts/${encodeURIComponent(vhost)}`);
    expect(info.description).toBe('email-gateway topology v7');
    const rescan = bindings
      .filter(
        (b) =>
          b.source === 'email.security' &&
          b.routing_key === 'org.*.mail.message.rescan_requested.v1',
      )
      .map((b) => `${b.destination_type}:${b.destination}`)
      .sort();
    // v2 bound five scan queues; v3 removed scan.auth's event bindings (authentication results
    // come from the rspamd engine on scan.spam, ADR-0026); v6's scan.bec is a stage-2 queue and
    // gets no rescan binding (a rescan round triggers it through scan_stage_ready.v1).
    expect(rescan).toEqual(
      ['scan.attachment', 'scan.dlp', 'scan.spam', 'scan.url'].map((q) => `queue:${q}`),
    );
    expect(bindings.filter((b) => b.source !== '')).toHaveLength(TOPOLOGY_BINDINGS);
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

  it('scan.attachment is a work queue (work policy, v4) for the scanner role user eg-scanner', async () => {
    expect(queueDefinition('scan.attachment')).toMatchObject({
      role: 'work',
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.attachment',
        service: 'email-worker',
      },
    });
    const attachment = bindings
      .filter((b) => b.source !== '' && b.destination === 'scan.attachment')
      .map((b) => `${b.source} [${b.routing_key}]`)
      .sort();
    expect(attachment).toEqual(
      [
        'email.ingestion [org.*.mail.message.parsed.v1]',
        'email.security [org.*.mail.message.rescan_requested.v1]',
        'email.security [retry.scan.attachment.#]',
      ].sort(),
    );
    const policy = policies.find((p) => p.name === 'eg.scan.attachment');
    expect(policy?.definition).toEqual(policyFor('work', 'scan.attachment'));
    expect(policy?.definition).toMatchObject({
      'dead-letter-routing-key': 'dead-letter.scan.attachment',
      overflow: 'reject-publish',
    });
    // The running stack consumes it (the email-worker attachment engine, step 4.2 WP3), only as
    // the scanner role user.
    const details = await api.get<{
      consumer_details?: { channel_details?: { user?: string } }[];
    }>(`/queues/${encodeURIComponent(vhost)}/scan.attachment`);
    const users = (details.consumer_details ?? []).map((c) => c.channel_details?.user);
    expect(users.length, 'consumers on scan.attachment').toBeGreaterThanOrEqual(1);
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    expect(new Set(users)).toEqual(new Set([scanner]));
  });

  /** The users of the consumers of `queue` on the running stack. */
  const consumerUsers = async (queue: string) => {
    const details = await api.get<{
      consumer_details?: { channel_details?: { user?: string } }[];
    }>(`/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(queue)}`);
    return (details.consumer_details ?? []).map((c) => c.channel_details?.user);
  };
  const bindingsOf = (queue: string) =>
    bindings
      .filter((b) => b.source !== '' && b.destination === queue)
      .map((b) => `${b.source} [${b.routing_key}]`)
      .sort();

  it('scan.url is a work queue (v5) with the qualified retry binding, for eg-scanner only', async () => {
    expect(queueDefinition('scan.url')).toMatchObject({
      role: 'work',
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.url', service: 'email-worker' },
    });
    // scan.url is a dot-prefix of scan.url.inspect / scan.url.results: retry.scan.url.org.# never
    // matches their retry hops (the unqualified retry.scan.url.# of v4 was pruned).
    expect(bindingsOf('scan.url')).toEqual(
      [
        'email.ingestion [org.*.mail.message.parsed.v1]',
        'email.security [org.*.mail.message.rescan_requested.v1]',
        'email.security [retry.scan.url.org.#]',
      ].sort(),
    );
    expect(policies.find((p) => p.name === 'eg.scan.url')?.definition).toEqual(
      policyFor('work', 'scan.url'),
    );
    // The URL engine (step 4.3 WP3) consumes it: at least one consumer, every one the scanner.
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    const users = await consumerUsers('scan.url');
    expect(users.length, 'consumers on scan.url').toBeGreaterThanOrEqual(1);
    for (const user of users) expect(user).toBe(scanner);
  });

  it('scan.bec is a stage-2 work queue (v6) bound only to scan_stage_ready.v1, for eg-scanner only', async () => {
    expect(queueDefinition('scan.bec')).toMatchObject({
      role: 'work',
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.bec', service: 'email-worker' },
    });
    expect(bindingsOf('scan.bec')).toEqual(
      [
        'email.security [org.*.mail.message.scan_stage_ready.v1]',
        'email.security [retry.scan.bec.#]',
      ].sort(),
    );
    expect(policies.find((p) => p.name === 'eg.scan.bec')?.definition).toEqual(
      policyFor('work', 'scan.bec'),
    );
    // The stage trigger reaches no other queue than scan.bec (and the firehose through
    // email.events); parsed.v1 / rescan_requested.v1 never reach scan.bec.
    const stage = bindings
      .filter((b) => b.source !== '' && b.routing_key === 'org.*.mail.message.scan_stage_ready.v1')
      .map((b) => `${b.destination_type}:${b.destination}`);
    expect(stage).toEqual(['queue:scan.bec']);
    // The BEC engine (step 4.4 WP3, SCAN_CONSUMERS containing bec) consumes it: at least one
    // consumer, every one the scanner. This assertion needs the WP3 email-worker running; before
    // WP3 the queue has no consumer and this case fails by design (as scan.url's did in 4.3).
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    const users = await consumerUsers('scan.bec');
    expect(users.length, 'consumers on scan.bec').toBeGreaterThanOrEqual(1);
    for (const user of users) expect(user).toBe(scanner);
  });

  it('scan.dlp is a stage-1 work queue (v7) bound to parsed.v1 and rescan_requested.v1, for eg-scanner only', async () => {
    expect(queueDefinition('scan.dlp')).toMatchObject({
      role: 'work',
      homeExchange: 'email.security',
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.dlp', service: 'email-worker' },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2_000,
        maxDelayMs: 60_000,
        maxRetryAgeMs: 86_400_000,
      },
    });
    expect(queueDefinition('scan.dlp').role).not.toBe('dormant');
    expect(bindingsOf('scan.dlp')).toEqual(
      [
        'email.ingestion [org.*.mail.message.parsed.v1]',
        'email.security [org.*.mail.message.rescan_requested.v1]',
        'email.security [retry.scan.dlp.#]',
      ].sort(),
    );
    // The applied policy is the work policy (dead-letters to email.dead-letter, reject-publish),
    // no longer the dormant drop-head buffer.
    const policy = policies.find((p) => p.name === 'eg.scan.dlp');
    expect(policy?.definition).toEqual(policyFor('work', 'scan.dlp'));
    expect(policy?.definition).toMatchObject({
      overflow: 'reject-publish',
      'dead-letter-routing-key': 'dead-letter.scan.dlp',
    });
    expect(queues.find((q) => q.name === 'scan.dlp')?.effective_policy_definition).toMatchObject({
      overflow: 'reject-publish',
    });
    // The stage trigger never reaches the stage-1 queue.
    expect(
      bindings.some(
        (b) =>
          b.destination === 'scan.dlp' &&
          b.routing_key === 'org.*.mail.message.scan_stage_ready.v1',
      ),
    ).toBe(false);
    // The DLP engine (step 4.5 WP3, SCAN_CONSUMERS containing dlp) consumes it: at least one
    // consumer, every one the scanner. This assertion needs the WP3 email-worker running; before
    // WP3 the queue has no consumer and this case fails by design (as scan.bec's did in 4.4).
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    const users = await consumerUsers('scan.dlp');
    expect(users.length, 'consumers on scan.dlp').toBeGreaterThanOrEqual(1);
    for (const user of users) expect(user).toBe(scanner);
  });

  it('mail.message.dlp_incident.v1 (v7) reaches no work queue: only the email.events firehose', () => {
    const type = 'mail.message.dlp_incident.v1';
    // No queue binding names the incident (the notification-worker binds it in step 6.2).
    const direct = bindings.filter((b) => b.source !== '' && b.routing_key === `org.*.${type}`);
    expect(direct).toEqual([]);
    // What the live bindings route an incident key to: from email.security only the exchange
    // binding to email.events (org.#), and from email.events only the dormant firehose.
    const key = `org.42.${type}`;
    const matches = (pattern: string) => topicMatches(pattern, key);
    const fromSecurity = bindings
      .filter((b) => b.source === 'email.security' && matches(b.routing_key))
      .map((b) => `${b.destination_type}:${b.destination}`);
    expect(fromSecurity).toEqual(['exchange:email.events']);
    const fromEvents = bindings
      .filter((b) => b.source === 'email.events' && matches(b.routing_key))
      .map((b) => `${b.destination_type}:${b.destination}`);
    expect(fromEvents).toEqual(['queue:email.analytics']);
    expect(queueDefinition('email.analytics').role).toBe('dormant');
  });

  it('scan.url.inspect is a lossy work queue (v5) for the stateless browser worker', async () => {
    expect(queueDefinition('scan.url.inspect')).toMatchObject({
      role: 'work',
      lossy: true,
      consumer: { kind: 'stateless', service: 'url-browser-worker' },
    });
    expect(bindingsOf('scan.url.inspect')).toEqual(
      [
        'email.security [org.*.mail.url.inspection_requested.v1]',
        'email.security [retry.scan.url.inspect.#]',
      ].sort(),
    );
    const policy = policies.find((p) => p.name === 'eg.scan.url.inspect');
    expect(policy?.definition).toEqual(policyFor('work-lossy', 'scan.url.inspect'));
    expect(policy?.definition).toMatchObject({
      overflow: 'drop-head',
      'max-length': 10_000,
      'dead-letter-routing-key': 'dead-letter.scan.url.inspect',
    });
    const browser = process.env.RABBITMQ_URL_BROWSER_USER || 'eg-url-browser';
    for (const user of await consumerUsers('scan.url.inspect')) expect(user).toBe(browser);
  });

  it('scan.url.results is a work queue (v5) for eg-scanner only', async () => {
    expect(queueDefinition('scan.url.results')).toMatchObject({
      role: 'work',
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.url.results',
        service: 'email-worker',
      },
    });
    expect(bindingsOf('scan.url.results')).toEqual(
      [
        'email.security [org.*.mail.url.inspection_completed.v1]',
        'email.security [retry.scan.url.results.#]',
      ].sort(),
    );
    expect(policies.find((p) => p.name === 'eg.scan.url.results')?.definition).toEqual(
      policyFor('work', 'scan.url.results'),
    );
    // The results consumer runs wherever SCAN_CONSUMERS contains url (U15).
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    const users = await consumerUsers('scan.url.results');
    expect(users.length, 'consumers on scan.url.results').toBeGreaterThanOrEqual(1);
    for (const user of users) expect(user).toBe(scanner);
  });

  it('scan.sandbox stays dormant, bound to the now registered sandbox_requested.v1 (v4)', () => {
    expect(queueDefinition('scan.sandbox')).toMatchObject({
      role: 'dormant',
      consumer: { kind: 'planned', plannedStep: '4.6' },
    });
    const sandbox = bindings
      .filter((b) => b.source !== '' && b.destination === 'scan.sandbox')
      .map((b) => `${b.source} [${b.routing_key}]`)
      .sort();
    expect(sandbox).toEqual(
      [
        'email.security [org.*.mail.attachment.sandbox_requested.v1]',
        'email.security [retry.scan.sandbox.#]',
      ].sort(),
    );
    expect(policies.find((p) => p.name === 'eg.scan.sandbox')?.definition).toEqual(
      policyFor('dormant', 'scan.sandbox'),
    );
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
    expect((await api.bindings(vhost)).filter((b) => b.source !== '')).toHaveLength(
      TOPOLOGY_BINDINGS,
    );
    await api.purge(vhost, 'scan.auth');
  });
});
