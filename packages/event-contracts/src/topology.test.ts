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
  LOSSY_WORK_QUEUE_MAX_LENGTH,
  parseRoutingKey,
  policyFor,
  policyKindOf,
  QUEUE_NAMES,
  type QueueDefinition,
  queueDefinition,
  type QueueName,
  retryBindingKey,
  retryPolicyViolations,
  retryRoutingKey,
  routeMessage,
  SCAN_AUTH_RESERVED_REASON,
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

describe('TOPOLOGY v11', () => {
  it('satisfies every invariant of design §3', () => {
    expect(validateTopology(TOPOLOGY)).toEqual([]);
  });

  it('declares exactly the six exchanges and twenty-one queues (v11)', () => {
    expect(TOPOLOGY_VERSION).toBe(11);
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
    expect(QUEUE_NAMES).toHaveLength(21);
    expect(TOPOLOGY.queues.map((q) => q.name)).toEqual([...QUEUE_NAMES]);
    expect(new Set(QUEUE_NAMES).size).toBe(21);
    expect(QUEUE_NAMES).toEqual(
      expect.arrayContaining([
        'scan.url.inspect',
        'scan.url.results',
        'scan.bec',
        'scan.sandbox.submissions',
        'scan.sandbox.results',
        // v9 (step 5.2 P15).
        'email.notifications',
        // v11 (step 6.2 §4.3).
        'email.webhooks',
      ]),
    );
  });

  it('assigns roles: sixteen work queues, one delay, one dead-letter, three dormant (v11)', () => {
    const byRole = (role: string) =>
      TOPOLOGY.queues.filter((q) => q.role === role).map((q) => q.name);
    expect(byRole('work')).toEqual([
      'email.received',
      'scan.spam',
      'scan.url',
      'scan.url.inspect',
      'scan.url.results',
      'scan.attachment',
      'scan.bec',
      'scan.dlp',
      'scan.sandbox',
      'scan.sandbox.submissions',
      'scan.sandbox.results',
      'email.policy.evaluate',
      'email.delivery.pending',
      // v10 (step 5.3 Q27): the release executor.
      'email.quarantine',
      'email.notifications',
      // v11 (step 6.2 W1): the webhook-worker fanout.
      'email.webhooks',
    ]);
    expect(byRole('delay')).toEqual(['email.delivery.retry']);
    expect(byRole('dead-letter')).toEqual(['email.dead-letter']);
    expect(byRole('dormant')).toEqual(['scan.auth', 'email.archive', 'email.analytics']);
    expect(byRole('dormant')).not.toContain('scan.url');
    // v7 (step 4.5 D2): scan.dlp is no longer dormant; v8 (step 4.6 X11): nor scan.sandbox.
    expect(byRole('dormant')).not.toContain('scan.dlp');
    expect(byRole('dormant')).not.toContain('scan.sandbox');
    // v9 (step 5.2 P13): the policy engine is the delivery gate; never lossy.
    expect(byRole('dormant')).not.toContain('email.policy.evaluate');
    expect(queueDefinition('email.policy.evaluate').lossy).toBeUndefined();
    expect(queueDefinition('email.notifications').lossy).toBeUndefined();
    // v10 (step 5.3): a queued release is never dropped.
    expect(queueDefinition('email.quarantine').lossy).toBeUndefined();
    // v11 (step 6.2 §4.3): webhook events are never dropped while the worker is down.
    expect(queueDefinition('email.webhooks').lossy).toBeUndefined();
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
      // v3 (step 4.1 S2): reserved, only its retry binding.
      'scan.auth': ['email.security', 'email.security retry.scan.auth.#'],
      'scan.spam': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security org.*.mail.message.rescan_requested.v1',
        'email.security retry.scan.spam.#',
      ],
      // v5 (step 4.3 U2): the qualified retry binding, because scan.url is a dot-prefix of
      // scan.url.inspect and scan.url.results.
      'scan.url': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security org.*.mail.message.rescan_requested.v1',
        'email.security retry.scan.url.org.#',
      ],
      'scan.url.inspect': [
        'email.security',
        'email.security org.*.mail.url.inspection_requested.v1',
        'email.security retry.scan.url.inspect.#',
      ],
      'scan.url.results': [
        'email.security',
        'email.security org.*.mail.url.inspection_completed.v1',
        'email.security retry.scan.url.results.#',
      ],
      'scan.attachment': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security org.*.mail.message.rescan_requested.v1',
        'email.security retry.scan.attachment.#',
      ],
      // v6 (step 4.4 B3): the stage-2 engine queue binds only the stage-ready event.
      'scan.bec': [
        'email.security',
        'email.security org.*.mail.message.scan_stage_ready.v1',
        'email.security retry.scan.bec.#',
      ],
      // v7 (step 4.5 D2): the stage-1 DLP engine queue keeps the bindings of the dormant queue.
      'scan.dlp': [
        'email.security',
        'email.ingestion org.*.mail.message.parsed.v1',
        'email.security org.*.mail.message.rescan_requested.v1',
        'email.security retry.scan.dlp.#',
      ],
      // v8 (step 4.6 X11): the controller's tasks; the qualified retry binding, because
      // scan.sandbox is a dot-prefix of scan.sandbox.submissions and scan.sandbox.results.
      'scan.sandbox': [
        'email.security',
        'email.security org.*.mail.sandbox.task_requested.v1',
        'email.security retry.scan.sandbox.org.#',
      ],
      'scan.sandbox.submissions': [
        'email.security',
        'email.security org.*.mail.attachment.sandbox_requested.v1',
        'email.security retry.scan.sandbox.submissions.#',
      ],
      'scan.sandbox.results': [
        'email.security',
        'email.security org.*.mail.sandbox.task_completed.v1',
        'email.security retry.scan.sandbox.results.#',
      ],
      // v9 (step 5.2 P15): a work queue; bindings unchanged from the dormant v1–v8 queue.
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
      // v10 (step 5.3 Q27): release requests replace mail.policy.decided.v1 (pruned).
      'email.quarantine': [
        'email.policy',
        'email.policy org.*.mail.quarantine.release_requested.v1',
        'email.policy retry.email.quarantine.#',
      ],
      // v9 (step 5.2 P15): the archive request replaces mail.policy.decided.v1 (still dormant).
      'email.archive': [
        'email.archive',
        'email.archive org.*.mail.message.archive_requested.v1',
        'email.archive retry.email.archive.#',
      ],
      // v9 (step 5.2 P15, P25): policy notifications for the notification-worker.
      'email.notifications': [
        'email.policy',
        'email.policy org.*.mail.policy.notification_requested.v1',
        // v10 (step 5.3 Q20).
        'email.policy org.*.mail.quarantine.notification_requested.v1',
        // v11 (step 6.2 N2): security alerts of the webhook-worker.
        'email.policy org.*.notification.alert_requested.v1',
        'email.policy retry.email.notifications.#',
      ],
      // v11 (step 6.2 §4.3): each source event on the exchange it is published to.
      'email.webhooks': [
        'email.events',
        'email.ingestion org.*.mail.message.received.v1',
        'email.security org.*.mail.message.scanned.v1',
        'email.security org.*.mail.attachment.sandbox_completed.v1',
        'email.policy org.*.mail.policy.decided.v1',
        'email.delivery org.*.mail.delivery.approved.v1',
        'email.events org.*.mail.message.state_changed.v1',
        'email.events org.*.domain.status.changed.v1',
        'email.events org.*.domain.dns.records_changed.v1',
        'email.events retry.email.webhooks.#',
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
    // v3 (step 4.1 S2): the Rspamd engine of the email-worker scan role.
    expect(queueDefinition('scan.spam').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.rspamd',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.spam').description).toBe(
      'Rspamd: spam, phishing, reputation and SPF/DKIM/DMARC/ARC (step 4.1)',
    );
    // v4 (step 4.2 A2): the attachment engine of the email-worker scan role.
    expect(queueDefinition('scan.attachment').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.attachment',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.attachment').description).toBe(
      'Attachments: file type, known hashes, ClamAV, YARA, archive limits (step 4.2)',
    );
    expect(queueDefinition('scan.attachment').policy).toEqual(policyFor('work', 'scan.attachment'));
    expect(queueDefinition('scan.attachment').policy).toMatchObject({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.scan.attachment',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    // v5 (step 4.3 U1, U2, U15): the URL engine, the results consumer and the browser worker.
    expect(queueDefinition('scan.url').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.url',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.url.results').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.url.results',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.url.inspect').consumer).toEqual({
      kind: 'stateless',
      service: 'url-browser-worker',
      reason: 'no database; results are deduplicated by inspectionId in scan.url.results',
    });
    // v6 (step 4.4 B1, B3): the phishing/BEC engine of the email-worker scan role.
    expect(queueDefinition('scan.bec').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.bec',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.bec').description).toBe(
      'Phishing and BEC (step 4.4): stage 2, triggered when rspamd and url finalized',
    );
    expect(queueDefinition('scan.bec').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.scan.bec',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    // v7 (step 4.5 D1, D2): the data loss prevention engine of the email-worker scan role.
    expect(queueDefinition('scan.dlp').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.dlp',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.dlp').description).toBe(
      'Data loss prevention (step 4.5): stage 1',
    );
    expect(queueDefinition('scan.dlp').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.scan.dlp',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    // v8 (step 4.6 X11): the sandbox-controller (stateless) and the two email-worker queues.
    expect(queueDefinition('scan.sandbox').consumer).toEqual({
      kind: 'stateless',
      service: 'sandbox-controller',
      reason:
        'no database; results are deduplicated by analysis id, state and result MAC in scan.sandbox.results',
    });
    expect(queueDefinition('scan.sandbox.submissions').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.sandbox',
      service: 'email-worker',
    });
    expect(queueDefinition('scan.sandbox.results').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'email-worker.scan.sandbox.results',
      service: 'email-worker',
    });
    expect(
      TOPOLOGY.queues.filter((q) => q.consumer.kind === 'stateless').map((q) => q.name),
    ).toEqual(['scan.url.inspect', 'scan.sandbox']);
    expect(queueDefinition('scan.auth').consumer).toEqual({
      kind: 'none',
      reason: SCAN_AUTH_RESERVED_REASON,
    });
    expect(SCAN_AUTH_RESERVED_REASON).toBe(
      'reserved: authentication results come from the rspamd engine on scan.spam (step 4.1, ADR-0026)',
    );
    const planned = Object.fromEntries(
      TOPOLOGY.queues
        .filter((q) => q.consumer.kind === 'planned')
        .map((q) => [q.name, q.consumer.kind === 'planned' ? q.consumer.plannedStep : '']),
    );
    // v10 (step 5.3 Q13.2, Q27): the policy-engine's release executor.
    expect(queueDefinition('email.quarantine').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'policy-engine.quarantine',
      service: 'policy-engine',
    });
    expect(queueDefinition('email.quarantine').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2_000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 24 * 3_600_000,
    });
    expect(queueDefinition('email.quarantine').policy).toEqual(
      policyFor('work', 'email.quarantine'),
    );
    // v9 (step 5.2 P13, P25): the policy-engine and the notification-worker.
    expect(queueDefinition('email.policy.evaluate').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'policy-engine.evaluate',
      service: 'policy-engine',
    });
    expect(queueDefinition('email.policy.evaluate').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2_000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 24 * 3_600_000,
    });
    expect(queueDefinition('email.notifications').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'notification-worker.policy',
      service: 'notification-worker',
    });
    expect(queueDefinition('email.notifications').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 8,
      baseDelayMs: 5_000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 24 * 3_600_000,
    });
    // v11 (step 6.2 §4.3): the webhook-worker fanout.
    expect(queueDefinition('email.webhooks').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'webhook-worker.fanout',
      service: 'webhook-worker',
    });
    expect(queueDefinition('email.webhooks').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2_000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 24 * 3_600_000,
    });
    expect(planned).toEqual({
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
  it('applies the policy of each role (and the lossy work policy of scan.url.inspect, v5, and scan.sandbox, v8)', () => {
    for (const queue of TOPOLOGY.queues) {
      expect(queue.policy, queue.name).toEqual(policyFor(policyKindOf(queue), queue.name));
    }
    expect(TOPOLOGY.queues.filter((q) => q.lossy).map((q) => q.name)).toEqual([
      'scan.url.inspect',
      'scan.sandbox',
    ]);
    expect(queueDefinition('scan.url.inspect').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.scan.url.inspect',
      'dead-letter-strategy': 'at-most-once',
      overflow: 'drop-head',
      'max-length': 10_000,
    });
    expect(LOSSY_WORK_QUEUE_MAX_LENGTH).toBe(10_000);
    for (const name of [
      'scan.url',
      'scan.url.results',
      'scan.bec',
      'scan.dlp',
      'scan.sandbox.submissions',
      'scan.sandbox.results',
      'email.policy.evaluate',
      'email.notifications',
      'email.webhooks',
    ] as const) {
      expect(queueDefinition(name).policy, name).toEqual(policyFor('work', name));
    }
    // v11 (step 6.2 §4.3): reject-publish at 1 000 000, dead letters to email.dead-letter.
    expect(queueDefinition('email.webhooks').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.email.webhooks',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    // v9 (step 5.2): the delivery gate rejects publishes when full, it never drops mail.
    expect(queueDefinition('email.policy.evaluate').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.email.policy.evaluate',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    expect(queueDefinition('email.received').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.email.received',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    expect(queueDefinition('scan.spam').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.scan.spam',
      'dead-letter-strategy': 'at-least-once',
      overflow: 'reject-publish',
      'max-length': 1_000_000,
    });
    expect(queueDefinition('scan.auth').policy).toEqual(policyFor('dormant', 'scan.auth'));
    // v8 (step 4.6 X11): work-lossy, like scan.url.inspect.
    expect(queueDefinition('scan.sandbox').policy).toEqual({
      'delivery-limit': 20,
      'dead-letter-exchange': 'email.events',
      'dead-letter-routing-key': 'dead-letter.scan.sandbox',
      'dead-letter-strategy': 'at-most-once',
      overflow: 'drop-head',
      'max-length': 10_000,
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
      else if (queue.lossy) expect(queue.policy.overflow, queue.name).toBe('drop-head');
      else expect(queue.policy.overflow, queue.name).toBe('reject-publish');
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
    // v3 (step 4.1 S2): the engine budget (SCAN_RSPAMD_MAX_ATTEMPTS < 10) finalizes first.
    expect(queueDefinition('scan.spam').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 86_400_000,
    });
    // v4 (step 4.2 A2, A12): as scan.spam; SCAN_ATTACHMENT_MAX_ATTEMPTS (6) < 10 finalizes first.
    expect(queueDefinition('scan.attachment').retry).toEqual(queueDefinition('scan.spam').retry);
    // v5 (step 4.3 U2, U17): as scan.spam; SCAN_URL_MAX_ATTEMPTS (6) < 10 finalizes first.
    expect(queueDefinition('scan.url').retry).toEqual(queueDefinition('scan.spam').retry);
    expect(queueDefinition('scan.url.results').retry).toEqual(queueDefinition('scan.spam').retry);
    // v6 (step 4.4 B3): as scan.spam; SCAN_BEC_MAX_ATTEMPTS (3) < 10 finalizes first.
    expect(queueDefinition('scan.bec').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 86_400_000,
    });
    // v7 (step 4.5 D2): as scan.spam; SCAN_DLP_MAX_ATTEMPTS (3) < 10 finalizes first.
    expect(queueDefinition('scan.dlp').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 86_400_000,
    });
    expect(queueDefinition('scan.url.inspect').retry).toEqual({
      strategy: 'hold',
      maxAttempts: 3,
      baseDelayMs: 5000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 3_600_000,
    });
    // v8 (step 4.6 X11): the controller's queue as scan.url.inspect; the two email-worker queues
    // as scan.spam.
    expect(queueDefinition('scan.sandbox').retry).toEqual(
      queueDefinition('scan.url.inspect').retry,
    );
    expect(queueDefinition('scan.sandbox.submissions').retry).toEqual(
      queueDefinition('scan.spam').retry,
    );
    expect(queueDefinition('scan.sandbox.results').retry).toEqual(
      queueDefinition('scan.spam').retry,
    );
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

  it('returns null for keys the topology never produces', () => {
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
    expect(route('mail.message.received.v1')).toEqual([
      'email.analytics',
      'email.received',
      'email.webhooks',
    ]);
    // v3: scan.auth is unbound (step 4.1 S2).
    expect(route('mail.message.parsed.v1')).toEqual(
      ['email.analytics', 'scan.attachment', 'scan.dlp', 'scan.spam', 'scan.url'].sort(),
    );
    expect(route('mail.message.parse_failed.v1')).toEqual([
      'email.analytics',
      'email.policy.evaluate',
    ]);
    expect(route('mail.message.scanned.v1')).toEqual([
      'email.analytics',
      'email.policy.evaluate',
      'email.webhooks',
    ]);
    // Topology v10 (step 5.3 Q2, Q27): the decision reaches only the firehose; the archive and
    // notification requests their own queues; release requests the executor.
    // Topology v11 (step 6.2 §4.3): and the webhook fanout.
    expect(route('mail.policy.decided.v1')).toEqual(['email.analytics', 'email.webhooks']);
    expect(route('mail.quarantine.release_requested.v1')).toEqual([
      'email.analytics',
      'email.quarantine',
    ]);
    expect(route('mail.quarantine.notification_requested.v1')).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
    expect(route('mail.message.archive_requested.v1')).toEqual([
      'email.analytics',
      'email.archive',
    ]);
    expect(route('mail.policy.notification_requested.v1')).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
    expect(route('mail.delivery.approved.v1')).toEqual([
      'email.analytics',
      'email.delivery.pending',
      'email.webhooks',
    ]);
    expect(route('mail.delivery.status_changed.v1')).toEqual(['email.analytics']);
    expect(route('domain.status.changed.v1')).toEqual(['email.analytics', 'email.webhooks']);
    expect(route('domain.routing.changed.v1')).toEqual(['email.analytics']);
    // Topology v2 (step 3.3 L7); v11 adds the webhook fanout.
    expect(route('mail.message.state_changed.v1')).toEqual(['email.analytics', 'email.webhooks']);
    expect(route('mail.message.rescan_requested.v1')).toEqual(
      ['email.analytics', 'scan.attachment', 'scan.dlp', 'scan.spam', 'scan.url'].sort(),
    );
    // Topology v5 (step 4.3 U2): clicks reach only the firehose.
    expect(route('mail.url.inspection_requested.v1')).toEqual([
      'email.analytics',
      'scan.url.inspect',
    ]);
    expect(route('mail.url.inspection_completed.v1')).toEqual([
      'email.analytics',
      'scan.url.results',
    ]);
    expect(route('mail.url.clicked.v1')).toEqual(['email.analytics']);
    // Topology v6 (step 4.4 B3): the stage trigger reaches only scan.bec and the firehose; the
    // stage-1 events never reach scan.bec.
    expect(route('mail.message.scan_stage_ready.v1')).toEqual(['email.analytics', 'scan.bec']);
    expect(route('mail.message.parsed.v1')).not.toContain('scan.bec');
    expect(route('mail.message.rescan_requested.v1')).not.toContain('scan.bec');
    // Topology v7 (step 4.5 D2, D14): the DLP incident reaches no queue but the firehose (the
    // notification-worker binds it in step 6.2); scan.dlp is a stage-1 engine queue.
    expect(route('mail.message.dlp_incident.v1')).toEqual(['email.analytics']);
    expect(route('mail.message.scan_stage_ready.v1')).not.toContain('scan.dlp');
    // Topology v8 (step 4.6 X11): submissions go to the dispatcher, tasks to the controller,
    // results to the results consumer; the submission's completion reaches only the firehose.
    expect(route('mail.attachment.sandbox_requested.v1')).toEqual([
      'email.analytics',
      'scan.sandbox.submissions',
    ]);
    expect(route('mail.sandbox.task_requested.v1')).toEqual(['email.analytics', 'scan.sandbox']);
    expect(route('mail.sandbox.task_completed.v1')).toEqual([
      'email.analytics',
      'scan.sandbox.results',
    ]);
    // Topology v11 (step 6.2 §4.3): the late sandbox verdict reaches the webhook fanout.
    expect(route('mail.attachment.sandbox_completed.v1')).toEqual([
      'email.analytics',
      'email.webhooks',
    ]);
    // Topology v11: the new DNS record transitions reach only the fanout and the firehose; the
    // security alert requests only the notification-worker and the firehose.
    expect(route('domain.dns.records_changed.v1')).toEqual(['email.analytics', 'email.webhooks']);
    expect(route('notification.alert_requested.v1')).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
  });

  it('keeps the retry hops of dot-prefixed queue names apart (v5 scan.url, scan.url.*)', () => {
    expect(retryBindingKey('scan.url')).toBe('retry.scan.url.org.#');
    expect(retryBindingKey('scan.url.inspect')).toBe('retry.scan.url.inspect.#');
    expect(retryBindingKey('scan.url.results')).toBe('retry.scan.url.results.#');
    expect(retryBindingKey('scan.spam')).toBe('retry.scan.spam.#');
    expect(retryBindingKey('scan.bec')).toBe('retry.scan.bec.#');
    expect(retryBindingKey('scan.dlp')).toBe('retry.scan.dlp.#');
    // v8 (step 4.6 X11): scan.sandbox is a dot-prefix of its two sibling queues.
    expect(retryBindingKey('scan.sandbox')).toBe('retry.scan.sandbox.org.#');
    expect(retryBindingKey('scan.sandbox.submissions')).toBe('retry.scan.sandbox.submissions.#');
    expect(retryBindingKey('scan.sandbox.results')).toBe('retry.scan.sandbox.results.#');
    // v9 (step 5.2): no new dot-prefix: plain retry bindings.
    expect(retryBindingKey('email.policy.evaluate')).toBe('retry.email.policy.evaluate.#');
    expect(retryBindingKey('email.notifications')).toBe('retry.email.notifications.#');
    // v11 (step 6.2): no other queue name starts with email.webhooks.
    expect(retryBindingKey('email.webhooks')).toBe('retry.email.webhooks.#');
    // Every retry key of every work/dormant queue and every event type reaches exactly that queue.
    const types = [...Object.keys(EVENT_REGISTRY), ...Object.keys(RESERVED_EVENT_TYPES)];
    for (const queue of TOPOLOGY.queues.filter((q) => q.role === 'work' || q.role === 'dormant')) {
      for (const type of types) {
        expect(
          routeMessage(queue.homeExchange, retryRoutingKey(queue.name, '42', type)),
          `${queue.name} ${type}`,
        ).toEqual([queue.name]);
      }
    }
    // The unqualified key of the design text would also capture the inspect queue's retry hops.
    expect(
      topicMatches(
        'retry.scan.url.#',
        retryRoutingKey('scan.url.inspect', '42', 'mail.url.inspection_requested.v1'),
      ),
    ).toBe(true);
    expect(
      topicMatches(
        'retry.scan.url.org.#',
        retryRoutingKey('scan.url.inspect', '42', 'mail.url.inspection_requested.v1'),
      ),
    ).toBe(false);
    // The v1–v7 key retry.scan.sandbox.# would capture the dispatcher's retry hops in v8.
    const submissionRetry = retryRoutingKey(
      'scan.sandbox.submissions',
      '42',
      'mail.attachment.sandbox_requested.v1',
    );
    expect(topicMatches('retry.scan.sandbox.#', submissionRetry)).toBe(true);
    expect(topicMatches('retry.scan.sandbox.org.#', submissionRetry)).toBe(false);
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
    expect(eventTypesBoundTo('scan.sandbox')).toEqual(['mail.sandbox.task_requested.v1']);
    expect(eventTypesBoundTo('scan.sandbox.submissions')).toEqual([
      'mail.attachment.sandbox_requested.v1',
    ]);
    expect(eventTypesBoundTo('scan.sandbox.results')).toEqual(['mail.sandbox.task_completed.v1']);
    for (const queue of ['scan.spam', 'scan.url', 'scan.attachment', 'scan.dlp']) {
      expect(eventTypesBoundTo(queue), queue).toEqual([
        'mail.message.parsed.v1',
        'mail.message.rescan_requested.v1',
      ]);
    }
    expect(eventTypesBoundTo('scan.url.inspect')).toEqual(['mail.url.inspection_requested.v1']);
    expect(eventTypesBoundTo('scan.url.results')).toEqual(['mail.url.inspection_completed.v1']);
    expect(eventTypesBoundTo('scan.bec')).toEqual(['mail.message.scan_stage_ready.v1']);
    expect(eventTypesBoundTo('scan.auth')).toEqual([]);
    expect(eventTypesBoundTo('email.analytics')).toEqual(
      [...Object.keys(EVENT_REGISTRY), ...Object.keys(RESERVED_EVENT_TYPES)].sort(),
    );
    expect(eventTypesBoundTo('email.delivery.retry')).toEqual([]);
    expect(eventTypesBoundTo('email.dead-letter')).toEqual([]);
    // v11 (step 6.2 §4.3, W3): the eight source events of the projection.
    expect(eventTypesBoundTo('email.webhooks')).toEqual(
      [
        'mail.message.received.v1',
        'mail.message.scanned.v1',
        'mail.attachment.sandbox_completed.v1',
        'mail.policy.decided.v1',
        'mail.delivery.approved.v1',
        'mail.message.state_changed.v1',
        'domain.status.changed.v1',
        'domain.dns.records_changed.v1',
      ].sort(),
    );
    expect(eventTypesBoundTo('email.notifications')).toEqual([
      'mail.policy.notification_requested.v1',
      'mail.quarantine.notification_requested.v1',
      'notification.alert_requested.v1',
    ]);
  });

  it('keeps the webhook fanout hops apart (v11): retry and dead-letter reach exactly their queue', () => {
    for (const type of eventTypesBoundTo('email.webhooks')) {
      expect(
        routeMessage('email.events', retryRoutingKey('email.webhooks', '42', type)),
        type,
      ).toEqual(['email.webhooks']);
      expect(
        routeMessage('email.events', deadLetterRoutingKey('email.webhooks', '42', type)),
        type,
      ).toEqual(['email.dead-letter']);
    }
    expect(routeMessage('email.events', deadLetterRoutingKey('email.webhooks'))).toEqual([
      'email.dead-letter',
    ]);
    // A received event published once reaches email.webhooks once (direct binding on
    // email.ingestion; the email.events copy matches no email.webhooks binding).
    expect(
      routeMessage('email.ingestion', eventRoutingKey('42', 'mail.message.received.v1')),
    ).toEqual(['email.analytics', 'email.received', 'email.webhooks']);
    // Events that are not projected never reach the fanout.
    for (const type of [
      'mail.message.parsed.v1',
      'mail.delivery.status_changed.v1',
      'domain.routing.changed.v1',
      'mail.url.clicked.v1',
      'mail.quarantine.notification_requested.v1',
      'notification.alert_requested.v1',
    ]) {
      expect(eventTypesBoundTo('email.webhooks'), type).not.toContain(type);
    }
  });
});

describe('validateTopology (negative cases)', () => {
  it('detects a missing or extra queue and exchange', () => {
    const t = clone();
    t.queues = t.queues.filter((q) => q.name !== 'scan.sandbox');
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

  it('detects a dot-prefix queue whose retry binding would capture the other queue', () => {
    const t = clone();
    const url = mutableQueue(t, 'scan.url');
    url.bindings = url.bindings.map((b) =>
      b.routingKey.startsWith('retry.') ? { ...b, routingKey: 'retry.scan.url.#' } : b,
    );
    const violations = validateTopology(t);
    expect(violations).toContain(
      'scan.url: retry binding retry.scan.url.# is not retry.scan.url.org.#',
    );
    expect(violations).toContain(
      'scan.url.inspect: retry hops must reach exactly scan.url.inspect',
    );
    expect(violations).toContain(
      'scan.url.results: retry hops must reach exactly scan.url.results',
    );
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
      'scan.spam: retry binding retry.scan.# is not retry.scan.spam.#',
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
    expect(violations).toContain(
      'email.received: a work queue must have consumer kind ledger or stateless',
    );
  });

  it('allows the stateless consumer kind and the lossy policy on work queues only (v5)', () => {
    const t = clone();
    // v10: email.quarantine is a work queue; email.archive is the dormant example.
    mutableQueue(t, 'email.archive').consumer = {
      kind: 'stateless',
      service: 'x',
      reason: 'y',
    };
    expect(validateTopology(t)).toContain(
      'email.archive: a dormant queue must have consumer kind planned or none',
    );
    const u = clone();
    const archive = mutableQueue(u, 'email.archive');
    archive.lossy = true;
    expect(validateTopology(u)).toContain('email.archive: only a work queue can be lossy');
    // v8 (step 4.6 X11): scan.sandbox is work-lossy; without lossy its policy is wrong.
    const v = clone();
    delete mutableQueue(v, 'scan.sandbox').lossy;
    expect(validateTopology(v)).toContain('scan.sandbox: policy differs from the work policy');
    const w = clone();
    mutableQueue(w, 'scan.url.inspect').policy = policyFor('work', 'scan.url.inspect');
    expect(validateTopology(w)).toContain(
      'scan.url.inspect: policy differs from the work-lossy policy',
    );
    const x = clone();
    delete mutableQueue(x, 'scan.url.inspect').lossy;
    expect(validateTopology(x)).toContain('scan.url.inspect: policy differs from the work policy');
    const y = clone();
    mutableQueue(y, 'scan.spam').consumer = {
      kind: 'stateless',
      service: 'email-worker',
      reason: 'test',
    };
    expect(validateTopology(y)).toEqual([]);
  });

  it('allows only an unbound dormant queue to be reserved (consumer kind none)', () => {
    const t = clone();
    mutableQueue(t, 'scan.auth').bindings.unshift({
      exchange: 'email.ingestion',
      routingKey: 'org.*.mail.message.parsed.v1',
    });
    expect(validateTopology(t)).toContain('scan.auth: a reserved queue has no event binding');
    const u = clone();
    mutableQueue(u, 'email.quarantine').bindings = [
      { exchange: 'email.policy', routingKey: 'retry.email.quarantine.#' },
    ];
    expect(validateTopology(u)).toContain('email.quarantine: has no event binding');
    // A v1–v7 style unqualified retry binding on scan.sandbox is refused in v8.
    const x = clone();
    mutableQueue(x, 'scan.sandbox').bindings[1] = {
      exchange: 'email.security',
      routingKey: 'retry.scan.sandbox.#',
    };
    expect(validateTopology(x)).toContain(
      'scan.sandbox: retry binding retry.scan.sandbox.# is not retry.scan.sandbox.org.#',
    );
    const w = clone();
    mutableQueue(w, 'scan.auth').consumer = {
      kind: 'ledger',
      ledgerName: 'x',
      service: 'email-worker',
    };
    expect(validateTopology(w)).toContain(
      'scan.auth: a dormant queue must have consumer kind planned or none',
    );
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
    // v11: domain.status.changed.v1 also reaches email.webhooks; routing changes only the firehose.
    expect(validateTopology(t)).toContain('event type domain.routing.changed.v1 reaches no queue');
    expect(validateTopology(t)).not.toContain(
      'event type domain.status.changed.v1 reaches no queue',
    );
  });
});

describe('toRabbitDefinitions (Q5)', () => {
  const definitions = toRabbitDefinitions(TOPOLOGY, { vhost: DEFAULT_VHOST });

  it('declares topic exchanges and quorum queues with no other argument', () => {
    expect(definitions.topology_version).toBe(11);
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
    expect(definitions.queues).toHaveLength(21);
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
    // v7 (step 4.5 D2): scan.dlp turned from dormant into a work queue with the same three
    // bindings, so the count was the v6 count (36 queue + 5 exchange bindings = 41). v8 (step 4.6
    // X11): scan.sandbox keeps two bindings (task_requested.v1 replaces sandbox_requested.v1, the
    // retry key is qualified), the two new queues add two each: 40 queue + 5 exchange = 45. v9
    // (step 5.2 P15): email.policy.evaluate keeps its three bindings, email.archive keeps two
    // (archive_requested.v1 replaces policy.decided.v1), email.notifications adds two: 42 queue
    // + 5 exchange = 47. v10 (step 5.3 Q27): email.quarantine keeps two (release_requested.v1
    // replaces policy.decided.v1), email.notifications adds one: 43 queue + 5 exchange = 48.
    // v11 (step 6.2 §4.3): email.webhooks adds nine (eight events + retry), email.notifications
    // one (alert_requested.v1): 53 queue + 5 exchange = 58.
    expect(definitions.bindings).toHaveLength(58);
    const keys = definitions.bindings.map(
      (b) => `${b.source}|${b.destination_type}|${b.destination}|${b.routing_key}`,
    );
    expect(new Set(keys).size).toBe(keys.length);
    // Sorted field by field (source, destination type, destination, routing key): `scan.url`
    // sorts before `scan.url.inspect`, which a joined-string sort would not show (v5).
    const tuples = definitions.bindings.map((b) => [
      b.source,
      b.destination_type,
      b.destination,
      b.routing_key,
    ]);
    const byFields = (a: string[], b: string[]) => {
      for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1;
      }
      return 0;
    };
    expect([...tuples].sort(byFields)).toEqual(tuples);
    expect(definitions.bindings.filter((b) => b.destination_type === 'exchange')).toHaveLength(5);
    for (const binding of definitions.bindings) {
      expect(binding.arguments).toEqual({});
      expect(binding.vhost).toBe('email-gateway');
    }
  });

  it('generates one anchored policy per queue', () => {
    expect(definitions.policies).toHaveLength(21);
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
