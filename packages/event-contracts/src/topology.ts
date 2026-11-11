import {
  EVENT_REGISTRY,
  isRegisteredEventType,
  isReservedEventType,
  RESERVED_EVENT_TYPES,
  schemaVersionOf,
} from './registry';

/**
 * RabbitMQ topology v9 as data (step 3.2 §3, ADR-0024; v2: step 3.3 L7, ADR-0025; v3: step 4.1
 * S2, ADR-0026; v4: step 4.2 A2, ADR-0028; v5: step 4.3 U2, ADR-0029; v6: step 4.4 B3,
 * ADR-0033; v7: step 4.5 D2, ADR-0036; v8: step 4.6 X11, ADR-0040; v9: step 5.2 P15, ADR-0044):
 * exactly six topic exchanges and twenty quorum queues in the vhost `email-gateway`. v2 added the bindings of `mail.message.rescan_requested.v1`
 * (`email.security`) to the five scan queues, and `mail.message.state_changed.v1`
 * (`email.events`) reaches only the `email.analytics` firehose. v3 makes `scan.spam` a work queue
 * (the Rspamd engine of the email-worker scan role, ledger consumer `email-worker.scan.rspamd`)
 * and unbinds `scan.auth` (reserved: authentication results come from the Rspamd engine on
 * `scan.spam`). v4 makes `scan.attachment` a work queue (the attachment engine of the
 * email-worker scan role, ledger consumer `email-worker.scan.attachment`; bindings unchanged) and
 * registers `mail.attachment.sandbox_requested.v1`, the event the dormant `scan.sandbox` (step
 * 4.6) was already bound to. v5 makes `scan.url` a work queue (the URL engine of the email-worker
 * scan role, ledger consumer `email-worker.scan.url`; event bindings unchanged), adds
 * `scan.url.inspect` (inspection requests for the isolated browser worker: consumer kind
 * `stateless`, the bounded lossy work policy `work-lossy`) and `scan.url.results` (inspection
 * results, ledger consumer `email-worker.scan.url.results`), and registers the three URL events
 * (`mail.url.inspection_requested.v1`, `mail.url.inspection_completed.v1`, `mail.url.clicked.v1`;
 * the last reaches only the `email.analytics` firehose). Because `scan.url` is a dot-prefix of the
 * two new queue names, its retry binding is the qualified `retry.scan.url.org.#` (every retry key
 * is `retry.<queue>.org.<id>.<type>`), so it never captures their retry hops
 * (`retryBindingKey`). The exchanges and the other queues are unchanged.
 *
 * v6 adds `scan.bec`, the work queue of the phishing/BEC engine (email-worker scan role, ledger
 * consumer `email-worker.scan.bec`), the first **stage-2** engine queue: it binds only
 * `mail.message.scan_stage_ready.v1` (registered by v6), which the scan stage writes when every
 * dependency of the engine (`rspamd`, `url`) in the round's required set has its final result,
 * and never `parsed.v1` / `rescan_requested.v1`. `scan.bec` is no dot-prefix of another queue, so
 * its retry binding is the plain `retry.scan.bec.#`. `scan.auth` stays reserved (its reason is
 * unchanged); the exchanges and the other queues are unchanged.
 *
 * v7 makes `scan.dlp` a work queue: the data loss prevention engine of the email-worker scan role
 * (ledger consumer `email-worker.scan.dlp`), a **stage-1** engine like rspamd, url and
 * attachment, so its event bindings (`parsed.v1`, `rescan_requested.v1`) and its plain retry
 * binding `retry.scan.dlp.#` (no dot-prefix of another queue) are the ones the dormant queue
 * already had: only its role, consumer, retry policy and queue policy change, and the binding
 * count is unchanged. v7 registers `mail.message.dlp_incident.v1` on `email.security`, which no
 * queue binds in this step (it reaches only the `email.analytics` firehose; the notification
 * worker binds it in step 6.2). The exchanges and the other queues are unchanged.
 *
 * v8 (step 4.6 X11) builds the asynchronous sandbox engine. `scan.sandbox` becomes the work
 * queue of the isolated `sandbox-controller` (consumer kind `stateless`: no database, results
 * deduplicated downstream; policy `work-lossy`: a bounded lossy buffer, the controller is
 * optional and an undelivered task expires at the analysis deadline). It binds the new
 * `mail.sandbox.task_requested.v1` instead of `mail.attachment.sandbox_requested.v1` (its v1–v7
 * binding is removed by `init.mjs`'s prune step). Two new work queues of the email-worker:
 * `scan.sandbox.submissions` (ledger `email-worker.scan.sandbox`, binds
 * `mail.attachment.sandbox_requested.v1`: the dispatcher) and `scan.sandbox.results` (ledger
 * `email-worker.scan.sandbox.results`, binds `mail.sandbox.task_completed.v1`, published
 * directly by the controller with confirms). Because `scan.sandbox` is now a dot-prefix of both,
 * its retry binding is the qualified `retry.scan.sandbox.org.#` (`retryBindingKey`).
 * `mail.attachment.sandbox_completed.v1` is registered but bound by no queue (analytics firehose
 * only). The exchanges and the other queues are unchanged.
 *
 * v9 (step 5.2 P13, P15, ADR-0044) builds the policy engine. `email.policy.evaluate` becomes the
 * work queue of the `policy-engine` (ledger `policy-engine.evaluate`; event bindings
 * `mail.message.scanned.v1` on `email.security` and `mail.message.parse_failed.v1` on
 * `email.ingestion` and its retry binding unchanged; policy `work`: reject-publish at 1 000 000,
 * so evaluations are never dropped while the engine is down). New work queue
 * `email.notifications` (home exchange `email.policy`, ledger `notification-worker.policy`) binds
 * the new `mail.policy.notification_requested.v1` (policy ALERT and sender non-delivery notices).
 * The dormant `email.archive` (step 8.1) binds the new `mail.message.archive_requested.v1` on
 * `email.archive` instead of `mail.policy.decided.v1` (its v1–v8 binding is removed by
 * `init.mjs`'s prune step); `mail.policy.decided.v1` (redefined in place) stays bound to the
 * dormant `email.quarantine` (5.3) only. No new queue name is a dot-prefix of another, so every
 * new retry binding is the plain `retry.<queue>.#`. The exchanges and the other queues are
 * unchanged.
 *
 * `infrastructure/rabbitmq/definitions.json` is
 * generated from `TOPOLOGY` (`pnpm --filter @email-gateway/event-contracts topology:export`) and
 * imported by `infrastructure/rabbitmq/init.mjs`; services never declare, they verify passively.
 *
 * Only `x-queue-type: quorum` is a queue argument; everything mutable (delivery limit, dead-letter
 * target, overflow, length limits) is a per-queue policy `eg.<queue>` (Q4), so it changes without
 * re-declaring a queue.
 */
export const TOPOLOGY_VERSION = 9;
export const DEFAULT_VHOST = 'email-gateway';

/** The six exchanges of the topology (ADR-0024): all topic, durable, not internal. */
export const EXCHANGE_NAMES = [
  'email.ingestion',
  'email.security',
  'email.policy',
  'email.delivery',
  'email.archive',
  'email.events',
] as const;
export type ExchangeName = (typeof EXCHANGE_NAMES)[number];

export const QUEUE_NAMES = [
  'email.received',
  'scan.auth',
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
  'email.delivery.retry',
  'email.quarantine',
  'email.archive',
  'email.notifications',
  'email.analytics',
  'email.dead-letter',
] as const;
export type QueueName = (typeof QUEUE_NAMES)[number];

/**
 * - `work`: consumed in this step; bounded by reject-publish, dead-letters to `email.dead-letter`
 *   (a `lossy` work queue is bounded by drop-head instead: policy `work-lossy`, v5).
 * - `dormant`: bound for a stage not built yet; bounded lossy buffer (drop-head), no consumer. A
 *   dormant queue with consumer kind `none` is reserved: it keeps only its retry binding and
 *   receives no event (v3 `scan.auth`).
 * - `delay`: per-message TTL hop of the delivery retry; expires back to its work queue.
 * - `dead-letter`: `email.dead-letter`; operators replay through the api.
 */
export type QueueRole = 'work' | 'dormant' | 'delay' | 'dead-letter';

/** Hold strategy: the delay is waited while holding the delivery, so it is capped (Q8). */
export const HOLD_MAX_DELAY_MS = 60_000;

export interface RetryPolicy {
  strategy: 'hold' | 'delay-queue';
  /** Counted (retryable) failures before dead-letter. */
  maxAttempts: number;
  baseDelayMs: number;
  /** `hold`: ≤ 60 000 (a held message keeps its prefetch slot). */
  maxDelayMs: number;
  /** Transient retries stop after this age since `x-eg-first-failed-at`. */
  maxRetryAgeMs: number;
  /** `delay-queue` only: the delay queue (role `delay`). */
  delayQueue?: QueueName;
}

export interface Binding {
  exchange: ExchangeName;
  routingKey: string;
}

export interface ExchangeBinding {
  source: ExchangeName;
  destination: ExchangeName;
  routingKey: string;
}

/**
 * Who consumes a queue: a ledger consumer of this step, a stateless consumer (v5: a service with
 * no database, hence no `message_idempotency` ledger; its effects are deduplicated downstream, so
 * the reconciler never re-drives it), a planned stage, or nobody by design.
 */
export type QueueConsumerInfo =
  | { kind: 'ledger'; ledgerName: string; service: string }
  | { kind: 'stateless'; service: string; reason: string }
  | { kind: 'planned'; plannedStep: string; plannedService: string }
  | { kind: 'none'; reason: string };

export interface QueueDefinition {
  name: QueueName;
  role: QueueRole;
  /** The exchange that carries this queue's retry hops (`retryBindingKey(queue)`). */
  homeExchange: ExchangeName;
  bindings: Binding[];
  consumer: QueueConsumerInfo;
  /**
   * Work queues only (v5): the queue is a bounded lossy buffer (policy `work-lossy`: drop-head
   * at `LOSSY_WORK_QUEUE_MAX_LENGTH`) instead of rejecting publishes when full.
   */
  lossy?: true;
  /** Present for work and dormant queues (dormant: for their future consumer). */
  retry?: RetryPolicy;
  /** The definition of policy `eg.<queue>` (Q4). */
  policy: Record<string, string | number>;
  description: string;
}

export interface Topology {
  version: number;
  exchanges: readonly ExchangeName[];
  exchangeBindings: readonly ExchangeBinding[];
  queues: readonly QueueDefinition[];
}

const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;
const ORG_KEY = /^org\.([1-9][0-9]{0,19})\.(.+)$/;

/** Routing key of the delay queue's expiry (broker dead-letter, fixed key). */
export const DELAY_EXPIRED_ROUTING_KEY = 'retry.email.delivery.pending.expired';

// ---------------------------------------------------------------------------------------------
// Policies (Q4)
// ---------------------------------------------------------------------------------------------

const WORK_QUEUE_MAX_LENGTH = 1_000_000;
const DORMANT_QUEUE_MAX_LENGTH = 10_000;
/** Length bound of a lossy work queue (v5 `scan.url.inspect`, step 4.3 U2). */
export const LOSSY_WORK_QUEUE_MAX_LENGTH = 10_000;

/**
 * `delivery-limit: -1` disables the quorum-queue delivery limit. RabbitMQ 4.x applies a default
 * limit of 20 when a policy sets none, and a message over it is dropped when the queue has no
 * dead-letter target. Queues that are not consumed by a stage (dead-letter, delay, dormant) are
 * only ever read with `basic.get` + `nack(requeue)` (dead-letter replay scans, operator
 * inspection), and every such return counts as a delivery (§13.6), so without this a dead
 * letter would silently disappear after about 20 replay scans (review finding, round 1).
 */
export const UNLIMITED_DELIVERIES = -1;

/**
 * Policy kinds: one per queue role, plus `work-lossy` (v5, step 4.3 U2) for a work queue that is a
 * bounded lossy buffer by design (`scan.url.inspect`: the browser worker is an optional
 * deployable, a dropped request is expired by the sweeper, and the outbox relay must never be
 * blocked by `reject-publish` on it; v8 `scan.sandbox`: the same for the sandbox-controller).
 */
export type PolicyKind = QueueRole | 'work-lossy';

/** The policy kind of a queue definition. */
export const policyKindOf = (queue: Pick<QueueDefinition, 'role' | 'lossy'>): PolicyKind =>
  queue.role === 'work' && queue.lossy === true ? 'work-lossy' : queue.role;

/** The Q4 policy definition of a queue of policy kind `kind`. */
export function policyFor(kind: PolicyKind, queue: string): Record<string, string | number> {
  switch (kind) {
    case 'work':
      return {
        'delivery-limit': 20,
        'dead-letter-exchange': 'email.events',
        'dead-letter-routing-key': `dead-letter.${queue}`,
        'dead-letter-strategy': 'at-least-once',
        overflow: 'reject-publish',
        'max-length': WORK_QUEUE_MAX_LENGTH,
      };
    case 'work-lossy':
      // Dead-lettered like a work queue (delivery limit, consumer dead letters). RabbitMQ
      // supports at-least-once dead-lettering of quorum queues only with overflow reject-publish
      // (with drop-head it falls back to at-most-once), so the strategy is stated as what the
      // broker does: at-most-once. Heads dropped at max-length are dead-lettered (reason maxlen)
      // at most once to email.dead-letter (itself bounded, reject-publish).
      return {
        'delivery-limit': 20,
        'dead-letter-exchange': 'email.events',
        'dead-letter-routing-key': `dead-letter.${queue}`,
        'dead-letter-strategy': 'at-most-once',
        overflow: 'drop-head',
        'max-length': LOSSY_WORK_QUEUE_MAX_LENGTH,
      };
    case 'dormant':
      return {
        'delivery-limit': UNLIMITED_DELIVERIES,
        'max-length': DORMANT_QUEUE_MAX_LENGTH,
        overflow: 'drop-head',
      };
    case 'delay':
      return {
        'delivery-limit': UNLIMITED_DELIVERIES,
        'dead-letter-exchange': 'email.delivery',
        'dead-letter-routing-key': DELAY_EXPIRED_ROUTING_KEY,
        'dead-letter-strategy': 'at-least-once',
        overflow: 'reject-publish',
        'max-length': WORK_QUEUE_MAX_LENGTH,
      };
    case 'dead-letter':
      return {
        'delivery-limit': UNLIMITED_DELIVERIES,
        overflow: 'reject-publish',
        'max-length': WORK_QUEUE_MAX_LENGTH,
      };
  }
}

// ---------------------------------------------------------------------------------------------
// Retry policies (Q8)
// ---------------------------------------------------------------------------------------------

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;

const DORMANT_RETRY: RetryPolicy = {
  strategy: 'hold',
  maxAttempts: 5,
  baseDelayMs: SECOND,
  maxDelayMs: MINUTE,
  maxRetryAgeMs: 24 * HOUR,
};

/** Bound violations of a retry policy (also used to validate per-service overrides). */
export function retryPolicyViolations(policy: RetryPolicy): string[] {
  const violations: string[] = [];
  const positiveInt = (value: number) => Number.isSafeInteger(value) && value > 0;
  if (!positiveInt(policy.maxAttempts)) violations.push('maxAttempts must be a positive integer');
  if (!positiveInt(policy.baseDelayMs)) violations.push('baseDelayMs must be a positive integer');
  if (!positiveInt(policy.maxDelayMs)) violations.push('maxDelayMs must be a positive integer');
  if (!positiveInt(policy.maxRetryAgeMs)) {
    violations.push('maxRetryAgeMs must be a positive integer');
  }
  if (policy.baseDelayMs > policy.maxDelayMs) violations.push('baseDelayMs exceeds maxDelayMs');
  if (policy.strategy === 'hold') {
    if (policy.maxDelayMs > HOLD_MAX_DELAY_MS) {
      violations.push(`hold maxDelayMs exceeds ${HOLD_MAX_DELAY_MS}`);
    }
    if (policy.delayQueue !== undefined) violations.push('hold has no delayQueue');
  } else if (policy.delayQueue === undefined) {
    violations.push('delay-queue requires delayQueue');
  }
  return violations;
}

// ---------------------------------------------------------------------------------------------
// TOPOLOGY
// ---------------------------------------------------------------------------------------------

const eventBinding = (exchange: ExchangeName, eventType: string): Binding => ({
  exchange,
  routingKey: `org.*.${eventType}`,
});

/**
 * The retry binding key of `queue`: `retry.<queue>.#`, or the qualified `retry.<queue>.org.#`
 * when `queue` is a dot-prefix of another queue name (v5: `scan.url` of `scan.url.inspect` and
 * `scan.url.results`), so that it never matches the other queue's retry hops. Retry keys are
 * always `retry.<queue>.org.<organizationId>.<eventType>` (`retryRoutingKey`).
 */
export function retryBindingKey(
  queue: string,
  queueNames: readonly string[] = QUEUE_NAMES,
): string {
  const prefixOfAnother = queueNames.some((other) => other.startsWith(`${queue}.`));
  return prefixOfAnother ? `retry.${queue}.org.#` : `retry.${queue}.#`;
}

const retryBinding = (exchange: ExchangeName, queue: QueueName): Binding => ({
  exchange,
  routingKey: retryBindingKey(queue),
});

function dormant(
  name: QueueName,
  homeExchange: ExchangeName,
  eventBindings: Binding[],
  plannedStep: string,
  plannedService: string,
  description: string,
): QueueDefinition {
  return {
    name,
    role: 'dormant',
    homeExchange,
    bindings: [...eventBindings, retryBinding(homeExchange, name)],
    consumer: { kind: 'planned', plannedStep, plannedService },
    retry: { ...DORMANT_RETRY },
    policy: policyFor('dormant', name),
    description,
  };
}

const parsed = (): Binding => eventBinding('email.ingestion', 'mail.message.parsed.v1');
/** Topology v2 (step 3.3 L7): an administrative rescan reaches every scan stage. */
const rescan = (): Binding => eventBinding('email.security', 'mail.message.rescan_requested.v1');

/** Reason of the reserved `scan.auth` queue (v3, step 4.1 S2). */
export const SCAN_AUTH_RESERVED_REASON =
  'reserved: authentication results come from the rspamd engine on scan.spam (step 4.1, ADR-0026)';

export const TOPOLOGY: Topology = {
  version: TOPOLOGY_VERSION,
  exchanges: EXCHANGE_NAMES,
  exchangeBindings: (
    [
      'email.ingestion',
      'email.security',
      'email.policy',
      'email.delivery',
      'email.archive',
    ] as const
  ).map((source) => ({ source, destination: 'email.events', routingKey: 'org.#' })),
  queues: [
    {
      name: 'email.received',
      role: 'work',
      homeExchange: 'email.ingestion',
      bindings: [
        eventBinding('email.ingestion', 'mail.message.received.v1'),
        retryBinding('email.ingestion', 'email.received'),
      ],
      consumer: { kind: 'ledger', ledgerName: 'email-worker.mime-parser', service: 'email-worker' },
      retry: {
        strategy: 'hold',
        maxAttempts: 8,
        baseDelayMs: SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'email.received'),
      description: 'Received messages awaiting MIME ingestion',
    },
    {
      // v3 (step 4.1 S2): no event bindings; the queue stays (fourteen queues) so a future
      // first-party authentication engine can bind it. Only the retry binding is kept, for
      // uniformity with the other scan queues.
      name: 'scan.auth',
      role: 'dormant',
      homeExchange: 'email.security',
      bindings: [retryBinding('email.security', 'scan.auth')],
      consumer: { kind: 'none', reason: SCAN_AUTH_RESERVED_REASON },
      retry: { ...DORMANT_RETRY },
      policy: policyFor('dormant', 'scan.auth'),
      description: 'Reserved for a first-party authentication engine (SPF/DKIM/DMARC/ARC)',
    },
    {
      // v3 (step 4.1 S2): the Rspamd engine of the email-worker scan role.
      name: 'scan.spam',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [parsed(), rescan(), retryBinding('email.security', 'scan.spam')],
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.rspamd',
        service: 'email-worker',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.spam'),
      description: 'Rspamd: spam, phishing, reputation and SPF/DKIM/DMARC/ARC (step 4.1)',
    },
    {
      // v5 (step 4.3 U1, U2): the URL engine of the email-worker scan role.
      name: 'scan.url',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [parsed(), rescan(), retryBinding('email.security', 'scan.url')],
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.url', service: 'email-worker' },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.url'),
      description:
        'URLs: extraction, normalization, reputation, lookalikes, redirect chains, rewriting (step 4.3)',
    },
    {
      // v5 (step 4.3 U2, U15): inspection requests for the isolated browser worker. A bounded
      // lossy buffer by design (work-lossy): the browser worker is optional, a dropped request is
      // expired by the email-worker's sweeper.
      name: 'scan.url.inspect',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [
        eventBinding('email.security', 'mail.url.inspection_requested.v1'),
        retryBinding('email.security', 'scan.url.inspect'),
      ],
      consumer: {
        kind: 'stateless',
        service: 'url-browser-worker',
        reason: 'no database; results are deduplicated by inspectionId in scan.url.results',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 3,
        baseDelayMs: 5 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: HOUR,
      },
      lossy: true,
      policy: policyFor('work-lossy', 'scan.url.inspect'),
      description: 'Dynamic URL inspection requests for the isolated browser worker (step 4.3)',
    },
    {
      // v5 (step 4.3 U2, U15): inspection results, applied by the email-worker scan role.
      name: 'scan.url.results',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [
        eventBinding('email.security', 'mail.url.inspection_completed.v1'),
        retryBinding('email.security', 'scan.url.results'),
      ],
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.url.results',
        service: 'email-worker',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.url.results'),
      description: 'Dynamic URL inspection results of the browser worker (step 4.3)',
    },
    {
      // v4 (step 4.2 A2): the attachment engine of the email-worker scan role.
      name: 'scan.attachment',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [parsed(), rescan(), retryBinding('email.security', 'scan.attachment')],
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.attachment',
        service: 'email-worker',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.attachment'),
      description: 'Attachments: file type, known hashes, ClamAV, YARA, archive limits (step 4.2)',
    },
    {
      // v6 (step 4.4 B1, B3): the phishing/BEC engine of the email-worker scan role, a stage-2
      // engine triggered only by the stage-ready event of its dependencies (rspamd, url).
      name: 'scan.bec',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [
        eventBinding('email.security', 'mail.message.scan_stage_ready.v1'),
        retryBinding('email.security', 'scan.bec'),
      ],
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.bec', service: 'email-worker' },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.bec'),
      description: 'Phishing and BEC (step 4.4): stage 2, triggered when rspamd and url finalized',
    },
    {
      // v7 (step 4.5 D1, D2): the data loss prevention engine of the email-worker scan role, a
      // stage-1 engine (bindings unchanged from the dormant v1–v6 queue).
      name: 'scan.dlp',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [parsed(), rescan(), retryBinding('email.security', 'scan.dlp')],
      consumer: { kind: 'ledger', ledgerName: 'email-worker.scan.dlp', service: 'email-worker' },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.dlp'),
      description: 'Data loss prevention (step 4.5): stage 1',
    },
    {
      // v8 (step 4.6 X1, X7, X11): tasks for the isolated sandbox-controller (no database). A
      // bounded lossy buffer by design (work-lossy): the controller is optional, an undelivered
      // task's analysis expires at its deadline (verdict timeout, never clean). The v1–v7 binding
      // of mail.attachment.sandbox_requested.v1 moved to scan.sandbox.submissions.
      name: 'scan.sandbox',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [
        eventBinding('email.security', 'mail.sandbox.task_requested.v1'),
        retryBinding('email.security', 'scan.sandbox'),
      ],
      consumer: {
        kind: 'stateless',
        service: 'sandbox-controller',
        reason:
          'no database; results are deduplicated by analysis id, state and result MAC in scan.sandbox.results',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 3,
        baseDelayMs: 5 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: HOUR,
      },
      lossy: true,
      policy: policyFor('work-lossy', 'scan.sandbox'),
      description: 'Sandbox tasks for the isolated sandbox-controller (step 4.6)',
    },
    {
      // v8 (step 4.6 X13): the sandbox dispatcher of the email-worker (staging, dedup, tasks).
      name: 'scan.sandbox.submissions',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [
        eventBinding('email.security', 'mail.attachment.sandbox_requested.v1'),
        retryBinding('email.security', 'scan.sandbox.submissions'),
      ],
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.sandbox',
        service: 'email-worker',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.sandbox.submissions'),
      description:
        'Sandbox submissions of the attachment engine, dispatched by the email-worker (step 4.6)',
    },
    {
      // v8 (step 4.6 X13): sandbox task results, applied by the email-worker (token-checked).
      name: 'scan.sandbox.results',
      role: 'work',
      homeExchange: 'email.security',
      bindings: [
        eventBinding('email.security', 'mail.sandbox.task_completed.v1'),
        retryBinding('email.security', 'scan.sandbox.results'),
      ],
      consumer: {
        kind: 'ledger',
        ledgerName: 'email-worker.scan.sandbox.results',
        service: 'email-worker',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'scan.sandbox.results'),
      description: 'Sandbox task results of the sandbox-controller (step 4.6)',
    },
    {
      // v9 (step 5.2 P13, ADR-0044): the policy-engine; bindings unchanged from the dormant
      // v1–v8 queue. A work queue (reject-publish, never lossy): mail is held until evaluated.
      name: 'email.policy.evaluate',
      role: 'work',
      homeExchange: 'email.policy',
      bindings: [
        eventBinding('email.security', 'mail.message.scanned.v1'),
        eventBinding('email.ingestion', 'mail.message.parse_failed.v1'),
        retryBinding('email.policy', 'email.policy.evaluate'),
      ],
      consumer: {
        kind: 'ledger',
        ledgerName: 'policy-engine.evaluate',
        service: 'policy-engine',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 2 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'email.policy.evaluate'),
      description:
        'Policy evaluation of scanned, scan-failed and parse-failed messages (step 5.2): the delivery gate',
    },
    {
      name: 'email.delivery.pending',
      role: 'work',
      homeExchange: 'email.delivery',
      bindings: [
        eventBinding('email.delivery', 'mail.delivery.approved.v1'),
        retryBinding('email.delivery', 'email.delivery.pending'),
      ],
      consumer: {
        kind: 'ledger',
        ledgerName: 'delivery-worker.planner',
        service: 'delivery-worker',
      },
      retry: {
        strategy: 'delay-queue',
        maxAttempts: 10,
        baseDelayMs: 5 * SECOND,
        maxDelayMs: 15 * MINUTE,
        maxRetryAgeMs: 48 * HOUR,
        delayQueue: 'email.delivery.retry',
      },
      policy: policyFor('work', 'email.delivery.pending'),
      description: 'Approved deliveries awaiting planning and reinjection',
    },
    {
      name: 'email.delivery.retry',
      role: 'delay',
      homeExchange: 'email.delivery',
      bindings: [{ exchange: 'email.delivery', routingKey: 'delay.email.delivery.pending.#' }],
      consumer: {
        kind: 'none',
        reason: 'delay queue: expired messages return to email.delivery.pending',
      },
      policy: policyFor('delay', 'email.delivery.retry'),
      description: 'Per-message TTL delay of delivery retries',
    },
    dormant(
      'email.quarantine',
      'email.policy',
      [eventBinding('email.policy', 'mail.policy.decided.v1')],
      '5.3',
      'quarantine',
      'Quarantine of messages whose policy action is quarantine',
    ),
    // v9 (step 5.2 P15): binds the archive request of a policy ARCHIVE action instead of
    // mail.policy.decided.v1 (still dormant: the consumer is step 8.1).
    dormant(
      'email.archive',
      'email.archive',
      [eventBinding('email.archive', 'mail.message.archive_requested.v1')],
      '8.1',
      'archive-worker',
      'Archive requests of policy ARCHIVE actions (consumer: step 8.1)',
    ),
    {
      // v9 (step 5.2 P15, P25): policy ALERT notifications and sender non-delivery notices, sent
      // by the notification-worker (at least once).
      name: 'email.notifications',
      role: 'work',
      homeExchange: 'email.policy',
      bindings: [
        eventBinding('email.policy', 'mail.policy.notification_requested.v1'),
        retryBinding('email.policy', 'email.notifications'),
      ],
      consumer: {
        kind: 'ledger',
        ledgerName: 'notification-worker.policy',
        service: 'notification-worker',
      },
      retry: {
        strategy: 'hold',
        maxAttempts: 8,
        baseDelayMs: 5 * SECOND,
        maxDelayMs: MINUTE,
        maxRetryAgeMs: 24 * HOUR,
      },
      policy: policyFor('work', 'email.notifications'),
      description: 'Policy alert and sender non-delivery notifications (step 5.2)',
    },
    dormant(
      'email.analytics',
      'email.events',
      [{ exchange: 'email.events', routingKey: 'org.#' }],
      'not scheduled (ADR-0009)',
      'ClickHouse ingestion',
      'The firehose of every event for analytics',
    ),
    {
      name: 'email.dead-letter',
      role: 'dead-letter',
      homeExchange: 'email.events',
      bindings: [{ exchange: 'email.events', routingKey: 'dead-letter.#' }],
      consumer: { kind: 'none', reason: 'operators replay through the api (Q9)' },
      policy: policyFor('dead-letter', 'email.dead-letter'),
      description: 'Dead letters of every queue',
    },
  ],
};

// ---------------------------------------------------------------------------------------------
// Lookups and routing keys (Q2)
// ---------------------------------------------------------------------------------------------

export function isQueueName(name: string): name is QueueName {
  return (QUEUE_NAMES as readonly string[]).includes(name);
}

export function isExchangeName(name: string): name is ExchangeName {
  return (EXCHANGE_NAMES as readonly string[]).includes(name);
}

/** The definition of `name` in `TOPOLOGY`. Throws for an unknown queue. */
export function queueDefinition(name: string): QueueDefinition {
  const queue = TOPOLOGY.queues.find((q) => q.name === name);
  if (!queue) throw new Error('Unknown queue');
  return queue;
}

function organizationIdString(organizationId: string | number | bigint): string {
  const value = String(organizationId);
  if (!DECIMAL_ID.test(value)) throw new Error('Organization id must be a positive decimal id');
  return value;
}

function checkedEventType(eventType: string): string {
  schemaVersionOf(eventType);
  return eventType;
}

function checkedQueue(queue: string): QueueName {
  if (!isQueueName(queue)) throw new Error('Unknown queue');
  return queue;
}

/** `org.<organizationId>.<eventType>`. */
export function eventRoutingKey(
  organizationId: string | number | bigint,
  eventType: string,
): string {
  return `org.${organizationIdString(organizationId)}.${checkedEventType(eventType)}`;
}

/** `retry.<queue>.org.<organizationId>.<eventType>` (on the queue's home exchange). */
export function retryRoutingKey(
  queue: QueueName,
  organizationId: string | number | bigint,
  eventType: string,
): string {
  return `retry.${checkedQueue(queue)}.${eventRoutingKey(organizationId, eventType)}`;
}

/** `delay.<queue>.org.<organizationId>.<eventType>` (into the queue's delay queue). */
export function delayRoutingKey(
  queue: QueueName,
  organizationId: string | number | bigint,
  eventType: string,
): string {
  return `delay.${checkedQueue(queue)}.${eventRoutingKey(organizationId, eventType)}`;
}

/**
 * `dead-letter.<queue>.org.<organizationId>.<eventType>` (consumer-published) or
 * `dead-letter.<queue>` (broker-published through the policy) on `email.events`.
 */
export function deadLetterRoutingKey(
  queue: QueueName,
  organizationId?: string | number | bigint,
  eventType?: string,
): string {
  const base = `dead-letter.${checkedQueue(queue)}`;
  if (organizationId === undefined && eventType === undefined) return base;
  if (organizationId === undefined || eventType === undefined) {
    throw new Error('Dead-letter keys carry both organization and event type, or neither');
  }
  return `${base}.${eventRoutingKey(organizationId, eventType)}`;
}

export type RoutingKeyKind = 'event' | 'retry' | 'delay' | 'dead-letter';

export interface ParsedRoutingKey {
  kind: RoutingKeyKind;
  queue?: QueueName;
  organizationId?: string;
  eventType?: string;
}

function parseOrgPart(rest: string): { organizationId: string; eventType: string } | null {
  const match = ORG_KEY.exec(rest);
  if (!match?.[1] || !match[2]) return null;
  try {
    schemaVersionOf(match[2]);
  } catch {
    return null;
  }
  return { organizationId: match[1], eventType: match[2] };
}

/** Queue names sorted longest first, so a dotted name is matched as a whole. */
const QUEUES_LONGEST_FIRST = [...QUEUE_NAMES].sort((a, b) => b.length - a.length);

/**
 * Parses any routing key of the topology; `null` for keys this topology never produces. Queue
 * names contain dots, so the queue is the longest queue name that matches whole words.
 */
export function parseRoutingKey(key: string): ParsedRoutingKey | null {
  if (key.startsWith('org.')) {
    const org = parseOrgPart(key);
    return org ? { kind: 'event', ...org } : null;
  }
  const prefix = (['retry', 'delay', 'dead-letter'] as const).find((p) => key.startsWith(`${p}.`));
  if (!prefix) return null;
  const remainder = key.slice(prefix.length + 1);
  const queue = QUEUES_LONGEST_FIRST.find((q) => remainder === q || remainder.startsWith(`${q}.`));
  if (!queue) return null;
  const rest = remainder.slice(queue.length + 1);
  if (rest === '') {
    return prefix === 'dead-letter' ? { kind: prefix, queue } : null;
  }
  if (prefix === 'retry' && rest === 'expired') return { kind: 'retry', queue };
  const org = parseOrgPart(rest);
  return org ? { kind: prefix, queue, ...org } : null;
}

// ---------------------------------------------------------------------------------------------
// Routing simulation (AMQP topic semantics)
// ---------------------------------------------------------------------------------------------

/** AMQP topic match: `*` = exactly one word, `#` = zero or more words. */
export function topicMatches(pattern: string, routingKey: string): boolean {
  const p = pattern.split('.');
  const k = routingKey === '' ? [] : routingKey.split('.');
  const memo = new Map<string, boolean>();
  const match = (i: number, j: number): boolean => {
    const id = `${i}:${j}`;
    const cached = memo.get(id);
    if (cached !== undefined) return cached;
    let result: boolean;
    if (i === p.length) result = j === k.length;
    else if (p[i] === '#') result = match(i + 1, j) || (j < k.length && match(i, j + 1));
    else result = j < k.length && (p[i] === '*' || p[i] === k[j]) && match(i + 1, j + 1);
    memo.set(id, result);
    return result;
  };
  return match(0, 0);
}

/**
 * The queues a message published to `exchange` with `routingKey` reaches, following
 * exchange-to-exchange bindings (each queue at most once, as the broker delivers it).
 */
export function routeMessage(
  exchange: string,
  routingKey: string,
  topology: Topology = TOPOLOGY,
): string[] {
  const queues = new Set<string>();
  const visited = new Set<string>();
  const visit = (current: string) => {
    if (visited.has(current)) return;
    visited.add(current);
    for (const queue of topology.queues) {
      if (
        queue.bindings.some((b) => b.exchange === current && topicMatches(b.routingKey, routingKey))
      ) {
        queues.add(queue.name);
      }
    }
    for (const binding of topology.exchangeBindings) {
      if (binding.source === current && topicMatches(binding.routingKey, routingKey)) {
        visit(binding.destination);
      }
    }
  };
  visit(exchange);
  return [...queues].sort();
}

const SAMPLE_ORGANIZATION_ID = '42';

/** The exchange an event type is published to: registered or reserved. */
function exchangeOfEventType(type: string): ExchangeName | undefined {
  if (isRegisteredEventType(type)) return EVENT_REGISTRY[type].exchange;
  if (isReservedEventType(type)) return RESERVED_EVENT_TYPES[type]?.exchange;
  return undefined;
}

const ALL_EVENT_TYPES: readonly string[] = [
  ...Object.keys(EVENT_REGISTRY),
  ...Object.keys(RESERVED_EVENT_TYPES),
];

/**
 * Registered and reserved event types whose event key reaches `queue`, directly or through the
 * `org.#` firehose of `email.events`. Sorted.
 */
export function eventTypesBoundTo(queue: string, topology: Topology = TOPOLOGY): string[] {
  return ALL_EVENT_TYPES.filter((type) => {
    const exchange = exchangeOfEventType(type);
    return (
      exchange !== undefined &&
      routeMessage(exchange, `org.${SAMPLE_ORGANIZATION_ID}.${type}`, topology).includes(queue)
    );
  }).sort();
}

// ---------------------------------------------------------------------------------------------
// Invariants (§3)
// ---------------------------------------------------------------------------------------------

function sameMembers(actual: readonly string[], expected: readonly string[]): boolean {
  return (
    actual.length === expected.length &&
    new Set(actual).size === actual.length &&
    expected.every((name) => actual.includes(name))
  );
}

/** Violations of the §3 topology invariants; empty for a valid topology. */
export function validateTopology(topology: Topology): string[] {
  const violations: string[] = [];
  const add = (message: string) => violations.push(message);
  const exchanges = new Set<string>(topology.exchanges);
  const queueNames = topology.queues.map((q) => q.name);

  if (topology.version !== TOPOLOGY_VERSION) add(`version must be ${TOPOLOGY_VERSION}`);
  if (!sameMembers(topology.exchanges, EXCHANGE_NAMES)) {
    add(`exchanges must be exactly ${EXCHANGE_NAMES.join(', ')}`);
  }
  if (!sameMembers(queueNames, QUEUE_NAMES))
    add(`queues must be exactly ${QUEUE_NAMES.join(', ')}`);

  // A queue may be a dot-prefix of another (v5 scan.url / scan.url.inspect) only because its retry
  // binding is then the qualified retry.<queue>.org.# (retryBindingKey); the routing checks below
  // prove that every retry hop still reaches exactly its own queue.

  const expectedSources = EXCHANGE_NAMES.filter((name) => name !== 'email.events');
  for (const source of expectedSources) {
    const e2e = topology.exchangeBindings.filter((b) => b.source === source);
    if (
      e2e.length !== 1 ||
      e2e[0]?.destination !== 'email.events' ||
      e2e[0]?.routingKey !== 'org.#'
    ) {
      add(`exchange ${source} must be bound to email.events with org.# exactly once`);
    }
  }
  for (const binding of topology.exchangeBindings) {
    if (!exchanges.has(binding.source) || !exchanges.has(binding.destination)) {
      add(
        `exchange binding ${binding.source} -> ${binding.destination} uses an undeclared exchange`,
      );
    }
    if (binding.source === 'email.events')
      add('email.events must not be bound to another exchange');
  }

  for (const queue of topology.queues) {
    const q = queue.name;
    if (!exchanges.has(queue.homeExchange)) add(`${q}: home exchange is not declared`);

    for (const binding of queue.bindings) {
      if (!exchanges.has(binding.exchange)) add(`${q}: binding on undeclared exchange`);
      const key = binding.routingKey;
      if (key.startsWith('org.*.')) {
        const type = key.slice('org.*.'.length);
        const exchange = exchangeOfEventType(type);
        if (exchange === undefined) add(`${q}: binding for unknown event type ${type}`);
        else if (exchange !== binding.exchange) {
          add(`${q}: ${type} is published to ${exchange}, bound on ${binding.exchange}`);
        }
      } else if (key === 'org.#') {
        if (binding.exchange !== 'email.events') add(`${q}: org.# is allowed on email.events only`);
      } else if (key.startsWith('org.')) {
        add(`${q}: unsupported event binding ${key}`);
      } else if (key.startsWith('retry.')) {
        if (key !== retryBindingKey(q, queueNames)) {
          add(`${q}: retry binding ${key} is not ${retryBindingKey(q, queueNames)}`);
        }
      } else if (key.startsWith('delay.')) {
        if (queue.role !== 'delay') add(`${q}: only a delay queue binds delay keys`);
      } else if (key === 'dead-letter.#') {
        if (queue.role !== 'dead-letter' || binding.exchange !== 'email.events') {
          add(`${q}: only the dead-letter queue binds dead-letter.# (on email.events)`);
        }
      } else {
        add(`${q}: unsupported binding ${key}`);
      }
    }

    const retryBindings = queue.bindings.filter((b) => b.routingKey.startsWith('retry.'));
    if (queue.role === 'work' || queue.role === 'dormant') {
      if (
        retryBindings.length !== 1 ||
        retryBindings[0]?.exchange !== queue.homeExchange ||
        retryBindings[0]?.routingKey !== retryBindingKey(q, queueNames)
      ) {
        add(
          `${q}: needs exactly one retry binding ${retryBindingKey(q, queueNames)} on its home exchange`,
        );
      }
      const eventBound = queue.bindings.some((b) => b.routingKey.startsWith('org.'));
      if (queue.consumer.kind === 'none') {
        // A reserved dormant queue (v3 scan.auth) receives no event at all.
        if (queue.role !== 'dormant') add(`${q}: only a dormant queue can be reserved`);
        if (eventBound) add(`${q}: a reserved queue has no event binding`);
      } else if (!eventBound) {
        add(`${q}: has no event binding`);
      }
    } else if (retryBindings.length > 0) {
      add(`${q}: a ${queue.role} queue has no retry binding`);
    }

    if (queue.lossy !== undefined && queue.role !== 'work') {
      add(`${q}: only a work queue can be lossy`);
    }
    const policyKind = policyKindOf(queue);
    const expectedPolicy = policyFor(policyKind, q);
    if (JSON.stringify(queue.policy) !== JSON.stringify(expectedPolicy)) {
      add(`${q}: policy differs from the ${policyKind} policy`);
    }

    const consumerKinds: Record<QueueRole, readonly QueueConsumerInfo['kind'][]> = {
      // `stateless` (v5): a work queue consumer without a ledger (scan.url.inspect).
      work: ['ledger', 'stateless'],
      // `none`: reserved (no event binding, checked above).
      dormant: ['planned', 'none'],
      delay: ['none'],
      'dead-letter': ['none'],
    };
    if (!consumerKinds[queue.role].includes(queue.consumer.kind)) {
      add(
        `${q}: a ${queue.role} queue must have consumer kind ${consumerKinds[queue.role].join(' or ')}`,
      );
    }

    if (queue.role === 'work' || queue.role === 'dormant') {
      if (!queue.retry) add(`${q}: needs a retry policy`);
      else {
        for (const v of retryPolicyViolations(queue.retry)) add(`${q}: ${v}`);
        if (queue.retry.delayQueue !== undefined) {
          const delay = topology.queues.find((d) => d.name === queue.retry?.delayQueue);
          if (delay?.role !== 'delay') add(`${q}: delayQueue must be a queue of role delay`);
          else {
            const target = routeMessage(
              String(delay.policy['dead-letter-exchange']),
              String(delay.policy['dead-letter-routing-key']),
              topology,
            );
            if (target.length !== 1 || target[0] !== q) {
              add(`${q}: its delay queue must dead-letter to exactly ${q}`);
            }
            const delayKey = `delay.${q}.org.${SAMPLE_ORGANIZATION_ID}.mail.delivery.approved.v1`;
            const viaDelay = routeMessage(queue.homeExchange, delayKey, topology);
            if (viaDelay.length !== 1 || viaDelay[0] !== delay.name) {
              add(`${q}: delay hops must reach exactly ${delay.name}`);
            }
          }
        }
      }
    } else if (queue.retry) {
      add(`${q}: a ${queue.role} queue has no retry policy`);
    }

    if (queue.role === 'work') {
      const target = routeMessage(
        String(queue.policy['dead-letter-exchange']),
        String(queue.policy['dead-letter-routing-key']),
        topology,
      );
      if (target.length !== 1 || target[0] !== 'email.dead-letter') {
        add(`${q}: broker dead letters must reach exactly email.dead-letter`);
      }
    }

    // Internal hops: never in the firehose, never in another queue.
    for (const type of eventTypesBoundTo(q, topology)) {
      const org = `org.${SAMPLE_ORGANIZATION_ID}.${type}`;
      if (queue.role === 'work' || queue.role === 'dormant') {
        const retry = routeMessage(queue.homeExchange, `retry.${q}.${org}`, topology);
        if (retry.length !== 1 || retry[0] !== q) add(`${q}: retry hops must reach exactly ${q}`);
      }
      const deadLetter = routeMessage('email.events', `dead-letter.${q}.${org}`, topology);
      if (deadLetter.length !== 1 || deadLetter[0] !== 'email.dead-letter') {
        add(`${q}: dead-letter hops must reach exactly email.dead-letter`);
      }
    }
    const brokerDeadLetter = routeMessage('email.events', `dead-letter.${q}`, topology);
    if (brokerDeadLetter.length !== 1 || brokerDeadLetter[0] !== 'email.dead-letter') {
      add(`${q}: dead-letter.${q} must reach exactly email.dead-letter`);
    }
  }

  for (const type of Object.keys(EVENT_REGISTRY)) {
    const exchange = exchangeOfEventType(type);
    if (
      exchange &&
      routeMessage(exchange, `org.${SAMPLE_ORGANIZATION_ID}.${type}`, topology).length === 0
    ) {
      add(`event type ${type} reaches no queue`);
    }
  }

  return violations;
}
