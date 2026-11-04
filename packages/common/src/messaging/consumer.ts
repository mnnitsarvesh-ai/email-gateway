import { performance } from 'node:perf_hooks';
import {
  deadLetterRoutingKey,
  delayRoutingKey,
  eventDefinition,
  eventTypesBoundTo,
  HOLD_MAX_DELAY_MS,
  parseRoutingKey,
  type QueueName,
  queueDefinition,
  type RetryPolicy,
  retryPolicyViolations,
  retryRoutingKey,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { Channel, ChannelModel, ConsumeMessage } from 'amqplib';
import type { EventFeed, EventHandler } from '../outbox/event-feed';
import type { PayloadSchema } from '../outbox/outbox-poller';
import { type BackoffPolicy, backoffDelay, sleep } from './backoff';
import { decodeDelivery, retryState } from './codec';
import type { AmqpConnection } from './connection';
import {
  amqpReplyName,
  defaultClassify,
  errorFields,
  FAILURE_CODE,
  type FailureClass,
  NonRetryableError,
} from './errors';
import { BROKER_HEADERS, HEADERS, RETRY_AND_FAILURE_HEADERS, stringHeader } from './headers';
import type { MessagingMetrics } from './metrics';
import { type ConfirmPublisher, PublishFailedError } from './publisher';

/**
 * Where a consumer left an event it did not handle (step 3.2 review round 1): `retrying` after a
 * confirmed retry hop (the copy waits in the queue or its delay queue), `dead_lettered` after a
 * confirmed dead-letter copy (or a rejection to the broker's dead-letter target). The outbox
 * reconciler reads it, so an event that is still retrying, or was dead-lettered on purpose, is
 * never re-driven as if it had been lost. Codes and counters only.
 */
export interface ConsumerProgressEntry {
  /** The ledger name (`QueueConsumerOptions.consumer`). */
  consumer: string;
  eventId: string;
  state: 'retrying' | 'dead_lettered';
  /** The dead-letter reason code (`dead_lettered` only). */
  reason?: string;
  attempt: number;
  transientRetries: number;
}

/** Durable store of `ConsumerProgressEntry` (`PrismaConsumerProgress`, table `message_consumer_progress`). */
export interface ConsumerProgressRecorder {
  record(entry: ConsumerProgressEntry): Promise<void>;
}

/** Longest wait for a progress write before the delivery is acked anyway. */
export const PROGRESS_TIMEOUT_MS = 5_000;

// `T` (the accepted payload type) ties the options to `QueueConsumer<T>` (design Q6 API).
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export interface QueueConsumerOptions<T> {
  connection: AmqpConnection;
  /** For retry and dead-letter copies. */
  publisher: ConfirmPublisher;
  /** A work (or, in tests, dormant) queue of TOPOLOGY. */
  queue: QueueName;
  /** Ledger name; for logs, metrics and `x-eg-dead-lettered-by`. */
  consumer: string;
  /** Accepted event types, ⊆ the types bound to the queue (checked at construction). */
  eventTypes: string[];
  /** = max concurrent handlers (1..1000). */
  prefetch: number;
  /** Overrides of the topology's retry policy (validated). */
  retry?: Partial<RetryPolicy>;
  /** Default `defaultClassify`. `NonRetryableError` is always fatal. */
  classify?: (error: unknown) => FailureClass;
  logger: Logger;
  metrics?: MessagingMetrics;
  now?: () => Date;
  random?: () => number;
  /** Longest wait for in-flight handlers on `stop()` (default 30 000 ms). */
  stopTimeoutMs?: number;
  /** Backoff before re-subscribing after the channel closed (default 1 000 / 30 000 ms). */
  resubscribe?: BackoffPolicy;
  /**
   * Records retry and dead-letter hops for the outbox reconciler (required for a queue the
   * reconciler tracks). Written after the copy was confirmed and before the original is acked;
   * a failed or slow write (over `PROGRESS_TIMEOUT_MS`) is logged and the ack goes ahead (the
   * reconciler may then re-drive the event once: a bounded duplicate that every ledger absorbs).
   */
  progress?: ConsumerProgressRecorder;
}

interface Subscription {
  model: ChannelModel;
  channel: Channel;
  consumerTag?: string;
  closed: boolean;
  closeReason: string;
  /** Aborted when the channel closes: held deliveries stop waiting. */
  abort: AbortController;
}

type HoldResult = 'elapsed' | 'stopped' | 'closed';

/** What a retry or dead-letter hop writes into the copy's headers. */
interface FailureState {
  /** The event id (decoded envelope, or a well-formed AMQP `messageId`); for progress records. */
  eventId?: string;
  attempt: number;
  transientRetries: number;
  firstFailedAt?: Date;
  lastErrorClass?: string;
  organizationId?: string;
  eventType?: string;
}

const CONSUMER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOG_TOKEN = /^[A-Za-z0-9_.:-]{1,128}$/;
const EVENT_TYPE = /^[a-z]+(\.[a-z_]+)+\.v[1-9][0-9]{0,5}$/;
const RETRY_KEYS: readonly (keyof RetryPolicy)[] = [
  'strategy',
  'maxAttempts',
  'baseDelayMs',
  'maxDelayMs',
  'maxRetryAgeMs',
  'delayQueue',
];

/** The topology's retry policy of `queue` merged with validated overrides. */
export function resolveRetryPolicy(
  queue: QueueName,
  overrides?: Partial<RetryPolicy>,
): RetryPolicy {
  const base = queueDefinition(queue).retry;
  if (!base) throw new Error(`queue ${queue} has no retry policy`);
  const merged: RetryPolicy = { ...base };
  for (const [key, value] of Object.entries(overrides ?? {})) {
    if (!(RETRY_KEYS as readonly string[]).includes(key)) {
      throw new Error(`unknown retry option ${key}`);
    }
    if (value !== undefined) (merged as unknown as Record<string, unknown>)[key] = value;
  }
  if (merged.strategy === 'hold') delete merged.delayQueue;
  const violations = retryPolicyViolations(merged);
  if (merged.delayQueue !== undefined) {
    const delay = queueDefinition(merged.delayQueue);
    if (delay.role !== 'delay') violations.push('delayQueue must be a queue of role delay');
    else if (!delay.bindings.some((b) => b.routingKey === `delay.${queue}.#`)) {
      violations.push(`delayQueue ${delay.name} does not carry delay hops of ${queue}`);
    }
  }
  if (violations.length > 0) {
    throw new Error(`invalid retry policy for ${queue}: ${violations.join('; ')}`);
  }
  return merged;
}

/**
 * A RabbitMQ consumer of one queue behind `EventFeed` (step 3.2 Q6, Q8): one channel, manual
 * acks, `prefetch` = max deliveries in flight (held retries keep their slot = backpressure).
 * Subscribes on every (re)connect; re-subscribes with backoff when its channel closes.
 *
 * Per delivery: `decodeDelivery` (type accepted, schema version, envelope + payload schema,
 * tenant agreement) → on failure dead-letter at once; else the handler runs with a logger child
 * `{ queue, eventId, eventType, organizationId, correlationId }`; `handled` / `duplicate` → ack;
 * a throw → classify:
 *
 * - **fatal** (`NonRetryableError`) → dead-letter, reason = its code;
 * - **transient** → `x-eg-transient-retries + 1`, attempts unchanged; dead-letter
 *   `retry_age_exceeded` once older than `maxRetryAgeMs` since `x-eg-first-failed-at`;
 * - **retryable** → `x-eg-attempt + 1`; dead-letter `max_attempts_exceeded` at `maxAttempts`.
 *
 * Retry hops: `hold` waits the backoff while holding the delivery, then republishes a copy with
 * `retry.<queue>.org.<id>.<type>` to the home exchange; `delay-queue` republishes with
 * `delay.<queue>.…` and `expiration` to the delay queue's exchange. Dead letters go to
 * `email.events` with `dead-letter.<queue>.org.<id>.<type>` and the Q2 failure headers. The
 * original is acked only after its copy was confirmed; otherwise it is nacked with requeue
 * after the delay. A result arriving after its channel died is dropped (the broker redelivers).
 */
export class QueueConsumer<T> implements EventFeed<T> {
  readonly queue: QueueName;
  readonly consumerName: string;
  readonly retryPolicy: RetryPolicy;
  private readonly accepted = new Map<string, PayloadSchema<T>>();
  private readonly homeExchange: string;
  private readonly delayExchange: string | undefined;
  private readonly logger: Logger;
  private readonly classify: (error: unknown) => FailureClass;
  private readonly now: () => Date;
  private readonly random: () => number;
  private readonly stopTimeoutMs: number;
  private readonly resubscribePolicy: BackoffPolicy;
  private readonly inFlight = new Set<Promise<void>>();
  private readonly stopAbort = new AbortController();
  private handler: EventHandler<T> | undefined;
  private unregister: (() => void) | undefined;
  private model: ChannelModel | undefined;
  private subscription: Subscription | undefined;
  private subscribeFailures = 0;
  private stopping: Promise<void> | undefined;

  constructor(private readonly options: QueueConsumerOptions<T>) {
    const definition = queueDefinition(options.queue);
    if (definition.role !== 'work' && definition.role !== 'dormant') {
      throw new Error(
        `QueueConsumer needs a work or dormant queue, ${options.queue} is ${definition.role}`,
      );
    }
    if (!CONSUMER_NAME.test(options.consumer)) {
      throw new Error('QueueConsumer consumer must be a token of at most 64 characters');
    }
    if (
      !Number.isSafeInteger(options.prefetch) ||
      options.prefetch < 1 ||
      options.prefetch > 1000
    ) {
      throw new Error('QueueConsumer prefetch must be an integer in 1..1000');
    }
    if (options.eventTypes.length === 0)
      throw new Error('QueueConsumer needs at least one event type');
    const bound = eventTypesBoundTo(options.queue);
    for (const type of options.eventTypes) {
      if (!bound.includes(type)) {
        throw new Error(`event type ${type} is not bound to queue ${options.queue}`);
      }
      const registered = eventDefinition(type);
      if (!registered) throw new Error(`event type ${type} has no registered schema`);
      this.accepted.set(type, registered.schema as PayloadSchema<T>);
    }
    this.queue = options.queue;
    this.consumerName = options.consumer;
    this.retryPolicy = resolveRetryPolicy(options.queue, options.retry);
    this.homeExchange = definition.homeExchange;
    this.delayExchange =
      this.retryPolicy.delayQueue === undefined
        ? undefined
        : queueDefinition(this.retryPolicy.delayQueue).homeExchange;
    this.classify = options.classify ?? defaultClassify;
    this.now = options.now ?? (() => new Date());
    this.random = options.random ?? Math.random;
    this.stopTimeoutMs = options.stopTimeoutMs ?? 30_000;
    this.resubscribePolicy = options.resubscribe ?? { baseMs: 1_000, maxMs: 30_000 };
    this.logger = options.logger.child({
      component: 'queue-consumer',
      consumer: options.consumer,
    });
    options.metrics?.consumerActive(this.queue, false);
    options.metrics?.inFlight(this.queue, 0);
  }

  /** Subscribes on every (re)connect (manual ack) and hands each event to `handler`. */
  start(handler: EventHandler<T>): void {
    if (this.handler) throw new Error('QueueConsumer already started');
    if (this.stopping) throw new Error('QueueConsumer was stopped');
    this.handler = handler;
    const exchanges = [this.homeExchange, 'email.events'];
    if (this.delayExchange) exchanges.push(this.delayExchange);
    this.options.connection.requireTopology({ queues: [this.queue], exchanges });
    this.unregister = this.options.connection.onConnected((model) => this.setup(model));
  }

  /**
   * Cancels the subscription, releases held deliveries (nack with requeue), waits for running
   * handlers up to `stopTimeoutMs`, then closes the channel (the broker requeues the rest).
   */
  stop(): Promise<void> {
    this.stopping ??= this.doStop();
    return this.stopping;
  }

  // -------------------------------------------------------------------------------------------

  private async doStop(): Promise<void> {
    this.unregister?.();
    const sub = this.subscription;
    if (sub && !sub.closed && sub.consumerTag) {
      await sub.channel.cancel(sub.consumerTag).catch(() => undefined);
    }
    this.stopAbort.abort();
    if (this.inFlight.size > 0) {
      const settled = await Promise.race([
        Promise.allSettled([...this.inFlight]).then(() => true),
        sleep(this.stopTimeoutMs).then(() => false),
      ]);
      if (!settled) {
        this.logger.warn(
          { queue: this.queue, inFlight: this.inFlight.size },
          'QueueConsumer stop timed out; unfinished deliveries return to the queue',
        );
      }
    }
    if (sub && !sub.closed) await sub.channel.close().catch(() => undefined);
    this.subscription = undefined;
    this.options.metrics?.consumerActive(this.queue, false);
    this.logger.info({ queue: this.queue }, 'QueueConsumer stopped');
  }

  private isStopping(): boolean {
    return this.stopping !== undefined;
  }

  private async setup(model: ChannelModel): Promise<void> {
    this.model = model;
    this.subscribeFailures = 0;
    await this.subscribe(model);
  }

  private async subscribe(model: ChannelModel): Promise<void> {
    if (this.isStopping() || model !== this.model) return;
    let channel: Channel;
    try {
      channel = await model.createChannel();
    } catch (error) {
      this.logger.warn(
        { queue: this.queue, reply: amqpReplyName(error, 'channel_open_failed') },
        'QueueConsumer could not open a channel',
      );
      this.scheduleResubscribe(model);
      return;
    }
    const sub: Subscription = {
      model,
      channel,
      closed: false,
      closeReason: 'channel_closed',
      abort: new AbortController(),
    };
    channel.on('error', (error: unknown) => {
      sub.closeReason = amqpReplyName(error);
    });
    channel.on('close', () => this.onChannelClosed(sub));
    this.subscription = sub;
    try {
      await channel.prefetch(this.options.prefetch);
      await channel.checkQueue(this.queue);
      if (this.isStopping()) {
        await channel.close().catch(() => undefined);
        return;
      }
      const reply = await channel.consume(this.queue, (msg) => this.onDelivery(sub, msg), {
        noAck: false,
      });
      sub.consumerTag = reply.consumerTag;
      this.subscribeFailures = 0;
      this.options.metrics?.consumerActive(this.queue, true);
      this.logger.info(
        { queue: this.queue, prefetch: this.options.prefetch },
        'QueueConsumer subscribed',
      );
    } catch (error) {
      this.logger.warn(
        { queue: this.queue, reply: amqpReplyName(error, sub.closeReason), ...errorFields(error) },
        'QueueConsumer could not subscribe',
      );
      // A failed passive declare closes the channel already; its close handler re-subscribes.
      if (!sub.closed) await channel.close().catch(() => undefined);
    }
  }

  private onChannelClosed(sub: Subscription): void {
    if (sub.closed) return;
    sub.closed = true;
    sub.abort.abort();
    if (this.subscription === sub) {
      this.subscription = undefined;
      this.options.metrics?.consumerActive(this.queue, false);
    }
    if (this.isStopping()) return;
    this.logger.warn({ queue: this.queue, reply: sub.closeReason }, 'QueueConsumer channel closed');
    this.scheduleResubscribe(sub.model);
  }

  private scheduleResubscribe(model: ChannelModel): void {
    if (this.isStopping() || model !== this.model) return;
    this.subscribeFailures += 1;
    const delayMs = backoffDelay(this.subscribeFailures, this.resubscribePolicy, this.random);
    void sleep(delayMs, this.stopAbort.signal).then((elapsed) => {
      // A lost connection re-subscribes through onConnected with its new model instead.
      if (elapsed && model === this.model && this.options.connection.connected) {
        return this.subscribe(model);
      }
      return undefined;
    });
  }

  private onDelivery(sub: Subscription, msg: ConsumeMessage | null): void {
    if (msg === null) {
      // The broker cancelled the consumer (queue deleted or failed over): re-subscribe.
      this.logger.warn({ queue: this.queue }, 'QueueConsumer cancelled by the broker');
      sub.closeReason = 'consumer_cancelled';
      void sub.channel.close().catch(() => undefined);
      return;
    }
    this.options.metrics?.delivery(this.queue, msg.fields.redelivered);
    const handler = this.handler;
    if (this.isStopping() || !handler) {
      this.settle(sub, msg, 'nack-requeue');
      return;
    }
    const task: Promise<void> = this.process(sub, msg, handler)
      .catch((error: unknown) => {
        this.logger.error({ queue: this.queue, ...errorFields(error) }, 'QueueConsumer failure');
        this.settle(sub, msg, 'nack-requeue');
      })
      .finally(() => {
        this.inFlight.delete(task);
        this.options.metrics?.inFlight(this.queue, this.inFlight.size);
      });
    this.inFlight.add(task);
    this.options.metrics?.inFlight(this.queue, this.inFlight.size);
  }

  private async process(sub: Subscription, msg: ConsumeMessage, handler: EventHandler<T>) {
    const decoded = decodeDelivery(msg, this.accepted);
    if (!decoded.ok) {
      const log = this.logger.child(this.rawLogFields(msg));
      log.warn({ reason: decoded.reason, failureClass: 'fatal' }, 'Delivery rejected by the codec');
      await this.deadLetter(sub, msg, log, decoded.reason, 'fatal', {
        ...retryState(msg),
        ...this.rawTenant(msg),
        ...this.rawEventId(msg),
      });
      return;
    }
    const { event } = decoded;
    const log = this.logger.child({
      queue: this.queue,
      eventId: event.eventId,
      eventType: event.eventType,
      organizationId: event.organizationId,
      correlationId: event.correlationId,
    });
    const started = performance.now();
    let outcome: 'handled' | 'duplicate';
    try {
      outcome = await handler(event);
    } catch (error) {
      this.options.metrics?.handleSeconds(this.queue, (performance.now() - started) / 1000);
      await this.onFailure(sub, msg, log, decoded, error);
      return;
    }
    this.options.metrics?.handleSeconds(this.queue, (performance.now() - started) / 1000);
    if (sub.closed) {
      log.debug({ outcome }, 'Handler result after its channel closed; dropped (redelivered)');
      return;
    }
    if (this.settle(sub, msg, 'ack')) {
      this.options.metrics?.message(this.queue, outcome === 'duplicate' ? 'duplicate' : 'handled');
    }
  }

  private async onFailure(
    sub: Subscription,
    msg: ConsumeMessage,
    log: Logger,
    decoded: {
      attempt: number;
      transientRetries: number;
      firstFailedAt?: Date;
      event: { eventId: string; organizationId: string; eventType: string };
    },
    error: unknown,
  ): Promise<void> {
    const fields = errorFields(error);
    let failureClass: FailureClass;
    if (error instanceof NonRetryableError) failureClass = 'fatal';
    else {
      try {
        failureClass = this.classify(error);
      } catch {
        failureClass = 'retryable';
      }
    }
    const now = this.now();
    const state: FailureState = {
      eventId: decoded.event.eventId,
      attempt: decoded.attempt,
      transientRetries: decoded.transientRetries,
      firstFailedAt: decoded.firstFailedAt ?? now,
      lastErrorClass: fields.errCode ?? fields.errName ?? 'unknown',
      organizationId: decoded.event.organizationId,
      eventType: decoded.event.eventType,
    };
    const policy = this.retryPolicy;

    if (failureClass === 'fatal') {
      const reason =
        error instanceof NonRetryableError && FAILURE_CODE.test(error.code)
          ? error.code
          : 'handler_rejected';
      state.attempt += 1;
      log.warn(
        { failureClass, reason, attempt: state.attempt, ...fields },
        'Handler failed (fatal)',
      );
      await this.deadLetter(sub, msg, log, reason, failureClass, state);
      return;
    }

    if (failureClass === 'transient') {
      state.transientRetries += 1;
      const ageMs = now.getTime() - (state.firstFailedAt ?? now).getTime();
      if (ageMs > policy.maxRetryAgeMs) {
        log.warn(
          {
            failureClass,
            attempt: state.attempt,
            transientRetries: state.transientRetries,
            ...fields,
          },
          'Handler failed (transient) past the retry age; dead-lettering',
        );
        await this.deadLetter(sub, msg, log, 'retry_age_exceeded', failureClass, state);
        return;
      }
      const delayMs = backoffDelay(state.transientRetries, this.delayPolicy(), this.random);
      log.warn(
        {
          failureClass,
          attempt: state.attempt,
          transientRetries: state.transientRetries,
          delayMs,
          ...fields,
        },
        'Handler failed (transient); retrying',
      );
      await this.retryHop(sub, msg, log, state, delayMs, failureClass);
      return;
    }

    state.attempt += 1;
    if (state.attempt >= policy.maxAttempts) {
      log.warn(
        { failureClass, attempt: state.attempt, ...fields },
        'Handler failed (retryable) at the attempt limit; dead-lettering',
      );
      await this.deadLetter(sub, msg, log, 'max_attempts_exceeded', failureClass, state);
      return;
    }
    const delayMs = backoffDelay(state.attempt, this.delayPolicy(), this.random);
    log.warn(
      { failureClass, attempt: state.attempt, delayMs, ...fields },
      'Handler failed; retrying',
    );
    await this.retryHop(sub, msg, log, state, delayMs, failureClass);
  }

  private delayPolicy(): BackoffPolicy {
    return { baseMs: this.retryPolicy.baseDelayMs, maxMs: this.retryPolicy.maxDelayMs };
  }

  private async retryHop(
    sub: Subscription,
    msg: ConsumeMessage,
    log: Logger,
    state: FailureState,
    delayMs: number,
    failureClass: 'transient' | 'retryable',
  ): Promise<void> {
    const headers = this.hopHeaders(msg, state);
    const organizationId = state.organizationId ?? '';
    const eventType = state.eventType ?? '';
    if (this.retryPolicy.strategy === 'hold') {
      const held = await this.hold(sub, delayMs);
      if (held === 'closed') {
        log.debug('Channel closed while holding a retry; the broker redelivers it');
        return;
      }
      if (held === 'stopped') {
        if (this.settle(sub, msg, 'nack-requeue'))
          this.options.metrics?.message(this.queue, 'requeued');
        return;
      }
      try {
        await this.options.publisher.republish(msg, {
          exchange: this.homeExchange,
          routingKey: retryRoutingKey(this.queue, organizationId, eventType),
          headers,
        });
      } catch (error) {
        log.warn(
          { hop: 'retry', ...errorFields(error), ...publishFailure(error) },
          'Retry copy not confirmed; requeueing',
        );
        if (this.settle(sub, msg, 'nack-requeue'))
          this.options.metrics?.message(this.queue, 'requeued');
        return;
      }
    } else {
      try {
        await this.options.publisher.republish(msg, {
          exchange: this.delayExchange ?? this.homeExchange,
          routingKey: delayRoutingKey(this.queue, organizationId, eventType),
          headers,
          expirationMs: delayMs,
        });
      } catch (error) {
        log.warn(
          { hop: 'delay', ...errorFields(error), ...publishFailure(error) },
          'Delay copy not confirmed; requeueing after the delay',
        );
        await this.requeueAfter(sub, msg, Math.min(delayMs, HOLD_MAX_DELAY_MS));
        return;
      }
    }
    this.options.metrics?.retry(this.queue, failureClass);
    await this.recordProgress(log, state, 'retrying');
    if (this.settle(sub, msg, 'ack')) this.options.metrics?.message(this.queue, 'retried');
  }

  private async deadLetter(
    sub: Subscription,
    msg: ConsumeMessage,
    log: Logger,
    reason: string,
    failureClass: FailureClass,
    state: FailureState,
  ): Promise<void> {
    const headers = this.hopHeaders(msg, state);
    headers[HEADERS.sourceQueue] = this.queue;
    headers[HEADERS.failureReason] = reason;
    headers[HEADERS.failureClass] = failureClass;
    headers[HEADERS.attempts] = state.attempt;
    headers[HEADERS.deadLetteredAt] = this.now().toISOString();
    headers[HEADERS.deadLetteredBy] = this.consumerName;
    let routingKey: string;
    try {
      routingKey =
        state.organizationId !== undefined && state.eventType !== undefined
          ? deadLetterRoutingKey(this.queue, state.organizationId, state.eventType)
          : deadLetterRoutingKey(this.queue);
    } catch {
      routingKey = deadLetterRoutingKey(this.queue);
    }
    try {
      await this.options.publisher.republish(msg, {
        exchange: 'email.events',
        routingKey,
        headers,
      });
    } catch (error) {
      if (error instanceof PublishFailedError && error.outcome === 'refused') {
        // The delivery itself carries content the guard refuses to copy: reject it to the
        // broker's dead-letter target of the queue policy instead (work queues: email.events
        // dead-letter.<queue>; it is never republished by this library).
        log.error(
          { reason, guard: error.code },
          'Dead-letter copy refused by the content guard; rejecting to the broker',
        );
        await this.recordProgress(log, state, 'dead_lettered', reason);
        if (this.settle(sub, msg, 'reject')) {
          this.options.metrics?.message(this.queue, 'dead_lettered');
          this.options.metrics?.deadLettered(this.queue, reason);
        }
        return;
      }
      log.warn(
        { hop: 'dead-letter', reason, ...errorFields(error), ...publishFailure(error) },
        'Dead-letter copy not confirmed; requeueing after a delay',
      );
      await this.requeueAfter(sub, msg, backoffDelay(1, this.delayPolicy(), this.random));
      return;
    }
    await this.recordProgress(log, state, 'dead_lettered', reason);
    if (this.settle(sub, msg, 'ack')) {
      this.options.metrics?.message(this.queue, 'dead_lettered');
      this.options.metrics?.deadLettered(this.queue, reason);
    }
    log.warn({ reason, failureClass, attempt: state.attempt }, 'Delivery dead-lettered');
  }

  /**
   * Writes the progress record of a confirmed hop (never throws; bounded by
   * `PROGRESS_TIMEOUT_MS`). Without an event id (an undecodable delivery without a well-formed
   * `messageId`) there is nothing the reconciler could match, so nothing is written.
   */
  private async recordProgress(
    log: Logger,
    state: FailureState,
    progress: ConsumerProgressEntry['state'],
    reason?: string,
  ): Promise<void> {
    const recorder = this.options.progress;
    if (!recorder || state.eventId === undefined) return;
    const entry: ConsumerProgressEntry = {
      consumer: this.consumerName,
      eventId: state.eventId,
      state: progress,
      ...(reason !== undefined ? { reason } : {}),
      attempt: state.attempt,
      transientRetries: state.transientRetries,
    };
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        recorder.record(entry),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('consumer progress write timed out')),
            PROGRESS_TIMEOUT_MS,
          );
          timer.unref?.();
        }),
      ]);
    } catch (error) {
      log.warn(
        { progress, ...errorFields(error) },
        'Consumer progress not recorded; the reconciler may re-drive this event once',
      );
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Holds the delivery (its prefetch slot) for `delayMs`, then nacks it with requeue. */
  private async requeueAfter(
    sub: Subscription,
    msg: ConsumeMessage,
    delayMs: number,
  ): Promise<void> {
    const held = await this.hold(sub, delayMs);
    if (held === 'closed') return;
    if (this.settle(sub, msg, 'nack-requeue'))
      this.options.metrics?.message(this.queue, 'requeued');
  }

  private async hold(sub: Subscription, delayMs: number): Promise<HoldResult> {
    if (sub.closed) return 'closed';
    if (this.isStopping()) return 'stopped';
    const elapsed = await sleep(
      delayMs,
      AbortSignal.any([sub.abort.signal, this.stopAbort.signal]),
    );
    if (sub.closed) return 'closed';
    return elapsed ? 'elapsed' : 'stopped';
  }

  /** Acks / nacks on the delivery's own channel; false when that channel is gone. */
  private settle(
    sub: Subscription,
    msg: ConsumeMessage,
    action: 'ack' | 'nack-requeue' | 'reject',
  ): boolean {
    if (sub.closed) return false;
    try {
      if (action === 'ack') sub.channel.ack(msg);
      else sub.channel.nack(msg, false, action === 'nack-requeue');
      return true;
    } catch {
      return false;
    }
  }

  /** The copy's headers: the original's without broker and previous failure headers, + state. */
  private hopHeaders(msg: ConsumeMessage, state: FailureState): Record<string, unknown> {
    const headers: Record<string, unknown> = { ...(msg.properties.headers ?? {}) };
    for (const name of [...BROKER_HEADERS, ...RETRY_AND_FAILURE_HEADERS]) delete headers[name];
    headers[HEADERS.attempt] = state.attempt;
    headers[HEADERS.transientRetries] = state.transientRetries;
    if (state.firstFailedAt) headers[HEADERS.firstFailedAt] = state.firstFailedAt.toISOString();
    if (state.lastErrorClass) headers[HEADERS.lastErrorClass] = state.lastErrorClass;
    return headers;
  }

  /** Organization and type of an undecodable delivery, when they are well-formed tokens. */
  private rawTenant(msg: ConsumeMessage): { organizationId?: string; eventType?: string } {
    const key = parseRoutingKey(msg.fields.routingKey);
    const organizationId =
      key?.organizationId ?? stringHeader(msg.properties.headers, HEADERS.organizationId);
    const type: unknown = msg.properties.type ?? key?.eventType;
    return {
      ...(organizationId !== undefined && DECIMAL_ID.test(organizationId)
        ? { organizationId }
        : {}),
      ...(typeof type === 'string' && EVENT_TYPE.test(type) ? { eventType: type } : {}),
    };
  }

  /** The AMQP `messageId` (= event id, Q2) of an undecodable delivery, when it is a UUID. */
  private rawEventId(msg: ConsumeMessage): { eventId?: string } {
    const { messageId } = msg.properties as { messageId?: unknown };
    return typeof messageId === 'string' && UUID.test(messageId)
      ? { eventId: messageId.toLowerCase() }
      : {};
  }

  /** Log fields of an undecodable delivery: well-formed tokens only, never content. */
  private rawLogFields(msg: ConsumeMessage): Record<string, string> {
    const fields: Record<string, string> = { queue: this.queue };
    const { messageId, correlationId } = msg.properties as {
      messageId?: unknown;
      correlationId?: unknown;
    };
    if (typeof messageId === 'string' && UUID.test(messageId)) fields.eventId = messageId;
    const tenant = this.rawTenant(msg);
    if (tenant.eventType) fields.eventType = tenant.eventType;
    if (tenant.organizationId) fields.organizationId = tenant.organizationId;
    if (typeof correlationId === 'string' && LOG_TOKEN.test(correlationId)) {
      fields.correlationId = correlationId;
    }
    return fields;
  }
}

function publishFailure(error: unknown): { outcome?: string; publishCode?: string } {
  if (!(error instanceof PublishFailedError)) return {};
  return error.code === undefined
    ? { outcome: error.outcome }
    : { outcome: error.outcome, publishCode: error.code };
}
