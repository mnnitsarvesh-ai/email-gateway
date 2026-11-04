import { performance } from 'node:perf_hooks';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { ConfirmChannel, Message, MessageProperties, Options } from 'amqplib';
import { backoffDelay, sleep } from './backoff';
import { encodeEvent, UnknownEventTypeError } from './codec';
import type { AmqpConnection } from './connection';
import { assertMetadataOnly, ContentGuardError } from './content-guard';
import { amqpReplyName, BrokerUnavailableError, errorFields } from './errors';
import type { MessagingMetrics } from './metrics';

export type PublishOutcome = 'confirmed' | 'nacked' | 'returned' | 'timeout' | 'refused';

export interface PublishItem {
  envelope: EventEnvelope;
  /** Defaults: registry exchange and `org.<id>.<eventType>`. */
  exchange?: string;
  routingKey?: string;
  /** Added to (and overriding) the Q2 base headers. */
  headers?: Record<string, string | number>;
  expirationMs?: number;
}

export interface PublishResult {
  outcome: PublishOutcome;
  /** Guard code (`refused`) or the return reply (`returned`, e.g. `NO_ROUTE`). */
  code?: string;
}

/** `publish` / `republish` of a message that was not confirmed. */
export class PublishFailedError extends Error {
  override readonly name = 'PublishFailedError';
  constructor(
    readonly outcome: Exclude<PublishOutcome, 'confirmed'>,
    readonly code?: string,
  ) {
    super(`publish ${outcome}${code ? ` (${code})` : ''}`);
  }
}

export interface ConfirmPublisherOptions {
  connection: AmqpConnection;
  logger: Logger;
  metrics?: MessagingMetrics;
  /** AMQP `appId` of every publish (the publishing service). */
  appId: string;
  confirmTimeoutMs: number;
  /** Encoded size limit (default 131 072, hard max 262 144). */
  maxMessageBytes: number;
  /** Backoff before re-creating a channel the broker closed (default 100 / 5 000 ms). */
  channelBackoff?: { baseMs: number; maxMs: number };
  random?: () => number;
}

export const DEFAULT_MAX_MESSAGE_BYTES = 131_072;
export const HARD_MAX_MESSAGE_BYTES = 262_144;

interface Prepared {
  exchange: string;
  routingKey: string;
  content: Buffer;
  options: Options.Publish;
}

interface InFlight {
  exchange: string;
  routingKey: string;
  messageId: unknown;
  returned: boolean;
  returnCode?: string;
  settled: boolean;
}

interface ChannelState {
  channel: ConfirmChannel;
  closed: boolean;
  /** Closed by this publisher after a lost confirm: unresolved items become `timeout`. */
  closedByTimeout: boolean;
  closeReason: string;
  inFlight: InFlight[];
  closeListeners: Set<() => void>;
}

type SendOutcome = Exclude<PublishOutcome, 'refused'>;

/**
 * Publisher confirms on one confirm channel (step 3.2 Q6): publishes in order, resolves per
 * item with the broker's verdict. Rules:
 *
 * - every path runs the content guard and the size check first (`refused` + guard code, nothing
 *   is sent);
 * - `mandatory`: a `basic.return` (unroutable) marks the item `returned` although the broker
 *   acks it afterwards;
 * - a confirm missing after `confirmTimeoutMs` → `timeout`, and the channel is closed and
 *   re-created (it is unreliable after a lost confirm);
 * - the channel or connection dying with confirms pending rejects the call with
 *   `BrokerUnavailableError` (no unresolved item is confirmed);
 * - while the connection is `blocked`, waits for `unblocked` up to `confirmTimeoutMs`, then
 *   returns `timeout` for every item.
 */
export class ConfirmPublisher {
  private readonly logger: Logger;
  private readonly maxMessageBytes: number;
  private readonly channelBackoff: { baseMs: number; maxMs: number };
  private readonly random: () => number;
  private state: ChannelState | undefined;
  private opening: Promise<ChannelState> | undefined;
  private channelFailures = 0;
  private retryAt = 0;
  private closing = false;

  constructor(private readonly options: ConfirmPublisherOptions) {
    if (!Number.isSafeInteger(options.confirmTimeoutMs) || options.confirmTimeoutMs <= 0) {
      throw new Error('ConfirmPublisher confirmTimeoutMs must be a positive integer');
    }
    const max = options.maxMessageBytes;
    if (!Number.isSafeInteger(max) || max <= 0 || max > HARD_MAX_MESSAGE_BYTES) {
      throw new Error(`ConfirmPublisher maxMessageBytes must be 1..${HARD_MAX_MESSAGE_BYTES}`);
    }
    if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(options.appId)) {
      throw new Error('ConfirmPublisher appId must be a token');
    }
    this.maxMessageBytes = max;
    this.channelBackoff = options.channelBackoff ?? { baseMs: 100, maxMs: 5_000 };
    this.random = options.random ?? Math.random;
    this.logger = options.logger.child({ component: 'amqp-publisher' });
  }

  /**
   * Publishes every item on one confirm channel, in order, and resolves per item. Rejects with
   * `BrokerUnavailableError` (all unresolved items unconfirmed) when the channel/connection dies.
   */
  async publishBatch(items: PublishItem[]): Promise<PublishResult[]> {
    const results: (PublishResult | undefined)[] = new Array<PublishResult | undefined>(
      items.length,
    );
    const sendable: { index: number; prepared: Prepared }[] = [];
    items.forEach((item, index) => {
      const prepared = this.prepareEvent(item);
      if ('refused' in prepared) {
        results[index] = { outcome: 'refused', code: prepared.refused };
        this.options.metrics?.published(prepared.exchange, 'refused');
      } else {
        sendable.push({ index, prepared });
      }
    });
    if (sendable.length > 0) {
      const outcomes = await this.send(sendable.map((s) => s.prepared));
      sendable.forEach((s, i) => {
        results[s.index] = outcomes[i];
      });
    }
    return results.map((r) => r ?? { outcome: 'timeout' });
  }

  /** Publishes one event; throws `PublishFailedError` unless `confirmed`. */
  async publish(item: PublishItem): Promise<void> {
    const [result] = await this.publishBatch([item]);
    if (!result || result.outcome !== 'confirmed') {
      throw new PublishFailedError(
        result?.outcome === 'confirmed' || !result ? 'timeout' : result.outcome,
        result?.code,
      );
    }
  }

  /**
   * Re-publishes an existing delivery's bytes (retry, dead-letter, replay) after the guard:
   * same body, `messageId`, `correlationId`, `type`, `timestamp`, `appId`, content type and
   * encoding; `headers` replace the original headers; persistent; `expiration` only when
   * `expirationMs` is given. Throws `PublishFailedError` unless confirmed, or
   * `BrokerUnavailableError`.
   */
  async republish(
    raw: { content: Buffer; properties: MessageProperties },
    target: {
      exchange: string;
      routingKey: string;
      headers: Record<string, unknown>;
      expirationMs?: number;
    },
  ): Promise<void> {
    const refused = this.guardRaw(raw.content, target.headers);
    if (refused) {
      this.options.metrics?.published(target.exchange, 'refused');
      throw new PublishFailedError('refused', refused);
    }
    const p = raw.properties;
    const options: Options.Publish = {
      persistent: true,
      deliveryMode: 2,
      contentType: typeof p.contentType === 'string' ? p.contentType : 'application/json',
      contentEncoding: typeof p.contentEncoding === 'string' ? p.contentEncoding : 'utf-8',
      headers: target.headers,
      mandatory: true,
      appId: typeof p.appId === 'string' ? p.appId : this.options.appId,
    };
    if (typeof p.messageId === 'string') options.messageId = p.messageId;
    if (typeof p.correlationId === 'string') options.correlationId = p.correlationId;
    if (typeof p.type === 'string') options.type = p.type;
    if (typeof p.timestamp === 'number') options.timestamp = p.timestamp;
    if (target.expirationMs !== undefined) {
      options.expiration = String(Math.max(0, Math.floor(target.expirationMs)));
    }
    const [result] = await this.send([
      { exchange: target.exchange, routingKey: target.routingKey, content: raw.content, options },
    ]);
    if (!result || result.outcome !== 'confirmed') {
      throw new PublishFailedError(
        result?.outcome === 'confirmed' || !result ? 'timeout' : result.outcome,
        result?.code,
      );
    }
  }

  async close(): Promise<void> {
    this.closing = true;
    const state = this.state;
    this.state = undefined;
    if (state && !state.closed) await state.channel.close().catch(() => undefined);
  }

  // -------------------------------------------------------------------------------------------

  private prepareEvent(item: PublishItem): Prepared | { refused: string; exchange: string } {
    let encoded;
    try {
      encoded = encodeEvent(item.envelope, this.options.appId);
    } catch (error) {
      const code = error instanceof UnknownEventTypeError ? error.code : 'contract_invalid';
      return { refused: code, exchange: item.exchange ?? 'unknown' };
    }
    const exchange = item.exchange ?? encoded.exchange;
    try {
      assertMetadataOnly(item.envelope);
      if (item.headers) assertMetadataOnly(item.headers);
    } catch (error) {
      if (error instanceof ContentGuardError) return { refused: error.code, exchange };
      throw error;
    }
    if (encoded.content.length > this.maxMessageBytes) {
      return { refused: 'message_too_large', exchange };
    }
    const options: Options.Publish = {
      ...encoded.options,
      headers: { ...(encoded.options.headers as Record<string, unknown>), ...item.headers },
    };
    if (item.expirationMs !== undefined) {
      options.expiration = String(Math.max(0, Math.floor(item.expirationMs)));
    }
    return {
      exchange,
      routingKey: item.routingKey ?? encoded.routingKey,
      content: encoded.content,
      options,
    };
  }

  private guardRaw(content: Buffer, headers: Record<string, unknown>): string | undefined {
    if (content.length > this.maxMessageBytes) return 'message_too_large';
    const text = content.toString('utf8');
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      // Not JSON (a dead letter of an undecodable delivery): guard the text itself.
    }
    try {
      assertMetadataOnly(parsed);
      assertMetadataOnly(headers);
    } catch (error) {
      if (error instanceof ContentGuardError) return error.code;
      throw error;
    }
    return undefined;
  }

  private async channel(): Promise<ChannelState> {
    if (this.state && !this.state.closed) return this.state;
    if (this.opening) return this.opening;
    this.opening = (async () => {
      const waitMs = this.retryAt - Date.now();
      if (this.channelFailures > 0 && waitMs > 0) {
        await sleep(Math.min(waitMs, this.options.confirmTimeoutMs));
      }
      const channel = await this.options.connection.createConfirmChannel();
      const state: ChannelState = {
        channel,
        closed: false,
        closedByTimeout: false,
        closeReason: 'channel_closed',
        inFlight: [],
        closeListeners: new Set(),
      };
      channel.on('error', (error: unknown) => {
        state.closeReason = amqpReplyName(error);
      });
      channel.on('close', () => this.onChannelClosed(state));
      channel.on('return', (msg: Message) => this.onReturn(state, msg));
      this.state = state;
      return state;
    })().finally(() => {
      this.opening = undefined;
    });
    return this.opening;
  }

  private onChannelClosed(state: ChannelState): void {
    if (state.closed) return;
    state.closed = true;
    if (this.state === state) this.state = undefined;
    if (!this.closing) {
      this.channelFailures += 1;
      this.retryAt =
        Date.now() + backoffDelay(this.channelFailures, this.channelBackoff, this.random);
      this.logger.warn({ reply: state.closeReason }, 'AMQP publish channel closed');
    }
    for (const listener of [...state.closeListeners]) listener();
  }

  /** Closes a channel whose confirm went missing; unresolved items become `timeout`. */
  private invalidate(state: ChannelState): void {
    if (state.closed) return;
    state.closedByTimeout = true;
    state.closeReason = 'confirm_timeout';
    this.onChannelClosed(state);
    void state.channel.close().catch(() => undefined);
  }

  private onReturn(state: ChannelState, msg: Message): void {
    const fields = msg.fields as Message['fields'] & { replyCode?: unknown };
    const record = state.inFlight.find(
      (r) =>
        !r.settled &&
        !r.returned &&
        r.exchange === fields.exchange &&
        r.routingKey === fields.routingKey &&
        r.messageId === msg.properties.messageId,
    );
    if (!record) return;
    record.returned = true;
    record.returnCode = amqpReplyName(fields.replyCode, 'returned');
  }

  private async send(items: Prepared[]): Promise<PublishResult[]> {
    const outcomes: PublishResult[] = [];
    const record = (exchange: string, outcome: SendOutcome, code?: string): PublishResult => {
      this.options.metrics?.published(exchange, outcome);
      return code === undefined ? { outcome } : { outcome, code };
    };
    if (this.options.connection.blocked) {
      const unblocked = await this.options.connection.waitUntilUnblocked(
        this.options.confirmTimeoutMs,
      );
      if (!unblocked) {
        this.logger.warn({ items: items.length }, 'AMQP connection blocked; publishes timed out');
        return items.map((item) => record(item.exchange, 'timeout'));
      }
    }
    const state = await this.channel();
    const timeoutMs = this.options.confirmTimeoutMs;

    return new Promise<PublishResult[]>((resolve, reject) => {
      let remaining = items.length;
      let done = false;
      const timers: NodeJS.Timeout[] = [];
      const cleanup = () => {
        done = true;
        for (const timer of timers) clearTimeout(timer);
        state.closeListeners.delete(onClose);
      };
      const settle = (index: number, exchange: string, outcome: SendOutcome, code?: string) => {
        if (done || outcomes[index] !== undefined) return;
        outcomes[index] = record(exchange, outcome, code);
        remaining -= 1;
        if (remaining === 0) {
          cleanup();
          resolve(outcomes);
        }
      };
      const records: InFlight[] = [];
      const onClose = () => {
        if (done) return;
        if (state.closedByTimeout) {
          records.forEach((r, index) => {
            if (!r.settled) {
              r.settled = true;
              settle(index, r.exchange, 'timeout');
            }
          });
          // Items not yet published when the channel was invalidated.
          for (let index = records.length; index < items.length; index += 1) {
            const item = items[index];
            if (item) settle(index, item.exchange, 'timeout');
          }
          return;
        }
        cleanup();
        reject(new BrokerUnavailableError(state.closeReason));
      };
      state.closeListeners.add(onClose);

      const publishAll = async () => {
        for (let index = 0; index < items.length; index += 1) {
          const item = items[index];
          if (!item || done) return;
          if (state.closed) {
            onClose();
            return;
          }
          const r: InFlight = {
            exchange: item.exchange,
            routingKey: item.routingKey,
            messageId: item.options.messageId,
            returned: false,
            settled: false,
          };
          records.push(r);
          state.inFlight.push(r);
          const started = performance.now();
          const finish = (outcome: SendOutcome, code?: string) => {
            r.settled = true;
            const at = state.inFlight.indexOf(r);
            if (at >= 0) state.inFlight.splice(at, 1);
            if (outcome !== 'timeout') {
              this.options.metrics?.confirmSeconds(
                item.exchange,
                (performance.now() - started) / 1000,
              );
            }
            if (outcome === 'confirmed' || outcome === 'returned') this.channelFailures = 0;
            settle(index, item.exchange, outcome, code);
          };
          const timer = setTimeout(() => {
            if (r.settled) return;
            this.logger.warn({ exchange: item.exchange, timeoutMs }, 'AMQP confirm timed out');
            finish('timeout');
            this.invalidate(state);
          }, timeoutMs);
          timers.push(timer);
          let writable: boolean;
          try {
            writable = state.channel.publish(
              item.exchange,
              item.routingKey,
              item.content,
              item.options,
              (err: unknown) => {
                clearTimeout(timer);
                if (r.settled) return;
                if (err === null || err === undefined) {
                  finish(
                    r.returned ? 'returned' : 'confirmed',
                    r.returned ? r.returnCode : undefined,
                  );
                  return;
                }
                // amqplib rejects pending confirms with an error when the channel closes; the
                // close listener runs right after in the same tick, so decide in a microtask.
                queueMicrotask(() => {
                  if (r.settled || state.closed) return;
                  finish('nacked');
                });
              },
            );
          } catch (error) {
            clearTimeout(timer);
            this.logger.warn({ ...errorFields(error) }, 'AMQP publish failed on a closed channel');
            if (!state.closed) this.onChannelClosed(state);
            else onClose();
            return;
          }
          if (!writable) {
            await new Promise<void>((resume) => {
              const wake = () => {
                state.closeListeners.delete(wake);
                resume();
              };
              state.channel.once('drain', wake);
              state.closeListeners.add(wake);
            });
          }
        }
      };
      publishAll().catch((error: unknown) => {
        if (done) return;
        cleanup();
        reject(error instanceof Error ? error : new BrokerUnavailableError('publish_failed'));
      });
    });
  }
}
