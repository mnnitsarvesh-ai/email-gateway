import { EventEmitter } from 'node:events';
import { Writable } from 'node:stream';
import { createLogger, type Logger } from '@email-gateway/logger';
import type { ChannelModel, ConsumeMessage, Message, Options } from 'amqplib';

/**
 * In-memory fakes of the amqplib surface the messaging library uses (unit tests only; not
 * exported from the package). They follow amqplib's observable behaviour: a closing channel
 * first rejects pending confirms with `channel closed`, then emits `close`; a server-closed
 * channel emits `error` (with the reply code) before `close`; operations on a closed channel
 * throw.
 */

export interface FakePublish {
  exchange: string;
  routingKey: string;
  content: Buffer;
  options: Options.Publish;
  callback?: (err: unknown) => void;
  settled: boolean;
}

export class FakeChannel extends EventEmitter {
  closed = false;
  readonly published: FakePublish[] = [];
  readonly acks: number[] = [];
  readonly nacks: { tag: number; requeue: boolean }[] = [];
  readonly cancelled: string[] = [];
  prefetchCount: number | undefined;
  /** publish() returns this (false = write buffer full until `drain`). */
  writable = true;
  /** Names that `checkQueue` / `checkExchange` report as missing (404). */
  missing = new Set<string>();
  private consumer: ((msg: ConsumeMessage | null) => void) | undefined;
  private tags = 0;

  constructor(
    readonly model: FakeModel,
    readonly isConfirm: boolean,
  ) {
    super();
  }

  publish(
    exchange: string,
    routingKey: string,
    content: Buffer,
    options: Options.Publish = {},
    callback?: (err: unknown) => void,
  ): boolean {
    if (this.closed)
      throw Object.assign(new Error('Channel closed'), { name: 'IllegalOperationError' });
    const index =
      this.published.push({ exchange, routingKey, content, options, callback, settled: false }) - 1;
    const mode = this.model.confirmMode;
    if (mode === 'ack') queueMicrotask(() => this.confirm(index));
    else if (mode === 'nack') queueMicrotask(() => this.nackPublish(index));
    return this.writable;
  }

  /** Broker confirm (ack) of publish `index`. */
  confirm(index: number): void {
    const p = this.published[index];
    if (!p || p.settled) return;
    p.settled = true;
    p.callback?.(null);
  }

  /** Consumer ack of a delivery. */
  ack(message: Message): void {
    if (this.closed) throw new Error('Channel closed');
    this.acks.push(message.fields.deliveryTag);
  }

  /** Broker nack of publish `index`. */
  nackPublish(index: number): void {
    const p = this.published[index];
    if (!p || p.settled) return;
    p.settled = true;
    p.callback?.(new Error('message nacked'));
  }

  /** basic.return of publish `index` (mandatory, unroutable). */
  returnPublish(index: number, replyCode = 312): void {
    const p = this.published[index];
    if (!p) return;
    this.emit('return', {
      content: p.content,
      fields: { replyCode, replyText: 'NO_ROUTE', exchange: p.exchange, routingKey: p.routingKey },
      properties: { ...p.options },
    });
  }

  /** Confirms every unsettled publish. */
  confirmAll(): void {
    this.published.forEach((_, i) => this.confirm(i));
  }

  nack(message: Message, _allUpTo = false, requeue = true): void {
    if (this.closed) throw new Error('Channel closed');
    this.nacks.push({ tag: message.fields.deliveryTag, requeue });
  }

  prefetch(count: number): Promise<void> {
    this.prefetchCount = count;
    return Promise.resolve();
  }

  checkQueue(
    name: string,
  ): Promise<{ queue: string; messageCount: number; consumerCount: number }> {
    if (this.missing.has(name)) {
      this.serverClose(404);
      return Promise.reject(Object.assign(new Error('NOT_FOUND'), { code: 404 }));
    }
    return Promise.resolve({ queue: name, messageCount: 0, consumerCount: 0 });
  }

  checkExchange(name: string): Promise<void> {
    if (this.missing.has(name)) {
      this.serverClose(404);
      return Promise.reject(Object.assign(new Error('NOT_FOUND'), { code: 404 }));
    }
    return Promise.resolve();
  }

  consume(
    _queue: string,
    onMessage: (msg: ConsumeMessage | null) => void,
    options: Options.Consume = {},
  ): Promise<{ consumerTag: string }> {
    if (options.noAck !== false) throw new Error('fake: consumers must use manual acks');
    this.consumer = onMessage;
    return Promise.resolve({ consumerTag: 'ctag-1' });
  }

  cancel(tag: string): Promise<void> {
    this.cancelled.push(tag);
    this.consumer = undefined;
    return Promise.resolve();
  }

  /** Broker delivery to the consumer. */
  deliver(msg: ConsumeMessage): void {
    if (!this.consumer) throw new Error('fake: no consumer');
    this.consumer(msg);
  }

  nextTag(): number {
    this.tags += 1;
    return this.tags;
  }

  close(): Promise<void> {
    this.toClosed();
    return Promise.resolve();
  }

  /** The broker closes the channel (e.g. 403 ACCESS_REFUSED, 404 NOT_FOUND). */
  serverClose(code: number): void {
    if (this.closed) return;
    this.emit('error', Object.assign(new Error(`server closed channel ${code}`), { code }));
    this.toClosed();
  }

  toClosed(): void {
    if (this.closed) return;
    this.closed = true;
    for (const p of this.published) {
      if (!p.settled) {
        p.settled = true;
        p.callback?.(new Error('channel closed'));
      }
    }
    this.emit('close');
  }
}

/** How the fake broker answers publishes: manually (tests call confirm/nack), or at once. */
export type ConfirmMode = 'manual' | 'ack' | 'nack';

export class FakeModel extends EventEmitter {
  readonly channels: FakeChannel[] = [];
  confirmMode: ConfirmMode = 'manual';
  closed = false;
  /** Names every channel of this model reports missing. */
  missing = new Set<string>();
  failChannelOpen = false;

  constructor(readonly url: string) {
    super();
  }

  createChannel(): Promise<FakeChannel> {
    return this.open(false);
  }

  createConfirmChannel(): Promise<FakeChannel> {
    return this.open(true);
  }

  private open(confirm: boolean): Promise<FakeChannel> {
    if (this.closed || this.failChannelOpen) {
      return Promise.reject(
        Object.assign(new Error('Connection closed'), { name: 'IllegalOperationError' }),
      );
    }
    const channel = new FakeChannel(this, confirm);
    channel.missing = this.missing;
    this.channels.push(channel);
    return Promise.resolve(channel);
  }

  close(): Promise<void> {
    this.drop();
    return Promise.resolve();
  }

  /** The connection dies (socket closed, heartbeat lost). */
  drop(): void {
    if (this.closed) return;
    this.closed = true;
    for (const channel of this.channels) channel.toClosed();
    this.emit('close');
  }

  asModel(): ChannelModel {
    return this as unknown as ChannelModel;
  }
}

/** A `connect` replacement that hands out fake models; `fail` makes the next attempts reject. */
export class FakeBroker {
  readonly attempts: string[] = [];
  readonly models: FakeModel[] = [];
  failures = 0;
  missing = new Set<string>();
  confirmMode: ConfirmMode = 'manual';

  readonly connect = (url: string): Promise<ChannelModel> => {
    this.attempts.push(url);
    if (this.failures > 0) {
      this.failures -= 1;
      return Promise.reject(
        Object.assign(new Error('connect ECONNREFUSED 10.0.0.1:5672'), { code: 'ECONNREFUSED' }),
      );
    }
    const model = new FakeModel(url);
    model.missing = this.missing;
    model.confirmMode = this.confirmMode;
    this.models.push(model);
    return Promise.resolve(model.asModel());
  };

  get current(): FakeModel | undefined {
    const model = this.models.at(-1);
    return model && !model.closed ? model : undefined;
  }
}

/** A logger whose JSON lines are kept in memory. */
export function memoryLogger(): {
  logger: Logger;
  lines: () => Record<string, unknown>[];
  raw: () => string;
} {
  const chunks: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      chunks.push(chunk.toString('utf8'));
      callback();
    },
  });
  const logger = createLogger({ service: 'test', level: 'debug', destination });
  const raw = () => chunks.join('');
  const lines = () =>
    raw()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  return { logger, lines, raw };
}

/** Polls `condition` until true (default 2 s). */
export async function waitFor(
  condition: () => boolean,
  timeoutMs = 2_000,
  what = 'condition',
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}
