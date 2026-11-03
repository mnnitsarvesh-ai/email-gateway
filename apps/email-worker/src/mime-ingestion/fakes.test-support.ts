/**
 * In-memory fakes of the stage's collaborators for the unit tests (excluded from the build).
 * The store reproduces the repository's semantics: ledger, conditional finalize, attempts.
 */
import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { type HandleOutcome, MetricsService, uuidv7 } from '@email-gateway/common';
import type { EventEnvelope, MessageReceivedV1 } from '@email-gateway/event-contracts';
import { EventTypes } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  DEFAULT_MIME_LIMITS,
  type MimeLimits,
  type PartInfo,
  type PartWriter,
  type StoredPart,
} from '@email-gateway/mime-parser';
import { EML_MISSING, type EmlSource } from './eml-source';
import { MimeIngestionService } from './mime-ingestion.service';
import { MimeMetrics } from './mime-metrics';
import type {
  FinalizeInput,
  FinalizeResult,
  MarkParsingResult,
  MessageRecord,
  MimeStore,
  ParseRowState,
} from './mime-store';
import { buildParsedPayload, buildParseFailedPayload } from './payloads';
import { partKey, type PartKeyTarget } from './part-keys';
import type { RecordingPartSink } from './s3-part-sink';

export const ORG = 42n;

export function emlMessage(
  eml: string | Buffer,
  overrides: Partial<MessageRecord> = {},
): MessageRecord {
  const bytes = typeof eml === 'string' ? Buffer.from(eml, 'utf8') : eml;
  const id = overrides.id ?? 1000n + BigInt(Math.floor(Math.random() * 1_000_000));
  return {
    id,
    receivedAt: new Date('2026-11-03T10:00:00.000Z'),
    organizationId: ORG,
    direction: 'inbound',
    emlObjectKey: `org/${(overrides.organizationId ?? ORG).toString()}/eml/2026/11/03/${id.toString()}.eml`,
    emlSha256: createHash('sha256').update(bytes).digest('hex'),
    sizeBytes: bytes.length,
    ...overrides,
  };
}

export function receivedEvent(
  message: MessageRecord,
  overrides: { eventId?: string; organizationId?: string } = {},
): EventEnvelope<MessageReceivedV1> {
  return {
    eventId: overrides.eventId ?? uuidv7(),
    eventType: EventTypes.MessageReceived,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-unit-test',
    organizationId: overrides.organizationId ?? message.organizationId.toString(),
    payload: {
      messageId: message.id.toString(),
      receivedAt: message.receivedAt.toISOString(),
      direction: message.direction,
      emlS3Key: message.emlObjectKey,
      sizeBytes: message.sizeBytes,
      envelopeFrom: 'sender@example.org',
      recipientCount: 1,
    },
  };
}

interface ParseRow extends ParseRowState {
  final?: FinalizeInput;
}

export interface Outbox {
  eventId: string;
  eventType: string;
  organizationId: bigint;
  correlationId: string;
  payload: unknown;
}

export class FakeStore implements MimeStore {
  readonly ledger = new Set<string>();
  readonly messages: MessageRecord[] = [];
  readonly parses = new Map<bigint, ParseRow>();
  readonly outbox: Outbox[] = [];
  readonly events: { eventType: string; eventId: string; details: unknown }[] = [];
  readonly headers: { messageId: bigint; seq: number; name: string; value: string }[] = [];
  readonly attachments: { messageId: bigint; partIndex: number; objectKey: string | null }[] = [];
  readonly subjects = new Map<bigint, string>();
  /** Throws from the next finalize (an outage of the writer). */
  failFinalize: Error | null = null;
  decrements = 0;

  add(message: MessageRecord): MessageRecord {
    this.messages.push(message);
    return message;
  }

  isProcessed(consumer: string, eventId: string): Promise<boolean> {
    return Promise.resolve(this.ledger.has(`${consumer}|${eventId}`));
  }

  recordNoop(consumer: string, eventId: string): Promise<HandleOutcome> {
    const key = `${consumer}|${eventId}`;
    if (this.ledger.has(key)) return Promise.resolve('duplicate');
    this.ledger.add(key);
    return Promise.resolve('handled');
  }

  loadMessage(messageId: bigint, receivedAt: Date, organizationId: bigint) {
    return Promise.resolve(
      this.messages.find(
        (m) =>
          m.id === messageId &&
          m.receivedAt.getTime() === receivedAt.getTime() &&
          m.organizationId === organizationId,
      ) ?? null,
    );
  }

  loadParse(message: MessageRecord): Promise<ParseRowState | null> {
    const row = this.parses.get(message.id);
    return Promise.resolve(row ? { status: row.status, attempts: row.attempts } : null);
  }

  markParsing(message: MessageRecord): Promise<MarkParsingResult> {
    const row = this.parses.get(message.id);
    if (!row) {
      this.parses.set(message.id, { status: 'parsing', attempts: 1 });
      return Promise.resolve({ kind: 'parsing', attempts: 1 });
    }
    if (row.status !== 'parsing') return Promise.resolve({ kind: 'final' });
    row.attempts += 1;
    return Promise.resolve({ kind: 'parsing', attempts: row.attempts });
  }

  decrementAttempts(message: MessageRecord): Promise<void> {
    const row = this.parses.get(message.id);
    if (row && row.status === 'parsing' && row.attempts > 0) row.attempts -= 1;
    this.decrements += 1;
    return Promise.resolve();
  }

  finalize(input: FinalizeInput): Promise<FinalizeResult> {
    if (this.failFinalize) {
      const err = this.failFinalize;
      this.failFinalize = null;
      return Promise.reject(err);
    }
    const key = `${input.consumer}|${input.event.eventId}`;
    if (this.ledger.has(key)) return Promise.resolve({ outcome: 'duplicate' });
    const row = this.parses.get(input.message.id);
    if (!row || row.status !== 'parsing') return Promise.resolve({ outcome: 'duplicate' });
    // Validated exactly like the repository does before writing.
    const payload =
      input.outcome.status === 'parse_failed'
        ? buildParseFailedPayload(input)
        : buildParsedPayload(input);
    this.ledger.add(key);
    row.status = input.outcome.status;
    row.attempts = input.attempts;
    row.final = input;
    const result = input.outcome.result;
    if (result) {
      for (const h of result.headers) this.headers.push({ messageId: input.message.id, ...h });
      for (const a of result.attachments) {
        this.attachments.push({
          messageId: input.message.id,
          partIndex: a.partIndex,
          objectKey: a.key,
        });
      }
      if (result.subject !== null) this.subjects.set(input.message.id, result.subject);
    }
    const outboxEventId = uuidv7();
    this.events.push({
      eventType: input.outcome.status === 'parse_failed' ? 'parse_failed' : 'parsed',
      eventId: outboxEventId,
      details: { status: input.outcome.status },
    });
    this.outbox.push({
      eventId: outboxEventId,
      eventType:
        input.outcome.status === 'parse_failed'
          ? EventTypes.MessageParseFailed
          : EventTypes.MessageParsed,
      organizationId: input.message.organizationId,
      correlationId: input.event.correlationId,
      payload,
    });
    return Promise.resolve({ outcome: 'handled', outboxEventId });
  }
}

export class FakeEmlSource implements EmlSource {
  readonly objects = new Map<string, Buffer>();
  /** Thrown from the next open (an S3 outage). */
  failOpen: Error | null = null;
  opened = 0;

  put(key: string, eml: string | Buffer): void {
    this.objects.set(key, typeof eml === 'string' ? Buffer.from(eml, 'utf8') : eml);
  }

  open(key: string, _signal?: AbortSignal): Promise<Readable | typeof EML_MISSING> {
    this.opened += 1;
    if (this.failOpen) {
      const err = this.failOpen;
      this.failOpen = null;
      return Promise.reject(err);
    }
    const bytes = this.objects.get(key);
    if (!bytes) return Promise.resolve(EML_MISSING);
    // Chunked, so the parser sees a real stream.
    const chunks: Buffer[] = [];
    for (let i = 0; i < bytes.length; i += 1024) chunks.push(bytes.subarray(i, i + 1024));
    return Promise.resolve(Readable.from(chunks));
  }
}

/** Object storage of the fake sinks, shared across attempts. */
export class FakeObjectStore {
  readonly objects = new Map<string, Buffer>();
  readonly deleted: string[] = [];
  /** Thrown by the next write (an S3 outage while uploading). */
  failWrite: Error | null = null;

  sinkFor = (target: PartKeyTarget): RecordingPartSink => {
    const written: string[] = [];
    const objects = this.objects;
    const deleted = this.deleted;
    const takeFailure = (): Error | null => {
      const err = this.failWrite;
      this.failWrite = null;
      return err;
    };
    return {
      get writtenKeys() {
        return written;
      },
      open(part: PartInfo): Promise<PartWriter> {
        const key = partKey(target, part);
        const chunks: Buffer[] = [];
        return Promise.resolve({
          write(chunk: Buffer): Promise<void> {
            const err = takeFailure();
            if (err) return Promise.reject(err);
            chunks.push(Buffer.from(chunk));
            return Promise.resolve();
          },
          finish(): Promise<StoredPart> {
            const bytes = Buffer.concat(chunks);
            objects.set(key, bytes);
            written.push(key);
            return Promise.resolve({
              key,
              readRange: (start: number, end: number) =>
                Promise.resolve(bytes.subarray(start, end + 1)),
            });
          },
          abort(): Promise<void> {
            chunks.length = 0;
            return Promise.resolve();
          },
        });
      },
      deleteWritten(): Promise<number> {
        for (const key of written) {
          objects.delete(key);
          deleted.push(key);
        }
        return Promise.resolve(0);
      },
    };
  };
}

export const silent = (): Logger => {
  const noop = () => undefined;
  const logger = {
    info: noop,
    warn: noop,
    error: noop,
    debug: noop,
    trace: noop,
    fatal: noop,
  } as unknown as Logger;
  (logger as unknown as { child: () => Logger }).child = () => logger;
  return logger;
};

export function newMetricsService(): MetricsService {
  return new MetricsService({ service: `email-worker-unit-${randomUUID().slice(0, 8)}` });
}

/** The value of one series in the exposition text (0 when absent). */
export async function metricValue(
  registry: MetricsService,
  name: string,
  label: string,
): Promise<number> {
  const text = await registry.metrics();
  const line = text.split('\n').find((l) => l.startsWith(`${name}{`) && l.includes(label));
  return line ? Number(line.split(' ').pop()) : 0;
}

export interface Harness {
  service: MimeIngestionService;
  store: FakeStore;
  source: FakeEmlSource;
  objects: FakeObjectStore;
  metrics: MimeMetrics;
  registry: MetricsService;
}

export function harness(
  options: {
    limits?: Partial<MimeLimits>;
    maxAttempts?: number;
    logger?: Logger;
    clock?: () => number;
  } = {},
): Harness {
  const store = new FakeStore();
  const source = new FakeEmlSource();
  const objects = new FakeObjectStore();
  const registry = newMetricsService();
  const metrics = new MimeMetrics(registry);
  const service = new MimeIngestionService({
    store,
    emlSource: source,
    sinkFor: objects.sinkFor,
    metrics,
    logger: options.logger ?? silent(),
    limits: { ...DEFAULT_MIME_LIMITS, ...options.limits },
    maxAttempts: options.maxAttempts ?? 5,
    ...(options.clock ? { clock: options.clock } : {}),
  });
  return { service, store, source, objects, metrics, registry };
}

/** A multipart message with a text body, an HTML body and one attachment. */
export function multipartEml(
  markers: Partial<Record<'subject' | 'from' | 'body' | 'filename' | 'header', string>> = {},
): string {
  const m = {
    subject: 'Quarterly numbers',
    from: 'Alice <alice@example.org>',
    body: 'Hello there.',
    filename: 'report.pdf',
    header: 'spf=pass',
    ...markers,
  };
  return [
    `From: ${m.from}`,
    'To: bob@example.net',
    `Subject: ${m.subject}`,
    'Message-ID: <unit@example.org>',
    'Date: Tue, 03 Nov 2026 10:00:00 +0000',
    `Authentication-Results: mx.example.net; ${m.header}`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: multipart/alternative; boundary="alt"',
    '',
    '--alt',
    'Content-Type: text/plain; charset=utf-8',
    '',
    m.body,
    '--alt',
    'Content-Type: text/html; charset=utf-8',
    '',
    `<p>${m.body}</p>`,
    '--alt--',
    '--outer',
    `Content-Type: application/pdf; name="${m.filename}"`,
    `Content-Disposition: attachment; filename="${m.filename}"`,
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(`%PDF-1.4 ${m.body}`).toString('base64'),
    '--outer--',
    '',
  ].join('\r\n');
}
