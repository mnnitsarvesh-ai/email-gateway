import { MetricsService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { EXAMPLE_EVENT_PAYLOADS, type EventEnvelope } from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import type { FactsSource } from './fanout/builders';
import type { MessageFacts } from './fanout/facts';
import { WebhookMetrics } from './metrics/webhook-metrics';

/** Unit-test support of the webhook-worker (fakes only; never imported by production code). */

export const ORG_ID = 42n;
export const ORG_PUBLIC_ID = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10';
export const MESSAGE_PUBLIC_ID = '0193a1b2-0000-7000-8000-00000000aaaa';
export const DOMAIN_PUBLIC_ID = '01890a5d-ac96-774b-bcce-b302099a8057';

export const silentLogger: Logger = createLogger({
  service: 'webhook-worker-test',
  level: 'silent',
});

export function testMetrics(): { metrics: WebhookMetrics; registry: MetricsService } {
  const registry = new MetricsService({ service: 'webhook-worker-test' });
  return { metrics: new WebhookMetrics(registry), registry };
}

/** A source envelope of `eventType` with the registry example payload (plus overrides). */
export function sourceEvent<T = Record<string, unknown>>(
  eventType: string,
  overrides: Partial<T> = {},
  envelope: Partial<EventEnvelope<unknown>> = {},
): EventEnvelope<unknown> {
  const example = (EXAMPLE_EVENT_PAYLOADS as Record<string, unknown>)[eventType];
  return {
    eventId: '01890a5d-ac96-774b-bcce-b302099a8f01',
    eventType,
    occurredAt: '2026-11-01T10:15:32.000Z',
    correlationId: 'corr-0001-test',
    organizationId: ORG_ID.toString(),
    payload: { ...(example as object), ...overrides },
    ...envelope,
  };
}

/** Message facts of the fake writer (domains only, never a local part). */
export function messageFacts(overrides: Partial<MessageFacts> = {}): MessageFacts {
  return {
    key: {
      organizationId: ORG_ID,
      messageId: 9001n,
      receivedAt: new Date('2026-11-01T10:15:30.123Z'),
    },
    publicId: MESSAGE_PUBLIC_ID,
    direction: 'inbound',
    domainId: 77n,
    domainPublicId: DOMAIN_PUBLIC_ID,
    internetMessageId: '<abc@partner.example>',
    senderDomain: 'partner.example',
    headerFromDomain: 'partner.example',
    recipientCount: 2,
    recipientDomains: ['corp.example'],
    sizeBytes: 2048,
    attachmentCount: 1,
    lifecycleRound: 0,
    ...overrides,
  };
}

/** A `FactsSource` answering with valid facts; every read is counted. */
export function fakeFacts(overrides: Partial<FactsSource> = {}): FactsSource & {
  calls: string[];
} {
  const calls: string[] = [];
  const track =
    <A extends unknown[], R>(name: string, fn: (...args: A) => Promise<R>) =>
    (...args: A): Promise<R> => {
      calls.push(name);
      return fn(...args);
    };
  const base: FactsSource = {
    message: () => Promise.resolve(messageFacts()),
    scanReasonCodes: () => Promise.resolve(['spam.score', 'phishing.known_bad_url']),
    executionLog: () =>
      Promise.resolve({
        matchedRules: [
          {
            policyId: '01890a5d-ac96-774b-bcce-b302099a80aa',
            versionNo: 3,
            ruleId: 'quarantine-malware-phishing',
          },
        ],
        actions: ['ARCHIVE', 'ALERT'],
      }),
    quarantineEntries: () =>
      Promise.resolve([
        {
          publicId: '01890a5d-ac96-774b-bcce-b302099a80a1',
          kind: 'quarantine' as const,
          reason: 'phishing',
          expiresAt: new Date('2026-12-01T10:00:00.000Z'),
        },
        {
          publicId: '01890a5d-ac96-774b-bcce-b302099a80a2',
          kind: 'review' as const,
          reason: 'policy',
          expiresAt: new Date('2026-11-20T10:00:00.000Z'),
        },
      ]),
    release: () =>
      Promise.resolve({
        releaseId: '01890a5d-ac96-774b-bcce-b302099a80a0',
        mode: 'approved' as const,
        entryIds: ['01890a5d-ac96-774b-bcce-b302099a80a1'],
      }),
    recipientOutcomes: () =>
      Promise.resolve({
        delivered: 1,
        failed: 0,
        bounced: 0,
        expired: 1,
        suppressed: 0,
        quarantined: 0,
        discarded: 0,
        other: 0,
      }),
    sandboxSubmission: () =>
      Promise.resolve({ partIndex: 3, sha256: 'c'.repeat(64), detectedType: 'seven_zip' }),
    domain: (_org, id, publicId) =>
      Promise.resolve({ id, publicId, name: 'acme.example', status: 'active' }),
  };
  const merged = { ...base, ...overrides };
  return {
    calls,
    message: track('message', merged.message),
    scanReasonCodes: track('scanReasonCodes', merged.scanReasonCodes),
    executionLog: track('executionLog', merged.executionLog),
    quarantineEntries: track('quarantineEntries', merged.quarantineEntries),
    release: track('release', merged.release),
    recipientOutcomes: track('recipientOutcomes', merged.recipientOutcomes),
    sandboxSubmission: track('sandboxSubmission', merged.sandboxSubmission),
    domain: track('domain', merged.domain),
  };
}

/** One SQL statement seen by `fakeSql` (text with `?` placeholders and its values). */
export interface SeenSql {
  text: string;
  values: unknown[];
}

/** Normalizes a tagged-template call or a `Prisma.Sql` object to text + values. */
export function sqlOf(first: unknown, rest: unknown[]): SeenSql {
  // Prisma.sql flattens nested fragments (Prisma.join, Prisma.empty) like the client does.
  const sql = (Array.isArray(first) ? Prisma.sql(first, ...rest) : first) as {
    sql?: string;
    values?: unknown[];
  };
  return { text: (sql.sql ?? '').replace(/\s+/g, ' ').trim(), values: sql.values ?? [] };
}
