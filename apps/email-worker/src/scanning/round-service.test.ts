import { Readable } from 'node:stream';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { NormalizedEngineResult } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import { CircuitBreaker } from './circuit-breaker';
import {
  EmlUnavailableError,
  EngineAttemptFailedError,
  type EngineScanContext,
  type EngineScanOutcome,
  type ScanEngineAdapter,
} from './engine';
import { classifyScanFailure } from './engine-consumer';
import { rspamdRegistration } from './engines/rspamd/registration';
import { FakeScanStore, newMetrics } from './fakes.test-support';
import { ScanRoundService, type ScanTriggerPayload } from './round-service';
import { decideOpen } from './scan-store';
import { SettingsResolver } from './settings-resolver';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://t:t@localhost:3306/t',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://a:b@localhost:5672/v',
  RABBITMQ_SCANNER_URL: 'amqp://a:b@localhost:5672/v',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  URL_CACHE_HMAC_KEY: 'test-url-cache-mac-key-0123456789abcdef',
  BEC_CONTEXT_HMAC_KEY: 'test-bec-context-hmac-key-0123456789abcdef',
  URL_TOKEN_KEY_CURRENT: '0123456789abcdef'.repeat(4),
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  SCAN_RSPAMD_MAX_ATTEMPTS: '3',
});
const logger = createLogger({ service: 'test', level: 'silent' });
const ORG = 42n;
const MSG = 1001n;
const RECEIVED = new Date('2026-11-05T10:00:00.000Z');
const KEY = `org/${ORG.toString()}/eml/2026/11/05/m.eml`;

const definite = (
  outcome: NormalizedEngineResult['outcome'],
  codes: string[],
): EngineScanOutcome => ({
  kind: 'definite',
  result: {
    engine: 'rspamd',
    engineVersion: '3.12.1',
    outcome,
    score: 1,
    requiredScore: 15,
    action: 'no action',
    reasonCodes: codes,
    signals: [{ name: 'R_SPF_ALLOW', score: -0.2, options: ['+ip4:192.0.2.10'] }],
    auth: {
      spf: { result: 'pass', domain: 'clean.scan.test' },
      dkim: { result: null, signatures: [] },
      dmarc: { result: null, policy: null, domain: null },
      arc: { result: null },
    },
    durationMs: 12,
    settingsVersion: 'rspamd-map/2;p=abc;t=none',
    mappingVersion: 'rspamd-map/2',
  },
});
const failure = (
  outcome: 'timeout' | 'error',
  errorCode: string,
  retryable = true,
): EngineScanOutcome => ({
  kind: 'failure',
  outcome,
  errorCode,
  retryable,
  durationMs: 5,
  engineVersion: null,
});

class ScriptedAdapter implements ScanEngineAdapter {
  readonly name = 'rspamd' as const;
  readonly contexts: EngineScanContext[] = [];
  constructor(private readonly script: Array<EngineScanOutcome | Error>) {}
  async scan(ctx: EngineScanContext): Promise<EngineScanOutcome> {
    this.contexts.push(ctx);
    const next = this.script.shift() ?? definite('clean', ['clean.below_threshold']);
    if (next instanceof Error) throw next;
    return Promise.resolve(next);
  }
}

function setup(
  script: Array<EngineScanOutcome | Error> = [],
  options: { now?: () => Date; failureThreshold?: number } = {},
) {
  const store = new FakeScanStore();
  store.addMessage({
    id: MSG,
    receivedAt: RECEIVED,
    organizationId: ORG,
    direction: 'inbound',
    emlObjectKey: KEY,
    sizeBytes: 100,
    clientIp: '192.0.2.10',
    clientHelo: 'mx.clean.scan.test',
    clientName: 'mx.clean.scan.test',
    envelopeFrom: 'alice@clean.scan.test',
    mtaQueueId: 'ABC123',
    recipients: ['bob@customer.scan.test'],
  });
  const { metrics, registry } = newMetrics();
  const adapter = new ScriptedAdapter(script);
  let clock = 0;
  const breaker = new CircuitBreaker({
    failureThreshold: options.failureThreshold ?? 5,
    failureRatio: 1,
    window: 10,
    openMs: 1000,
    halfOpenProbes: 1,
    now: () => clock,
  });
  const settings = new SettingsResolver({ source: store, config, metrics, logger, ttlMs: 0 });
  const service = new ScanRoundService({
    registration: rspamdRegistration,
    adapter,
    store,
    settings,
    openEml: () => Promise.resolve(Readable.from([Buffer.from('x')])),
    breaker,
    metrics,
    logger,
    budget: { concurrency: 1, timeoutMs: 1000, maxAttempts: 3 },
    requiredEngines: ['rspamd'],
    deadlineSeconds: 1800,
    consumer: 'test.scan.rspamd',
    ...(options.now ? { now: options.now } : {}),
  });
  return { store, service, adapter, registry, breaker, advance: (ms: number) => (clock += ms) };
}

let n = 0;
function parsed(overrides: Partial<{ eventId: string; org: string; key: string }> = {}) {
  n += 1;
  return {
    eventId: overrides.eventId ?? `00000000-0000-7000-8000-${String(n).padStart(12, '0')}`,
    eventType: EventTypes.MessageParsed,
    occurredAt: new Date(Date.now() - 2_000).toISOString(),
    correlationId: 'corr-test-0001',
    organizationId: overrides.org ?? ORG.toString(),
    payload: {
      messageId: MSG.toString(),
      receivedAt: RECEIVED.toISOString(),
      direction: 'inbound',
      emlS3Key: overrides.key ?? KEY,
    },
  } as unknown as EventEnvelope<ScanTriggerPayload>;
}
function rescan(round: number) {
  const e = parsed() as unknown as { eventType: string; payload: Record<string, unknown> };
  e.eventType = EventTypes.MessageRescanRequested;
  e.payload = { ...e.payload, lifecycleRound: round, scanKind: 'rescan' };
  return e as unknown as EventEnvelope<ScanTriggerPayload>;
}

describe('decideOpen (S5 step 3)', () => {
  it('maps the lifecycle under the lock to open / join / skip', () => {
    expect(decideOpen({ state: 'persisted', round: 0 }, 0, 'parsed')).toEqual({
      action: 'open_e3',
    });
    expect(decideOpen({ state: 'scanning', round: 0 }, 0, 'parsed')).toEqual({ action: 'open' });
    expect(decideOpen({ state: 'scanning', round: 2 }, 2, 'rescan')).toEqual({ action: 'open' });
    expect(decideOpen({ state: 'scanning', round: 2 }, 0, 'parsed')).toEqual({
      action: 'skip',
      reason: 'older_round',
    });
    expect(decideOpen({ state: 'scanned', round: 0 }, 0, 'parsed')).toEqual({
      action: 'check_final',
    });
    expect(decideOpen({ state: 'persisted', round: 0 }, 1, 'rescan')).toEqual({
      action: 'skip',
      reason: 'lifecycle_persisted',
    });
    expect(decideOpen({ state: 'approved', round: 0 }, 0, 'parsed')).toEqual({
      action: 'skip',
      reason: 'lifecycle_approved',
    });
  });
});

describe('ScanRoundService (S5)', () => {
  it('opens the round with E3, records the final result and completes scanned', async () => {
    const { store, service, adapter, registry } = setup([
      definite('clean', ['clean.below_threshold']),
    ]);
    expect(await service.handle(parsed())).toBe('handled');
    expect(store.transitions.map((t) => [t.to, t.reason])).toEqual([
      ['scanning', 'scan_started'],
      ['scanned', 'scan_complete'],
    ]);
    expect(store.scans[0]).toMatchObject({
      status: 'completed',
      verdict: 'clean',
      round: 0,
      scanKind: 'initial',
    });
    expect(store.outbox).toEqual([{ outcome: 'scanned', verdict: 'clean', round: 0 }]);
    const rows = store.rowsOf(store.scans[0]!.scanId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ isFinal: true, attempt: 1, outcome: 'clean' });
    expect(rows[0]!.final!.auth?.spf.result).toBe('pass');
    expect(rows[0]!.final!.evidence).toMatchObject({ signals: [{ name: 'R_SPF_ALLOW' }] });
    // The adapter got the trusted envelope of the row and the platform settings.
    expect(adapter.contexts[0]!.envelope).toEqual({
      clientIp: '192.0.2.10',
      clientHelo: 'mx.clean.scan.test',
      clientName: 'mx.clean.scan.test',
      envelopeFrom: 'alice@clean.scan.test',
      recipients: ['bob@customer.scan.test'],
      queueId: 'ABC123',
    });
    expect(adapter.contexts[0]!.settingsVersion).toMatch(/^rspamd-map\/2;p=[0-9a-f]{12};t=none$/);
    const text = await registry.metrics();
    expect(text).toMatch(
      /scan_rounds_completed_total\{outcome="scanned",verdict="clean",scan_kind="initial"[^}]*\} 1/,
    );
    expect(text).toMatch(
      /scan_engine_results_total\{engine="rspamd",outcome="clean",final="true"[^}]*\} 1/,
    );
    expect(text).toMatch(/scan_engine_info\{engine="rspamd",version="3.12.1"[^}]*\} 1/);
    expect(text).toMatch(/scan_event_lag_seconds_count\{[^}]*engine="rspamd"[^}]*\} 1/);
  });

  it('a duplicate event id is a ledger duplicate; another event id finds the final row', async () => {
    const { store, service } = setup();
    const event = parsed();
    await service.handle(event);
    expect(await service.handle(event)).toBe('duplicate');
    expect(await service.handle(parsed())).toBe('duplicate');
    expect(store.rowsOf(store.scans[0]!.scanId)).toHaveLength(1);
    expect(store.transitions.filter((t) => t.to === 'scanned')).toHaveLength(1);
  });

  it('a retryable failure is a non-final attempt and EngineAttemptFailedError; the last attempt finalizes', async () => {
    const { store, service } = setup([
      failure('error', 'unavailable'),
      failure('timeout', 'timeout'),
      failure('error', 'unavailable'),
    ]);
    const event = parsed();
    const first = await service.handle(event).catch((e: unknown) => e);
    expect(first).toBeInstanceOf(EngineAttemptFailedError);
    expect(classifyScanFailure(first)).toBe('retryable');
    await expect(service.handle(event)).rejects.toBeInstanceOf(EngineAttemptFailedError);
    // Attempt 3 of SCAN_RSPAMD_MAX_ATTEMPTS = 3: final error, scan_failed, never clean.
    expect(await service.handle(event)).toBe('handled');
    const rows = store.rowsOf(store.scans[0]!.scanId);
    expect(rows.map((r) => [r.attempt, r.isFinal, r.outcome, r.reasonCodes[0]])).toEqual([
      [1, false, 'error', 'engine.error'],
      [2, false, 'timeout', 'engine.timeout'],
      [3, true, 'error', 'engine.error'],
    ]);
    expect(store.state(MSG)).toEqual({ state: 'scan_failed', round: 0 });
    expect(store.scans[0]).toMatchObject({ status: 'failed', verdict: 'error' });
    expect(store.ledger.has(`test.scan.rspamd:${event.eventId}`)).toBe(true);
  });

  it('a non-retryable failure finalizes at once (eml_unavailable)', async () => {
    const { store, service } = setup([failure('error', 'eml_unavailable', false)]);
    expect(await service.handle(parsed())).toBe('handled');
    expect(store.transitions.at(-1)).toMatchObject({
      to: 'scan_failed',
      reason: 'eml_unavailable',
    });
  });

  it('a mismatched EML key is a final error without a scan', async () => {
    const { store, service, adapter } = setup();
    await service.handle(parsed({ key: 'org/7/eml/x.eml' }));
    expect(adapter.contexts).toHaveLength(0);
    expect(store.rowsOf(store.scans[0]!.scanId)[0]).toMatchObject({
      isFinal: true,
      errorCode: 'eml_key_mismatch',
    });
    expect(store.state(MSG)!.state).toBe('scan_failed');
  });

  it('an infrastructure error is thrown unchanged: no row, transient, no breaker count', async () => {
    const outage = Object.assign(new Error('socket'), { code: 'ECONNRESET' });
    const { store, service, breaker } = setup([outage, outage, outage]);
    for (let i = 0; i < 3; i += 1) {
      const err = await service.handle(parsed()).catch((e: unknown) => e);
      expect(classifyScanFailure(err)).toBe('transient');
    }
    expect(store.rowsOf(store.scans[0]!.scanId)).toEqual([]);
    expect(breaker.state).toBe('closed');
  });

  it('the open breaker fails fast with circuit_open attempts, never calling the engine', async () => {
    const { store, service, adapter, breaker, registry } = setup(
      [failure('error', 'unavailable'), failure('error', 'unavailable')],
      { failureThreshold: 2 },
    );
    const event = parsed();
    await expect(service.handle(event)).rejects.toThrow();
    await expect(service.handle(event)).rejects.toThrow();
    expect(breaker.state).toBe('open');
    expect(await service.handle(event)).toBe('handled');
    expect(adapter.contexts).toHaveLength(2);
    const rows = store.rowsOf(store.scans[0]!.scanId);
    expect(rows.at(-1)).toMatchObject({
      isFinal: true,
      errorCode: 'circuit_open',
      reasonCodes: ['engine.circuit_open'],
    });
    // Counted as a result, but only the two engine calls are latency observations.
    const text = await registry.metrics();
    expect(text).toMatch(/scan_engine_results_total\{[^}]*outcome="error",final="true"[^}]*\} 1/);
    expect(text).toMatch(/scan_engine_duration_seconds_count\{[^}]*outcome="error"[^}]*\} 2/);
  });

  it('records a failure as final once the round deadline passed', async () => {
    let now = new Date('2026-11-05T10:00:00Z');
    const { store, service } = setup([failure('timeout', 'timeout')], { now: () => now });
    const event = parsed();
    // Open the round at t0, then fail after the deadline.
    const opened = await store.openRound({
      message: store.messages.get(MSG.toString())!,
      round: 0,
      scanKind: 'initial',
      trigger: 'parsed',
      engine: 'rspamd',
      eventId: event.eventId,
      correlationId: 'c',
      requiredEngines: ['rspamd'],
      deadlineSeconds: 10,
      now,
    });
    expect(opened.kind).toBe('open');
    now = new Date(now.getTime() + 60_000);
    expect(await service.handle(event)).toBe('handled');
    expect(store.rowsOf(store.scans[0]!.scanId)[0]).toMatchObject({
      isFinal: true,
      outcome: 'timeout',
    });
  });

  it('skips a message of another organization (tenant from the envelope) with a ledger row', async () => {
    const { store, service, registry } = setup();
    const event = parsed({ org: '43' });
    expect(await service.handle(event)).toBe('handled');
    expect(store.scans).toHaveLength(0);
    expect(store.ledger.has(`test.scan.rspamd:${event.eventId}`)).toBe(true);
    expect(await registry.metrics()).toMatch(
      /scan_events_skipped_total\{engine="rspamd",reason="message_not_found"/,
    );
  });

  it('rescans open a new round and leave the old one untouched; an old-round event is skipped', async () => {
    const { store, service } = setup([
      definite('clean', ['clean.below_threshold']),
      definite('spam', ['spam.score']),
    ]);
    await service.handle(parsed());
    store.setState(MSG, 'scanning', 1); // the api applied E19
    expect(await service.handle(rescan(1))).toBe('handled');
    expect(store.scans.map((s) => [s.round, s.scanKind, s.status, s.verdict])).toEqual([
      [0, 'initial', 'completed', 'clean'],
      [1, 'rescan', 'completed', 'spam'],
    ]);
    expect(store.state(MSG)).toEqual({ state: 'scanned', round: 1 });
    // A late parsed.v1 (round 0) after the rescan: older round, skipped.
    expect(await service.handle(parsed())).toBe('handled');
    expect(store.scans).toHaveLength(2);
  });

  it('a superseded round completes its row but writes no scanned event', async () => {
    const { store, service } = setup([failure('error', 'unavailable')]);
    const event = parsed();
    await expect(service.handle(event)).rejects.toThrow();
    store.setState(MSG, 'expired', 0);
    // Another delivery finalizes after the message expired.
    const { store: _s } = { store };
    void _s;
    store.setState(MSG, 'scanning', 0);
    // Simulate the round being superseded between open and completion.
    const original = store.finalize.bind(store);
    store.finalize = async (input) => {
      store.setState(MSG, 'scanning', 1);
      return original(input);
    };
    expect(await service.handle(event)).toBe('handled');
    expect(store.scans[0]!.status).toBe('completed');
    expect(store.outbox).toEqual([]);
  });

  it('applies the tenant settings and their version', async () => {
    const { store, service, adapter } = setup();
    store.settings.set(`${ORG.toString()}:rspamd`, { settings: { spamScore: 5 }, version: 4 });
    await service.handle(parsed());
    expect(adapter.contexts[0]!.settings).toMatchObject({ spamScore: 5, suspiciousScore: 4 });
    expect(adapter.contexts[0]!.settingsVersion).toMatch(/;t=4$/);
  });

  it('the adapter sees EmlUnavailableError from the opener as a typed error', () => {
    const err = new EmlUnavailableError();
    expect(classifyScanFailure(err)).toBe('retryable');
    expect(err.name).toBe('EmlUnavailableError');
  });

  it('carries engine child rows into the final row and records a skipped outcome (step 4.2 A12)', async () => {
    const childRows = {
      attachments: [
        {
          attachmentId: 9n,
          contentVersion: '0123456789abcdef',
          result: { partIndex: 1 } as never,
        },
      ],
      sandbox: [],
    };
    const base = definite('clean', ['clean.no_findings']) as Extract<
      EngineScanOutcome,
      { kind: 'definite' }
    >;
    const withRows: EngineScanOutcome = { ...base, childRows };
    const { store, service } = setup([withRows]);
    expect(await service.handle(parsed())).toBe('handled');
    const final = store.rowsOf(store.scans[0]!.scanId).find((r) => r.isFinal)!;
    expect(final.final!.childRows).toEqual(childRows);

    const skipped: EngineScanOutcome = {
      kind: 'definite',
      result: { ...base.result, outcome: 'skipped', reasonCodes: ['attachment.none'], signals: [] },
      childRows: {},
    };
    const second = setup([skipped]);
    expect(await second.service.handle(parsed())).toBe('handled');
    const row = second.store.rowsOf(second.store.scans[0]!.scanId).find((r) => r.isFinal)!;
    expect(row).toMatchObject({ outcome: 'skipped', reasonCodes: ['attachment.none'] });
    // A skipped required engine satisfies completion and never decides the verdict.
    expect(second.store.scans[0]).toMatchObject({ status: 'completed', verdict: 'unknown' });
  });
});
