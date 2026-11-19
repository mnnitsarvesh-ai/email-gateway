import { createHmac } from 'node:crypto';
import { smtpAuthRecordedV1, smtpSubmissionRecordedV1 } from '@email-gateway/event-contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  metricValue,
  newMetrics,
  prismaService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import {
  type AuthTelemetry,
  AtoTelemetryRecorder,
  type SubmissionTelemetry,
  telemetryInstanceName,
} from './telemetry-recorder';

const bigintSafe = (_: string, v: unknown) => (typeof v === 'bigint' ? String(v) : v);

interface OutboxData {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  correlationId: string;
  payload: { producer: { instance: string }; entries: Record<string, unknown>[] };
}

function harness(env: Record<string, string> = {}, platform: bigint | null = 1n) {
  const inserts: OutboxData[][] = [];
  const createMany = vi.fn(({ data }: { data: OutboxData[] }) => {
    inserts.push(data);
    return Promise.resolve({ count: data.length });
  });
  const findFirst = vi.fn(() => Promise.resolve(platform === null ? null : { id: platform }));
  const metrics = newMetrics();
  const config = testConfig(env);
  const recorder = new AtoTelemetryRecorder(
    prismaService({ messageOutbox: { createMany }, organization: { findFirst } }),
    metrics,
    config,
    silentLogger(),
  );
  return { recorder, createMany, findFirst, inserts, metrics, config };
}

const auth = (overrides: Partial<AuthTelemetry> = {}): AuthTelemetry => ({
  occurredAt: new Date('2026-11-18T10:00:00.000Z'),
  result: 'ok',
  mechanism: 'plain',
  clientIp: '203.0.113.7',
  connector: { id: 5n, organizationId: 7n },
  username: null,
  failureReason: null,
  ...overrides,
});

const submission = (overrides: Partial<SubmissionTelemetry> = {}): SubmissionTelemetry => ({
  occurredAt: new Date('2026-11-18T10:00:01.000Z'),
  organizationId: 7n,
  context: 'submission',
  connectorId: 5n,
  connectorAuthType: 'sasl',
  queueId: '4XyZ1abC',
  clientIp: '203.0.113.7',
  heloName: 'mail.tenant.test',
  tlsProtocol: 'TLSv1.3',
  senderAddress: 'Alice@Tenant.test',
  recipientCount: 2,
  sizeBytes: 1234,
  ...overrides,
});

describe('AtoTelemetryRecorder (step 8.4 D4)', () => {
  afterEach(() => vi.useRealTimers());

  it('groups by organization and kind into one multi-row outbox insert per flush', async () => {
    const h = harness();
    h.recorder.recordAuth(auth());
    h.recorder.recordAuth(auth({ connector: { id: 9n, organizationId: 8n } }));
    h.recorder.recordSubmission(submission());
    h.recorder.recordAuth(auth({ result: 'fail', failureReason: 'bad_credentials' }));
    expect(h.recorder.size).toBe(4);
    await h.recorder.flush();
    expect(h.createMany).toHaveBeenCalledTimes(1);
    const rows = h.inserts[0]!;
    expect(rows.map((r) => [r.organizationId, r.eventType, r.payload.entries.length])).toEqual([
      [7n, 'smtp.auth.recorded.v1', 2],
      [8n, 'smtp.auth.recorded.v1', 1],
      [7n, 'smtp.submission.recorded.v1', 1],
    ]);
    for (const row of rows) {
      expect(row.aggregateType).toBe('smtp_telemetry');
      expect(row.aggregateId).toBe(String(row.organizationId));
      expect(row.eventId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/);
      expect(row.payload.producer.instance).toBe(h.recorder.instance);
      const schema =
        row.eventType === 'smtp.auth.recorded.v1' ? smtpAuthRecordedV1 : smtpSubmissionRecordedV1;
      expect(schema.safeParse(row.payload).success).toBe(true);
    }
    expect(rows[0]!.payload.entries.map((e) => e.seq)).toEqual([0, 1]);
    expect(rows[2]!.payload.entries[0]).toMatchObject({
      senderAddress: 'alice@tenant.test',
      connectorId: '5',
      queueId: '4XyZ1abC',
      tlsProtocol: 'TLSv1.3',
    });
    expect(h.recorder.size).toBe(0);
    expect(
      await metricValue(h.metrics, 'smtp_ato_telemetry_total', { kind: 'auth', result: 'flushed' }),
    ).toBe(3);
    expect(
      await metricValue(h.metrics, 'smtp_ato_telemetry_total', {
        kind: 'submission',
        result: 'recorded',
      }),
    ).toBe(1);
  });

  it('splits a group into batches of SMTP_ATO_TELEMETRY_BATCH_MAX', async () => {
    const h = harness({ SMTP_ATO_TELEMETRY_BATCH_MAX: '10' });
    for (let i = 0; i < 25; i += 1) h.recorder.recordAuth(auth());
    await h.recorder.flush();
    expect(h.inserts[0]!.map((r) => r.payload.entries.length)).toEqual([10, 10, 5]);
    expect(h.inserts[0]![2]!.payload.entries.map((e) => e.seq)).toEqual([0, 1, 2, 3, 4]);
  });

  it('hashes unknown usernames (16 hex of HMAC) into platform-organization batches', async () => {
    const h = harness({}, 1n);
    const generated = `egc-${'b'.repeat(20)}`;
    h.recorder.recordAuth(
      auth({
        result: 'fail',
        failureReason: 'bad_credentials',
        connector: null,
        username: generated,
      }),
    );
    h.recorder.recordAuth(
      auth({ result: 'fail', failureReason: 'malformed', connector: null, username: 'Someone' }),
    );
    await h.recorder.flush();
    const [row] = h.inserts[0]!;
    expect(row!.organizationId).toBe(1n);
    const key = h.config.SMTP_ATO_USERNAME_HASH_KEY!;
    const expected = createHmac('sha256', key).update(generated).digest('hex').slice(0, 16);
    expect(row!.payload.entries[0]).toMatchObject({
      usernameClass: 'unknown_generated_format',
      usernameHash: expected,
      connectorId: null,
    });
    expect(row!.payload.entries[1]).toMatchObject({ usernameClass: 'unknown_other' });
    expect(JSON.stringify(h.inserts, bigintSafe)).not.toContain(generated);
    expect(JSON.stringify(h.inserts, bigintSafe)).not.toContain('Someone');
    // Resolved once.
    h.recorder.recordAuth(auth({ result: 'fail', failureReason: 'malformed', connector: null }));
    await h.recorder.flush();
    expect(h.findFirst).toHaveBeenCalledTimes(1);
  });

  it('drops unknown-username entries when no platform organization exists (counted)', async () => {
    const h = harness({}, null);
    h.recorder.recordAuth(auth({ result: 'fail', failureReason: 'malformed', connector: null }));
    h.recorder.recordAuth(auth());
    await h.recorder.flush();
    expect(h.inserts[0]!.map((r) => r.organizationId)).toEqual([7n]);
    expect(
      await metricValue(h.metrics, 'smtp_ato_telemetry_total', { kind: 'auth', result: 'dropped' }),
    ).toBe(1);
  });

  it('drops the newest entry when the buffer is full (never blocks)', async () => {
    const h = harness({ SMTP_ATO_TELEMETRY_BUFFER_MAX: '1000' });
    for (let i = 0; i < 1003; i += 1) h.recorder.recordAuth(auth());
    expect(h.recorder.size).toBe(1000);
    expect(
      await metricValue(h.metrics, 'smtp_ato_telemetry_total', { kind: 'auth', result: 'dropped' }),
    ).toBe(3);
    expect(await metricValue(h.metrics, 'smtp_ato_telemetry_buffer_entries')).toBe(1000);
  });

  it('keeps entries on a database error and expires them after SMTP_ATO_TELEMETRY_MAX_AGE_MS', async () => {
    vi.useFakeTimers({ now: new Date('2026-11-18T10:00:00Z') });
    const h = harness({ SMTP_ATO_TELEMETRY_MAX_AGE_MS: '5000' });
    h.createMany.mockRejectedValueOnce(new Error('db down'));
    h.recorder.recordAuth(auth());
    await h.recorder.flush();
    expect(h.recorder.size).toBe(1);
    expect(
      await metricValue(h.metrics, 'smtp_ato_telemetry_total', { kind: 'auth', result: 'error' }),
    ).toBe(1);
    // Retried successfully within the age bound.
    await h.recorder.flush();
    expect(h.inserts).toHaveLength(1);
    expect(h.recorder.size).toBe(0);

    h.createMany.mockRejectedValue(new Error('db down'));
    h.recorder.recordSubmission(submission());
    await h.recorder.flush();
    vi.setSystemTime(new Date('2026-11-18T10:00:06Z'));
    await h.recorder.flush();
    expect(h.recorder.size).toBe(0);
    expect(
      await metricValue(h.metrics, 'smtp_ato_telemetry_total', {
        kind: 'submission',
        result: 'expired',
      }),
    ).toBe(1);
  });

  it('records nothing when SMTP_ATO_TELEMETRY_ENABLED=false', async () => {
    const h = harness({ SMTP_ATO_TELEMETRY_ENABLED: 'false' });
    h.recorder.recordAuth(auth());
    h.recorder.recordSubmission(submission());
    expect(h.recorder.size).toBe(0);
    h.recorder.onApplicationBootstrap();
    await h.recorder.onModuleDestroy();
    expect(h.createMany).not.toHaveBeenCalled();
  });

  it('skips submissions without a usable sender and normalizes optional fields', async () => {
    const h = harness();
    h.recorder.recordSubmission(submission({ senderAddress: '' }));
    h.recorder.recordSubmission(submission({ senderAddress: undefined }));
    h.recorder.recordSubmission(
      submission({
        queueId: 'not a queue id',
        heloName: 'bad helo',
        tlsProtocol: '',
        clientIp: 'unknown',
        recipientCount: 50_000,
      }),
    );
    await h.recorder.flush();
    const entries = h.inserts[0]![0]!.payload.entries;
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      queueId: null,
      heloName: null,
      tlsProtocol: null,
      clientIp: null,
      recipientCount: 10_000,
    });
  });

  it('flushes on its timer and once more on shutdown', async () => {
    vi.useFakeTimers();
    const h = harness({ SMTP_ATO_TELEMETRY_FLUSH_MS: '1000' });
    h.recorder.onApplicationBootstrap();
    h.recorder.recordAuth(auth());
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.createMany).toHaveBeenCalledTimes(1);
    h.recorder.recordAuth(auth());
    await h.recorder.onModuleDestroy();
    expect(h.createMany).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(5000);
    expect(h.createMany).toHaveBeenCalledTimes(2);
  });

  it('bounds the shutdown flush to 5 s on a hanging database', async () => {
    vi.useFakeTimers();
    const h = harness();
    h.createMany.mockImplementation(() => new Promise(() => undefined));
    h.recorder.recordAuth(auth());
    const done = h.recorder.onModuleDestroy();
    await vi.advanceTimersByTimeAsync(5000);
    await expect(done).resolves.toBeUndefined();
  });

  it('derives a contract-safe producer instance name', () => {
    expect(telemetryInstanceName('smtp adapter/host_1', 42)).toBe('smtp-adapter-host_1.42');
    expect(telemetryInstanceName('x'.repeat(80), 1).length).toBeLessThanOrEqual(64);
  });
});
