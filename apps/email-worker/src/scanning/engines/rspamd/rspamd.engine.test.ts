import { Readable } from 'node:stream';
import {
  type RspamdCheckInput,
  type RspamdCheckResult,
  RspamdHttpError,
  RspamdProtocolError,
  RspamdRequestError,
  RspamdSoftRejectError,
  RspamdTimeoutError,
  RspamdUnavailableError,
} from '@email-gateway/rspamd';
import { RSPAMD_PLATFORM_DEFAULTS, resolveRspamdSettings } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { EmlUnavailableError, type EngineScanContext } from '../../engine';
import { failureFromRspamd, RspamdEngine, type RspamdScanClient } from './rspamd.engine';

const settings = (() => {
  const r = resolveRspamdSettings(RSPAMD_PLATFORM_DEFAULTS, null);
  if (!r.ok) throw new Error('x');
  return r.settings;
})();

function ctx(overrides: Partial<EngineScanContext> = {}, open?: EngineScanContext['eml']['open']) {
  return {
    organizationId: 42n,
    messageId: 7n,
    receivedAt: new Date(),
    round: 1,
    scanId: 9n,
    scanKind: 'rescan',
    direction: 'inbound',
    envelope: {
      clientIp: '192.0.2.10',
      clientHelo: 'mx.clean.scan.test',
      clientName: 'mx.clean.scan.test',
      envelopeFrom: 'alice@clean.scan.test',
      recipients: ['bob@customer.scan.test'],
      queueId: 'Q1',
    },
    eml: {
      key: 'org/42/eml/x.eml',
      sizeBytes: 5,
      open: open ?? (() => Promise.resolve(Readable.from([Buffer.from('hello')]))),
    },
    settings,
    settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
    ...overrides,
  } satisfies EngineScanContext;
}

class FakeClient implements RspamdScanClient {
  readonly inputs: RspamdCheckInput[] = [];
  versionCalls = 0;
  constructor(
    private readonly answer: () => Promise<RspamdCheckResult>,
    private readonly versionAnswer: () => Promise<string> = () => Promise.resolve('3.12.0'),
  ) {}
  check(input: RspamdCheckInput): Promise<RspamdCheckResult> {
    this.inputs.push(input);
    return this.answer();
  }
  version(): Promise<string> {
    this.versionCalls += 1;
    return this.versionAnswer();
  }
}

const result = (
  reply: Record<string, unknown>,
  serverVersion: string | null = '3.12.1',
  rcptTruncated = false,
): RspamdCheckResult => ({
  reply: {
    is_skipped: false,
    score: 0,
    required_score: 15,
    action: 'no action',
    symbols: {},
    ...reply,
  },
  serverVersion,
  rcptTruncated,
  omittedHeaders: [],
  durationMs: 3,
});

const engine = (
  client: RspamdScanClient,
  extra: Partial<ConstructorParameters<typeof RspamdEngine>[0]> = {},
) =>
  new RspamdEngine({
    client,
    maxBytes: 1000,
    versionTtlMs: 60_000,
    controllerConfigured: true,
    ...extra,
  });

describe('RspamdEngine (S9)', () => {
  it('maps a complete reply into a validated NormalizedEngineResult with auth and bounded signals', async () => {
    const options = Array.from({ length: 8 }, (_, i) => `opt-${String(i)}-${'x'.repeat(300)}`);
    const client = new FakeClient(() =>
      Promise.resolve(
        result({
          score: 0.1,
          symbols: {
            R_SPF_ALLOW: { name: 'R_SPF_ALLOW', score: -0.2, options: ['+ip4:192.0.2.10'] },
            R_DKIM_ALLOW: {
              name: 'R_DKIM_ALLOW',
              score: -0.2,
              options: ['clean.scan.test:s=eg2026'],
            },
            DKIM_TRACE: { name: 'DKIM_TRACE', score: 0, options: ['clean.scan.test:+'] },
            DMARC_POLICY_ALLOW: {
              name: 'DMARC_POLICY_ALLOW',
              score: -0.5,
              options: ['clean.scan.test', 'reject'],
            },
            BIG: { name: 'BIG', score: 0.3, options },
          },
        }),
      ),
    );
    const outcome = await engine(client).scan(ctx(), AbortSignal.timeout(1000));
    expect(outcome.kind).toBe('definite');
    if (outcome.kind !== 'definite') return;
    expect(outcome.result).toMatchObject({
      engine: 'rspamd',
      engineVersion: '3.12.1',
      outcome: 'clean',
      reasonCodes: ['clean.below_threshold'],
      mappingVersion: 'rspamd-map/2',
      settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
      auth: {
        spf: { result: 'pass', domain: 'clean.scan.test' },
        dkim: {
          result: 'pass',
          signatures: [{ domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' }],
        },
        dmarc: { result: 'pass', policy: 'reject', domain: 'clean.scan.test' },
      },
    });
    const big = outcome.result.signals.find((s) => s.name === 'BIG')!;
    expect(big.options).toHaveLength(5);
    expect(big.options.every((o) => o.length <= 200)).toBe(true);
    // The trusted envelope and an ids-only log tag; no User header input for inbound mail.
    expect(client.inputs[0]).toMatchObject({
      sizeBytes: 5,
      logTag: 'm7r1',
      envelope: {
        direction: 'inbound',
        organizationId: 42n,
        clientName: 'mx.clean.scan.test',
        queueId: 'Q1',
      },
    });
    expect(client.versionCalls).toBe(0);
  });

  it('GTUBE passthrough is spam, not a skip', async () => {
    const client = new FakeClient(() =>
      Promise.resolve(
        result({
          is_skipped: true,
          passthrough_module: 'GTUBE',
          score: 15,
          action: 'reject',
          symbols: { GTUBE: { name: 'GTUBE', score: 0, options: [] } },
        }),
      ),
    );
    const outcome = await engine(client).scan(ctx(), AbortSignal.timeout(1000));
    expect(outcome).toMatchObject({ kind: 'definite', result: { outcome: 'spam' } });
  });

  it('refuses a message above SCAN_RSPAMD_MAX_BYTES without calling Rspamd (unknown, engine.too_large)', async () => {
    const client = new FakeClient(() => Promise.reject(new Error('must not be called')));
    const outcome = await engine(client, { maxBytes: 4 }).scan(ctx(), AbortSignal.timeout(1000));
    expect(outcome).toMatchObject({
      kind: 'definite',
      result: { outcome: 'unknown', reasonCodes: ['engine.too_large'], signals: [], score: null },
    });
    expect(client.inputs).toHaveLength(0);
  });

  it('a missing EML is the non-retryable failure eml_unavailable (not an engine fault)', async () => {
    const client = new FakeClient(() => Promise.reject(new Error('unused')));
    const outcome = await engine(client).scan(
      ctx({}, () => Promise.reject(new EmlUnavailableError())),
      AbortSignal.timeout(1000),
    );
    expect(outcome).toMatchObject({
      kind: 'failure',
      outcome: 'error',
      errorCode: 'eml_unavailable',
      retryable: false,
      engineFault: false,
    });
  });

  it('an S3 outage is thrown (infrastructure), never an engine result', async () => {
    const s3 = Object.assign(new Error('s3'), { name: 'S3Stalled' });
    const client = new FakeClient(() => Promise.reject(s3));
    await expect(engine(client).scan(ctx(), AbortSignal.timeout(1000))).rejects.toBe(s3);
    await expect(
      engine(client).scan(
        ctx({}, () => Promise.reject(s3)),
        AbortSignal.timeout(1000),
      ),
    ).rejects.toBe(s3);
  });

  it('R0: every transport failure is an attempt failure, never clean', () => {
    expect(failureFromRspamd(new RspamdTimeoutError('checkv2', 10), 1, null)).toMatchObject({
      outcome: 'timeout',
      errorCode: 'timeout',
      retryable: true,
    });
    expect(
      failureFromRspamd(new RspamdUnavailableError('checkv2', 'ECONNREFUSED'), 1, null),
    ).toMatchObject({
      outcome: 'error',
      errorCode: 'unavailable',
      retryable: true,
    });
    expect(failureFromRspamd(new RspamdHttpError('checkv2', 503), 1, null).retryable).toBe(true);
    expect(failureFromRspamd(new RspamdHttpError('checkv2', 413), 1, null).retryable).toBe(false);
    expect(
      failureFromRspamd(new RspamdProtocolError('checkv2', 'invalid_json'), 1, null).errorCode,
    ).toBe('protocol_error');
    expect(failureFromRspamd(new RspamdSoftRejectError('checkv2'), 1, null).errorCode).toBe(
      'soft_reject',
    );
    expect(
      failureFromRspamd(new RspamdRequestError('checkv2', 'From', 'x'), 1, null),
    ).toMatchObject({
      retryable: false,
      engineFault: false,
    });
  });

  it('uses the controller version when the reply has no Server header, cached for the TTL', async () => {
    let now = 0;
    const client = new FakeClient(() =>
      Promise.resolve(result({ symbols: { X: { name: 'X', score: 0 } } }, null)),
    );
    const e = engine(client, { now: () => now });
    const a = await e.scan(ctx(), AbortSignal.timeout(1000));
    expect(a).toMatchObject({ result: { engineVersion: '3.12.0' } });
    await e.scan(ctx(), AbortSignal.timeout(1000));
    expect(client.versionCalls).toBe(1);
    now = 61_000;
    await e.scan(ctx(), AbortSignal.timeout(1000));
    expect(client.versionCalls).toBe(2);
    const noController = engine(client, { controllerConfigured: false });
    const b = await noController.scan(ctx(), AbortSignal.timeout(1000));
    expect(b).toMatchObject({ result: { engineVersion: 'unknown' } });
  });

  it('flags truncated recipients in the evidence', async () => {
    const client = new FakeClient(() =>
      Promise.resolve(result({ symbols: { X: { name: 'X', score: 0 } } }, '3.12.1', true)),
    );
    const outcome = await engine(client).scan(ctx(), AbortSignal.timeout(1000));
    expect(outcome).toMatchObject({ kind: 'definite', evidence: { rcptTruncated: true } });
  });
});
