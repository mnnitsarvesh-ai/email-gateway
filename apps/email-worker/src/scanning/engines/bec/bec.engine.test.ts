import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import {
  type AiAssessment,
  type AiInput,
  type AuthResultRow,
  type BecAiProvider,
  type BecHeaders,
  contextKeyHash,
  canonicalPair,
  FakeBecLlmProvider,
  loadBecStaticData,
  loadLocalModel,
} from '@email-gateway/bec';
import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import {
  BEC_PLATFORM_DEFAULTS,
  type BecEffectiveSettings,
  becRuleEvidenceSchema,
  normalizedEngineResultSchema,
  resolveBecSettings,
  URL_PLATFORM_DEFAULTS,
  resolveUrlSettings,
  type UrlEffectiveSettings,
} from '@email-gateway/security-contracts';
import { DEFAULT_LOOKALIKE_PARAMS } from '@email-gateway/url-security';
import { beforeEach, describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../../circuit-breaker';
import type { EngineDefinite, EngineFailure, EngineScanContext } from '../../engine';
import type { PartPrefixRead, PartRead } from '../../parts/part-reader';
import { BecAiLayer } from './ai-layer';
import { BecMetrics } from './bec-metrics';
import {
  type BecFinalRow,
  type BecHeaderRead,
  type BecHistoryRead,
  type BecParseRow,
  type BecReadScope,
  type BecRoundRow,
  type BecStore,
  type BecTenantRecord,
  type BecUrlResultRow,
  InconsistentBecReadError,
} from './bec-store';
import { BecEngine } from './bec.engine';
import type { BudgetResult } from './bec-metrics';

const logger = createLogger({ service: 'test', level: 'silent' });
const ORG = 77n;
const MSG = 5005n;
const SCAN = 900n;
const RECEIVED = new Date('2026-11-06T09:15:00.000Z');
const KEY = 'test-bec-context-hmac-key-0123456789abcdef';
const data = loadBecStaticData();
const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

const GMAIL_AUTH: AuthResultRow = {
  spf: 'pass',
  spfDomain: 'gmail.com',
  dkim: 'pass',
  dkimSignatures: [{ domain: 'gmail.com', result: 'pass', selector: 's1' }],
  dmarc: 'pass',
  dmarcPolicy: 'reject',
  dmarcDomain: 'gmail.com',
  arc: null,
};

const CEO_TEXT =
  'Hi, are you at your desk? I need you to buy gift cards for a client presentation today. ' +
  'Keep this confidential, I am in a meeting and cannot talk now. It is urgent, send me the codes.';

class FakeStore implements BecStore {
  round: BecRoundRow | null = {
    round: 0,
    scanKind: 'initial',
    requiredEngines: ['rspamd', 'url', 'bec'],
  };
  finals: BecFinalRow[] = [
    { engine: 'rspamd', outcome: 'clean' },
    { engine: 'url', outcome: 'skipped' },
  ];
  auth: AuthResultRow | null = GMAIL_AUTH;
  urls: BecUrlResultRow[] = [];
  headers: BecHeaders = {
    From: ['Anita Sharma <anita.sharma.office@gmail.com>'],
    To: ['finance@acmecorp.test'],
    Subject: ['Quick favour'],
  };
  headersTruncated = false;
  parse: BecParseRow | null = {
    status: 'parsed',
    limitsExceeded: [],
    defects: [],
    textBody: { key: null, sha256: null, sizeBytes: null },
    htmlBody: { key: null, sha256: null, sizeBytes: null },
  };
  subject: string | null = 'Quick favour';
  tenant: BecTenantRecord = {
    tenantDomains: ['acmecorp.test'],
    executives: [
      {
        publicId: '0193a000-0000-7000-8000-000000000001',
        name: 'Anita Sharma',
        aliases: [],
        knownAddresses: ['anita.sharma@acmecorp.test'],
      },
    ],
    vendors: [],
    trustedSenders: [],
    suppressions: [],
    urlSettingsRow: null,
  };
  history = new Map<string, BecHistoryRead>();
  failOn: { read: string; error: Error } | null = null;
  readonly calls: string[] = [];

  private guard(read: string): void {
    this.calls.push(read);
    if (this.failOn?.read === read) throw this.failOn.error;
  }
  loadRound(): Promise<BecRoundRow | null> {
    this.guard('scan');
    return Promise.resolve(this.round);
  }
  loadFinals(_: BecReadScope, engines: readonly string[]): Promise<BecFinalRow[]> {
    this.guard('finals');
    return Promise.resolve(this.finals.filter((f) => engines.includes(f.engine)));
  }
  loadAuth(): Promise<AuthResultRow | null> {
    this.guard('auth');
    return Promise.resolve(this.auth);
  }
  loadUrlResults(): Promise<BecUrlResultRow[]> {
    this.guard('urls');
    return Promise.resolve(this.urls);
  }
  loadHeaders(): Promise<BecHeaderRead> {
    this.guard('headers');
    return Promise.resolve({ headers: this.headers, truncated: this.headersTruncated });
  }
  loadParse(): Promise<BecParseRow | null> {
    this.guard('parse');
    return Promise.resolve(this.parse);
  }
  loadSubject(): Promise<string | null> {
    this.guard('message');
    return Promise.resolve(this.subject);
  }
  tenantData(): Promise<BecTenantRecord> {
    this.guard('tenant');
    return Promise.resolve(this.tenant);
  }
  loadHistory(
    _: bigint,
    scope: 'sender' | 'pair',
    keys: readonly string[],
  ): Promise<BecHistoryRead[]> {
    this.guard('history');
    return Promise.resolve(
      keys.map((k) => this.history.get(`${scope}:${k}`)).filter((r): r is BecHistoryRead => !!r),
    );
  }
}

class FakeParts {
  readonly objects = new Map<string, Buffer>();
  prefixReads = 0;
  read(key: string, sizeBytes: number, sha256: string): Promise<PartRead> {
    const bytes = this.objects.get(key);
    if (!bytes) return Promise.resolve({ kind: 'missing' });
    if (bytes.length !== sizeBytes || sha(bytes) !== sha256)
      return Promise.resolve({ kind: 'integrity' });
    return Promise.resolve({ kind: 'ok', bytes });
  }
  readPrefix(key: string, maxBytes: number): Promise<PartPrefixRead> {
    this.prefixReads += 1;
    const bytes = this.objects.get(key);
    if (!bytes) return Promise.resolve({ kind: 'missing' });
    return Promise.resolve({ kind: 'ok', bytes: bytes.subarray(0, maxBytes) });
  }
}

class CountingProvider implements BecAiProvider {
  readonly kind = 'llm' as const;
  readonly modelId = 'fake';
  readonly modelVersion = 'fake/1';
  calls = 0;
  private readonly inner = new FakeBecLlmProvider({ nodeEnv: 'test' });
  assess(input: AiInput, signal: AbortSignal): Promise<AiAssessment> {
    this.calls += 1;
    return this.inner.assess(input, signal);
  }
}

class FixedBudget {
  checks = 0;
  constructor(public result: BudgetResult) {}
  check(): Promise<BudgetResult> {
    this.checks += 1;
    return Promise.resolve(this.result);
  }
}

const urlSettings = (): UrlEffectiveSettings => {
  const r = resolveUrlSettings(
    {
      scanTimeFetch: URL_PLATFORM_DEFAULTS.scanTimeFetch,
      rewrite: { ...URL_PLATFORM_DEFAULTS.rewrite },
      dynamicInspection: URL_PLATFORM_DEFAULTS.dynamicInspection,
    },
    null,
  );
  if (!r.ok) throw new Error('url settings');
  return r.settings;
};

function settings(override: Record<string, unknown> | null = null): BecEffectiveSettings {
  const r = resolveBecSettings(
    { ...BEC_PLATFORM_DEFAULTS, llmMode: 'active', localModelMode: 'active' },
    override,
  );
  if (!r.ok) throw new Error(JSON.stringify(r.violations));
  return r.settings;
}

function build(
  options: { budget?: FixedBudget; llm?: CountingProvider | null; textMaxBytes?: number } = {},
) {
  const store = new FakeStore();
  const parts = new FakeParts();
  const registry = new MetricsService({ service: 'bec-test' });
  const metrics = BecMetrics.for(registry);
  const llm = options.llm === undefined ? new CountingProvider() : options.llm;
  const budget = options.budget ?? new FixedBudget('allowed');
  const breaker = new CircuitBreaker({
    failureThreshold: 2,
    failureRatio: 1,
    window: 10,
    openMs: 60_000,
    halfOpenProbes: 1,
  });
  const ai = new BecAiLayer({
    local: { active: loadLocalModel('bec-lr/1'), shadow: null },
    llm: { provider: 'fake', active: llm, shadow: null },
    budget,
    breaker,
    concurrency: 2,
    timeoutMs: 5_000,
    minScore: 15,
    maxExcerptChars: 1_500,
    metrics,
    logger,
  });
  const engine = new BecEngine({
    store,
    parts,
    data,
    ai,
    dependencies: { auth: 'rspamd', url: 'url' },
    historyKey: KEY,
    limits: {
      textMaxBytes: options.textMaxBytes ?? 65_536,
      textMaxChars: 40_000,
      textTimeoutMs: 2_000,
      historyMaxRecipients: 50,
      historyMinMessages: 3,
      suppressionMaxWeight: 40,
    },
    lookalike: DEFAULT_LOOKALIKE_PARAMS,
    platformExtraDomains: [],
    urlSettings,
    readiness: { localModel: 'bec-lr/1' },
    metrics,
    logger,
    now: () => new Date('2026-11-06T09:20:00.000Z'),
  });
  return { engine, store, parts, registry, budget, llm, breaker };
}

function ctx(
  overrides: Partial<EngineScanContext> = {},
  s: BecEffectiveSettings = settings(),
): EngineScanContext {
  return {
    organizationId: ORG,
    messageId: MSG,
    receivedAt: RECEIVED,
    round: 0,
    scanId: SCAN,
    scanKind: 'initial',
    direction: 'inbound',
    envelope: {
      clientIp: '198.51.100.23',
      clientHelo: 'mail.gmail.test',
      clientName: 'mail.gmail.test',
      envelopeFrom: 'anita.sharma.office@gmail.com',
      recipients: ['finance@acmecorp.test'],
      queueId: 'Q1',
    },
    eml: {
      key: `org/${ORG.toString()}/eml/m.eml`,
      sizeBytes: 10,
      open: () => Promise.resolve(Readable.from([])),
    },
    settings: s,
    settingsVersion: 'bec-map/1;p=000000000000;t=none',
    ...overrides,
  };
}

function withText(
  store: FakeStore,
  parts: FakeParts,
  text: string,
  key = `org/${ORG.toString()}/part/t1`,
): void {
  const bytes = Buffer.from(text, 'utf8');
  parts.objects.set(key, bytes);
  store.parse = {
    ...store.parse!,
    textBody: { key, sha256: sha(bytes), sizeBytes: bytes.length },
  };
}

/** A DKIM-aligned, authenticated partner sender (nothing identity-related fires). */
function partner(store: FakeStore, subject: string): EngineScanContext['envelope'] {
  store.headers = { From: ['Bob <bob@partner.test>'], Subject: [subject] };
  store.subject = subject;
  store.auth = {
    ...GMAIL_AUTH,
    spfDomain: 'partner.test',
    dkimSignatures: [{ domain: 'partner.test', result: 'pass', selector: 's' }],
    dmarcDomain: 'partner.test',
  };
  return { ...ctx().envelope, envelopeFrom: 'bob@partner.test' };
}

const run = async (engine: BecEngine, c: EngineScanContext = ctx()) =>
  engine.scan(c, AbortSignal.timeout(10_000));
const definite = (o: Awaited<ReturnType<typeof run>>): EngineDefinite => {
  if (o.kind !== 'definite') throw new Error(`expected definite, got ${JSON.stringify(o)}`);
  return o;
};
const failed = (o: Awaited<ReturnType<typeof run>>): EngineFailure => {
  if (o.kind !== 'failure') throw new Error('expected failure');
  return o;
};

describe('BecEngine (step 4.4 B4)', () => {
  let t: ReturnType<typeof build>;
  beforeEach(() => {
    t = build();
  });

  it('classifies CEO fraud as malicious with explainable child rows (deterministic first)', async () => {
    withText(t.store, t.parts, CEO_TEXT);
    const out = definite(
      await run(t.engine, ctx({}, settings({ ai: { llm: 'off', localModel: 'shadow' } }))),
    );
    expect(out.result.outcome).toBe('malicious');
    expect(normalizedEngineResultSchema.safeParse(out.result).success).toBe(true);
    expect(out.result.reasonCodes).toEqual(
      expect.arrayContaining([
        'bec.impersonation.executive_name',
        'bec.impersonation.executive_freemail',
        'bec.content.gift_card',
        'bec.content.secrecy',
      ]),
    );
    expect(out.result.engineVersion).toBe(data.engineVersion);
    expect(out.result.requiredScore).toBe(40);
    // The effective thresholds go to scan_engine_results.evidence for the read API (§12 WP4 dev. 2).
    expect(out.evidence).toEqual({ thresholds: { suspicious: 40, malicious: 80 } });
    const row = out.childRows!.bec!.result;
    expect(row).toMatchObject({
      lifecycleRound: 0,
      rulesVersion: 'bec-map/1',
      lexiconVersion: data.lexicon.version,
      textVersion: 'bec-text/1',
      deterministicVerdict: 'malicious',
      verdict: 'malicious',
      inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      ai: null,
    });
    // Local model in shadow: stored, never applied.
    expect(row.aiShadow).toHaveLength(1);
    expect(row.aiShadow![0]).toMatchObject({
      layer: 'local',
      mode: 'shadow',
      provider: 'local',
      status: 'ok',
    });
    expect(row.aiShadow![0]).not.toHaveProperty('effect');
    expect(row.rules.length).toBeGreaterThan(0);
    for (const rule of row.rules) {
      for (const evidence of rule.evidence as unknown[]) {
        expect(becRuleEvidenceSchema.safeParse(evidence).success).toBe(true);
      }
    }
    // No text in the row: spans are offsets, never strings of the body.
    expect(JSON.stringify(row)).not.toContain('gift cards');
    expect(out.childRows!.bec!.history).toEqual([]);
    const text = await t.registry.metrics();
    expect(text).toMatch(
      /scan_bec_results_total\{verdict="malicious",deterministic_verdict="malicious"[^}]*\} 1/,
    );
    expect(text).toMatch(/scan_bec_rules_total\{code="bec.content.gift_card"[^}]*\} 1/);
    expect(text).toMatch(/scan_bec_inputs_total\{input="history",state="disabled"[^}]*\} 1/);
    expect(text).toMatch(
      /scan_bec_ai_total\{layer="local",mode="shadow",status="ok",effect="none"[^}]*\} 1/,
    );
  });

  it('a missing or failed upstream result is recorded as not available, never clean', async () => {
    t.store.headers = { From: ['Bob <bob@partner.test>'], Subject: ['Hello'] };
    t.store.finals = [
      { engine: 'rspamd', outcome: 'error' },
      { engine: 'url', outcome: 'timeout' },
    ];
    const out = definite(
      await run(t.engine, ctx({}, settings({ ai: { llm: 'off', localModel: 'off' } }))),
    );
    expect(out.result.outcome).toBe('unknown');
    expect(out.result.reasonCodes).toEqual(
      expect.arrayContaining(['bec.input_unavailable.auth', 'bec.input_unavailable.url']),
    );
    expect(out.childRows!.bec!.result.inputs).toMatchObject({
      auth: 'failed',
      url: 'failed',
      text: 'absent',
    });
    expect(t.store.calls).not.toContain('auth');
    expect(t.store.calls).not.toContain('urls');

    t.store.finals = [{ engine: 'rspamd', outcome: 'clean' }];
    t.store.round = { round: 0, scanKind: 'initial', requiredEngines: ['rspamd', 'bec'] };
    t.store.auth = null;
    const missing = definite(
      await run(t.engine, ctx({}, settings({ ai: { llm: 'off', localModel: 'off' } }))),
    );
    expect(missing.childRows!.bec!.result.inputs).toMatchObject({
      auth: 'missing',
      url: 'not_in_round',
    });
    expect(missing.result.outcome).not.toBe('clean');
  });

  it('a dependency final the trigger promised but the read misses is an inconsistent read (retryable)', async () => {
    t.store.finals = [{ engine: 'rspamd', outcome: 'clean' }];
    const out = failed(await run(t.engine));
    expect(out).toMatchObject({
      outcome: 'error',
      errorCode: 'inconsistent_read',
      retryable: true,
      engineFault: false,
    });
    expect(await t.registry.metrics()).toMatch(
      /scan_bec_inconsistent_reads_total\{read="finals"[^}]*\} 1/,
    );
  });

  it('every loader echo mismatch is an inconsistent_read attempt with its read label', async () => {
    for (const read of ['scan', 'auth', 'headers', 'parse', 'message', 'tenant'] as const) {
      const local = build();
      local.store.failOn = { read, error: new InconsistentBecReadError(read, 'identity echo') };
      const out = failed(await run(local.engine));
      expect(out.errorCode).toBe('inconsistent_read');
      expect(await local.registry.metrics()).toMatch(
        new RegExp(`scan_bec_inconsistent_reads_total\\{read="${read}"[^}]*\\} 1`),
      );
    }
  });

  it('infrastructure errors are thrown (transient); part and parse problems are final failures', async () => {
    t.store.failOn = {
      read: 'headers',
      error: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
    };
    await expect(run(t.engine)).rejects.toThrow(/ECONNREFUSED/);

    const parseless = build();
    parseless.store.parse = null;
    expect(failed(await run(parseless.engine))).toMatchObject({
      errorCode: 'parse_row_missing',
      retryable: false,
    });

    const missing = build();
    missing.store.parse = {
      ...missing.store.parse!,
      textBody: { key: `org/${ORG.toString()}/part/gone`, sha256: 'a'.repeat(64), sizeBytes: 3 },
    };
    expect(failed(await run(missing.engine))).toMatchObject({
      errorCode: 'part_unavailable',
      retryable: false,
    });

    const corrupt = build();
    withText(corrupt.store, corrupt.parts, 'hello');
    corrupt.parts.objects.set(`org/${ORG.toString()}/part/t1`, Buffer.from('HELLO'));
    expect(failed(await run(corrupt.engine))).toMatchObject({
      errorCode: 'part_integrity',
      retryable: false,
    });

    const foreign = build();
    withText(foreign.store, foreign.parts, 'hello', 'org/999/part/t1');
    expect(failed(await run(foreign.engine))).toMatchObject({
      errorCode: 'part_key_mismatch',
      retryable: false,
    });
  });

  it('an incomplete stored header set is never clean (stored_headers_truncated or more rows than read)', async () => {
    const off = settings({ ai: { llm: 'off', localModel: 'off' } });
    const baseline = build();
    const envelope = partner(baseline.store, 'Lunch');
    withText(baseline.store, baseline.parts, 'See you at lunch.');
    expect(definite(await run(baseline.engine, ctx({ envelope }, off))).result.outcome).toBe(
      'clean',
    );

    const defect = build();
    partner(defect.store, 'Lunch');
    withText(defect.store, defect.parts, 'See you at lunch.');
    defect.store.parse = { ...defect.store.parse!, defects: ['stored_headers_truncated'] };
    const viaDefect = definite(await run(defect.engine, ctx({ envelope }, off)));
    expect(viaDefect.result.outcome).toBe('unknown');
    expect(viaDefect.result.reasonCodes).toContain('bec.content_incomplete');
    expect(viaDefect.result.reasonCodes).not.toContain('clean.below_threshold');

    const capped = build();
    partner(capped.store, 'Lunch');
    withText(capped.store, capped.parts, 'See you at lunch.');
    capped.store.headersTruncated = true;
    const viaCap = definite(await run(capped.engine, ctx({ envelope }, off)));
    expect(viaCap.result.outcome).toBe('unknown');
    expect(viaCap.result.reasonCodes).toContain('bec.content_incomplete');
  });

  it('a body above BEC_TEXT_MAX_BYTES is read as a prefix (no hash check) and the text is incomplete', async () => {
    const local = build({ textMaxBytes: 1_024 });
    withText(local.store, local.parts, `${'é'.repeat(700)} gift card`);
    const out = definite(
      await run(local.engine, ctx({}, settings({ ai: { llm: 'off', localModel: 'off' } }))),
    );
    expect(local.parts.prefixReads).toBe(1);
    expect(out.childRows!.bec!.result.inputs.text).toBe('incomplete');
    expect(out.result.reasonCodes).toContain('bec.content_incomplete');
    expect(out.result.outcome).not.toBe('clean');
  });

  it('outbound mail is skipped (bec.not_inbound) with history pair updates only when enabled (round 0)', async () => {
    t.store.headers = {
      From: ['Finance <finance@acmecorp.test>'],
      To: ['billing@globexsupplies.test'],
    };
    const outbound = {
      direction: 'outbound' as const,
      envelope: {
        clientIp: '10.0.0.5',
        clientHelo: null,
        clientName: null,
        envelopeFrom: 'finance@acmecorp.test',
        recipients: ['billing@globexsupplies.test', 'ops@acmecorp.test'],
        queueId: null,
      },
    };
    const enabled = settings({ history: { enabled: true } });
    const out = definite(await run(t.engine, ctx(outbound, enabled)));
    expect(out.result).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['bec.not_inbound'],
      score: null,
    });
    expect(t.store.calls).not.toContain('parse');
    expect(out.childRows!.bec!.result).toMatchObject({
      verdict: 'skipped',
      deterministicVerdict: 'skipped',
      features: null,
    });
    // One pair (internal sender, external recipient); the internal recipient is not counted.
    expect(out.childRows!.bec!.history).toEqual([
      {
        scope: 'pair',
        keyHash: contextKeyHash(
          KEY,
          ORG,
          'pair',
          canonicalPair('finance@acmecorp.test', 'billing@globexsupplies.test'),
        ),
        inbound: 0,
        outbound: 1,
        receivedAt: RECEIVED,
        fingerprintHash: null,
      },
    ]);
    // A rescan round or a tenant without history: no updates.
    expect(
      definite(await run(t.engine, ctx({ ...outbound, round: 1, scanKind: 'rescan' }, enabled)))
        .childRows!.bec!.history,
    ).toEqual([]);
    expect(definite(await run(t.engine, ctx(outbound))).childRows!.bec!.history).toEqual([]);
  });

  it('inbound history: reads keyed hashes, fires first contact, writes sender + pair updates on round 0', async () => {
    const enabled = settings({ history: { enabled: true }, ai: { llm: 'off', localModel: 'off' } });
    // An authenticated partner below suspicious is counted (B12).
    const partnerRun = build();
    const envelope = partner(partnerRun.store, 'Notes');
    withText(partnerRun.store, partnerRun.parts, 'Please find the meeting notes attached.');
    const counted = definite(await run(partnerRun.engine, ctx({ envelope }, enabled)));
    expect(counted.result.reasonCodes).toContain('bec.history.first_contact');
    expect(['clean', 'unknown']).toContain(counted.result.outcome);
    const partnerUpdates = counted.childRows!.bec!.history;
    expect(partnerUpdates.map((u) => u.scope)).toEqual(['pair', 'sender']);
    const partnerSender = partnerUpdates.find((u) => u.scope === 'sender')!;
    expect(partnerSender.keyHash).toBe(contextKeyHash(KEY, ORG, 'sender', 'bob@partner.test'));
    expect(partnerSender.fingerprintHash).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(partnerUpdates)).not.toContain('partner');

    // The same partner From without authentication (spoofed warm-up): nothing counted.
    const spoofRun = build();
    partner(spoofRun.store, 'Notes');
    spoofRun.store.auth = {
      ...spoofRun.store.auth!,
      spf: 'fail',
      dkim: 'none',
      dmarc: 'fail',
      dkimSignatures: [],
    };
    withText(spoofRun.store, spoofRun.parts, 'Please find the meeting notes attached.');
    const spoofed = definite(await run(spoofRun.engine, ctx({ envelope }, enabled)));
    expect(spoofed.childRows!.bec!.result.inputs.history).toBe('enabled');
    expect(spoofed.childRows!.bec!.history).toEqual([]);

    // Suspicious or malicious mail (executive name from free mail) is never counted either.
    withText(t.store, t.parts, 'Please find the meeting notes attached.');
    const out = definite(await run(t.engine, ctx({}, enabled)));
    expect(out.childRows!.bec!.result.inputs.history).toBe('enabled');
    expect(out.result.reasonCodes).toContain('bec.history.first_contact');
    expect(['suspicious', 'malicious']).toContain(out.result.outcome);
    expect(out.childRows!.bec!.history).toEqual([]);
    const sender = {
      keyHash: contextKeyHash(KEY, ORG, 'sender', 'anita.sharma.office@gmail.com'),
    };

    // Known sender: rows present → no first contact.
    t.store.history.set(`sender:${sender.keyHash}`, {
      keyHash: sender.keyHash,
      row: {
        messageCount: 12,
        firstSeenAt: new Date('2026-01-01T00:00:00Z'),
        lastSeenAt: new Date('2026-11-01T00:00:00Z'),
        infra: [],
      },
    });
    const known = definite(await run(t.engine, ctx({}, enabled)));
    expect(known.result.reasonCodes).not.toContain('bec.history.first_contact');

    // A failed history read is recorded as unavailable (E1), never a failed attempt.
    t.store.failOn = { read: 'history', error: new Error('lost connection') };
    const errored = definite(await run(t.engine, ctx({}, enabled)));
    expect(errored.childRows!.bec!.result.inputs.history).toBe('error');
    expect(errored.result.reasonCodes).toContain('bec.history_unavailable');
    expect(errored.result.outcome).not.toBe('clean');
  });

  it('LLM active (fake) raises a below-threshold message to suspicious; shadow never changes it', async () => {
    const envelope = partner(t.store, 'Payment');
    withText(t.store, t.parts, 'Please process the payment for the attached invoice today.');
    const shadow = definite(
      await run(
        t.engine,
        ctx({ envelope }, settings({ ai: { llm: 'shadow', localModel: 'off' } })),
      ),
    );
    const deterministic = shadow.childRows!.bec!.result.deterministicVerdict;
    expect(shadow.result.outcome).toBe(deterministic);
    expect(shadow.childRows!.bec!.result.aiShadow![0]).toMatchObject({
      layer: 'llm',
      mode: 'shadow',
      provider: 'fake',
    });
    expect(t.llm!.calls).toBe(1);

    const active = definite(
      await run(
        t.engine,
        ctx({ envelope }, settings({ ai: { llm: 'active', localModel: 'off' } })),
      ),
    );
    const row = active.childRows!.bec!.result;
    expect(['clean', 'unknown']).toContain(row.deterministicVerdict);
    expect(row.verdict).toBe('suspicious');
    expect(active.result.reasonCodes).toContain('bec.ai.flagged');
    expect(row.ai![0]).toMatchObject({
      layer: 'llm',
      mode: 'active',
      effect: 'raised_to_suspicious',
    });
    expect(row.score).toBeGreaterThanOrEqual(40);
    expect(row.deterministicScore).toBeLessThan(40);
    expect(await t.registry.metrics()).toMatch(/bec_llm_budget_total\{result="allowed"[^}]*\} 2/);
  });

  it('never calls the LLM without a passed budget check; exhausted → budget_exceeded, Redis down → skipped', async () => {
    for (const [result, status] of [
      ['tenant_exhausted', 'budget_exceeded'],
      ['platform_exhausted', 'budget_exceeded'],
      ['unavailable', 'skipped'],
    ] as const) {
      const local = build({ budget: new FixedBudget(result) });
      const envelope = partner(local.store, 'Payment');
      withText(
        local.store,
        local.parts,
        'Please process the payment for the attached invoice today.',
      );
      const out = definite(
        await run(
          local.engine,
          ctx({ envelope }, settings({ ai: { llm: 'active', localModel: 'off' } })),
        ),
      );
      expect(local.llm!.calls).toBe(0);
      expect(local.budget.checks).toBe(1);
      const row = out.childRows!.bec!.result;
      expect(row.ai![0]).toMatchObject({ status, effect: 'none', labels: [], confidence: null });
      // An AI problem never changes the deterministic verdict (P6) and is informational only.
      expect(row.verdict).toBe(row.deterministicVerdict);
      expect(out.result.reasonCodes).toContain('bec.ai.unavailable');
    }
  });

  it('gates the LLM: nothing to send for a message without any signal or with a malicious verdict', async () => {
    const envelope = partner(t.store, 'Lunch');
    withText(t.store, t.parts, 'See you at lunch.');
    const out = definite(
      await run(
        t.engine,
        ctx({ envelope }, settings({ ai: { llm: 'active', localModel: 'off' } })),
      ),
    );
    expect(out.result.outcome).toBe('clean');
    expect(t.llm!.calls).toBe(0);
    expect(t.budget.checks).toBe(0);
    expect(out.childRows!.bec!.result.ai).toBeNull();
    expect(await t.registry.metrics()).toMatch(
      /scan_bec_ai_total\{layer="llm",mode="active",status="gated",effect="none"[^}]*\} 1/,
    );

    const ceo = build();
    withText(ceo.store, ceo.parts, CEO_TEXT);
    const malicious = definite(
      await run(ceo.engine, ctx({}, settings({ ai: { llm: 'active', localModel: 'off' } }))),
    );
    expect(malicious.result.outcome).toBe('malicious');
    expect(ceo.llm!.calls).toBe(0);
  });

  it('an open LLM breaker answers circuit_open without a budget check or a call', async () => {
    const permit1 = t.breaker.tryAcquire()!;
    permit1.failure();
    t.breaker.tryAcquire()!.failure();
    expect(t.breaker.state).toBe('open');
    const envelope = partner(t.store, 'Payment');
    withText(t.store, t.parts, 'Please process the payment for the attached invoice today.');
    const out = definite(
      await run(
        t.engine,
        ctx({ envelope }, settings({ ai: { llm: 'active', localModel: 'off' } })),
      ),
    );
    expect(out.childRows!.bec!.result.ai![0]).toMatchObject({ status: 'circuit_open' });
    expect(t.budget.checks).toBe(0);
    expect(t.llm!.calls).toBe(0);
  });

  it('reports a bec-engine readiness check without requiring the LLM', async () => {
    const check = t.engine.healthChecks().find((c) => c.name === 'bec-engine')!;
    expect(await check.check()).toMatchObject({
      engineVersion: data.engineVersion,
      lexicon: data.lexicon.version,
    });
  });
});
