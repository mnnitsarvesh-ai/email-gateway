import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createBecJobs } from '../src/scanning/scanning.module';
import { PrismaBecStore } from '../src/scanning/engines/bec/bec-store';
import { EngineAttemptFailedError } from '../src/scanning/engine';
import { BecFixtures, type BecEnvelope, BecPipeline, type BecState, plainEml } from './support/bec';
import { silentLogger } from './support/fixtures';
import { corpusEml, loadCorpus, ScanFixtures, type ScanMessage } from './support/scan';
import { emlWithBodies, linksHtml, requireUrlTest, testCaFile, UrlFixtures } from './support/urls';

/**
 * The bec engine against the real stack (step 4.4 §9 "email-worker package integration"): MySQL
 * writer, MinIO, Redis, the running Rspamd (real authentication results for the 4.1 scan corpus
 * through dns-sink), the url engine on dns-sink/url-test (real URL results for the 4.3 corpus),
 * the bec engine with BEC_LLM_PROVIDER=fake. Messages are parsed by the real MIME stage; every
 * engine is called through its round service; the stage trigger is read from the outbox as the
 * event-relay would publish it.
 */

const fx = new ScanFixtures();
const ufx = new UrlFixtures(fx);
const bfx = new BecFixtures(fx);
let ca: ReturnType<typeof testCaFile>;
let pipeline: BecPipeline;
const run = (): string => `run=${fx.suffix}`;

const corpus = (file: string) => {
  const fixture = loadCorpus().find((f) => f.file === file);
  if (!fixture) throw new Error(`corpus fixture missing: ${file}`);
  return { eml: corpusEml(fixture), envelope: fixture.envelope };
};

beforeAll(async () => {
  ca = testCaFile();
  await requireUrlTest();
  pipeline = BecPipeline.start(fx, ca.path);
});

afterAll(async () => {
  await pipeline?.close();
  await bfx.cleanup();
  await ufx.cleanup();
  await fx.cleanup();
  ca?.cleanup();
});

/**
 * Per-tenant active domain (`domains.verified_name` is unique across organizations). Not under
 * `scan.test`: `.test` has no public-suffix entry, so every `*.scan.test` host has the
 * registrable domain `scan.test`, and a tenant domain there would make the corpus senders look
 * like the tenant's own domain (A6).
 */
const domains = new Map<bigint, string>();
const rcptOf = (org: bigint): string => `bob@${domains.get(org)!}`;

/** A tenant organization with its own active domain; its recipients are `bob@<domain>`. */
async function tenant(label: string): Promise<bigint> {
  const org = await fx.organization(label);
  const domain = `it-bec-${fx.suffix}-${label}.test`;
  await bfx.domain(org, domain);
  domains.set(org, domain);
  return org;
}

interface RoundResult {
  message: ScanMessage;
  state: BecState;
  codes: string[];
  rules: Array<{ id: string; code: string; suppressed: string | null }>;
}

const codesOf = (state: BecState, round = 0): string[] => {
  const final = state.finals.find(
    (f) =>
      f.engine === 'bec' && state.scans.find((s) => s.id === f.scanId)?.lifecycleRound === round,
  );
  return (final?.reasonCodes as string[] | undefined) ?? [];
};

/**
 * One round: rspamd and url finals (the last one writes the stage trigger), then the bec
 * delivery of the trigger as the relay would publish it.
 */
async function runRound(
  p: BecPipeline,
  message: ScanMessage,
  trigger = fx.parsed(message),
): Promise<RoundResult> {
  expect(await p.deliver('rspamd', trigger)).toBe('handled');
  expect(await p.deliver('url', trigger)).toBe('handled');
  const events = await bfx.stageEvents(message);
  const round = 'lifecycleRound' in trigger.payload ? trigger.payload.lifecycleRound : 0;
  const event = events.find(
    (e) => 'lifecycleRound' in e.payload && e.payload.lifecycleRound === round,
  );
  if (!event) throw new Error('no stage trigger written for the round');
  expect(await p.deliver('bec', event)).toBe('handled');
  const state = await bfx.state(message);
  return {
    message,
    state,
    codes: codesOf(state, round),
    rules: (state.bec.find((b) => b.lifecycleRound === round)?.rules ?? []) as RoundResult['rules'],
  };
}

async function scanCorpus(
  org: bigint,
  file: string,
  envelope: BecEnvelope = {},
): Promise<RoundResult> {
  const fixture = corpus(file);
  const message = await bfx.message(org, fixture.eml, {
    ...fixture.envelope,
    rcpt: [rcptOf(org)],
    ...envelope,
  });
  return runRound(pipeline, message);
}

describe('real authentication results (Rspamd through dns-sink)', () => {
  it('a DMARC-failing executive impersonation with an intent cue is never clean (A1, X1, C-codes)', async () => {
    const org = await tenant('dmarc');
    await bfx.executive(org, 'Chief Executive', [`ceo@${domains.get(org)!}`]);
    const { state, codes } = await scanCorpus(org, 'spoofed/spf-fail.eml');
    // The auth row is Rspamd's own (4.1): SPF fail, DMARC fail with policy reject.
    expect(state.auth).toHaveLength(1);
    expect(state.auth[0]).toMatchObject({ spf: 'fail', dmarc: 'fail', dmarcPolicy: 'reject' });
    const row = state.bec[0]!;
    expect(row.inputs).toEqual({
      auth: 'available',
      url: 'available',
      text: 'complete',
      history: 'disabled',
    });
    expect(codes).toEqual(
      expect.arrayContaining([
        'bec.auth.dmarc_fail',
        'bec.auth.spf_fail',
        'bec.sender.not_authenticated',
        'bec.impersonation.executive_name',
        'bec.content.secrecy',
      ]),
    );
    expect(codes).not.toContain('bec.auth.tenant_domain_spoof');
    expect(['suspicious', 'malicious']).toContain(row.verdict);
    expect(state.finals.find((f) => f.engine === 'bec')).toMatchObject({
      outcome: row.verdict,
      engineVersion: row.engineVersion,
      isFinal: true,
    });
    expect(state.scans[0]).toMatchObject({ status: 'completed' });
    expect(state.message.status).toBe('scanned');
  });

  it('a DKIM-aligned, authenticated partner message with no cue is clean (no A/X codes)', async () => {
    const org = await tenant('aligned');
    const { state, codes } = await scanCorpus(org, 'clean/clean-dkim-aligned.eml');
    expect(state.auth[0]).toMatchObject({ dkim: 'pass' });
    expect(state.bec[0]).toMatchObject({ verdict: 'clean', deterministicVerdict: 'clean' });
    expect(
      codes.filter((c) => c.startsWith('bec.auth.') || c.startsWith('bec.impersonation.')),
    ).toEqual([]);
    expect(codes).toContain('clean.below_threshold');
  });
});

describe('an incomplete stored header set (§2.0 invariant 1)', () => {
  it('a Reply-To after the stored-header cap was never examined: bec.content_incomplete, never clean', async () => {
    const org = await tenant('hdr-cap');
    const fixture = corpus('clean/clean-dkim-aligned.eml');
    const raw = fixture.eml.toString('utf8');
    const end = raw.indexOf('\r\n\r\n') >= 0 ? raw.indexOf('\r\n\r\n') : raw.indexOf('\n\n');
    const nl = raw.indexOf('\r\n') >= 0 ? '\r\n' : '\n';
    // 200 allow-listed, repeatable headers after From/To/Subject, then the attacker's Reply-To.
    const filler = Array.from(
      { length: 200 },
      (_, i) => `Authentication-Results: it-${i}.scan.test; none`,
    ).join(nl);
    const eml = `${raw.slice(0, end)}${nl}${filler}${nl}Reply-To: pay.${fx.suffix}@gmail.com${raw.slice(end)}`;
    const message = await bfx.message(org, eml, { ...fixture.envelope, rcpt: [rcptOf(org)] });
    const { state, codes } = await runRound(pipeline, message);
    const stored = await bfx.prisma.emailHeader.count({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
    });
    expect(stored).toBe(200);
    expect(
      await bfx.prisma.emailHeader.count({
        where: { messageId: message.messageId, receivedAt: message.receivedAt, name: 'Reply-To' },
      }),
    ).toBe(0);
    const parse = await bfx.prisma.emailMessageParse.findFirstOrThrow({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      select: { defects: true },
    });
    expect(parse.defects).toEqual(expect.arrayContaining(['stored_headers_truncated']));
    expect(codes).toContain('bec.content_incomplete');
    expect(codes).not.toContain('clean.below_threshold');
    expect(state.bec[0]!.verdict).not.toBe('clean');
    expect(state.finals.find((f) => f.engine === 'bec')!.outcome).not.toBe('clean');
  });
});

describe('real URL results (url engine, 4.3 corpus on url-test)', () => {
  it('a link to the high-confidence phishing page fires K1 (credential harvesting)', async () => {
    const org = await tenant('k1');
    const phish = `http://examp1ebank.test/login?${run()}`;
    ufx.track(phish);
    const message = await bfx.message(
      org,
      emlWithBodies('Please verify your account here', linksHtml(phish)),
      {
        from: 'alice@clean.scan.test',
        ip: '192.0.2.10',
        helo: 'mx.clean.scan.test',
        hostname: 'mx.clean.scan.test',
        rcpt: [rcptOf(org)],
      },
    );
    const { state, codes, rules } = await runRound(pipeline, message);
    const url = state.finals.find((f) => f.engine === 'url')!;
    expect(url.outcome).toBe('malicious');
    expect(codes).toContain('bec.link.credential_harvesting');
    const k1 = rules.find((r) => r.id === 'K1') as unknown as {
      evidence: Array<{ urls?: number[] }>;
    };
    expect(k1.evidence[0]!.urls).toEqual([expect.any(Number)]);
    expect(['suspicious', 'malicious']).toContain(state.bec[0]!.verdict);
  });
});

describe('missing upstream results are not available, never clean', () => {
  it('an Rspamd final error (engine unreachable) → bec.input_unavailable.auth, verdict ≥ unknown', async () => {
    const down = BecPipeline.start(fx, ca.path, {
      overrides: { SCAN_RSPAMD_URL: 'http://127.0.0.1:9', SCAN_RSPAMD_MAX_ATTEMPTS: '1' },
    });
    try {
      const org = await tenant('auth-down');
      const fixture = corpus('clean/clean-dkim-aligned.eml');
      const message = await bfx.message(org, fixture.eml, {
        ...fixture.envelope,
        rcpt: [rcptOf(org)],
      });
      const { state, codes } = await runRound(down, message);
      expect(state.finals.find((f) => f.engine === 'rspamd')).toMatchObject({ outcome: 'error' });
      expect(state.auth).toHaveLength(0);
      expect(state.bec[0]!.inputs).toMatchObject({ auth: 'failed' });
      expect(codes).toContain('bec.input_unavailable.auth');
      expect(state.bec[0]!.verdict).not.toBe('clean');
      // The round fails because rspamd failed; bec still recorded its own verdict.
      expect(state.scans[0]).toMatchObject({ status: 'failed' });
    } finally {
      await down.close();
    }
  });
});

describe('idempotency and rescans (§2.0 invariant 6)', () => {
  it('the same stage event three times and a re-drive: one final, one bec row, history counted once', async () => {
    const org = await tenant('dup');
    await bfx.settings(org, { history: { enabled: true } });
    const fixture = corpus('clean/clean-dkim-aligned.eml');
    const message = await bfx.message(org, fixture.eml, {
      ...fixture.envelope,
      rcpt: [rcptOf(org)],
    });
    const trigger = fx.parsed(message);
    await pipeline.deliver('rspamd', trigger);
    await pipeline.deliver('url', trigger);
    // A second delivery of the dependency (another event id) writes no second trigger.
    await pipeline.deliver('url', fx.parsed(message));
    const events = await bfx.stageEvents(message);
    expect(events).toHaveLength(1);
    expect(events[0]!.payload).toMatchObject({
      engine: 'bec',
      scanKind: 'initial',
      lifecycleRound: 0,
      dependencies: [
        { engine: 'rspamd', outcome: 'clean' },
        { engine: 'url', outcome: 'skipped' },
      ],
    });
    const event = events[0]!;
    expect(await pipeline.deliver('bec', event)).toBe('handled');
    expect(await pipeline.deliver('bec', event)).toBe('duplicate');
    expect(await pipeline.deliver('bec', event)).toBe('duplicate');
    // The reconciler's re-drive under a new delivery id finds the final row.
    expect(await pipeline.deliver('bec', { ...event, eventId: fx.parsed(message).eventId })).toBe(
      'duplicate',
    );
    const state = await bfx.state(message);
    expect(state.finals.filter((f) => f.engine === 'bec')).toHaveLength(1);
    expect(state.bec).toHaveLength(1);
    const history = await bfx.historyRows(org);
    // ENUM order: sender before pair.
    expect(history.map((h) => [h.scope, h.messageCount, h.inboundCount])).toEqual([
      ['sender', 1, 1],
      ['pair', 1, 1],
    ]);
  });

  it('a rescan creates a new round with a new bec row; history is not incremented', async () => {
    const org = await tenant('rescan');
    await bfx.settings(org, { history: { enabled: true } });
    const fixture = corpus('clean/clean-dkim-aligned.eml');
    const message = await bfx.message(org, fixture.eml, {
      ...fixture.envelope,
      rcpt: [rcptOf(org)],
    });
    await runRound(pipeline, message);
    const before = await bfx.historyRows(org);
    const rescan = await fx.rescan(message);
    const second = await runRound(pipeline, message, rescan);
    expect(second.state.scans).toHaveLength(2);
    expect(second.state.bec.map((b) => [b.lifecycleRound, b.scanId])).toEqual([
      [0, second.state.scans[0]!.id],
      [1, second.state.scans[1]!.id],
    ]);
    expect(second.state.stageEvents).toHaveLength(2);
    const after = await bfx.historyRows(org);
    expect(after.map((h) => h.messageCount)).toEqual(before.map((h) => h.messageCount));
    // The rescan sees the same history: first contact again (first_seen_at = received_at).
    expect(second.codes).toContain('bec.history.first_contact');
    expect(second.state.message).toEqual({ status: 'scanned', lifecycleRound: 1 });
  });
});

describe('tenant feedback, trust and history (B7, B11, B12)', () => {
  it('a suppression row suppresses only an allowed code (S1); a non-suppressible code stays active', async () => {
    const org = await tenant('suppress');
    const eml = plainEml(
      {
        From: 'Alice Martin <alice@clean.scan.test>',
        To: 'bob@customer.scan.test',
        Subject: 'Status',
      },
      'Please reply urgently, today, with the meeting notes.',
    );
    const envelope = { ...corpus('clean/clean-dkim-aligned.eml').envelope, rcpt: [rcptOf(org)] };
    const first = await runRound(pipeline, await bfx.message(org, eml, envelope));
    expect(first.codes).toContain('bec.content.urgency');
    await bfx.suppression(org, 'bec.content.urgency', 'address', 'alice@clean.scan.test');
    // The api refuses a non-suppressible code; a row that exists anyway is ignored at use.
    await bfx.suppression(org, 'bec.auth.none', 'address', 'alice@clean.scan.test');
    const second = await runRound(pipeline, await bfx.message(org, eml, envelope));
    expect(second.codes).not.toContain('bec.content.urgency');
    expect(second.codes).toContain('bec.feedback_suppressed');
    const c7 = second.rules.find((r) => r.id === 'C7');
    expect(c7?.suppressed).toBe('feedback');
  });

  it('a trusted sender with a spoofed (unauthenticated) From fires T2 and neutralizes nothing', async () => {
    const org = await tenant('trust');
    // Domain entries are registrable domains (the api normalizes them): spoof.scan.test → scan.test.
    await bfx.trustedSender(org, 'domain', 'scan.test');
    const { codes, rules } = await scanCorpus(org, 'spoofed/spf-fail.eml');
    expect(codes).toContain('bec.trusted_sender_unauthenticated');
    expect(codes).not.toContain('bec.trusted_sender');
    expect(codes).toContain('bec.auth.dmarc_fail');
    expect(rules.every((r) => r.suppressed === null)).toBe(true);
  });

  it('history off writes no rows; on writes keyed hashes only; the retention sweeper deletes expired rows', async () => {
    const off = await tenant('history-off');
    await scanCorpus(off, 'clean/clean-dkim-aligned.eml');
    expect(await bfx.historyRows(off)).toEqual([]);

    const on = await tenant('history-on');
    await bfx.settings(on, { history: { enabled: true, retentionDays: 30 } });
    await scanCorpus(on, 'clean/clean-dkim-aligned.eml');
    const rows = await bfx.historyRows(on);
    expect(rows.map((r) => r.scope)).toEqual(['sender', 'pair']);
    for (const row of rows) {
      expect(row.keyHash).toMatch(/^[0-9a-f]{64}$/);
      expect(
        JSON.stringify(row, (_, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
      ).not.toMatch(/clean\.scan\.test|alice|bob/);
    }
    const sender = rows.find((r) => r.scope === 'sender')!;
    expect(sender.infra).toEqual([
      { fp: expect.stringMatching(/^[0-9a-f]{16}$/), count: 1, lastSeenAt: expect.any(String) },
    ]);

    // Age one row beyond the 30-day retention: the sweeper (leader lock of the run) deletes it.
    await bfx.prisma.becContactHistory.updateMany({
      where: { organizationId: on, scope: 'pair' },
      data: { lastSeenAt: new Date(Date.now() - 31 * 86_400_000) },
    });
    const { AdvisoryLocks } = await import('@email-gateway/common');
    const locks = new AdvisoryLocks(process.env.DATABASE_URL!);
    try {
      const jobs = createBecJobs({
        config: pipeline.config,
        prisma: bfx.prisma,
        locks,
        registry: pipeline.registry,
        logger: silentLogger,
        lockName: `it-bec-history-${fx.suffix}`,
        organizationIds: [on, off],
      });
      const report = await jobs.sweeper.sweepOnce();
      expect(report).toMatchObject({ outcome: 'swept', deleted: 1 });
    } finally {
      await locks.close();
    }
    expect((await bfx.historyRows(on)).map((r) => r.scope)).toEqual(['sender']);
    expect(await pipeline.text()).toMatch(/bec_history_rows_deleted_total(\{[^}]*\})? [1-9]/);
  });

  it('spoofed warm-up mail never makes a sender known (unauthenticated From: no history rows)', async () => {
    const org = await tenant('history-spoof');
    await bfx.settings(org, { history: { enabled: true } });
    for (let i = 0; i < 3; i += 1) {
      const { state } = await scanCorpus(org, 'spoofed/spf-fail.eml');
      expect(state.auth[0]).toMatchObject({ dmarc: 'fail' });
    }
    expect(await bfx.historyRows(org)).toEqual([]);
    // The next spoofed message is still a first contact.
    const next = await scanCorpus(org, 'spoofed/spf-fail.eml');
    expect(next.codes).toContain('bec.history.first_contact');
    // An authenticated, clean message is counted.
    await scanCorpus(org, 'clean/clean-dkim-aligned.eml');
    expect((await bfx.historyRows(org)).map((r) => r.scope)).toEqual(['sender', 'pair']);
  });
});

describe('the AI layer (fake LLM provider, B9/B10)', () => {
  const urgentPayment = plainEml(
    {
      From: 'Alice Martin <alice@clean.scan.test>',
      To: 'bob@customer.scan.test',
      Subject: 'Payment',
    },
    'Please process the payment for the attached invoice.',
  );

  it('shadow: stored in ai_shadow, verdict unchanged; active: raises to suspicious only', async () => {
    const envelope = corpus('clean/clean-dkim-aligned.eml').envelope;
    const shadowOrg = await tenant('llm-shadow');
    await bfx.settings(shadowOrg, { ai: { llm: 'shadow' } });
    const shadow = await runRound(
      pipeline,
      await bfx.message(shadowOrg, urgentPayment, { ...envelope, rcpt: [rcptOf(shadowOrg)] }),
    );
    const shadowRow = shadow.state.bec[0]!;
    expect(shadowRow.verdict).toBe(shadowRow.deterministicVerdict);
    expect(shadowRow.ai).toBeNull();
    expect(shadowRow.aiShadow).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ layer: 'llm', mode: 'shadow', provider: 'fake', status: 'ok' }),
      ]),
    );

    const activeOrg = await tenant('llm-active');
    await bfx.settings(activeOrg, { ai: { llm: 'active' } });
    const active = await runRound(
      pipeline,
      await bfx.message(activeOrg, urgentPayment, { ...envelope, rcpt: [rcptOf(activeOrg)] }),
    );
    const row = active.state.bec[0]!;
    expect(['clean', 'unknown']).toContain(row.deterministicVerdict);
    expect(row.verdict).toBe('suspicious');
    expect(active.codes).toContain('bec.ai.flagged');
    expect(row.ai).toEqual([
      expect.objectContaining({ layer: 'llm', mode: 'active', effect: 'raised_to_suspicious' }),
    ]);
    // Never text: the stored assessment has hashes, offsets and enums only.
    expect(JSON.stringify(row.ai)).not.toMatch(/process the|attached invoice/i);
  });

  it('LLM budget exhaustion with the real Redis counters: the second call is budget_exceeded', async () => {
    const envelope = corpus('clean/clean-dkim-aligned.eml').envelope;
    const org = await tenant('llm-budget');
    await bfx.settings(org, { ai: { llm: 'active', llmDailyCallLimit: 1 } });
    const first = await runRound(
      pipeline,
      await bfx.message(org, urgentPayment, { ...envelope, rcpt: [rcptOf(org)] }),
    );
    expect((first.state.bec[0]!.ai as Array<{ status: string }>)[0]!.status).toBe('ok');
    const second = await runRound(
      pipeline,
      await bfx.message(org, urgentPayment, { ...envelope, rcpt: [rcptOf(org)] }),
    );
    const row = second.state.bec[0]!;
    expect((row.ai as Array<{ status: string }>)[0]).toMatchObject({
      status: 'budget_exceeded',
      effect: 'none',
    });
    expect(row.verdict).toBe(row.deterministicVerdict);
    expect(second.codes).toContain('bec.ai.unavailable');
    const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    expect(await bfx.redis.client.get(`eg:bec:llm:t:${org.toString()}:${day}`)).toBe('1');
    expect(await pipeline.text()).toMatch(
      /bec_llm_budget_total\{result="tenant_exhausted"[^}]*\} [1-9]/,
    );
  });
});

describe('wrong-read guard (§6)', () => {
  it('a forged auth read (another organization echoed) is an inconsistent_read attempt, then succeeds', async () => {
    let forge = true;
    const forging = new Proxy(fx.prisma, {
      get(target, prop, receiver) {
        if (prop === 'emailAuthResult') {
          return {
            findFirst: async (args: unknown) => {
              const row = await (
                target.emailAuthResult.findFirst as (
                  a: unknown,
                ) => Promise<Record<string, unknown> | null>
              )(args);
              if (!forge || !row) return row;
              forge = false;
              return { ...row, organizationId: BigInt(row.organizationId as bigint) + 1n };
            },
          };
        }
        const value: unknown = Reflect.get(target, prop, receiver);
        return typeof value === 'function'
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });
    const guarded = BecPipeline.start(fx, ca.path, {
      bec: {
        store: new PrismaBecStore(
          forging,
          { executives: 500, vendors: 2000, trustedSenders: 1000, suppressions: 200 },
          { ttlMs: 0 },
        ),
      },
    });
    try {
      const org = await tenant('wrong-read');
      const fixture = corpus('clean/clean-dkim-aligned.eml');
      const message = await bfx.message(org, fixture.eml, {
        ...fixture.envelope,
        rcpt: [rcptOf(org)],
      });
      const trigger = fx.parsed(message);
      await guarded.deliver('rspamd', trigger);
      await guarded.deliver('url', trigger);
      const [event] = await bfx.stageEvents(message);
      await expect(guarded.handle('bec', event!)).rejects.toBeInstanceOf(EngineAttemptFailedError);
      let state = await bfx.state(message);
      expect(state.attempts.filter((a) => a.engine === 'bec')).toEqual([
        expect.objectContaining({ errorCode: 'inconsistent_read', isFinal: false, attempt: 1 }),
      ]);
      expect(state.bec).toHaveLength(0);
      expect(await guarded.text()).toMatch(
        /scan_bec_inconsistent_reads_total\{read="auth"[^}]*\} 1/,
      );
      expect(await guarded.deliver('bec', event!)).toBe('handled');
      state = await bfx.state(message);
      expect(state.bec).toHaveLength(1);
      expect(state.finals.find((f) => f.engine === 'bec')).toMatchObject({ attempt: 2 });
    } finally {
      await guarded.close();
    }
  });
});
