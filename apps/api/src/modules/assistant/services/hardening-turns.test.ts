import {
  FakeProvider,
  LlmError,
  type LlmProvider,
  type PseudonymEntry,
} from '@email-gateway/assistant';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { immediateAssistantRunner, testUser } from '../../../../test/support/assistant-fixtures';
import {
  callTool,
  CollectingSink,
  createAssistantHarness,
  reply,
  ScriptedProvider,
} from '../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { type AssistantConfig, assistantKeys, utcDayKey } from '../assistant.constants';
import type { TurnFinish, TurnStart } from '../repositories/conversations.repository';
import type { PseudonymsRepository } from '../repositories/pseudonyms.repository';
import type {
  ReportJobsRepository,
  UnreportedReportJob,
} from '../repositories/report-jobs.repository';
import type { UsageDelta, UsageRepository } from '../repositories/usage.repository';
import { AssistantAvailabilityService } from './assistant-availability.service';
import { AssistantLimitsService } from './assistant-limits.service';
import { AssistantProviderService } from './assistant-provider.service';
import { ConfirmationViewsService } from './confirmation-views.service';
import { ownerOf } from './conversation.service';
import type { ProviderFactorySpec } from './llm-provider-factory';
import type { TenantKeyService } from './tenant-key.service';
import { TurnEngineService } from './turn-engine.service';

/**
 * Step AI-6 in the turn engine (docs/plan/steps/34-ai-chat-hardening-operations.md): the
 * `pseudonymized` level (D3, I25), the per-user budget and usage rows (D1), the provider route
 * with the same-turn switch, segment rebinding and tenant keys (D6, D7), and the report job
 * action updates (D5). The real services over the in-memory world; only the provider factory, the
 * pseudonym store and the report-job reads are local doubles.
 */

const ORG = 7001n;
const ALICE = 'alice@contoso.example';
const CAROL = 'carol@contoso.example';

afterEach(() => vi.restoreAllMocks());

interface Options {
  env?: Record<string, string>;
  /** The provider of a candidate (default: the deterministic fake). */
  llm?: (spec: ProviderFactorySpec) => LlmProvider;
  principal?: UserPrincipal;
  tenantKeys?: TenantKeyService;
  settings?: Parameters<ReturnType<typeof createAssistantHarness>['world']['enable']>[1];
  jobs?: UnreportedReportJob[];
}

function build(options: Options = {}) {
  const principal =
    options.principal ??
    testUser({
      permissions: new Set([
        'assistant:use',
        'assistant:configure',
        'policy:read',
        'archive:search',
      ]),
    });
  const h = createAssistantHarness(options.env ?? {}, undefined, principal);
  const c = h.config as AssistantConfig;
  h.world.enable(ORG, options.settings ?? {});
  const conversation = h.world.addConversation(ownerOf(principal, scopeFromPrincipal(principal)));

  // Usage: the world's double plus the per-user rows of D1 (recorded deltas).
  const usage = h.world.usageDouble();
  const deltas: UsageDelta[] = [];
  const add = usage.add.bind(usage);
  usage.add = (scope, delta, tx) => {
    deltas.push(structuredClone(delta));
    return add(scope, delta, tx);
  };
  (usage as UsageRepository & { userDayTokens: UsageRepository['userDayTokens'] }).userDayTokens = (
    _org,
    userId,
  ) =>
    Promise.resolve(
      deltas
        .filter((d) => d.user?.userId === userId)
        .reduce((s, d) => s + d.inputTokens + d.outputTokens, 0),
    );
  const limits = new AssistantLimitsService(c, h.kv, usage, h.metrics);
  const specs: ProviderFactorySpec[] = [];
  const router = new AssistantProviderService(
    c,
    (spec) => {
      specs.push(spec);
      return options.llm?.(spec) ?? new FakeProvider({ nodeEnv: 'test', model: spec.model });
    },
    h.kv,
    h.metrics,
    options.tenantKeys,
  );
  const availability = new AssistantAvailabilityService(
    c,
    h.world.settingsDouble(),
    h.world.featuresDouble(),
    router,
    limits,
    h.metrics,
  );
  // D3: the conversation's stored mapping.
  const pseudonyms: PseudonymEntry[] = [];
  const pseudonymRepo = {
    load: vi.fn(() => Promise.resolve(pseudonyms.map((e) => ({ ...e })))),
    insert: vi.fn((_o: unknown, _c: bigint, added: readonly PseudonymEntry[]) => {
      pseudonyms.push(...added.map((e) => ({ ...e })));
      return Promise.resolve();
    }),
  } as unknown as PseudonymsRepository;
  // D5: unreported terminal jobs of the conversation.
  const jobs = options.jobs ?? [];
  const reported: bigint[] = [];
  const jobsRepo = {
    unreported: vi.fn(() => Promise.resolve(jobs.filter((j) => !reported.includes(j.id)))),
    markReported: vi.fn((_o: unknown, ids: readonly bigint[]) => {
      reported.push(...ids);
      return Promise.resolve();
    }),
  } as unknown as ReportJobsRepository;
  // Step AI-6 D6: the provider and model of each stored turn of the segment.
  const repo = h.conversationsRepo;
  const segment = repo.segmentTranscripts.bind(repo);
  repo.segmentTranscripts = async (owner, conversationId, seg) =>
    (await segment(owner, conversationId, seg)).map((row) => {
      const turn = h.world.turns.find(
        (t) => t.conversationId === conversationId && t.seq === row.seq,
      )!;
      return { ...row, provider: turn.provider, model: turn.model };
    });
  const starts: TurnStart[] = [];
  const start = repo.startTurn.bind(repo);
  repo.startTurn = (owner, conv, data, tx) => {
    starts.push(data);
    return start(owner, conv, data, tx);
  };
  const finishes: TurnFinish[] = [];
  const finish = repo.finishTurn.bind(repo);
  repo.finishTurn = (owner, turn, data, conv, tx) => {
    finishes.push(data);
    return finish(owner, turn, data, conv, tx);
  };
  const confirmations = h.world.confirmationsDouble();
  const engine = new TurnEngineService(
    c,
    repo,
    h.world.executionsDouble(),
    usage,
    h.conversations,
    availability,
    limits,
    router,
    h.executor,
    h.loopback,
    immediateAssistantRunner,
    h.metrics,
    confirmations,
    new ConfirmationViewsService(confirmations, limits),
    pseudonymRepo,
    jobsRepo,
  );
  let n = 0;
  const ask = async (message: string) => {
    n += 1;
    const sink = new CollectingSink();
    const prepared = await engine.prepare(
      principal,
      scopeFromPrincipal(principal),
      conversation.publicId,
      { clientTurnId: `0193d000-0000-7000-8000-${String(n).padStart(12, '0')}`, message },
      { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' },
    );
    if (prepared.kind === 'run') await engine.run(prepared, sink);
    const text = sink.events
      .filter((e): e is { type: 'text.delta'; text: string } => e.type === 'text.delta')
      .map((e) => e.text)
      .join('');
    return { sink, prepared, text };
  };
  return {
    h,
    c,
    principal,
    conversation,
    engine,
    ask,
    deltas,
    specs,
    pseudonyms,
    pseudonymRepo,
    jobsRepo,
    reported,
    starts,
    finishes,
    router,
    limits,
  };
}

const coded = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    const e = error as { getStatus(): number; code: string; details?: unknown };
    return { status: e.getStatus(), code: e.code, details: e.details };
  }
  throw new Error('expected a coded error');
};

const ARCHIVE_PAGE = {
  kind: 'response' as const,
  status: 200,
  body: {
    data: [
      {
        id: '0193c000-0000-7000-8000-000000000101',
        sender: CAROL,
        subject: `Invoice from ${CAROL}`,
        receivedAt: '2026-11-20T10:00:00.000Z',
      },
    ],
    nextCursor: null,
  },
};

describe('pseudonymized turns (step AI-6 D3, I25)', () => {
  it('the model reads placeholders; the browser, the stored answer and the request read real values', async () => {
    const provider = new ScriptedProvider([
      () =>
        reply({
          toolCalls: [
            callTool('c1', 'archive_messages_list', {
              sender: '[EMAIL_1]',
              from: '2026-11-01T00:00:00Z',
              to: '2026-11-20T00:00:00Z',
            }),
          ],
        }),
      (_request, _signal, onDelta) => {
        // A placeholder split across two deltas is still replaced (hold-back buffer).
        onDelta('Found mail for [EMA');
        onDelta('IL_1] from [EMAIL_2].');
        return reply({ text: '' });
      },
    ]);
    const t = build({ settings: { dataSharing: 'pseudonymized' }, llm: () => provider });
    t.h.loopback.on('GET /api/v1/archive/messages', () => ARCHIVE_PAGE);
    const { sink, text } = await t.ask(`Show mail from ${ALICE} please`);
    expect(sink.types.at(-1)).toBe('turn.completed');

    // What the model read: the user entry, the context block and the envelope have placeholders.
    const [first, second] = provider.requests;
    const firstJson = JSON.stringify(first);
    expect(firstJson).toContain('Show mail from [EMAIL_1] please');
    expect(firstJson).not.toContain(ALICE);
    expect(first!.system).toContain('Your organization');
    expect(first!.system).not.toContain('IT Org');
    expect(first!.system).not.toContain('IT User');
    expect(first!.system).toMatch(/\[PERSON_1\]/);
    const secondJson = JSON.stringify(second);
    expect(secondJson).not.toContain(CAROL);
    expect(secondJson).toContain('[EMAIL_2]');

    // The tool request and the stored parameters carry the real value.
    const call = t.h.loopback.toolCalls.at(-1)!;
    expect(decodeURIComponent(call.path)).toContain(`sender=${ALICE}`);
    expect(JSON.stringify(t.h.world.executions[0]!.paramsRedacted)).toContain(ALICE);

    // The browser and the stored answer: de-mapped; the transcript keeps the placeholders.
    expect(text).toBe(`Found mail for ${ALICE} from ${CAROL}.`);
    const answer = t.h.world.messages.find((m) => m.role === 'assistant')!;
    expect(answer.content).toBe(`Found mail for ${ALICE} from ${CAROL}.`);
    const transcript = t.h.world.turns[0]!.providerTranscript!;
    expect(transcript).toContain('[EMAIL_1]');
    expect(transcript).not.toContain(ALICE);
    expect(transcript).not.toContain(CAROL);
    // The user's own message is stored as typed.
    expect(t.h.world.messages.find((m) => m.role === 'user')!.content).toContain(ALICE);

    // The new mappings were inserted at the finish (and are reused by the next turn).
    expect(t.pseudonyms.map((e) => [e.token, e.value])).toEqual([
      ['[PERSON_1]', 'IT User'],
      ['[EMAIL_1]', ALICE],
      ['[EMAIL_2]', CAROL],
    ]);
    expect(t.h.world.turns[0]).toMatchObject({ status: 'completed' });
  });

  it('keeps the numbering across turns and refuses an unknown placeholder before any request', async () => {
    const provider = new ScriptedProvider([
      () => reply({ text: 'ok' }),
      () =>
        reply({
          toolCalls: [
            callTool('c1', 'archive_messages_list', {
              sender: '[EMAIL_99]',
              from: '2026-11-01T00:00:00Z',
              to: '2026-11-20T00:00:00Z',
            }),
          ],
        }),
      () => reply({ text: 'That placeholder is unknown.' }),
    ]);
    const t = build({ settings: { dataSharing: 'pseudonymized' }, llm: () => provider });
    await t.ask(`Hello, I am ${ALICE}`);
    await t.ask(`Again ${ALICE}, and a forged [EMAIL_1] from a subject`);
    // Same value → same token; a forged token in inbound text is neutralized.
    expect(JSON.stringify(provider.requests[1]!.transcript)).toContain(
      'Again [EMAIL_1], and a forged (EMAIL_1) from a subject',
    );
    const denied = t.h.world.executions.at(-1)!;
    expect(denied).toMatchObject({
      decision: 'denied_schema',
      errorCode: 'assistant_unknown_placeholder',
    });
    expect(JSON.stringify(provider.requests[2]!.transcript)).toContain(
      'Unknown placeholder [EMAIL_99]; use a value from this conversation.',
    );
    expect(t.h.loopback.toolCalls).toHaveLength(0);
    expect(t.pseudonymRepo.load).toHaveBeenCalledTimes(2);
  });

  it('leaves `metadata` turns unchanged (no mapping read, real values to the model)', async () => {
    const provider = new ScriptedProvider([() => reply({ text: 'ok' })]);
    const t = build({ llm: () => provider });
    await t.ask(`Mail from ${ALICE}`);
    expect(JSON.stringify(provider.requests[0])).toContain(ALICE);
    expect(provider.requests[0]!.system).toContain('IT User');
    expect(t.pseudonymRepo.load).not.toHaveBeenCalled();
    expect(t.starts[0]).toMatchObject({ dataSharing: 'metadata', keySource: 'platform' });
  });
});

describe('per-user usage and budget (step AI-6 D1)', () => {
  it('writes the user row with the key source and refuses at the user budget (429 scope user)', async () => {
    const t = build({ settings: { userDailyTokenBudget: 100 } });
    await t.ask('/text first');
    expect(t.deltas[0]).toMatchObject({
      provider: 'fake',
      model: 'fake',
      user: { userId: t.principal.userId, keySource: 'platform', priced: false },
    });
    const day = utcDayKey(new Date());
    const counter = await t.h.kv.get(assistantKeys.userTokens(t.principal.userPublicId, day));
    expect(Number(counter)).toBeGreaterThanOrEqual(100);
    const refused = await coded(t.ask('/text second'));
    expect(refused).toMatchObject({
      status: 429,
      code: 'assistant_budget_exhausted',
      details: { scope: 'user' },
    });
  });

  it('the platform daily cap counts platform-key turns only', async () => {
    const t = build({ env: { ASSISTANT_PLATFORM_DAILY_TOKENS: '10' } });
    const now = new Date();
    await t.h.kv.set(assistantKeys.platformTokens(utcDayKey(now)), '10', 60);
    await expect(t.limits.exhaustedScope(ORG, null, now, { keySource: 'platform' })).resolves.toBe(
      'platform',
    );
    await expect(
      t.limits.exhaustedScope(ORG, null, now, { keySource: 'tenant' }),
    ).resolves.toBeNull();
    // A tenant-key turn's tokens never reach the platform counter.
    await t.limits.recordTokens(ORG, 5, now, { keySource: 'tenant', userPublicId: 'u-1' });
    expect(await t.h.kv.get(assistantKeys.platformTokens(utcDayKey(now)))).toBe('10');
  });
});

describe('provider routing in a turn (step AI-6 D6)', () => {
  const FALLBACK = {
    ASSISTANT_FALLBACK_PROVIDER: 'fake',
    ASSISTANT_FALLBACK_MODEL: 'fake-secondary',
  };

  it('switches to the secondary when the first call fails before any output', async () => {
    const primary = new ScriptedProvider([
      () => {
        throw new LlmError('server_error', { httpStatus: 503 });
      },
      () => {
        throw new LlmError('server_error', { httpStatus: 503 });
      },
    ]);
    const secondary = new ScriptedProvider([
      (_r, _s, onDelta) => reply({ text: 'answered by the secondary' }, onDelta),
    ]);
    const t = build({
      env: FALLBACK,
      llm: (spec) => (spec.role === 'primary' ? primary : secondary),
    });
    const { text, sink } = await t.ask('hello');
    expect(sink.types.at(-1)).toBe('turn.completed');
    expect(text).toBe('answered by the secondary');
    expect(t.h.world.turns[0]).toMatchObject({ provider: 'fake', model: 'fake' });
    expect(t.finishes[0]!.route).toEqual({
      provider: 'fake',
      model: 'fake-secondary',
      keySource: 'platform',
      fallbackFrom: 'fake',
    });
    expect(t.deltas[0]).toMatchObject({ model: 'fake-secondary' });
    // The failed primary counted toward its breaker (the retry policy tried it twice).
    expect(await t.h.kv.get('as:brk:fake')).toBe('1');
  });

  it('does not switch after text was streamed (the turn fails as before)', async () => {
    const primary = new ScriptedProvider([
      (_r, _s, onDelta) => {
        onDelta('partial');
        throw new LlmError('server_error', { httpStatus: 503, afterDelta: true });
      },
    ]);
    const secondary = new ScriptedProvider([() => reply({ text: 'never' })]);
    const t = build({
      env: FALLBACK,
      llm: (spec) => (spec.role === 'primary' ? primary : secondary),
    });
    const { sink } = await t.ask('hello');
    expect(sink.events.at(-1)).toMatchObject({
      type: 'turn.failed',
      code: 'assistant_provider_error',
    });
    expect(secondary.requests).toHaveLength(0);
  });

  it('starts a new segment from the recap when the provider or model changes', async () => {
    const t = build({ env: FALLBACK });
    await t.ask('/text first answer');
    expect(t.h.world.turns[0]).toMatchObject({ segment: 1, model: 'fake' });
    // The primary is unhealthy: the next turn runs on the secondary (another model).
    await t.h.kv.set('as:brk:fake', '5', 60);
    const spy = vi.spyOn(FakeProvider.prototype, 'complete');
    await t.ask('/text second answer');
    const transcript = spy.mock.calls[0]![0].transcript as Array<{ text?: string }>;
    expect(transcript).toHaveLength(1);
    expect(JSON.stringify(transcript)).toContain('Conversation recap');
    expect(t.starts[1]).toMatchObject({
      model: 'fake-secondary',
      keySource: 'platform',
      fallbackFrom: 'fake',
    });
    expect(t.h.world.turns[1]).toMatchObject({ model: 'fake-secondary', segment: 2 });
  });

  it('fails a turn whose tenant key was refused when no platform fallback is allowed', async () => {
    const refusing = new ScriptedProvider([
      () => {
        throw new LlmError('auth', { httpStatus: 401 });
      },
    ]);
    const invalidate = vi.fn(() => Promise.resolve());
    const keys = {
      enabled: true,
      client: () =>
        Promise.resolve({
          provider: refusing,
          providerId: 'anthropic',
          model: 'claude-sonnet-5-5',
          keyVersion: 4,
        }),
      invalidate,
    } as unknown as TenantKeyService;
    const t = build({ tenantKeys: keys, settings: { useTenantKey: true } });
    const { sink } = await t.ask('hello');
    expect(sink.events.at(-1)).toMatchObject({
      type: 'turn.failed',
      code: 'assistant_tenant_key_invalid',
    });
    expect(invalidate).toHaveBeenCalledWith(t.principal, expect.anything(), 4);
    expect(t.starts[0]).toMatchObject({
      provider: 'anthropic',
      model: 'claude-sonnet-5-5',
      keySource: 'tenant',
    });
    expect(t.h.world.turns[0]).toMatchObject({ errorCode: 'assistant_tenant_key_invalid' });
    expect(t.deltas[0]).toMatchObject({ user: { keySource: 'tenant' } });
  });
});

describe('report job action updates (step AI-6 D5)', () => {
  it('reports finished jobs to the model once and marks them reported when the turn completes', async () => {
    const provider = new ScriptedProvider([
      () => reply({ text: 'noted' }),
      () => reply({ text: 'ok' }),
    ]);
    const t = build({
      llm: () => provider,
      jobs: [
        { id: 1n, status: 'succeeded', errorCode: null, executionSeq: 3 },
        { id: 2n, status: 'failed', errorCode: 'assistant_report_job_expired', executionSeq: 5 },
      ],
    });
    await t.ask('anything new?');
    const entry = JSON.stringify(provider.requests[0]!.transcript);
    expect(entry).toContain('report_generate (call r3): the background report is ready.');
    expect(entry).toContain(
      'report_generate (call r5): the background report failed (assistant_report_job_expired).',
    );
    expect(t.reported).toEqual([1n, 2n]);
    await t.ask('and now?');
    const last = provider.requests[1]!.transcript.at(-1);
    expect(JSON.stringify(last)).toContain('and now?');
    expect(JSON.stringify(last)).not.toContain('report_generate (call');
  });
});
