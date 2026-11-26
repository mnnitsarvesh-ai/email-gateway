/**
 * Step AI-6 provider fallback, health and tenant-supplied keys on the real stack (docs/plan/steps/
 * 34-ai-chat-hardening-operations.md D6, D7, I27, R4, R5, §9 item 5; ADR-0097; contracts §35.6):
 * real MySQL and Redis (the `as:brk:*` breakers, token counters) from the local `.env`, the api on
 * its ephemeral loopback port. Platform candidates are fakes only (a scripted failing primary,
 * a fake secondary); a tenant key is served by the REAL Anthropic/OpenAI provider classes over an
 * injected local fake `fetch` (`FakeLlmEndpoint`): nothing reaches a real LLM or the internet.
 *
 * Fallback: a primary failing with `server_error` before any output switches to the secondary in
 * the same turn (`fallback_from` recorded, a new transcript segment because the model changed);
 * the breaker opens after the threshold and the next turn starts on the secondary (status
 * `fallbackActive`); the primary is used again once its window ended (new segment again); a
 * failure after streamed text or after a tool ran never switches; both breakers open → `503
 * assistant_provider_unavailable`.
 *
 * Tenant keys: the platform gate off → `403 assistant_tenant_keys_disabled`; MFA and permission
 * refusals; set through a probe answered 401 (`422 assistant_tenant_key_rejected`), 5xx (`502
 * assistant_tenant_key_unverified`) — nothing stored — and 200 (stored encrypted, fingerprint and
 * status only); validate; turns on the tenant key (`key_source = tenant`, the per-user usage row);
 * the tenant budget enforced on tenant-key turns while the platform daily cap neither applies to
 * nor counts them; a key refused during a turn is invalidated (`503 assistant_tenant_key_invalid`
 * without fallback, the platform with `tenantKeyFallbackToPlatform`); removal. The synthetic key
 * never appears in an HTTP response, an `audit_logs` row, a database column other than its
 * ciphertext, or a captured log line. Synthetic `it-*` organizations only.
 */
// @covers put /api/v1/assistant/settings/provider-key
// @covers delete /api/v1/assistant/settings/provider-key
// @covers post /api/v1/assistant/settings/provider-key/validate
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers get /api/v1/assistant/status
// @covers get /api/v1/assistant/settings
// @covers put /api/v1/assistant/settings
import { createHash, randomBytes } from 'node:crypto';
import type { FakeTranscriptEntry, LlmRequest } from '@email-gateway/assistant';
import type { Response } from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { utcDayKey } from '../src/modules/assistant/assistant.constants';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  call,
  clearAssistantCounters,
  createAssistantApp,
  directive,
  enableAssistant,
  FALLBACK_FAKE_MODEL,
  type HoldableFakeProvider,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  turn,
  updateSettings,
} from './support/assistant';
import {
  clearHardeningKeys,
  FakeLlmEndpoint,
  needlesIn,
  putProviderKey,
  removeProviderKey,
  TENANT_KEY_A,
  TENANT_KEY_B,
  TENANT_OPENAI_MODEL,
} from './support/assistant-hardening';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';

const KEY = `${A}/settings/provider-key`;

async function turnRows(ctx: IntegrationApp, conversation: string) {
  return ctx.prisma.aiChatTurn.findMany({
    where: { conversation: { publicId: conversation } },
    orderBy: { seq: 'asc' },
    select: {
      seq: true,
      status: true,
      provider: true,
      model: true,
      segment: true,
      keySource: true,
      fallbackFrom: true,
      errorCode: true,
    },
  });
}

const hasToolResult = (request: LlmRequest): boolean =>
  (request.transcript as readonly FakeTranscriptEntry[]).some((e) => e.role === 'tool');

describe('platform fallback with Redis breakers (D6)', () => {
  let ctx: IntegrationApp;
  let fx: Fixtures;
  let primary: HoldableFakeProvider;
  let secondary: HoldableFakeProvider;
  let org: FixtureOrganization;
  let admin: Member;

  beforeAll(async () => {
    const app = await createAssistantApp({
      fallback: true,
      env: { ASSISTANT_BREAKER_THRESHOLD: '2', ASSISTANT_BREAKER_RESET_MS: '30000' },
    });
    ctx = app.ctx;
    primary = app.provider;
    secondary = app.fallback!;
    expect(app.specs.map((s) => [s.role, s.provider, s.model])).toEqual([
      ['primary', 'fake', 'fake'],
      ['fallback', 'fake', FALLBACK_FAKE_MODEL],
    ]);
    fx = createFixtures(ctx);
    const operator = await platformMember(ctx, fx);
    org = await fx.createOrganization({ planCode: 'enterprise' });
    admin = await memberWith(ctx, fx, org, { permissions: [...ALL_TENANT_PERMISSIONS] });
    await enableAssistant(ctx, operator, org, admin);
  }, 120_000);

  afterEach(async () => {
    primary.failure = null;
    secondary.failure = null;
    await clearHardeningKeys(ctx);
  });

  afterAll(async () => {
    if (ctx) {
      await clearHardeningKeys(ctx);
      await clearAssistantCounters(ctx, [org.id]);
    }
    await fx?.cleanup();
    await ctx?.close();
  });

  it('switches in the same turn before any output, opens the breaker, starts on the secondary, returns to the primary', async () => {
    const conversation = await newConversation(ctx, admin);
    expect((await turn(ctx, admin.headers, conversation, '/text On the primary.')).status).toBe(
      200,
    );

    primary.failure = () => ({ reason: 'server_error' });
    const secondaryCalls = secondary.calls;
    const switched = await turn(ctx, admin.headers, conversation, '/text Switched.');
    expect(switched.status, JSON.stringify(switched.body)).toBe(200);
    expect(switched.body.turn.status).toBe('completed');
    expect(switched.body.message.content).toBe('Switched.');
    expect(secondary.calls).toBe(secondaryCalls + 1);
    // One failure counted (the retry policy's second call is the same model call).
    expect(await ctx.kv.get('as:brk:fake')).toBe('1');

    // Still below the threshold: the primary is tried first again, fails, the turn switches.
    const again = await turn(ctx, admin.headers, conversation, '/text Again switched.');
    expect(again.body.turn.status).toBe('completed');
    expect(await ctx.kv.get('as:brk:fake')).toBe('2');

    // The breaker is open: the next turn starts on the secondary without calling the primary.
    const primaryCalls = primary.calls;
    const status = await call(ctx, admin.headers, 'get', `${A}/status`);
    expect(status.body).toMatchObject({
      available: true,
      keySource: 'platform',
      fallbackActive: true,
      dataSharing: 'metadata',
    });
    const direct = await turn(ctx, admin.headers, conversation, '/text Started on the secondary.');
    expect(direct.body.turn.status).toBe('completed');
    expect(primary.calls).toBe(primaryCalls);

    // The window ends (the key expires): the primary answers again.
    primary.failure = null;
    await ctx.kv.del('as:brk:fake');
    const back = await turn(ctx, admin.headers, conversation, '/text Back on the primary.');
    expect(back.body.turn.status).toBe('completed');
    expect((await call(ctx, admin.headers, 'get', `${A}/status`)).body.fallbackActive).toBe(false);

    const rows = await turnRows(ctx, conversation);
    expect(rows.map((r) => [r.model, r.fallbackFrom, r.segment, r.keySource])).toEqual([
      ['fake', null, 1, 'platform'],
      // Same-turn switch: the model changed → a new segment from the recap (D6).
      [FALLBACK_FAKE_MODEL, 'fake', 2, 'platform'],
      [FALLBACK_FAKE_MODEL, 'fake', 2, 'platform'],
      // Breaker open at turn start: the secondary is selected, the skipped primary recorded.
      [FALLBACK_FAKE_MODEL, 'fake', 2, 'platform'],
      ['fake', null, 3, 'platform'],
    ]);
    expect(rows.every((r) => r.provider === 'fake' && r.status === 'completed')).toBe(true);
  });

  it('never switches after streamed text or after a tool ran; both breakers open → 503', async () => {
    const conversation = await newConversation(ctx, admin);
    const secondaryCalls = secondary.calls;
    // A failure after a text delta: the turn fails on the primary (no second provider's text).
    primary.failure = () => ({ reason: 'server_error', afterDelta: true });
    const afterText = await turn(ctx, admin.headers, conversation, '/text Never shown.');
    expect(afterText.status).toBe(200);
    expect(afterText.body.turn.status).toBe('failed');
    expect(afterText.body.turn.errorCode).toBe('assistant_provider_error');
    expect(secondary.calls).toBe(secondaryCalls);

    // A failure of the second round (a tool ran in the first): no switch either.
    primary.failure = (request) => (hasToolResult(request) ? { reason: 'server_error' } : null);
    const afterTool = await turn(
      ctx,
      admin.headers,
      conversation,
      directive('policy_management_list'),
    );
    expect(afterTool.body.turn.status).toBe('failed');
    expect(afterTool.body.executions).toHaveLength(1);
    expect(afterTool.body.executions[0]).toMatchObject({ status: 'succeeded' });
    expect(secondary.calls).toBe(secondaryCalls);
    const rows = await turnRows(ctx, conversation);
    expect(rows.every((r) => r.model === 'fake' && r.fallbackFrom === null)).toBe(true);

    // Every candidate's breaker open: 503 before any model call.
    await ctx.kv.set('as:brk:fake', '2', 30);
    await ctx.kv.set('as:brk:fake:fb', '2', 30);
    const none = await turn(ctx, admin.headers, conversation, '/text Nobody answers.');
    expect(none.status).toBe(503);
    expect(none.body.code).toBe('assistant_provider_unavailable');
    const status = await call(ctx, admin.headers, 'get', `${A}/status`);
    expect(status.body).toMatchObject({ available: false });
  });

  it('the platform gate off answers 403 assistant_tenant_keys_disabled and offers nothing', async () => {
    const settings = await call(ctx, admin.headers, 'get', `${A}/settings`);
    expect(settings.body.tenantKeysOffered).toMatchObject({ enabled: false });
    expect(settings.body.tenantKey).toBeNull();
    const res = await putProviderKey(ctx, admin, {
      provider: 'openai',
      model: TENANT_OPENAI_MODEL,
      apiKey: TENANT_KEY_A,
    });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('assistant_tenant_keys_disabled');
    expect(JSON.stringify(res.body)).not.toContain(TENANT_KEY_A);
    const validate = await call(ctx, admin.headers, 'post', `${KEY}/validate`);
    expect(validate.body.code).toBe('assistant_tenant_keys_disabled');
    const refused = await call(ctx, admin.headers, 'put', `${A}/settings`, {
      expectedRowVersion: (await call(ctx, admin.headers, 'get', `${A}/settings`)).body.rowVersion,
      enabled: true,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: null,
      retentionDays: 30,
      useTenantKey: true,
    });
    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('assistant_tenant_keys_disabled');
  });
});

describe('tenant-supplied provider keys (D7, I27)', () => {
  let ctx: IntegrationApp;
  let fx: Fixtures;
  let primary: HoldableFakeProvider;
  const endpoint = new FakeLlmEndpoint();
  let org: FixtureOrganization;
  let platformOrg: FixtureOrganization;
  let admin: Member;
  let user: Member;
  let noMfa: Member;
  let viewer: Member;
  let platformUser: Member;
  /** Every HTTP response of the tenant-key flows (scanned for the key at the end). */
  const responses: Response[] = [];
  const keep = (res: Response): Response => {
    responses.push(res);
    return res;
  };

  beforeAll(async () => {
    const app = await createAssistantApp({
      tenantFetch: endpoint.fetch,
      env: {
        ASSISTANT_TENANT_KEYS_ENABLED: 'true',
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
        ASSISTANT_TENANT_KEY_PROVIDERS: 'anthropic,openai',
        ASSISTANT_TENANT_KEY_MODELS: `claude-opus-5-5,${TENANT_OPENAI_MODEL}`,
        ASSISTANT_TENANT_KEY_VALIDATION_TIMEOUT_MS: '5000',
        // The platform daily cap: 1 token (A6-7: tenant-key turns are neither refused nor counted).
        ASSISTANT_PLATFORM_DAILY_TOKENS: '1',
      },
    });
    ctx = app.ctx;
    primary = app.provider;
    fx = createFixtures(ctx);
    const operator = await platformMember(ctx, fx);
    org = await fx.createOrganization({ planCode: 'enterprise' });
    platformOrg = await fx.createOrganization({ planCode: 'enterprise' });
    admin = await memberWith(ctx, fx, org, { permissions: [...ALL_TENANT_PERMISSIONS] });
    user = await memberWith(ctx, fx, org, { permissions: ['policy:read'] });
    noMfa = await memberWith(
      ctx,
      fx,
      org,
      { permissions: ['assistant:configure'] },
      { mfa: false },
    );
    viewer = await memberWith(ctx, fx, org, { permissions: ['organization:read'] });
    platformUser = await memberWith(ctx, fx, platformOrg, {
      permissions: [...ALL_TENANT_PERMISSIONS],
    });
    await enableAssistant(ctx, operator, org, admin);
    await enableAssistant(ctx, operator, platformOrg, platformUser);
  }, 120_000);

  afterEach(() => {
    endpoint.reset();
    primary.failure = null;
  });

  afterAll(async () => {
    if (ctx) {
      await clearHardeningKeys(ctx, {
        organizationPublicIds: [org.publicId],
        userPublicIds: [admin, user, platformUser].filter(Boolean).map((m) => m.user.publicId),
      });
      await clearAssistantCounters(ctx, [org.id, platformOrg.id]);
    }
    await fx?.cleanup();
    await ctx?.close();
  });

  const keyRow = () =>
    ctx.prisma.aiChatProviderKey.findUnique({ where: { organizationId: org.id } });

  it('refuses without an MFA session and without assistant:configure', async () => {
    const body = { provider: 'openai', model: TENANT_OPENAI_MODEL, apiKey: TENANT_KEY_A };
    const mfa = keep(await putProviderKey(ctx, noMfa, body));
    expect(mfa.status).toBe(403);
    expect(mfa.body.code).toBe('mfa_required');
    const forbidden = keep(await putProviderKey(ctx, viewer, body));
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.code).toBe('forbidden');
    keep(await call(ctx, noMfa.headers, 'post', `${KEY}/validate`));
    expect(endpoint.calls).toEqual([]);
    expect(await keyRow()).toBeNull();
  });

  it('a probe answered 401 or 5xx stores nothing; 200 stores the key encrypted (fingerprint and status only)', async () => {
    const body = { provider: 'openai', model: TENANT_OPENAI_MODEL, apiKey: TENANT_KEY_A };
    endpoint.reset('unauthorized');
    const rejected = keep(await putProviderKey(ctx, admin, body));
    expect(rejected.status).toBe(422);
    expect(rejected.body.code).toBe('assistant_tenant_key_rejected');
    endpoint.reset('server_error');
    const unverified = keep(await putProviderKey(ctx, admin, body));
    expect(unverified.status).toBe(502);
    expect(unverified.body.code).toBe('assistant_tenant_key_unverified');
    expect(await keyRow()).toBeNull();

    endpoint.reset('valid');
    const stored = keep(await putProviderKey(ctx, admin, body));
    expect(stored.status, JSON.stringify(stored.body)).toBe(200);
    const fingerprint = createHash('sha256').update(TENANT_KEY_A).digest('hex').slice(0, 16);
    expect(stored.body).toMatchObject({
      provider: 'openai',
      model: TENANT_OPENAI_MODEL,
      fingerprint,
      status: 'valid',
      setBy: { id: admin.user.publicId },
    });
    // The probe: GET {base}/models/{model} with the key as a bearer, no generation.
    expect(endpoint.calls).toHaveLength(1);
    expect(endpoint.calls[0]).toMatchObject({ method: 'GET' });
    expect(endpoint.calls[0]!.url).toMatch(new RegExp(`/models/${TENANT_OPENAI_MODEL}$`));
    expect(endpoint.sawKey(TENANT_KEY_A)).toBe(true);
    const row = (await keyRow())!;
    expect(row).toMatchObject({
      provider: 'openai',
      model: TENANT_OPENAI_MODEL,
      keyFingerprint: fingerprint,
      status: 'valid',
    });
    expect(row.keyCiphertext).toMatch(/^v1\.k[0-9a-f]{7}\./);
    expect(row.keyCiphertext).not.toContain(TENANT_KEY_A);
    const settings = keep(await call(ctx, admin.headers, 'get', `${A}/settings`));
    expect(settings.body.tenantKey).toMatchObject({ fingerprint, status: 'valid' });
    expect(settings.body.tenantKeysOffered).toEqual({
      enabled: true,
      providers: ['anthropic', 'openai'],
      models: ['claude-opus-5-5', TENANT_OPENAI_MODEL],
    });

    // Validate: re-probes the stored key (decrypted in memory) and records the outcome.
    endpoint.reset('valid');
    const validated = keep(await call(ctx, admin.headers, 'post', `${KEY}/validate`));
    expect(validated.status).toBe(200);
    expect(validated.body).toMatchObject({ status: 'valid', lastErrorCode: null });
    expect(endpoint.sawKey(TENANT_KEY_A)).toBe(true);

    // An Anthropic key through the real SDK class (probe = models.retrieve) replaces it.
    endpoint.reset('valid');
    const anthropic = keep(
      await putProviderKey(ctx, admin, {
        provider: 'anthropic',
        model: 'claude-opus-5-5',
        apiKey: TENANT_KEY_B,
      }),
    );
    expect(anthropic.status, JSON.stringify(anthropic.body)).toBe(200);
    expect(endpoint.calls[0]!.url).toMatch(/\/v1\/models\/claude-opus-5-5$/);
    expect(endpoint.sawKey(TENANT_KEY_B)).toBe(true);
    // Back to the OpenAI key for the turns below.
    endpoint.reset('valid');
    expect(keep(await putProviderKey(ctx, admin, body)).status).toBe(200);
  });

  it('turns use the tenant key; the platform cap neither applies to nor counts them; the tenant budget does', async () => {
    await updateSettings(ctx, admin, { useTenantKey: true, tenantKeyFallbackToPlatform: false });
    const status = keep(await call(ctx, user.headers, 'get', `${A}/status`));
    expect(status.body).toMatchObject({ keySource: 'tenant', fallbackActive: false });

    const platformKey = `as:tok:p:${utcDayKey(new Date())}`;
    // A platform-key organization is over the 1-token platform cap once anything counted today.
    const platformConversation = await newConversation(ctx, platformUser);
    let platformTurn = await turn(ctx, platformUser.headers, platformConversation, '/text One.');
    if (platformTurn.status === 200) {
      platformTurn = await turn(ctx, platformUser.headers, platformConversation, '/text Two.');
    }
    expect(platformTurn.status).toBe(429);
    expect(platformTurn.body).toMatchObject({
      code: 'assistant_budget_exhausted',
      scope: 'platform',
    });
    const platformBefore = await ctx.kv.get(platformKey);

    const conversation = await newConversation(ctx, user);
    const res = keep(await turn(ctx, user.headers, conversation, 'What is new today?'));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.turn.status).toBe('completed');
    expect(res.body.message.content).toBe(endpoint.answer);
    const chat = endpoint.calls.find((c) => c.url.endsWith('/chat/completions'));
    expect(chat?.authorization).toBe(`Bearer ${TENANT_KEY_A}`);
    const [row] = await turnRows(ctx, conversation);
    expect(row).toMatchObject({
      provider: 'openai',
      model: TENANT_OPENAI_MODEL,
      keySource: 'tenant',
    });
    expect(await ctx.kv.get(platformKey)).toBe(platformBefore);
    const usage = await ctx.prisma.aiChatUsageUserDaily.findMany({
      where: { organizationId: org.id, userId: user.user.id },
    });
    expect(usage).toHaveLength(1);
    expect(usage[0]).toMatchObject({ keySource: 'tenant', provider: 'openai', turns: 1 });
    expect(Number(usage[0]!.inputTokens)).toBe(endpoint.usage.prompt);

    // The tenant budget counts tenant-key turns: a budget below today's use refuses the next turn.
    await updateSettings(ctx, admin, { dailyTokenBudget: 1_000 });
    const refused = keep(await turn(ctx, user.headers, conversation, 'And now?'));
    expect(refused.status).toBe(429);
    expect(refused.body).toMatchObject({ code: 'assistant_budget_exhausted', scope: 'tenant' });
    await updateSettings(ctx, admin, { dailyTokenBudget: null });
    await clearAssistantCounters(ctx, [org.id]);
  });

  it('a key refused during a turn is invalidated: 503 without fallback, the platform with it', async () => {
    await updateSettings(ctx, admin, { useTenantKey: true, tenantKeyFallbackToPlatform: false });
    const conversation = await newConversation(ctx, user);
    endpoint.reset('unauthorized');
    const failed = keep(await turn(ctx, user.headers, conversation, 'Hello?'));
    expect(failed.status).toBe(200);
    expect(failed.body.turn).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_tenant_key_invalid',
    });
    expect((await keyRow())!).toMatchObject({ status: 'invalid', lastErrorCode: 'provider_auth' });
    const invalidated = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'assistant.provider_key_invalidated' },
    });
    expect(invalidated).toHaveLength(1);
    // The next turn: no usable key and no fallback → 503 at turn start.
    const next = keep(await turn(ctx, user.headers, conversation, 'Still there?'));
    expect(next.status).toBe(503);
    expect(next.body.code).toBe('assistant_tenant_key_invalid');

    // Allowed to fall back: the platform answers (the fake primary).
    endpoint.reset('valid');
    expect(keep(await call(ctx, admin.headers, 'post', `${KEY}/validate`)).body.status).toBe(
      'valid',
    );
    await updateSettings(ctx, admin, { useTenantKey: true, tenantKeyFallbackToPlatform: true });
    endpoint.reset('unauthorized');
    const fallback = keep(await turn(ctx, user.headers, conversation, '/text Platform answer.'));
    expect(fallback.status).toBe(200);
    expect(fallback.body.turn.status).toBe('completed');
    expect(fallback.body.message.content).toBe('Platform answer.');
    const rows = await turnRows(ctx, conversation);
    expect(rows.at(-1)).toMatchObject({
      provider: 'fake',
      keySource: 'platform',
      fallbackFrom: 'openai',
    });
    expect((await keyRow())!.status).toBe('invalid');
  });

  it('removes the key (useTenantKey off); the key never leaked to a response, audit row, column or log', async () => {
    const removed = keep(await removeProviderKey(ctx, admin));
    expect(removed.status).toBe(204);
    expect(await keyRow()).toBeNull();
    const settings = keep(await call(ctx, admin.headers, 'get', `${A}/settings`));
    expect(settings.body).toMatchObject({ useTenantKey: false, tenantKey: null });
    expect(keep(await removeProviderKey(ctx, admin)).status).toBe(404);

    const keys = [TENANT_KEY_A, TENANT_KEY_B];
    // HTTP responses (bodies and headers).
    for (const res of responses) {
      expect(needlesIn([res.body, res.headers, res.text], keys)).toEqual([]);
    }
    // Audit rows of the organization (key actions carry provider, model, fingerprint, outcome).
    const audit = await ctx.prisma.auditLog.findMany({ where: { organizationId: org.id } });
    const actions = new Set(audit.map((a) => a.action));
    for (const action of [
      'assistant.provider_key_set',
      'assistant.provider_key_validated',
      'assistant.provider_key_invalidated',
      'assistant.provider_key_removed',
    ]) {
      expect(actions.has(action), action).toBe(true);
    }
    expect(
      needlesIn(
        audit.map((a) => [a.metadata, a.resourceId]),
        keys,
      ),
    ).toEqual([]);
    // Database columns: settings, turns (transcripts), executions, the outbox.
    const columns = [
      await ctx.prisma.aiChatSettings.findMany({ where: { organizationId: org.id } }),
      await ctx.prisma.aiChatTurn.findMany({
        where: { organizationId: org.id },
        select: { providerTranscript: true, errorCode: true, fallbackFrom: true },
      }),
      await ctx.prisma.aiChatToolExecution.findMany({ where: { organizationId: org.id } }),
      await ctx.prisma.aiChatMessage.findMany({ where: { organizationId: org.id } }),
      await ctx.prisma.messageOutbox.findMany({ where: { organizationId: org.id } }),
    ];
    expect(
      needlesIn(
        JSON.parse(
          JSON.stringify(columns, (_k, v: unknown) => (typeof v === 'bigint' ? String(v) : v)),
        ),
        keys,
      ),
    ).toEqual([]);
    // Every log line the app wrote.
    expect(needlesIn(ctx.logs, keys)).toEqual([]);
    expect(ctx.logs.length).toBeGreaterThan(0);
  });
});
