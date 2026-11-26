/**
 * The 11 step AI-6 assistant operations (docs/plan/steps/34-ai-chat-hardening-operations.md §4.1,
 * contracts §35.6, §9 item 4) over HTTP with MySQL, Redis and S3 stubbed: the assistant tables
 * through `AssistantWorld` and the insight repositories through small in-memory doubles. For every
 * operation: 403 `user_required` for API keys, 403 without its permission, the MFA session the
 * tenant-key routes need, body/query validation, the platform gate of tenant keys, the coded
 * not-found/not-allowed answers and the shape of the views (feedback upsert and removal audited
 * without the comment, search snippets, empty admin and audit pages). The behaviour over real
 * MySQL/Redis/RabbitMQ is proven by the integration suites `assistant-admin.test.ts` and
 * `assistant-provider-fallback.test.ts`. Synthetic data only; the tenant-key value is a
 * non-secret-shaped fixture and must never appear in a response.
 */
// @covers put /api/v1/assistant/settings/provider-key
// @covers delete /api/v1/assistant/settings/provider-key
// @covers post /api/v1/assistant/settings/provider-key/validate
// @covers get /api/v1/assistant/search
// @covers put /api/v1/assistant/messages/:messageId/feedback
// @covers delete /api/v1/assistant/messages/:messageId/feedback
// @covers get /api/v1/assistant/admin/usage/users
// @covers get /api/v1/assistant/admin/feedback
// @covers get /api/v1/assistant/admin/conversations
// @covers get /api/v1/assistant/admin/conversations/:conversationId
// @covers get /api/v1/assistant/admin/executions
import { randomUUID } from 'node:crypto';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditRepository } from '../src/modules/assistant-insights/repositories/audit.repository';
import {
  type FeedbackRow,
  FeedbackRepository,
  type FeedbackWrite,
  type OwnedMessage,
} from '../src/modules/assistant-insights/repositories/feedback.repository';
import { IdentityRepository } from '../src/modules/assistant-insights/repositories/identity.repository';
import {
  type SearchRow,
  SearchRepository,
} from '../src/modules/assistant-insights/repositories/search.repository';
import { UserUsageRepository } from '../src/modules/assistant-insights/repositories/user-usage.repository';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import {
  AssistantWorld,
  FakeLoopback,
  overrideAssistant,
  RecordingAssistantAudit,
} from './support/assistant-fixtures';

const ORG = 7101n;
const USE = 'assistant:use';
const CONFIGURE = 'assistant:configure';
const AUDIT = 'audit:read';
const ALL = [USE, CONFIGURE, AUDIT];
const BASE = '/api/v1/assistant';
/** Synthetic tenant-key fixture (matches no secret-scanner pattern). */
const TENANT_KEY = 'test-tenant-key-0001-not-a-secret';

type Method = 'get' | 'post' | 'put' | 'delete';

/** JSON of audit entries (bigint ids as strings). */
const auditJson = (entries: unknown): string =>
  JSON.stringify(entries, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

/** In-memory stand-ins for the step AI-6 insight repositories (WP4). */
class InsightsWorld {
  messages: OwnedMessage[] = [];
  feedback: FeedbackRow[] = [];
  searchRows: SearchRow[] = [];
  searchCalls: Array<{ userId: bigint; organizationId: bigint; pattern: string }> = [];
  /** Conversations whose content was purged (`content_purged_at` set). */
  purgedConversations = new Set<bigint>();
  private nextId = 1n;

  reset(): void {
    this.messages = [];
    this.purgedConversations.clear();
    this.feedback = [];
    this.searchRows = [];
    this.searchCalls = [];
  }

  message(turnStatus: OwnedMessage['turnStatus'], role: OwnedMessage['role'] = 'assistant') {
    const row: OwnedMessage = {
      id: this.nextId++,
      publicId: randomUUID(),
      organizationId: ORG,
      conversationId: 50n,
      conversationPublicId: randomUUID(),
      turnId: 60n,
      role,
      turnStatus,
    };
    this.messages.push(row);
    return row;
  }

  override(builder: TestingModuleBuilder): TestingModuleBuilder {
    return builder
      .overrideProvider(FeedbackRepository)
      .useValue({
        findOwnedMessage: (_owner: unknown, publicId: string) =>
          Promise.resolve(this.messages.find((m) => m.publicId === publicId) ?? null),
        lockContentPurged: (_organizationId: bigint, conversationId: bigint) =>
          Promise.resolve(this.purgedConversations.has(conversationId)),
        findByMessage: (_scope: unknown, messageId: bigint) =>
          Promise.resolve(this.feedback.find((f) => f.messageId === messageId) ?? null),
        upsert: (_scope: unknown, data: FeedbackWrite) => {
          const now = new Date();
          const existing = this.feedback.find((f) => f.messageId === data.messageId);
          if (existing) {
            Object.assign(existing, {
              rating: data.rating,
              reason: data.reason,
              comment: data.comment,
              updatedAt: now,
            });
            return Promise.resolve({ ...existing });
          }
          const row: FeedbackRow = {
            id: this.nextId++,
            organizationId: ORG,
            ...data,
            createdAt: now,
            updatedAt: now,
          };
          this.feedback.push(row);
          return Promise.resolve({ ...row });
        },
        remove: (_scope: unknown, id: bigint) => {
          const before = this.feedback.length;
          this.feedback = this.feedback.filter((f) => f.id !== id);
          return Promise.resolve(this.feedback.length < before);
        },
        adminList: () => Promise.resolve([]),
        turnsMeta: () => Promise.resolve(new Map()),
        toolsOfTurns: () => Promise.resolve(new Map()),
      })
      .overrideProvider(SearchRepository)
      .useValue({
        search: (
          owner: { scope: { organizationId: bigint }; userId: bigint },
          input: { pattern: string; take: number },
        ) => {
          this.searchCalls.push({
            userId: owner.userId,
            organizationId: owner.scope.organizationId,
            pattern: input.pattern,
          });
          return Promise.resolve(this.searchRows.slice(0, input.take));
        },
      })
      .overrideProvider(UserUsageRepository)
      .useValue({
        page: () => Promise.resolve([]),
        totalsOfUsers: () => Promise.resolve([]),
        overall: () =>
          Promise.resolve({
            turns: 0,
            inputTokens: 0,
            outputTokens: 0,
            cacheReadTokens: 0,
            cacheWriteTokens: 0,
            costMicros: 0,
            pricedRows: 0,
          }),
      })
      .overrideProvider(IdentityRepository)
      .useValue({
        byIds: () => Promise.resolve(new Map()),
        idOfFilter: () => Promise.resolve(null),
      })
      .overrideProvider(AuditRepository)
      .useValue({
        conversationPage: () => Promise.resolve([]),
        findConversation: () => Promise.resolve(null),
        conversationIdOf: () => Promise.resolve(null),
        aggregates: () =>
          Promise.resolve({
            tokens: new Map(),
            executions: new Map(),
            confirmations: new Map(),
            reports: new Map(),
            feedback: new Map(),
          }),
        executionPage: () => Promise.resolve([]),
      });
  }
}

describe('assistant hardening routes (step AI-6, e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new AssistantWorld();
  const insights = new InsightsWorld();
  const audit = new RecordingAssistantAudit();
  const loopback = new FakeLoopback();

  beforeAll(async () => {
    // The platform gate of tenant keys stays off (the default): the routes answer 403
    // `assistant_tenant_keys_disabled` before any provider is contacted.
    api = await createStubbedApiApp(
      { ASSISTANT_ENABLED: 'true', ASSISTANT_PROVIDER: 'fake' },
      { override: (b) => insights.override(overrideAssistant(b, world, audit, loopback)) },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    insights.reset();
    audit.entries.length = 0;
    loopback.reset();
    api.kv.entries.clear();
    api.principals.organizationId = ORG;
    api.principals.apiKeyWith(ALL);
    world.enable(ORG);
  });

  const as = (permissions: string[] = ALL, mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();
  const send = async (
    method: Method,
    path: string,
    body?: object,
    permissions: string[] = ALL,
    mfa = true,
  ) => {
    const req = api
      .http()
      [method](path)
      .set(await as(permissions, mfa));
    return body === undefined ? req : req.send(body);
  };

  const keyBody = {
    provider: 'anthropic',
    model: 'claude-opus-5-5',
    apiKey: TENANT_KEY,
    expectedRowVersion: 0,
  };

  it('every route refuses API keys (403 user_required) and callers without the permission (403)', async () => {
    const message = randomUUID();
    const conversation = randomUUID();
    const routes: Array<[Method, string, string, object?]> = [
      ['put', `${BASE}/settings/provider-key`, CONFIGURE, keyBody],
      ['delete', `${BASE}/settings/provider-key?expectedRowVersion=0`, CONFIGURE],
      ['post', `${BASE}/settings/provider-key/validate`, CONFIGURE],
      ['get', `${BASE}/search?q=report`, USE],
      ['put', `${BASE}/messages/${message}/feedback`, USE, { rating: 'up' }],
      ['delete', `${BASE}/messages/${message}/feedback`, USE],
      ['get', `${BASE}/admin/usage/users`, CONFIGURE],
      ['get', `${BASE}/admin/feedback`, CONFIGURE],
      ['get', `${BASE}/admin/conversations`, AUDIT],
      ['get', `${BASE}/admin/conversations/${conversation}`, AUDIT],
      ['get', `${BASE}/admin/executions`, AUDIT],
    ];
    for (const [method, path, permission, body] of routes) {
      const keyed = api.http()[method](path).set(api.principals.apiKeyHeaders);
      const byKey = body === undefined ? await keyed : await keyed.send(body);
      expect(byKey.status, `${method} ${path} (api key)`).toBe(403);
      expect((byKey.body as { code: string }).code, path).toBe('user_required');
      const without = await send(
        method,
        path,
        body,
        ALL.filter((p) => p !== permission),
      );
      expect(without.status, `${method} ${path} (no ${permission})`).toBe(403);
      expect((without.body as { code: string }).code, path).toBe('forbidden');
      expect(JSON.stringify(byKey.body) + JSON.stringify(without.body)).not.toContain(TENANT_KEY);
    }
    // The audit permission alone never opens the configuration or the owner's search.
    expect((await send('get', `${BASE}/admin/usage/users`, undefined, [AUDIT])).status).toBe(403);
    expect((await send('get', `${BASE}/admin/feedback`, undefined, [AUDIT])).status).toBe(403);
    expect((await send('get', `${BASE}/search?q=report`, undefined, [AUDIT])).status).toBe(403);
    // assistant:configure alone never opens the audit view.
    expect((await send('get', `${BASE}/admin/conversations`, undefined, [CONFIGURE])).status).toBe(
      403,
    );
  });

  describe('tenant provider key (D7)', () => {
    it('needs an MFA session on all three routes (403 mfa_required)', async () => {
      for (const [method, path, body] of [
        ['put', `${BASE}/settings/provider-key`, keyBody],
        ['delete', `${BASE}/settings/provider-key?expectedRowVersion=0`, undefined],
        ['post', `${BASE}/settings/provider-key/validate`, undefined],
      ] as Array<[Method, string, object | undefined]>) {
        const res = await send(method, path, body, ALL, false);
        expect(res.status, `${method} ${path}`).toBe(403);
        expect((res.body as { code: string }).code).toBe('mfa_required');
      }
    });

    it('validates the body without echoing the key; the platform gate off answers 403 assistant_tenant_keys_disabled', async () => {
      for (const body of [
        { ...keyBody, apiKey: 'too-short' },
        { ...keyBody, apiKey: `${TENANT_KEY} with spaces` },
        { ...keyBody, provider: 'azure_openai' },
        { ...keyBody, extra: true },
        { provider: 'anthropic', model: 'claude-opus-5-5', apiKey: TENANT_KEY },
      ]) {
        const res = await send('put', `${BASE}/settings/provider-key`, body);
        expect(res.status, JSON.stringify(Object.keys(body))).toBe(400);
        expect(res.text).not.toContain(TENANT_KEY);
      }
      const off = await send('put', `${BASE}/settings/provider-key`, keyBody);
      expect(off.status).toBe(403);
      expect((off.body as { code: string }).code).toBe('assistant_tenant_keys_disabled');
      expect(off.text).not.toContain(TENANT_KEY);
      const validate = await send('post', `${BASE}/settings/provider-key/validate`);
      expect(validate.status).toBe(403);
      expect((validate.body as { code: string }).code).toBe('assistant_tenant_keys_disabled');
      // Removal works with the gate off (cleanup after a platform switch-off); none is stored.
      const removed = await send('delete', `${BASE}/settings/provider-key?expectedRowVersion=0`);
      expect(removed.status).toBe(404);
      expect((removed.body as { code: string }).code).toBe('assistant_tenant_key_not_found');
      expect(
        (await send('delete', `${BASE}/settings/provider-key?expectedRowVersion=-1`)).status,
      ).toBe(400);
      expect(auditJson(audit.entries)).not.toContain(TENANT_KEY);
      // Nothing was audited: no key was set, validated or removed.
      expect(audit.entries.filter((e) => e.action.startsWith('assistant.provider_key'))).toEqual(
        [],
      );
    });
  });

  describe('feedback (D2)', () => {
    it('PUT upserts the rating of a completed assistant message; audited without the comment; DELETE removes it', async () => {
      const message = insights.message('completed');
      const first = await send('put', `${BASE}/messages/${message.publicId}/feedback`, {
        rating: 'down',
        reason: 'incorrect',
        comment: 'The figure for it-synthetic.example looks wrong.',
      });
      expect(first.status).toBe(200);
      expect(first.body).toMatchObject({
        messageId: message.publicId,
        rating: 'down',
        reason: 'incorrect',
        comment: 'The figure for it-synthetic.example looks wrong.',
      });
      const second = await send('put', `${BASE}/messages/${message.publicId}/feedback`, {
        rating: 'up',
      });
      expect(second.status).toBe(200);
      expect(second.body).toMatchObject({ rating: 'up', reason: null, comment: null });
      expect(insights.feedback).toHaveLength(1);
      const recorded = audit.entries.filter((e) => e.action === 'assistant.feedback_recorded');
      expect(recorded).toHaveLength(2);
      expect(recorded[0]!.metadata).toEqual({
        messageId: message.publicId,
        conversationId: message.conversationPublicId,
        rating: 'down',
        reason: 'incorrect',
      });
      expect(auditJson(audit.entries)).not.toContain('looks wrong');
      const removed = await send('delete', `${BASE}/messages/${message.publicId}/feedback`);
      expect(removed.status).toBe(204);
      expect(insights.feedback).toHaveLength(0);
      expect(audit.entries.at(-1)!.action).toBe('assistant.feedback_removed');
      // A second removal: nothing to remove.
      const again = await send('delete', `${BASE}/messages/${message.publicId}/feedback`);
      expect(again.status).toBe(404);
      expect((again.body as { code: string }).code).toBe('assistant_message_not_found');
    });

    it('answers 404 for unknown and user messages, 409 for a turn that did not complete, 400 for a bad body', async () => {
      const running = insights.message('running');
      const user = insights.message('completed', 'user');
      const unknown = await send('put', `${BASE}/messages/${randomUUID()}/feedback`, {
        rating: 'up',
      });
      expect(unknown.status).toBe(404);
      expect((unknown.body as { code: string }).code).toBe('assistant_message_not_found');
      const ofUser = await send('put', `${BASE}/messages/${user.publicId}/feedback`, {
        rating: 'up',
      });
      expect((ofUser.body as { code: string }).code).toBe('assistant_message_not_found');
      const notDone = await send('put', `${BASE}/messages/${running.publicId}/feedback`, {
        rating: 'up',
      });
      expect(notDone.status).toBe(409);
      expect((notDone.body as { code: string }).code).toBe('assistant_feedback_not_allowed');
      // An answer of a conversation whose content was purged (the comment would outlive it).
      const purged = insights.message('completed');
      insights.purgedConversations.add(purged.conversationId);
      const afterPurge = await send('put', `${BASE}/messages/${purged.publicId}/feedback`, {
        rating: 'down',
        comment: 'after the purge',
      });
      expect(afterPurge.status).toBe(409);
      expect((afterPurge.body as { code: string }).code).toBe('assistant_feedback_not_allowed');
      insights.purgedConversations.clear();
      for (const body of [
        { rating: 'meh' },
        { rating: 'up', reason: 'boring' },
        { rating: 'up', comment: 'x'.repeat(501) },
        { rating: 'up', extra: 1 },
      ]) {
        const res = await send('put', `${BASE}/messages/${running.publicId}/feedback`, body);
        expect(res.status, JSON.stringify(body)).toBe(400);
      }
      expect(
        (await send('put', `${BASE}/messages/not-a-uuid/feedback`, { rating: 'up' })).status,
      ).toBe(400);
      expect(insights.feedback).toEqual([]);
    });
  });

  describe('owner content search (D4)', () => {
    it('validates q, searches the caller’s own scope with an escaped pattern and returns snippets', async () => {
      for (const q of ['', 'a', '  b  ', 'x'.repeat(201)]) {
        const res = await send('get', `${BASE}/search?q=${encodeURIComponent(q)}`);
        expect(res.status, JSON.stringify(q)).toBe(400);
      }
      const conversationId = randomUUID();
      const messageId = randomUUID();
      insights.searchRows = [
        {
          id: 9n,
          publicId: messageId,
          organizationId: ORG,
          conversationId: 3n,
          conversationPublicId: conversationId,
          conversationTitle: 'Weekly review',
          userId: 10n,
          role: 'assistant',
          seq: 2,
          createdAt: new Date('2026-11-20T10:00:00.000Z'),
          content: `${'Lorem ipsum '.repeat(30)}the 100%_quarantine figure${' dolor sit'.repeat(30)}`,
        },
      ];
      const res = await send('get', `${BASE}/search?q=${encodeURIComponent('100%_quarantine')}`);
      expect(res.status).toBe(200);
      const page = res.body as {
        data: Array<Record<string, unknown> & { snippet: string }>;
        nextCursor: string | null;
      };
      expect(page.nextCursor).toBeNull();
      expect(page.data).toHaveLength(1);
      expect(page.data[0]).toMatchObject({
        conversationId,
        conversationTitle: 'Weekly review',
        messageId,
        role: 'assistant',
        seq: 2,
      });
      expect(page.data[0]!.snippet).toContain('100%_quarantine');
      expect([...page.data[0]!.snippet].length).toBeLessThanOrEqual(160);
      // The owner scope comes from the session; `%` and `_` are escaped.
      expect(insights.searchCalls).toEqual([
        { userId: 10n, organizationId: ORG, pattern: '%100!%!_quarantine%' },
      ]);
    });
  });

  describe('administration and audit views (D1, D2, D4)', () => {
    it('usage per user: default window, empty page with zero totals; a window over 92 days is 400', async () => {
      const res = await send('get', `${BASE}/admin/usage/users`);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        data: [],
        nextCursor: null,
        totals: { users: [], overall: { turns: 0, totalTokens: 0 } },
      });
      const body = res.body as { from: string; to: string };
      expect(body.to).toBe(new Date().toISOString().slice(0, 10));
      const tooLong = await send('get', `${BASE}/admin/usage/users?from=2026-01-01&to=2026-06-30`);
      expect(tooLong.status).toBe(400);
      // An unknown user filter is an empty page, never a 404.
      const filtered = await send('get', `${BASE}/admin/usage/users?userId=${randomUUID()}`);
      expect(filtered.status).toBe(200);
      expect((filtered.body as { data: unknown[] }).data).toEqual([]);
    });

    it('feedback, audit conversations and executions: v1 empty pages; bad filters 400; unknown conversation 404', async () => {
      for (const path of [
        `${BASE}/admin/feedback`,
        `${BASE}/admin/conversations`,
        `${BASE}/admin/executions`,
      ]) {
        const res = await send('get', path);
        expect(res.status, path).toBe(200);
        expect(res.body, path).toEqual({ data: [], nextCursor: null });
      }
      for (const path of [
        `${BASE}/admin/feedback?rating=meh`,
        `${BASE}/admin/feedback?from=2026-01-01T00:00:00Z&to=2026-06-30T00:00:00Z`,
        `${BASE}/admin/conversations?status=gone`,
        `${BASE}/admin/executions?decision=maybe`,
        `${BASE}/admin/executions?from=2026-01-01T00:00:00Z&to=2026-06-30T00:00:00Z`,
        `${BASE}/admin/conversations/not-a-uuid`,
      ]) {
        expect((await send('get', path)).status, path).toBe(400);
      }
      const missing = await send('get', `${BASE}/admin/conversations/${randomUUID()}`);
      expect(missing.status).toBe(404);
      expect((missing.body as { code: string }).code).toBe(
        'assistant_admin_conversation_not_found',
      );
      expect(audit.entries.filter((e) => e.action === 'assistant.audit_viewed')).toEqual([]);
    });
  });
});
