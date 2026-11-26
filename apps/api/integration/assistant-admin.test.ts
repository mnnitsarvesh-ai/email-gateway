/**
 * Step AI-6 administration, feedback, content search and the metadata-only audit view on the
 * real stack (docs/plan/steps/34-ai-chat-hardening-operations.md D1, D2, D4, I24, §9 item 5;
 * contracts §35.6): real MySQL writer and replica and Redis from the local `.env`, the api on its
 * ephemeral loopback port, the deterministic fake provider (`assertFakeProvider`; never a real
 * LLM, nothing reaches the internet).
 *
 * Covered: usage per user and UTC day after turns of two users (`GET /assistant/admin/usage/
 * users`: rows, totals per user and overall, the user filter) and the shape of
 * `ai_chat_usage_user_daily` equal to the aggregate the migration's backfill computes from
 * `ai_chat_turns`; the per-user daily token budget (`429 assistant_budget_exhausted`,
 * `details.scope: 'user'`, other users unaffected); feedback set/update/remove by the message's
 * owner (`PUT`/`DELETE /assistant/messages/{id}/feedback`), the owner's messages view, the admin
 * feedback list (comment, turn metadata, tools of the turn), the audit rows without the comment,
 * another user's or a user message `404`, and the comment cleared by the conversation's content
 * purge; the owner's content search (own text only, case- and accent-insensitive, title matches,
 * `%`/`_` literal, purged content never found, another user's text never found); the audit view
 * (`GET /assistant/admin/conversations`, `…/{id}`, `GET /assistant/admin/executions`) for
 * `audit:read`: the deep scan of every JSON answer finds no conversation title, message text,
 * provider transcript, result card, report HTML/title or delivery recipient address, the
 * execution search filters, and the `assistant.audit_viewed` row; permission refusals of every
 * route. Synthetic `it-*` organizations and `.example` addresses only.
 */
// @covers get /api/v1/assistant/admin/usage/users
// @covers get /api/v1/assistant/admin/feedback
// @covers get /api/v1/assistant/admin/conversations
// @covers get /api/v1/assistant/admin/conversations/:conversationId
// @covers get /api/v1/assistant/admin/executions
// @covers put /api/v1/assistant/messages/:messageId/feedback
// @covers delete /api/v1/assistant/messages/:messageId/feedback
// @covers get /api/v1/assistant/search
// @covers get /api/v1/assistant/conversations/:conversationId/messages
// @covers put /api/v1/assistant/settings
import { randomUUID } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AssistantRetentionService } from '../src/modules/assistant/services/assistant-retention.service';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  allFeatures,
  call,
  clearAssistantCounters,
  createAssistantApp,
  directive,
  enableAssistant,
  generateReport,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  reportRow,
  seedDeliveries,
  trackReports,
  turn,
  updateSettings,
} from './support/assistant';
import { clearHardeningKeys, keysIn, needlesIn } from './support/assistant-hardening';
import { deleteAtoRows } from './support/ato';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  uniqueSuffix,
} from './support/fixtures';

const ADMIN = `${A}/admin`;

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let otherOrg: FixtureOrganization;
let admin: Member;
let alice: Member;
let bob: Member;
let auditor: Member;
let configurer: Member;
let foreigner: Member;
const orgIds: bigint[] = [];
const sfx = uniqueSuffix()
  .replace(/[^a-z0-9]/gi, '')
  .slice(-8)
  .toLowerCase();
/** Content markers: never in an administrator's answer (I24). */
const TITLE = `Confidential plans it${sfx}`;
const ALICE_TEXT = `Quokka${sfx} migration notes for the board`;
const BOB_TEXT = `Quokka${sfx} payroll memo of bob`;
const COMMENT = `The figure for it-${sfx}.example looks wrong`;

interface MessageJson {
  id: string;
  role: 'user' | 'assistant';
  content: string | null;
  feedback?: { rating: string; reason: string | null; comment: string | null } | null;
}

async function messagesOf(who: Member, conversation: string): Promise<MessageJson[]> {
  const res = await call(ctx, who.headers, 'get', `${A}/conversations/${conversation}/messages`);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body.data as MessageJson[];
}

async function assistantMessageOf(who: Member, conversation: string): Promise<MessageJson> {
  const found = (await messagesOf(who, conversation)).find((m) => m.role === 'assistant');
  expect(found).toBeDefined();
  return found!;
}

async function textTurn(who: Member, conversation: string, text: string): Promise<void> {
  const res = await turn(ctx, who.headers, conversation, `/text ${text}`);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  expect(res.body.message.content).toBe(text);
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  trackReports(ctx, fx, orgIds);
  // ato_detection is on: the live ato-worker records sign-ins of the fixture users.
  fx.registerCleanup(() => deleteAtoRows(ctx.prisma, orgIds), { rerunOnConflict: true });
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ features: allFeatures(), planCode: 'enterprise' });
  otherOrg = await fx.createOrganization({ features: allFeatures(), planCode: 'enterprise' });
  orgIds.push(org.id, otherOrg.id);
  admin = await memberWith(ctx, fx, org, { permissions: [...ALL_TENANT_PERMISSIONS] });
  alice = await memberWith(ctx, fx, org, { permissions: ['policy:read', 'report:read'] });
  bob = await memberWith(ctx, fx, org, { permissions: ['policy:read'] });
  auditor = await memberWith(ctx, fx, org, { permissions: ['audit:read'] });
  configurer = await memberWith(ctx, fx, org, { permissions: ['assistant:configure'] });
  foreigner = await memberWith(ctx, fx, otherOrg, { permissions: [...ALL_TENANT_PERMISSIONS] });
  await enableAssistant(ctx, operator, org, admin);
  await enableAssistant(ctx, operator, otherOrg, foreigner);
}, 180_000);

afterAll(async () => {
  if (ctx) {
    await clearAssistantCounters(ctx, orgIds);
    await clearHardeningKeys(ctx, {
      userPublicIds: [admin, alice, bob, auditor, configurer, foreigner]
        .filter(Boolean)
        .map((m) => m.user.publicId),
    });
  }
  await fx?.cleanup();
  await ctx?.close();
});

describe('usage per user and day, per-user budget (D1)', () => {
  afterEach(async () => {
    // Never leave a per-user budget behind for the next tests (also after a failure).
    await updateSettings(ctx, admin, { userDailyTokenBudget: null });
    await clearHardeningKeys(ctx, { userPublicIds: [alice.user.publicId] });
  });

  it('lists turns and tokens per user and UTC day with totals; the table equals the backfill aggregate', async () => {
    const a = await newConversation(ctx, alice);
    for (let i = 0; i < 2; i += 1) {
      expect((await turn(ctx, alice.headers, a, directive('policy_management_list'))).status).toBe(
        200,
      );
    }
    const b = await newConversation(ctx, bob);
    expect((await turn(ctx, bob.headers, b, directive('policy_management_list'))).status).toBe(200);

    const res = await call(ctx, admin.headers, 'get', `${ADMIN}/usage/users`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const today = new Date().toISOString().slice(0, 10);
    expect(res.body.to).toBe(today);
    type Row = {
      day: string;
      user: { id: string; displayName: string | null; email: string | null };
      keySource: string;
      turns: number;
      inputTokens: number;
      outputTokens: number;
      totalTokens: number;
      estimatedCostMicros: number | null;
    };
    const rows = res.body.data as Row[];
    const of = (m: Member) => rows.find((r) => r.user.id === m.user.publicId && r.day === today);
    // Token figures equal the turns' own columns (the fake reports usage).
    for (const [who, turns] of [
      [alice, 2],
      [bob, 1],
    ] as const) {
      const row = of(who)!;
      expect(row, who.user.email).toBeDefined();
      expect(row).toMatchObject({ keySource: 'platform', turns });
      expect(row.user).toEqual({
        id: who.user.publicId,
        displayName: who.user.displayName,
        email: who.user.email,
      });
      const sums = await ctx.prisma.aiChatTurn.aggregate({
        where: { organizationId: org.id, userId: who.user.id },
        _sum: { inputTokens: true, outputTokens: true },
      });
      expect(row.inputTokens).toBe(Number(sums._sum?.inputTokens ?? 0));
      expect(row.outputTokens).toBe(Number(sums._sum?.outputTokens ?? 0));
      expect(row.totalTokens).toBeGreaterThanOrEqual(row.inputTokens + row.outputTokens);
    }
    const totals = res.body.totals as {
      users: Array<{ user: { id: string }; turns: number }>;
      overall: { turns: number };
    };
    expect(totals.overall.turns).toBe(rows.reduce((n, r) => n + r.turns, 0));
    expect(totals.users.find((t) => t.user.id === alice.user.publicId)?.turns).toBe(2);
    // The user filter.
    const filtered = await call(
      ctx,
      admin.headers,
      'get',
      `${ADMIN}/usage/users?userId=${alice.user.publicId}`,
    );
    expect(filtered.status).toBe(200);
    expect((filtered.body.data as Row[]).every((r) => r.user.id === alice.user.publicId)).toBe(
      true,
    );
    expect(filtered.body.totals.overall.turns).toBe(2);
    // Another organization's id as a filter is an empty page (never its data).
    const foreignFilter = await call(
      ctx,
      admin.headers,
      'get',
      `${ADMIN}/usage/users?userId=${foreigner.user.publicId}`,
    );
    expect(foreignFilter.body.data).toEqual([]);

    // The table has the shape the migration's backfill computes from the turns (WP1 §11 #2:
    // UTC day of finished_at, statuses closed by finish).
    const table = await ctx.prisma.$queryRaw<
      Array<{ day: string; userId: bigint; provider: string; model: string; turns: bigint }>
    >`SELECT DATE_FORMAT(day, '%Y-%m-%d') AS day, user_id AS userId, provider, model,
        CAST(turns AS SIGNED) AS turns
      FROM ai_chat_usage_user_daily WHERE organization_id = ${org.id}
      ORDER BY day, user_id, provider, model`;
    const aggregate = await ctx.prisma.$queryRaw<
      Array<{ day: string; userId: bigint; provider: string; model: string; turns: bigint }>
    >`SELECT DATE_FORMAT(DATE(finished_at), '%Y-%m-%d') AS day, user_id AS userId, provider, model,
        COUNT(*) AS turns
      FROM ai_chat_turns
      WHERE organization_id = ${org.id} AND finished_at IS NOT NULL
        AND NOT (status = 'failed' AND error_code <=> 'assistant_turn_abandoned')
      GROUP BY 1, 2, 3, 4
      ORDER BY day, user_id, provider, model`;
    expect(table.map((r) => ({ ...r, turns: Number(r.turns) }))).toEqual(
      aggregate.map((r) => ({ ...r, turns: Number(r.turns) })),
    );
  });

  it('refuses a user over the per-user daily budget (429, scope user); other users and the tenant are unaffected', async () => {
    const conversation = await newConversation(ctx, alice);
    expect(
      (await turn(ctx, alice.headers, conversation, directive('policy_management_list'))).status,
    ).toBe(200);
    // A budget of 1 token per user and day: alice has used more today.
    const settings = await updateSettings(ctx, admin, { userDailyTokenBudget: 1 });
    expect(settings.userDailyTokenBudget).toBe(1);
    const refused = await turn(ctx, alice.headers, conversation, '/text over budget');
    expect(refused.status).toBe(429);
    // The AI-1 error shape: `scope` beside the code (`tenant | user | platform`).
    expect(refused.body).toMatchObject({ code: 'assistant_budget_exhausted', scope: 'user' });
    // A user without usage today may start one turn; then the same refusal.
    const fresh = await memberWith(ctx, fx, org, { permissions: ['policy:read'] });
    const own = await newConversation(ctx, fresh);
    expect((await turn(ctx, fresh.headers, own, '/text first today')).status).toBe(200);
    const after = await turn(ctx, fresh.headers, own, '/text second today');
    expect(after.status).toBe(429);
    expect(after.body).toMatchObject({ code: 'assistant_budget_exhausted', scope: 'user' });
    // The status view of the refused user says why.
    const status = await call(ctx, alice.headers, 'get', `${A}/status`);
    expect(status.body).toMatchObject({ available: false });
    // Without a per-user budget the turn runs again (the tenant budget was never used up).
    await updateSettings(ctx, admin, { userDailyTokenBudget: null });
    expect((await turn(ctx, alice.headers, conversation, '/text back again')).status).toBe(200);
    // Above the tenant's effective daily budget → 400.
    const tooHigh = await call(ctx, admin.headers, 'get', `${A}/settings`);
    const max = tooHigh.body.effectiveDailyTokenBudget as number;
    const res = await call(ctx, admin.headers, 'put', `${A}/settings`, {
      expectedRowVersion: tooHigh.body.rowVersion,
      enabled: true,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: null,
      retentionDays: 30,
      userDailyTokenBudget: max + 1,
    });
    expect(res.status).toBe(400);
    await clearHardeningKeys(ctx, { userPublicIds: [alice.user.publicId, fresh.user.publicId] });
  });
});

describe('feedback on assistant answers (D2)', () => {
  it('the owner rates, updates and removes; the admin list shows it with the turn metadata; the audit rows never hold the comment', async () => {
    const conversation = await newConversation(ctx, alice);
    expect(
      (await turn(ctx, alice.headers, conversation, directive('policy_management_list'))).status,
    ).toBe(200);
    const message = await assistantMessageOf(alice, conversation);
    expect(message.feedback).toBeNull();
    const path = `${A}/messages/${message.id}/feedback`;

    const set = await call(ctx, alice.headers, 'put', path, {
      rating: 'down',
      reason: 'incomplete',
      comment: COMMENT,
    });
    expect(set.status, JSON.stringify(set.body)).toBe(200);
    expect(set.body).toMatchObject({
      messageId: message.id,
      rating: 'down',
      reason: 'incomplete',
      comment: COMMENT,
    });
    expect((await assistantMessageOf(alice, conversation)).feedback).toEqual({
      rating: 'down',
      reason: 'incomplete',
      comment: COMMENT,
    });

    // The admin list (assistant:configure): comment, user, turn metadata, tools of the turn.
    const list = await call(ctx, configurer.headers, 'get', `${ADMIN}/feedback?rating=down`);
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    const item = (list.body.data as Array<Record<string, unknown>>).find(
      (f) => f.messageId === message.id,
    );
    expect(item).toMatchObject({
      conversationId: conversation,
      rating: 'down',
      reason: 'incomplete',
      comment: COMMENT,
      user: { id: alice.user.publicId, email: alice.user.email },
      turn: {
        provider: 'fake',
        model: 'fake',
        promptVersion: 'assistant-system/7',
        dataSharing: 'metadata',
      },
      tools: ['policy_management_list'],
    });
    expect(
      (await call(ctx, configurer.headers, 'get', `${ADMIN}/feedback?rating=up`)).body.data.some(
        (f: { messageId: string }) => f.messageId === message.id,
      ),
    ).toBe(false);

    // Update (upsert by message), then removal.
    const up = await call(ctx, alice.headers, 'put', path, { rating: 'up' });
    expect(up.status).toBe(200);
    expect(up.body).toMatchObject({ rating: 'up', reason: null, comment: null });
    expect(
      await ctx.prisma.aiChatFeedback.count({
        where: { organizationId: org.id, message: { publicId: message.id } },
      }),
    ).toBe(1);
    expect((await call(ctx, alice.headers, 'delete', path)).status).toBe(204);
    expect((await assistantMessageOf(alice, conversation)).feedback).toBeNull();
    const again = await call(ctx, alice.headers, 'delete', path);
    expect(again.status).toBe(404);
    expect(again.body.code).toBe('assistant_message_not_found');

    const audit = await ctx.prisma.auditLog.findMany({
      where: {
        organizationId: org.id,
        action: { in: ['assistant.feedback_recorded', 'assistant.feedback_removed'] },
      },
      orderBy: { id: 'asc' },
    });
    expect(audit.map((r) => r.action)).toEqual([
      'assistant.feedback_recorded',
      'assistant.feedback_recorded',
      'assistant.feedback_removed',
    ]);
    expect(audit[0]!.metadata).toMatchObject({
      messageId: message.id,
      conversationId: conversation,
      rating: 'down',
      reason: 'incomplete',
    });
    expect(
      needlesIn(
        audit.map((r) => r.metadata),
        [COMMENT],
      ),
    ).toEqual([]);
  });

  it('only the owner may rate, only assistant messages; 404 for others, 400 for a bad body', async () => {
    const conversation = await newConversation(ctx, alice);
    await textTurn(alice, conversation, 'A rated answer');
    const messages = await messagesOf(alice, conversation);
    const answer = messages.find((m) => m.role === 'assistant')!;
    const question = messages.find((m) => m.role === 'user')!;
    for (const [who, id] of [
      [bob, answer.id],
      [admin, answer.id],
      [foreigner, answer.id],
      [alice, question.id],
      [alice, randomUUID()],
    ] as const) {
      const res = await call(ctx, who.headers, 'put', `${A}/messages/${id}/feedback`, {
        rating: 'up',
      });
      expect(res.status, `${who.user.email} ${id}`).toBe(404);
      expect(res.body.code).toBe('assistant_message_not_found');
    }
    const bad = await call(ctx, alice.headers, 'put', `${A}/messages/${answer.id}/feedback`, {
      rating: 'up',
      comment: 'x'.repeat(501),
    });
    expect(bad.status).toBe(400);
    // The audit permission alone and a plain user never see the admin list.
    expect((await call(ctx, auditor.headers, 'get', `${ADMIN}/feedback`)).status).toBe(403);
    expect((await call(ctx, bob.headers, 'get', `${ADMIN}/feedback`)).status).toBe(403);
  });

  it('the content purge clears the comment (rating kept) and deletes nothing else of the row', async () => {
    const conversation = await newConversation(ctx, alice);
    await textTurn(alice, conversation, 'An answer to purge');
    const answer = await assistantMessageOf(alice, conversation);
    expect(
      (
        await call(ctx, alice.headers, 'put', `${A}/messages/${answer.id}/feedback`, {
          rating: 'down',
          reason: 'other',
          comment: `${COMMENT} (purge)`,
        })
      ).status,
    ).toBe(200);
    await ctx.prisma.aiChatConversation.update({
      where: { publicId: conversation },
      data: { purgeAfter: new Date(Date.now() - 60_000) },
    });
    expect(
      await ctx.get(AssistantRetentionService).purgeContent(new Date()),
    ).toBeGreaterThanOrEqual(1);
    const row = await ctx.prisma.aiChatFeedback.findFirstOrThrow({
      where: { organizationId: org.id, message: { publicId: answer.id } },
    });
    expect(row).toMatchObject({ rating: 'down', reason: 'other', comment: null });
    const list = await call(ctx, admin.headers, 'get', `${ADMIN}/feedback`);
    const item = (list.body.data as Array<Record<string, unknown>>).find(
      (f) => f.messageId === answer.id,
    );
    expect(item).toMatchObject({ rating: 'down', comment: null });
    // A rating after the purge would keep a comment no purge clears again: 409, row unchanged.
    const late = await call(ctx, alice.headers, 'put', `${A}/messages/${answer.id}/feedback`, {
      rating: 'up',
      comment: `${COMMENT} (after the purge)`,
    });
    expect(late.status).toBe(409);
    expect(late.body.code).toBe('assistant_feedback_not_allowed');
    expect(
      await ctx.prisma.aiChatFeedback.findFirstOrThrow({
        where: { organizationId: org.id, message: { publicId: answer.id } },
      }),
    ).toMatchObject({ rating: 'down', reason: 'other', comment: null });
  });
});

describe('content search of the owner (D4)', () => {
  let aliceConversation: string;
  let titled: string;

  beforeAll(async () => {
    aliceConversation = await newConversation(ctx, alice);
    await textTurn(alice, aliceConversation, ALICE_TEXT);
    titled = await newConversation(ctx, alice, `Quarterly zanzibar${sfx}`);
    await textTurn(alice, titled, 'Nothing special in the text');
    const bobConversation = await newConversation(ctx, bob);
    await textTurn(bob, bobConversation, BOB_TEXT);
  });

  const search = (who: Member, q: string) =>
    call(ctx, who.headers, 'get', `${A}/search?q=${encodeURIComponent(q)}`);

  it('finds the caller’s own user and assistant text with snippets, case- and accent-insensitive; never another user’s', async () => {
    const res = await search(alice, `QUÓKKA${sfx}`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const rows = res.body.data as Array<{
      conversationId: string;
      messageId: string;
      role: string;
      snippet: string;
    }>;
    expect(rows.map((r) => r.role).sort()).toEqual(['assistant', 'user']);
    expect(rows.every((r) => r.conversationId === aliceConversation)).toBe(true);
    expect(rows.every((r) => r.snippet.includes(`Quokka${sfx}`))).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain('payroll');
    // Bob finds his own text only.
    const theirs = await search(bob, `quokka${sfx}`);
    expect(theirs.body.data).toHaveLength(2);
    expect(JSON.stringify(theirs.body)).not.toContain('migration notes');
    // Another organization's user with the same word finds nothing.
    expect((await search(foreigner, `quokka${sfx}`)).body.data).toEqual([]);
  });

  it('matches titles (the first message of the conversation), treats % and _ literally, refuses bad q', async () => {
    const byTitle = await search(alice, `zanzibar${sfx}`);
    expect(byTitle.status).toBe(200);
    expect(byTitle.body.data).toHaveLength(1);
    expect(byTitle.body.data[0]).toMatchObject({
      conversationId: titled,
      conversationTitle: `Quarterly zanzibar${sfx}`,
    });
    expect((await search(alice, `q%${sfx}`)).body.data).toEqual([]);
    expect((await search(alice, `quokka_${sfx}`)).body.data).toEqual([]);
    expect((await search(alice, 'x')).status).toBe(400);
    expect((await search(alice, 'y'.repeat(201))).status).toBe(400);
  });

  it('never finds purged content', async () => {
    const conversation = await newConversation(ctx, alice);
    await textTurn(alice, conversation, `Ephemeral${sfx} words`);
    expect((await search(alice, `ephemeral${sfx}`)).body.data).toHaveLength(2);
    await ctx.prisma.aiChatConversation.update({
      where: { publicId: conversation },
      data: { purgeAfter: new Date(Date.now() - 60_000) },
    });
    await ctx.get(AssistantRetentionService).purgeContent(new Date());
    const after = await search(alice, `ephemeral${sfx}`);
    expect(after.status).toBe(200);
    expect(after.body.data).toEqual([]);
    // A deleted conversation is not searched either.
    expect((await call(ctx, alice.headers, 'delete', `${A}/conversations/${titled}`)).status).toBe(
      204,
    );
    expect((await search(alice, `zanzibar${sfx}`)).body.data).toEqual([]);
  });
});

describe('metadata-only conversation audit view (D4, I24)', () => {
  let conversation: string;
  let reportTitle: string;
  let recipients: string[];
  let reportPublicId: string;

  beforeAll(async () => {
    conversation = await newConversation(ctx, alice, TITLE);
    await textTurn(alice, conversation, ALICE_TEXT);
    expect(
      (await turn(ctx, alice.headers, conversation, directive('policy_management_list'))).status,
    ).toBe(200);
    const generated = await generateReport(ctx, alice, conversation, {
      args: { sections: ['traffic'] },
    });
    reportTitle = generated.report.title;
    reportPublicId = generated.report.reportId;
    const report = await reportRow(ctx, reportPublicId);
    await seedDeliveries(ctx, report, report.userId, 2);
    recipients = (
      await ctx.prisma.aiChatReportDelivery.findMany({
        where: { reportId: report.id },
        select: { recipientAddress: true },
      })
    )
      .map((d) => d.recipientAddress)
      .filter((a): a is string => a !== null);
    const answer = await assistantMessageOf(alice, conversation);
    expect(
      (
        await call(ctx, alice.headers, 'put', `${A}/messages/${answer.id}/feedback`, {
          rating: 'up',
          comment: COMMENT,
        })
      ).status,
    ).toBe(200);
  }, 60_000);

  /** Content of the conversation that an administrator must never receive (I24). */
  const forbidden = async (): Promise<string[]> => {
    const turns = await ctx.prisma.aiChatTurn.findMany({
      where: { conversation: { publicId: conversation } },
      select: { providerTranscript: true },
    });
    const cards = await ctx.prisma.aiChatToolExecution.findMany({
      where: { conversation: { publicId: conversation } },
      select: { resultCard: true },
    });
    const transcriptTexts = turns
      .flatMap((t) => (t.providerTranscript ?? '').match(/"text":"([^"\\]{12,})"/g) ?? [])
      .map((m) => m.slice(8, -1));
    expect(transcriptTexts.length).toBeGreaterThan(0);
    const cardTitles = cards
      .map((c) => (c.resultCard as { title?: string } | null)?.title)
      .filter((t): t is string => typeof t === 'string' && t.length > 8);
    return [
      TITLE,
      ALICE_TEXT,
      COMMENT,
      reportTitle,
      '<!doctype',
      '<html',
      ...recipients,
      ...transcriptTexts,
      ...cardTitles,
    ];
  };
  const FORBIDDEN_KEYS = [
    'title',
    'content',
    'comment',
    'html',
    'card',
    'transcript',
    'providerTranscript',
    'recipientAddress',
    'figures',
  ];

  it('lists the organization’s conversations without titles; the detail and executions carry metadata only', async () => {
    const list = await call(ctx, auditor.headers, 'get', `${ADMIN}/conversations`);
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    const header = (list.body.data as Array<Record<string, unknown>>).find(
      (c) => c.id === conversation,
    );
    expect(header).toMatchObject({
      user: { id: alice.user.publicId },
      status: 'active',
      contentPurged: false,
      underPlatformOverride: false,
      totals: { reports: 1, feedback: { up: 1, down: 0 } },
    });
    expect((header!.turnCount as number) >= 3).toBe(true);
    // Every conversation of the organization (bob's too), none of another organization.
    expect(
      (list.body.data as Array<{ user: { id: string } }>).some(
        (c) => c.user.id === bob.user.publicId,
      ),
    ).toBe(true);

    const detail = await call(
      ctx,
      auditor.headers,
      'get',
      `${ADMIN}/conversations/${conversation}`,
    );
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.turns.length).toBeGreaterThanOrEqual(3);
    expect(detail.body.turns[0]).toMatchObject({
      status: 'completed',
      provider: 'fake',
      keySource: 'platform',
      dataSharing: 'metadata',
      fallbackFrom: null,
      promptVersion: 'assistant-system/7',
    });
    const tools = (detail.body.executions as Array<{ tool: string }>).map((e) => e.tool);
    expect(tools).toEqual(expect.arrayContaining(['policy_management_list', 'report_generate']));
    expect(detail.body.reports).toHaveLength(1);
    expect(detail.body.reports[0]).toMatchObject({
      id: reportPublicId,
      status: 'available',
      async: false,
      jobStatus: null,
    });
    expect(detail.body.reports[0].deliveries).toHaveLength(2);
    for (const delivery of detail.body.reports[0].deliveries as Array<Record<string, unknown>>) {
      expect(delivery.recipientDomain).toBe('limits.example');
      // The recipient is never returned (the owner's report view has `to`; this view has not).
      expect(Object.keys(delivery)).not.toContain('to');
    }
    expect(detail.body.feedback).toEqual([expect.objectContaining({ rating: 'up', reason: null })]);

    const executions = await call(
      ctx,
      auditor.headers,
      'get',
      `${ADMIN}/executions?conversationId=${conversation}&tool=policy_management_list`,
    );
    expect(executions.status, JSON.stringify(executions.body)).toBe(200);
    expect(executions.body.data).toHaveLength(1);
    const execution = executions.body.data[0] as Record<string, unknown>;
    expect(execution).toMatchObject({
      tool: 'policy_management_list',
      module: expect.any(String),
      decision: 'allowed',
      status: 'succeeded',
      conversationId: conversation,
    });
    const byCorrelation = await call(
      ctx,
      auditor.headers,
      'get',
      `${ADMIN}/executions?correlationId=${encodeURIComponent(execution.correlationId as string)}`,
    );
    expect(byCorrelation.body.data.map((e: { id: string }) => e.id)).toEqual([execution.id]);
    const byUser = await call(
      ctx,
      auditor.headers,
      'get',
      `${ADMIN}/executions?userId=${bob.user.publicId}&decision=allowed`,
    );
    expect(
      (byUser.body.data as Array<{ conversationId: string }>).every(
        (e) => e.conversationId !== conversation,
      ),
    ).toBe(true);

    // I24: the deep scan of every administrator answer.
    const needles = await forbidden();
    for (const body of [list.body, detail.body, executions.body, byCorrelation.body]) {
      expect(needlesIn(body, needles)).toEqual([]);
      const keys = keysIn(body);
      expect(FORBIDDEN_KEYS.filter((k) => keys.has(k))).toEqual([]);
    }
    // The usage page and the admin feedback list hold no conversation content either (the
    // feedback list carries the comment the user chose to share, by design).
    const usage = await call(ctx, admin.headers, 'get', `${ADMIN}/usage/users`);
    expect(needlesIn(usage.body, needles)).toEqual([]);
    const feedback = await call(ctx, admin.headers, 'get', `${ADMIN}/feedback`);
    expect(
      needlesIn(
        feedback.body,
        needles.filter((n) => n !== COMMENT),
      ),
    ).toEqual([]);

    // The detail read is audited (resource: the conversation), the list is not.
    const viewed = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'assistant.audit_viewed', resourceId: conversation },
    });
    expect(viewed).toHaveLength(1);
    expect(viewed[0]).toMatchObject({ resourceType: 'assistant_conversation' });
    expect(needlesIn(viewed[0]!.metadata, needles)).toEqual([]);
  });

  it('404 for unknown and other organizations’ conversations; 403 without audit:read', async () => {
    const theirs = await newConversation(ctx, foreigner);
    for (const id of [theirs, randomUUID()]) {
      const res = await call(ctx, auditor.headers, 'get', `${ADMIN}/conversations/${id}`);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('assistant_admin_conversation_not_found');
    }
    for (const path of [
      `${ADMIN}/conversations`,
      `${ADMIN}/conversations/${conversation}`,
      `${ADMIN}/executions`,
    ]) {
      expect((await call(ctx, configurer.headers, 'get', path)).status, path).toBe(403);
      expect((await call(ctx, alice.headers, 'get', path)).status, path).toBe(403);
    }
    for (const path of [`${ADMIN}/usage/users`, `${ADMIN}/feedback`]) {
      expect((await call(ctx, auditor.headers, 'get', path)).status, path).toBe(403);
      expect((await call(ctx, alice.headers, 'get', path)).status, path).toBe(403);
    }
  });
});
