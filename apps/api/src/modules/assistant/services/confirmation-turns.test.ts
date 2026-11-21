import {
  ACTION_UPDATES_HEADER,
  type AssistantStreamEvent,
  type LlmRequest,
} from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import { testUser } from '../../../../test/support/assistant-fixtures';
import {
  callTool,
  createAssistantHarness,
  reply,
  ScriptedProvider,
} from '../../../../test/support/assistant-harness';
import { NULL_SINK } from './sse-writer';
import { ownerOf } from './conversation.service';
import type { PreparedTurn } from './turn-engine.service';

/**
 * Step AI-2 in the turn engine (D1 step 10, D6, D7; design §9 item 2): the stream pair
 * `tool.completed` (pending_confirmation) + `confirmation.required`, the JSON `confirmations`,
 * the action updates of the next turn, and the token's absence from everything stored or sent to
 * the model. No write request reaches the dispatcher during a turn.
 */

const POLICY = '0193c000-0000-7000-8000-000000000001';
const user = testUser({
  permissions: new Set(['assistant:use', 'policy:read', 'policy:manage', 'policy:publish']),
});

function setup(script: ConstructorParameters<typeof ScriptedProvider>[0]) {
  const provider = new ScriptedProvider(script);
  const h = createAssistantHarness({}, provider, user);
  h.world.enable(user.organizationId);
  const owner = ownerOf(user, h.scope);
  const conversation = h.world.addConversation(owner);
  let rowVersion = 3;
  h.loopback.on(`GET /api/v1/policies/${POLICY}`, () => ({
    kind: 'response',
    status: 200,
    body: { id: POLICY, name: 'Block executables', status: 'active', rowVersion },
  }));
  h.loopback.on(`POST /api/v1/policies/${POLICY}/disable`, () => {
    rowVersion += 1;
    return {
      kind: 'response',
      status: 200,
      body: { id: POLICY, name: 'Block executables', status: 'disabled', rowVersion },
    };
  });
  return { h, provider, owner, conversation };
}

const proposeDisable = (id = 'c1') => [
  () => reply({ toolCalls: [callTool(id, 'policy_management_disable', { policyId: POLICY })] }),
  () => reply({ text: 'I prepared this change.' }),
];

/** The text of the last user entry the provider saw. */
const lastUserText = (request: LlmRequest): string => {
  const entries = request.transcript as Array<{ role: string; text?: string }>;
  return [...entries].reverse().find((e) => e.role === 'user')?.text ?? '';
};

const without = (events: AssistantStreamEvent[], type: string) =>
  events.filter((e) => e.type !== type);

describe('turns with write proposals (step AI-2)', () => {
  it('streams tool.completed (pending_confirmation) then confirmation.required with the token', async () => {
    const { h, conversation } = setup(proposeDisable());
    const { sink } = await h.ask(conversation.publicId, 'disable the policy');
    expect(without(sink.events, 'text.delta').map((e) => e.type)).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'confirmation.required',
      'turn.completed',
    ]);
    const completed = sink.events.find((e) => e.type === 'tool.completed')!;
    expect(completed).toMatchObject({ status: 'pending_confirmation', decision: 'allowed' });
    const required = sink.events.find((e) => e.type === 'confirmation.required') as Extract<
      AssistantStreamEvent,
      { type: 'confirmation.required' }
    >;
    expect(required.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(required.confirmation).toMatchObject({
      executionId: (completed as { executionId: string }).executionId,
      status: 'pending',
      tool: 'policy_management_disable',
    });
    // No write request reached the dispatcher during the turn.
    expect(h.loopback.calls.every((c) => c.method === 'GET')).toBe(true);
    // The token is nowhere the model or storage sees it.
    const turn = h.world.turns[0]!;
    expect(turn.providerTranscript).not.toContain(required.token);
    expect(turn.providerTranscript).toContain('pending_confirmation');
    expect(
      JSON.stringify(h.world.messages, (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      ),
    ).not.toContain(required.token);
    expect(
      JSON.stringify(h.audit.entries, (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      ),
    ).not.toContain(required.token);
  });

  it('the JSON result carries confirmations with the token; a clientTurnId replay has token null', async () => {
    const { h, conversation } = setup(proposeDisable());
    const prepared = (await h.engine.prepare(
      user,
      h.scope,
      conversation.publicId,
      { clientTurnId: '0193d000-0000-7000-8000-00000000f001', message: 'disable it' },
      { authorization: 'Bearer it-access-token', clientIp: null },
    )) as PreparedTurn;
    await h.engine.run(prepared, NULL_SINK);
    const result = await h.engine.stored(prepared);
    expect(result.confirmations).toHaveLength(1);
    const [entry] = result.confirmations;
    expect(entry!.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const proposal = result.executions.find((e) => e.status === 'pending_confirmation')!;
    expect(proposal.confirmation).toEqual(entry!.confirmation);
    const replay = await h.engine.prepare(
      user,
      h.scope,
      conversation.publicId,
      { clientTurnId: '0193d000-0000-7000-8000-00000000f001', message: 'disable it' },
      { authorization: 'Bearer it-access-token', clientIp: null },
    );
    expect(replay.kind).toBe('replay');
    if (replay.kind !== 'replay') return;
    expect(replay.result.confirmations).toEqual([
      { confirmation: entry!.confirmation, token: null },
    ]);
    // The SSE replay never re-emits a token.
    const events: AssistantStreamEvent[] = [];
    h.engine.replayEvents(replay.result, { emit: (e) => events.push(e) });
    expect(events.some((e) => e.type === 'confirmation.required')).toBe(false);
  });

  it('reports outcomes at the start of the next turn (prefix, recorded once, content unchanged)', async () => {
    const { h, provider, conversation } = setup([
      ...proposeDisable('c1'),
      ...proposeDisable('c2'),
      () => reply({ text: 'Noted.' }),
      () => reply({ text: 'Nothing new.' }),
    ]);
    const first = await h.ask(conversation.publicId, 'disable the policy');
    const token = (
      first.sink.events.find((e) => e.type === 'confirmation.required') as {
        token: string;
      }
    ).token;
    const view = (
      first.sink.events.find((e) => e.type === 'confirmation.required') as {
        confirmation: { id: string; actionDigest: string };
      }
    ).confirmation;
    await h.confirmations.confirm(
      user,
      h.scope,
      view.id,
      { token, actionDigest: view.actionDigest },
      {
        authorization: 'Bearer it-access-token',
        clientIp: null,
      },
    );
    // A second proposal, cancelled.
    const second = await h.ask(conversation.publicId, 'and again');
    const secondView = (
      second.sink.events.find((e) => e.type === 'confirmation.required') as {
        confirmation: { id: string };
      }
    ).confirmation;
    // The confirmed outcome was reported at the start of the second turn.
    const seen2 = lastUserText(provider.requests[2]!);
    expect(seen2).toContain(ACTION_UPDATES_HEADER);
    expect(seen2).toMatch(
      /- policy_management_disable \(call r1\): the user confirmed it; it succeeded \(HTTP 200\)\. Result: ref r2, row ref r2\.1\./,
    );
    expect(seen2.endsWith('Current user message:\nand again')).toBe(true);
    await h.confirmations.cancel(user, h.scope, secondView.id, null);
    await h.ask(conversation.publicId, 'ok');
    const seen3 = lastUserText(provider.requests[4]!);
    expect(seen3).toContain(
      '- policy_management_disable (call r3): the user cancelled it; nothing changed.',
    );
    expect(seen3).not.toContain('(call r1)');
    await h.ask(conversation.publicId, 'anything else?');
    expect(lastUserText(provider.requests[5]!)).toBe('anything else?');
    expect(h.world.confirmations.every((k) => k.reportedAt !== null)).toBe(true);
    // ai_chat_messages keeps the user's text only.
    expect(h.world.messages.filter((m) => m.role === 'user').map((m) => m.content)).toEqual([
      'disable the policy',
      'and again',
      'ok',
      'anything else?',
    ]);
    // Stored transcripts never contain a token.
    for (const turn of h.world.turns) expect(turn.providerTranscript ?? '').not.toContain(token);
  });

  it('a failed turn does not mark its action updates reported (they are told again)', async () => {
    const { h, provider, conversation } = setup([
      ...proposeDisable('c1'),
      () => {
        throw new Error('provider exploded');
      },
      () => reply({ text: 'ok' }),
    ]);
    const first = await h.ask(conversation.publicId, 'disable');
    const required = first.sink.events.find((e) => e.type === 'confirmation.required') as {
      confirmation: { id: string };
    };
    await h.confirmations.cancel(user, h.scope, required.confirmation.id, null);
    await h.ask(conversation.publicId, 'second');
    expect(h.world.turns[1]!.status).toBe('failed');
    expect(h.world.confirmations[0]!.reportedAt).toBeNull();
    await h.ask(conversation.publicId, 'third');
    expect(lastUserText(provider.requests[3]!)).toContain('the user cancelled it');
    expect(h.world.confirmations[0]!.reportedAt).not.toBeNull();
  });

  it('messages and GET execution show the proposal with its confirmation view (never a token)', async () => {
    const { h, conversation } = setup(proposeDisable());
    const { sink } = await h.ask(conversation.publicId, 'disable the policy');
    const token = (sink.events.find((e) => e.type === 'confirmation.required') as { token: string })
      .token;
    const page = await h.conversations.messages(user, h.scope, conversation.publicId, {
      filters: {},
      sort: 'seq',
      limit: 25,
    } as never);
    const proposal = page.data
      .flatMap((m) => m.executions)
      .find((e) => e.status === 'pending_confirmation')!;
    expect(proposal.confirmation).toMatchObject({ status: 'pending', risk: 'medium' });
    const view = await h.executions.get(user, h.scope, proposal.id);
    expect(view.confirmation).toEqual(proposal.confirmation);
    expect(JSON.stringify(page)).not.toContain(token);
  });
});

describe('conversation delete and retention (D7)', () => {
  it('deleting a conversation cancels its pending confirmations (audited) and purges their content', async () => {
    const { h, conversation } = setup(proposeDisable());
    await h.ask(conversation.publicId, 'disable the policy');
    h.audit.entries.length = 0;
    await h.conversations.remove(user, h.scope, conversation.publicId, null);
    expect(h.world.confirmations[0]).toMatchObject({
      status: 'cancelled',
      request: null,
      preconditions: null,
      summary: null,
    });
    expect(h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.confirmation_cancelled',
      'assistant.conversation_deleted',
    ]);
    expect(h.audit.entries[0]!.metadata).toMatchObject({ reason: 'conversation_deleted' });
  });

  it('the job expires due pending rows and fails stale executing ones (outcome unknown), audited', async () => {
    const { h, conversation } = setup([...proposeDisable('c1'), ...proposeDisable('c2')]);
    await h.ask(conversation.publicId, 'one');
    await h.ask(conversation.publicId, 'two');
    const [a, b] = h.world.confirmations;
    const now = new Date();
    a!.expiresAt = new Date(now.getTime() - 1000);
    const timeout = h.config.ASSISTANT_TOOL_TIMEOUT_MS;
    // The write started longer ago than the tool timeout + 60 s (a crash during the write).
    b!.status = 'executing';
    b!.decidedAt = new Date(now.getTime() - timeout - 60_000 - 2000);
    b!.executionStartedAt = new Date(now.getTime() - timeout - 60_000 - 1000);
    h.audit.entries.length = 0;
    const result = await h.retention.runOnce(now);
    expect(result).toMatchObject({ confirmationsExpired: 1, confirmationsOutcomeUnknown: 1 });
    expect(a).toMatchObject({ status: 'expired' });
    expect(b).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_confirmation_outcome_unknown',
    });
    expect(h.audit.entries.map((e) => [e.action, e.actor.type])).toEqual([
      ['assistant.confirmation_expired', 'system'],
      ['assistant.confirmation_failed', 'system'],
    ]);
    // Never re-executed: no write call.
    expect(h.loopback.calls.every((c) => c.method === 'GET')).toBe(true);
    // A recent executing row is left alone.
    b!.status = 'executing';
    b!.decidedAt = new Date(now.getTime() - 1000);
    b!.executionStartedAt = null;
    await h.kv.del('as:jobs:lock');
    expect((await h.retention.runOnce(now))!.confirmationsOutcomeUnknown).toBe(0);
    // No write started: the re-read (up to 25 sequential reads) is measured from the decision,
    // so a row past the write's budget but within (25 + 1) × timeout + 60 s stays (AI-2 review).
    b!.decidedAt = new Date(now.getTime() - timeout - 60_000 - 1000);
    expect(await h.retention.failStaleConfirmations(now)).toBe(0);
    b!.decidedAt = new Date(now.getTime() - 26 * timeout - 60_000 - 1000);
    expect(await h.retention.failStaleConfirmations(now)).toBe(1);
    expect(b).toMatchObject({ status: 'failed', executionStartedAt: null });
    // A write that started recently stays, however old the decision.
    Object.assign(b!, {
      status: 'executing',
      errorCode: null,
      executionStartedAt: new Date(now.getTime() - 1000),
    });
    expect(await h.retention.failStaleConfirmations(now)).toBe(0);
    expect(h.retention.staleExecutingCutoff(now)).toEqual({
      decidedBefore: new Date(now.getTime() - 26 * timeout - 60_000),
      startedBefore: new Date(now.getTime() - timeout - 60_000),
    });
  });

  it('the content purge nulls the confirmation content; hard delete follows the executions', async () => {
    const { h, conversation } = setup(proposeDisable());
    await h.ask(conversation.publicId, 'one');
    const now = new Date();
    h.world.conversations[0]!.purgeAfter = new Date(now.getTime() - 1);
    expect(await h.retention.purgeContent(now)).toBe(1);
    expect(h.world.confirmations[0]).toMatchObject({ request: null, summary: null });
    for (const e of h.world.executions) e.createdAt = new Date(0);
    await h.kv.del('as:jobs:lock');
    await h.retention.runOnce(now);
    expect(h.world.confirmations).toHaveLength(0);
  });
});
