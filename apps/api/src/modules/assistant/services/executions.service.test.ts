import { describe, expect, it } from 'vitest';
import { policyPage, testUser } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import { assistantKeys } from '../assistant.constants';

const ORG = 7001n;
const request = { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' };

async function withList(nextCursor: string | null) {
  const h = createAssistantHarness();
  h.world.enable(ORG);
  h.loopback.on('GET /api/v1/policies', (call) =>
    call.path.includes('cursor=') ? policyPage(1, null) : policyPage(2, nextCursor),
  );
  const c = await h.conversations.create(h.user, h.scope, {});
  await h.ask(c.id, '/tool policy_management_list {"status":"active"}');
  return { h, c, parent: h.world.executions[0]! };
}

describe('ExecutionsService (§4.1)', () => {
  it('gets an own execution with its card; others answer 404', async () => {
    const { h, parent } = await withList(null);
    await expect(h.executions.get(h.user, h.scope, parent.publicId)).resolves.toMatchObject({
      id: parent.publicId,
      tool: 'policy_management_list',
      decision: 'allowed',
      hasMore: false,
      card: { kind: 'table' },
    });
    const other = testUser({ userId: 900n });
    await expect(h.executions.get(other, h.scope, parent.publicId)).rejects.toMatchObject({
      code: 'assistant_execution_not_found',
    });
  });

  it('loads the next page without a model call: same tool, stored params + cursor, new child execution', async () => {
    const { h, parent } = await withList('page-2-cursor');
    const signal = new AbortController().signal;
    const view = await h.executions.more(h.user, h.scope, parent.publicId, request, signal);
    expect(view).toMatchObject({
      parentExecutionId: parent.publicId,
      turnId: null,
      seq: 2,
      decision: 'allowed',
      hasMore: false,
    });
    const url = new URL(h.loopback.toolCalls.at(-1)!.path, 'http://x');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      status: 'active',
      cursor: 'page-2-cursor',
    });
    expect(h.audit.entries.at(-1)).toMatchObject({ action: 'assistant.tool_executed' });
    // The child has no next page: 409.
    await expect(
      h.executions.more(h.user, h.scope, view.id, request, signal),
    ).rejects.toMatchObject({
      code: 'assistant_no_more_results',
    });
  });

  it('answers 409 without a next cursor, and while a turn holds the conversation lock', async () => {
    const none = await withList(null);
    await expect(
      none.h.executions.more(
        none.h.user,
        none.h.scope,
        none.parent.publicId,
        request,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: 'assistant_no_more_results' });
    const busy = await withList('c2');
    await busy.h.kv.set(assistantKeys.turnLock(busy.c.id), 'running-turn', 60);
    await expect(
      busy.h.executions.more(
        busy.h.user,
        busy.h.scope,
        busy.parent.publicId,
        request,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: 'assistant_turn_in_progress' });
  });

  it('re-applies the permission pre-filter: a user who lost the permission gets denied_permission', async () => {
    const { h, parent } = await withList('c2');
    const demoted = testUser({ permissions: new Set(['assistant:use']) });
    const view = await h.executions.more(
      demoted,
      h.scope,
      parent.publicId,
      request,
      new AbortController().signal,
    );
    expect(view.decision).toBe('denied_permission');
    expect(h.loopback.toolCalls).toHaveLength(1);
  });
});
