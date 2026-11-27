import {
  GS_DOMAIN,
  MS_USERS,
  messageLocation,
  syntheticEml,
} from '@email-gateway/idp-adapters/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MailboxApiError, toMailboxApiError } from '../errors';
import { classifyRemediationError } from '../remediation/errors';
import {
  gmailLocateCandidates,
  gmailModifyFor,
  graphCategoriesWith,
  graphLocateCandidates,
  providerActionPlan,
} from '../remediation/provider-actions';
import { createMailboxTestbed, TEST_API_CONNECTION_ID, type MailboxTestbed } from '../testing';

// Step API-2 (note 36 R3, R5.3–R5.6, R6, §9.1): the remediation calls of the Graph and Gmail
// clients against the in-process simulators. Synthetic data only; no real provider is contacted.
const ALEX = MS_USERS.alex;
const GMAIL_ALEX = `alex@${GS_DOMAIN}`;
const FOLDER = 'Email Gateway Quarantine';
const QUARANTINE_LABEL = 'Email Gateway/Quarantine';
const TAG = 'Email Gateway: Suspicious';
const signal = () => new AbortController().signal;

async function failure(promise: Promise<unknown>): Promise<MailboxApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(MailboxApiError);
    return error as MailboxApiError;
  }
  throw new Error('expected a MailboxApiError');
}

let tb: MailboxTestbed;
beforeEach(async () => {
  tb = await createMailboxTestbed();
});
afterEach(async () => {
  await tb.stop();
});

describe('GraphMailClient remediation calls', () => {
  it('locates by Internet Message-ID (quotes escaped) in every folder; drafts and Sent Items are filtered', async () => {
    const id = "rem-o'neil-1@mail.example";
    const inbox = await tb.sims.deliver({ user: ALEX, eml: syntheticEml({ messageId: id }) });
    await tb.sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId: id }),
      folder: 'sentitems',
    });
    await tb.sims.deliver({ user: ALEX, eml: syntheticEml({ messageId: id }), isDraft: true });
    const found = await tb.graph.findMessagesByInternetMessageId(ALEX, id, signal());
    expect(found).toHaveLength(3);
    expect(found.filter((m) => m.isDraft)).toHaveLength(1);
    const call = tb.sims.script.calls({
      simulator: 'graph',
      path: `/v1.0/users/${ALEX}/messages`,
    })[0];
    expect(call?.query).toContain('$select=id,parentFolderId,isDraft&$top=10');
    expect(decodeURIComponent(call?.query ?? '')).toContain(
      `$filter=internetMessageId eq '<rem-o''neil-1@mail.example>'`,
    );
    const sent = await tb.graph.wellKnownFolderId(ALEX, 'sentitems', signal());
    expect(graphLocateCandidates(found, sent).map((m) => m.id)).toEqual([inbox.messageId]);
    // Already bracketed ids are sent as they are.
    expect(await tb.graph.findMessagesByInternetMessageId(ALEX, `<${id}>`, signal())).toHaveLength(
      3,
    );
    expect(
      await tb.graph.findMessagesByInternetMessageId(ALEX, '<none@mail.example>', signal()),
    ).toEqual([]);
  });

  it('refuses an empty, over-long or control-character id without a call', async () => {
    const before = tb.sims.script.calls().length;
    for (const bad of ['', '  ', `a\r\nb@x`, `${'a'.repeat(1000)}@x`]) {
      expect(
        (await failure(tb.graph.findMessagesByInternetMessageId(ALEX, bad, signal()))).code,
      ).toBe('bad_request');
    }
    expect(tb.sims.script.calls()).toHaveLength(before);
  });

  it('ensures the hidden quarantine folder once and reuses the already-hidden folder', async () => {
    const first = await tb.graph.ensureChildFolder(ALEX, 'msgfolderroot', FOLDER, true, signal());
    expect(first.created).toBe(true);
    const again = await tb.graph.ensureChildFolder(ALEX, 'msgfolderroot', FOLDER, true, signal());
    expect(again).toEqual({ id: first.id, created: false });
    const calls = tb.sims.script.calls({ simulator: 'graph' }).map((c) => c.method);
    expect(calls).toEqual(['GET', 'POST', 'GET']);
    expect(
      tb.sims.script
        .calls({ simulator: 'graph' })
        .every((c) =>
          c.method === 'POST'
            ? c.query === ''
            : (c.query ?? '').includes('includeHiddenFolders=true'),
        ),
    ).toBe(true);
    // A concurrent creation (lookup misses, create answers 409) resolves to the existing folder.
    tb.sims.script.inject({
      simulator: 'graph',
      method: 'GET',
      path: /\/childFolders$/,
      status: 200,
      rawBody: JSON.stringify({ value: [] }),
    });
    expect(await tb.graph.ensureChildFolder(ALEX, 'msgfolderroot', FOLDER, true, signal())).toEqual(
      {
        id: first.id,
        created: false,
      },
    );
    expect(
      (await failure(tb.graph.ensureChildFolder(ALEX, 'msgfolderroot', '', true, signal()))).code,
    ).toBe('bad_request');
  });

  it('moves (new id), the old id is gone and the locate step finds the new id', async () => {
    const id = 'rem-move-1@mail.example';
    const delivered = await tb.sims.deliver({ user: ALEX, eml: syntheticEml({ messageId: id }) });
    const folder = await tb.graph.ensureChildFolder(ALEX, 'msgfolderroot', FOLDER, true, signal());
    const before = await tb.graph.getMessageState(ALEX, delivered.messageId, signal());
    const inbox = await tb.graph.wellKnownFolderId(ALEX, 'inbox', signal());
    expect(before).toEqual({ id: delivered.messageId, parentFolderId: inbox, categories: [] });
    const moved = await tb.graph.moveMessage(ALEX, delivered.messageId, folder.id, signal());
    expect(moved.id).not.toBe(delivered.messageId);
    expect(moved.parentFolderId).toBe(folder.id);
    expect(
      (await failure(tb.graph.getMessageState(ALEX, delivered.messageId, signal()))).code,
    ).toBe('not_found');
    const located = await tb.graph.findMessagesByInternetMessageId(ALEX, id, signal());
    expect(located).toEqual([{ id: moved.id, parentFolderId: folder.id, isDraft: false }]);
    expect(messageLocation(tb.sims.script, ALEX, delivered.messageId)).toMatchObject({
      currentId: moved.id,
      folder: { displayName: FOLDER, isHidden: true },
    });
    // Restore by well-known name.
    const back = await tb.graph.moveMessage(ALEX, moved.id, 'inbox', signal());
    expect(back.parentFolderId).toBe(inbox);
    const junk = await tb.graph.wellKnownFolderId(ALEX, 'junkemail', signal());
    const deletions = await tb.graph.wellKnownFolderId(ALEX, 'recoverableitemsdeletions', signal());
    expect(new Set([inbox, junk, deletions, folder.id]).size).toBe(4);
  });

  it('adds and removes the tag category (no-op without a call) and deletes permanently', async () => {
    const { messageId } = await tb.sims.deliver({ user: ALEX, eml: syntheticEml() });
    const state = await tb.graph.getMessageState(ALEX, messageId, signal());
    const add = graphCategoriesWith(state.categories, TAG, true);
    expect(await tb.graph.setCategories(ALEX, messageId, add.categories, signal())).toEqual([TAG]);
    const tagged = await tb.graph.getMessageState(ALEX, messageId, signal());
    const writes = tb.sims.script.writes('graph').length;
    expect(graphCategoriesWith(tagged.categories, TAG, true).changed).toBe(false); // no PATCH needed
    expect(tb.sims.script.writes('graph')).toHaveLength(writes);
    const remove = graphCategoriesWith(tagged.categories, TAG, false);
    expect(await tb.graph.setCategories(ALEX, messageId, remove.categories, signal())).toEqual([]);
    const patch = tb.sims.script.calls({ simulator: 'graph', method: 'PATCH' });
    expect(patch).toHaveLength(2);
    await tb.graph.permanentDelete(ALEX, messageId, signal());
    expect(messageLocation(tb.sims.script, ALEX, messageId)?.state).toBe('deleted');
    expect((await failure(tb.graph.permanentDelete(ALEX, messageId, signal()))).code).toBe(
      'not_found',
    );
    expect(
      (await failure(tb.graph.setCategories(ALEX, messageId, ['bad\u0000'], signal()))).code,
    ).toBe('bad_request');
  });

  it('needs Mail.ReadWrite for writes (missing_permission → forbidden class)', async () => {
    await tb.stop();
    tb = await createMailboxTestbed({ microsoftPermissions: ['Mail.Read', 'User.Read.All'] });
    const { messageId } = await tb.sims.deliver({ user: ALEX, eml: syntheticEml() });
    expect((await tb.graph.getMessageState(ALEX, messageId, signal())).id).toBe(messageId);
    const denied = await failure(tb.graph.moveMessage(ALEX, messageId, 'junkemail', signal()));
    expect(denied).toMatchObject({ code: 'missing_permission', status: 403 });
    expect(classifyRemediationError(denied).class).toBe('forbidden');
  });
});

describe('GmailClient remediation calls', () => {
  it('locates by rfc822msgid incl. Spam/Trash and reads labels', async () => {
    const id = 'gm-rem-1@mail.example';
    const inbox = await tb.sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml({ messageId: id }) });
    const spam = await tb.sims.deliver({
      user: GMAIL_ALEX,
      eml: syntheticEml({ messageId: id }),
      labelIds: ['SPAM'],
    });
    const sent = await tb.sims.deliver({
      user: GMAIL_ALEX,
      eml: syntheticEml({ messageId: id }),
      labelIds: ['SENT'],
    });
    const found = await tb.gmail.findMessagesByRfc822Id(GMAIL_ALEX, `<${id}>`, signal());
    expect(found.map((m) => m.id).sort()).toEqual(
      [inbox.messageId, spam.messageId, sent.messageId].sort(),
    );
    const query = tb.sims.script.calls({ simulator: 'gmail' }).at(-1)?.query ?? '';
    expect(query).toContain('includeSpamTrash=true');
    expect(query).toContain('maxResults=10');
    expect(new URLSearchParams(query).get('q')).toBe(`rfc822msgid:${id}`);
    const labeled = await Promise.all(
      found.map((m) => tb.gmail.messageLabels(GMAIL_ALEX, m.id, signal())),
    );
    expect(
      gmailLocateCandidates(labeled)
        .map((m) => m.id)
        .sort(),
    ).toEqual([inbox.messageId, spam.messageId].sort());
    expect(
      (await failure(tb.gmail.findMessagesByRfc822Id(GMAIL_ALEX, 'a b@x', signal()))).code,
    ).toBe('bad_request');
    expect(
      await tb.gmail.findMessagesByRfc822Id(GMAIL_ALEX, 'none@mail.example', signal()),
    ).toEqual([]);
  });

  it('ensures hidden labels once (reuse, 409 race) and applies modify, trash and untrash', async () => {
    const { messageId } = await tb.sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() });
    const quarantine = await tb.gmail.ensureLabel(GMAIL_ALEX, QUARANTINE_LABEL, true, signal());
    expect(quarantine.created).toBe(true);
    expect(await tb.gmail.ensureLabel(GMAIL_ALEX, QUARANTINE_LABEL, true, signal())).toEqual({
      id: quarantine.id,
      created: false,
    });
    const labels = await tb.gmail.listLabels(GMAIL_ALEX, signal());
    expect(labels.find((l) => l.id === quarantine.id)).toEqual({
      id: quarantine.id,
      name: QUARANTINE_LABEL,
      type: 'user',
      labelListVisibility: 'labelHide',
      messageListVisibility: 'hide',
    });
    tb.sims.script.inject({
      simulator: 'gmail',
      method: 'GET',
      path: /\/labels$/,
      status: 200,
      rawBody: JSON.stringify({ labels: [] }),
    });
    expect(await tb.gmail.ensureLabel(GMAIL_ALEX, QUARANTINE_LABEL, true, signal())).toEqual({
      id: quarantine.id,
      created: false,
    });
    const tag = await tb.gmail.ensureLabel(GMAIL_ALEX, TAG, false, signal());
    expect(
      (await tb.gmail.listLabels(GMAIL_ALEX, signal())).find((l) => l.id === tag.id),
    ).toMatchObject({
      labelListVisibility: 'labelShow',
      messageListVisibility: 'show',
    });

    // move_quarantine through the plan's label changes.
    const gatewayLabels = { quarantineLabelId: quarantine.id, tagLabelId: tag.id };
    const before = await tb.gmail.messageLabels(GMAIL_ALEX, messageId, signal());
    const step = providerActionPlan('move_quarantine').gmail[1] as Parameters<
      typeof gmailModifyFor
    >[0];
    const change = gmailModifyFor(step, before.labelIds, gatewayLabels);
    const quarantined = await tb.gmail.modifyLabels(
      GMAIL_ALEX,
      messageId,
      change.add,
      change.remove,
      signal(),
    );
    expect(quarantined.labelIds).toEqual(['UNREAD', quarantine.id]);
    const trashed = await tb.gmail.trash(GMAIL_ALEX, messageId, signal());
    expect(trashed.labelIds).toContain('TRASH');
    const untrashed = await tb.gmail.untrash(GMAIL_ALEX, messageId, signal());
    expect(untrashed.labelIds).not.toContain('TRASH');
    const restore = providerActionPlan('restore_inbox').gmail[1] as typeof step;
    const back = gmailModifyFor(restore, untrashed.labelIds, gatewayLabels);
    expect(
      (await tb.gmail.modifyLabels(GMAIL_ALEX, messageId, back.add, back.remove, signal()))
        .labelIds,
    ).toEqual(['UNREAD', 'INBOX']);
    expect(
      (await failure(tb.gmail.modifyLabels(GMAIL_ALEX, messageId, ['Label_404'], [], signal())))
        .code,
    ).toBe('bad_request');
    expect((await failure(tb.gmail.ensureLabel(GMAIL_ALEX, '', true, signal()))).code).toBe(
      'bad_request',
    );
  });

  it('has no delete method, and the simulator refuses messages.delete under gmail.modify', async () => {
    const { messageId } = await tb.sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() });
    expect('delete' in tb.gmail).toBe(false);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(tb.gmail))).not.toContain('delete');
    // The grant's token (gmail.modify) at the simulator: 403 insufficientPermissions.
    let thrown: unknown;
    try {
      await tb.http.request({
        family: 'gmail',
        method: 'DELETE',
        url: `/gmail/v1/users/${encodeURIComponent(GMAIL_ALEX)}/messages/${messageId}`,
        pathTemplate: '/gmail/v1/users/{userId}/messages/{id}',
        token: await tokenFor(GMAIL_ALEX),
        signal: signal(),
      });
    } catch (e) {
      thrown = e;
    }
    const error = toMailboxApiError(thrown);
    expect(error).toMatchObject({
      code: 'missing_permission',
      status: 403,
      providerCode: 'insufficientPermissions',
    });
    expect(messageLocation(tb.sims.script, GMAIL_ALEX, messageId)?.state).toBe('present');
  });
});

/** The testbed's per-mailbox Gmail token source (created on first client use). */
async function tokenFor(mailbox: string) {
  await tb.gmail.profile(mailbox, signal());
  return tb.gmailTokens.get(mailbox)!;
}

describe('call discipline of the remediation calls (R5.6, R5.7)', () => {
  it('429 Retry-After pauses the family through the gate; nothing is called while paused', async () => {
    const { messageId } = await tb.sims.deliver({ user: ALEX, eml: syntheticEml() });
    tb.sims.script.inject({
      simulator: 'graph',
      method: 'POST',
      path: /\/move$/,
      status: 429,
      retryAfter: '7',
    });
    const throttled = await failure(tb.graph.moveMessage(ALEX, messageId, 'junkemail', signal()));
    expect(throttled).toMatchObject({ code: 'throttled', status: 429, retryAfterMs: 7000 });
    expect(classifyRemediationError(throttled)).toEqual({
      class: 'throttled',
      failureCode: null,
      retryAfterMs: 7000,
    });
    expect(tb.throttle.events.at(-1)).toMatchObject({
      apiConnectionPublicId: TEST_API_CONNECTION_ID,
      family: 'graph',
      retryAfterMs: 7000,
    });
    const calls = tb.sims.script.calls().length;
    const paused = await failure(tb.graph.getMessageState(ALEX, messageId, signal()));
    expect(paused).toMatchObject({ code: 'throttle_paused', retryAfterMs: 7000 });
    expect(classifyRemediationError(paused).class).toBe('throttled');
    expect(tb.sims.script.calls()).toHaveLength(calls);
    tb.clock.advance(7_000);
    expect((await tb.graph.moveMessage(ALEX, messageId, 'junkemail', signal())).id).not.toBe(
      messageId,
    );
    // Every call took the per-connection budget of its family.
    expect(tb.budget.takes.every((t) => t.integrationId === `mbx:${TEST_API_CONNECTION_ID}`)).toBe(
      true,
    );
  });

  it('503 with Retry-After pauses (throttled); 503 without is retryable and the retry succeeds', async () => {
    const { messageId } = await tb.sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() });
    tb.sims.script.inject({ simulator: 'gmail', path: /\/modify$/, status: 503 });
    const plain = await failure(
      tb.gmail.modifyLabels(GMAIL_ALEX, messageId, ['SPAM'], ['INBOX'], signal()),
    );
    expect(classifyRemediationError(plain)).toEqual({
      class: 'retryable',
      failureCode: 'provider_unavailable',
      retryAfterMs: null,
    });
    expect(tb.throttle.events).toEqual([]);
    expect(
      (await tb.gmail.modifyLabels(GMAIL_ALEX, messageId, ['SPAM'], ['INBOX'], signal())).labelIds,
    ).toContain('SPAM');
    tb.sims.script.inject({ simulator: 'gmail', path: /\/trash$/, status: 503, retryAfter: '5' });
    const paused = await failure(tb.gmail.trash(GMAIL_ALEX, messageId, signal()));
    expect(classifyRemediationError(paused)).toEqual({
      class: 'throttled',
      failureCode: null,
      retryAfterMs: 5000,
    });
    expect(tb.throttle.events.at(-1)).toMatchObject({
      family: 'gmail',
      status: 503,
      retryAfterMs: 5000,
    });
  });

  it('drops the token on 401 and retries a write once', async () => {
    const { messageId } = await tb.sims.deliver({ user: ALEX, eml: syntheticEml() });
    await tb.graph.getMessageState(ALEX, messageId, signal());
    tb.sims.tokens.invalidate(tb.graphToken.peek()!);
    const moved = await tb.graph.moveMessage(ALEX, messageId, 'junkemail', signal());
    expect(moved.id).not.toBe(messageId);
    expect(tb.graphToken.invalidations).toBe(1);
    // Two 401s in a row: unauthorized → forbidden class.
    tb.sims.script.inject({
      simulator: 'graph',
      method: 'PATCH',
      path: '/v1.0/users/',
      status: 401,
      times: 2,
    });
    const denied = await failure(tb.graph.setCategories(ALEX, moved.id, [TAG], signal()));
    expect(denied.code).toBe('unauthorized');
    expect(classifyRemediationError(denied).class).toBe('forbidden');
  });

  it.each([
    [403, 'missing_permission', 'forbidden'],
    [404, 'not_found', 'not_found'],
    [400, 'bad_request', 'rejected'],
    [409, 'conflict', 'rejected'],
    [500, 'provider_unavailable', 'retryable'],
  ] as const)('classifies %s on a write as %s (%s)', async (status, code, cls) => {
    const { messageId } = await tb.sims.deliver({ user: ALEX, eml: syntheticEml() });
    tb.sims.script.inject({
      simulator: 'graph',
      method: 'POST',
      path: /\/permanentDelete$/,
      status,
    });
    const error = await failure(tb.graph.permanentDelete(ALEX, messageId, signal()));
    expect(error).toMatchObject({ code, status });
    expect(classifyRemediationError(error).class).toBe(cls);
  });

  it('never puts a token, message id, query string, folder or body into errors or log lines', async () => {
    const internetId = 'redaction-marker-1@mail.example';
    const { messageId } = await tb.sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId: internetId, subject: 'EXAMPLE-subject-marker' }),
    });
    const gmailDelivered = await tb.sims.deliver({
      user: GMAIL_ALEX,
      eml: syntheticEml({ messageId: internetId }),
    });
    const errors: unknown[] = [];
    const record = async (promise: Promise<unknown>) => {
      try {
        await promise;
      } catch (error) {
        errors.push(error);
      }
    };
    for (const status of [400, 401, 403, 404, 409, 429, 500, 503]) {
      tb.sims.script.inject({
        simulator: 'graph',
        path: '/v1.0/users/',
        status,
        times: status === 401 ? 2 : 1,
        retryAfter: '1',
      });
      await record(tb.graph.findMessagesByInternetMessageId(ALEX, internetId, signal()));
      tb.clock.advance(2_000);
      tb.sims.script.inject({
        simulator: 'graph',
        path: '/v1.0/users/',
        status,
        times: status === 401 ? 2 : 1,
        retryAfter: '1',
      });
      await record(tb.graph.moveMessage(ALEX, messageId, 'junkemail', signal()));
      tb.clock.advance(2_000);
      tb.sims.script.inject({
        simulator: 'graph',
        path: '/v1.0/users/',
        status,
        times: status === 401 ? 2 : 1,
        retryAfter: '1',
      });
      await record(tb.graph.ensureChildFolder(ALEX, 'msgfolderroot', FOLDER, true, signal()));
      tb.clock.advance(2_000);
      tb.sims.script.inject({
        simulator: 'gmail',
        path: '/gmail/',
        status,
        times: status === 401 ? 2 : 1,
        retryAfter: '1',
      });
      await record(tb.gmail.findMessagesByRfc822Id(GMAIL_ALEX, internetId, signal()));
      tb.clock.advance(2_000);
      tb.sims.script.inject({
        simulator: 'gmail',
        path: '/gmail/',
        status,
        times: status === 401 ? 2 : 1,
        retryAfter: '1',
      });
      await record(
        tb.gmail.modifyLabels(GMAIL_ALEX, gmailDelivered.messageId, ['SPAM'], ['INBOX'], signal()),
      );
      tb.clock.advance(2_000);
    }
    expect(errors).toHaveLength(40);
    const dump = [
      tb.logger.text(),
      ...errors.map((e) => JSON.stringify(e)),
      ...errors.map((e) => (e instanceof Error ? `${e.message} ${e.stack ?? ''}` : '')),
    ].join('\n');
    for (const secret of [
      tb.graphToken.peek() ?? 'EXAMPLE-sim-token',
      'EXAMPLE-sim-token',
      'Bearer',
      ALEX,
      GMAIL_ALEX,
      messageId,
      gmailDelivered.messageId,
      internetId,
      'rfc822msgid',
      '$filter',
      'includeHiddenFolders',
      FOLDER,
      'destinationId',
      'EXAMPLE-subject-marker',
    ]) {
      expect(dump, secret).not.toContain(secret);
    }
    // Log lines carry path templates only.
    expect(tb.logger.text()).toContain('/v1.0/users/{id}/messages/{mid}/move');
  });
});
