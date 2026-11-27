import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GS_CUSTOMER_ID, GS_DOMAIN, googleCustomer } from '../datasets/google';
import { syntheticEml } from '../datasets/mail';
import { MS_DOMAIN, MS_TENANT_ID, MS_USERS, microsoftDirectory } from '../datasets/microsoft';
import { GMAIL_MAIL_SCOPES } from './gmail-mail';
import { messageLocation } from './mail';
import { runStandalone, startSimulators, type RunningSimulators } from './main';
import { SimTokenRegistry } from './tokens';

// Step API-2 R7: the remediation endpoints of the Graph and Gmail simulators (per-mailbox
// location state, folders, labels, move with a new id, categories, permanent delete, trash),
// permission enforcement, and the admin API additions. Synthetic data only.
const NOW = new Date('2026-11-26T12:00:00.000Z');
const ALEX = MS_USERS.alex;
const GMAIL_ALEX = `alex@${GS_DOMAIN}`;
const FOLDER_NAME = 'Email Gateway Quarantine';

let sims: RunningSimulators;
let tokens: SimTokenRegistry;
const clock = NOW.getTime();

beforeEach(async () => {
  tokens = new SimTokenRegistry({ now: () => clock });
  sims = await startSimulators({
    dataset: {
      microsoft: { directories: [microsoftDirectory(NOW)] },
      google: { customers: [googleCustomer(NOW)] },
    },
    tokens,
    now: () => clock,
  });
  tokens.setGrant(MS_TENANT_ID, 'm365.mailbox_remediation', ['Mail.ReadWrite', 'User.Read.All']);
  tokens.setGrant(MS_TENANT_ID, 'm365.read_only', ['Mail.Read']);
  tokens.setGrant(GS_CUSTOMER_ID, 'google.mailbox_remediation', [GMAIL_MAIL_SCOPES.modify]);
  tokens.setGrant(GS_CUSTOMER_ID, 'google.readonly', [GMAIL_MAIL_SCOPES.readonly]);
  tokens.setGrant(GS_CUSTOMER_ID, 'google.full', [GMAIL_MAIL_SCOPES.full]);
});

afterEach(async () => {
  await sims.stop();
});

const graphToken = (profile = 'm365.mailbox_remediation') =>
  tokens.issue({ directoryId: MS_TENANT_ID, resource: 'graph', profile, expiresAt: clock + 3.6e6 });
const gmailToken = (subject: string, profile = 'google.mailbox_remediation') =>
  tokens.issue({
    directoryId: GS_CUSTOMER_ID,
    resource: 'google',
    profile,
    subject,
    expiresAt: clock + 3.6e6,
  });

async function graph(
  path: string,
  init: { method?: string; body?: unknown; token?: string } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${sims.baseUrl('graph')}${path}`, {
    method: init.method ?? 'GET',
    headers: {
      Authorization: `Bearer ${init.token ?? graphToken()}`,
      ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
  };
}

async function gmail(
  path: string,
  init: { method?: string; body?: unknown; token?: string } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(
    `${sims.baseUrl('gmail')}/gmail/v1/users/${encodeURIComponent(GMAIL_ALEX)}${path}`,
    {
      method: init.method ?? 'GET',
      headers: {
        Authorization: `Bearer ${init.token ?? gmailToken(GMAIL_ALEX)}`,
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    },
  );
  const text = await response.text();
  return {
    status: response.status,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
  };
}

const errorCode = (body: Record<string, unknown>) => (body.error as { code?: unknown }).code;
const errorReason = (body: Record<string, unknown>) =>
  ((body.error as { errors?: { reason?: string }[] }).errors ?? [])[0]?.reason;
const locate = (id: string) =>
  `/v1.0/users/${ALEX}/messages?$filter=${encodeURIComponent(`internetMessageId eq '${id.replace(/'/g, "''")}'`)}&$select=id,parentFolderId,isDraft&$top=10`;

describe('Graph remediation endpoints', () => {
  it('locates by Internet Message-ID in every folder (OData quote escaping) and reports drafts', async () => {
    const id = "it-o'brien-1@mail.example";
    const inbox = await sims.deliver({ user: ALEX, eml: syntheticEml({ messageId: id }) });
    const sent = await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId: id }),
      folder: 'sentitems',
    });
    const draft = await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId: id }),
      isDraft: true,
    });
    await sims.deliver({ user: ALEX, eml: syntheticEml({ messageId: 'other@mail.example' }) });
    const found = await graph(locate(`<${id}>`));
    expect(found.status).toBe(200);
    const value = found.body.value as Record<string, unknown>[];
    expect(value.map((v) => v.id)).toEqual([inbox.messageId, sent.messageId, draft.messageId]);
    expect(Object.keys(value[0]!).sort()).toEqual(['id', 'isDraft', 'parentFolderId']);
    const sentItems = await graph(`/v1.0/users/${ALEX}/mailFolders/sentitems?$select=id`);
    expect(value[1]!.parentFolderId).toBe(sentItems.body.id);
    expect(value[2]!.isDraft).toBe(true);
    const bad = await graph(
      `/v1.0/users/${ALEX}/messages?$filter=${encodeURIComponent("subject eq 'x'")}`,
    );
    expect(bad.status).toBe(400);
    expect((await graph(`/v1.0/users/nobody/messages`)).status).toBe(404);
  });

  it('creates a hidden child folder that only includeHiddenFolders=true lists; duplicates 409', async () => {
    const base = `/v1.0/users/${ALEX}/mailFolders/msgfolderroot/childFolders`;
    const created = await graph(base, {
      method: 'POST',
      body: { displayName: FOLDER_NAME, isHidden: true },
    });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ displayName: FOLDER_NAME, isHidden: true });
    const filter = `$filter=${encodeURIComponent(`displayName eq '${FOLDER_NAME}'`)}`;
    expect((await graph(`${base}?${filter}`)).body.value).toEqual([]);
    const hidden = await graph(`${base}?includeHiddenFolders=true&${filter}`);
    expect((hidden.body.value as { id: string }[]).map((f) => f.id)).toEqual([created.body.id]);
    const visible = await graph(`${base}`);
    expect((visible.body.value as { displayName: string }[]).map((f) => f.displayName)).toContain(
      'Inbox',
    );
    const dup = await graph(base, { method: 'POST', body: { displayName: FOLDER_NAME } });
    expect(dup.status).toBe(409);
    expect(errorCode(dup.body)).toBe('ErrorFolderExists');
    expect((await graph(base, { method: 'POST', body: { displayName: '' } })).status).toBe(400);
    expect(
      (await graph(base, { method: 'POST', body: { displayName: 'x', color: 'red' } })).status,
    ).toBe(400);
    expect((await graph(`/v1.0/users/${ALEX}/mailFolders/nope`)).status).toBe(404);
  });

  it('moves with a new id (old id 404), updates the Inbox delta and the location state', async () => {
    const delivered = await sims.deliver({ user: ALEX, eml: syntheticEml() });
    const init = await graph(`/v1.0/users/${ALEX}/mailFolders('inbox')/messages/delta`);
    const deltaLink = init.body['@odata.deltaLink'] as string;
    const folder = await graph(`/v1.0/users/${ALEX}/mailFolders/msgfolderroot/childFolders`, {
      method: 'POST',
      body: { displayName: FOLDER_NAME, isHidden: true },
    });
    const moved = await graph(`/v1.0/users/${ALEX}/messages/${delivered.messageId}/move`, {
      method: 'POST',
      body: { destinationId: folder.body.id },
    });
    expect(moved.status).toBe(201);
    expect(moved.body.id).not.toBe(delivered.messageId);
    expect(moved.body.parentFolderId).toBe(folder.body.id);
    const old = await graph(`/v1.0/users/${ALEX}/messages/${delivered.messageId}`);
    expect(old.status).toBe(404);
    expect(errorCode(old.body)).toBe('ErrorItemNotFound');
    const state = await graph(
      `/v1.0/users/${ALEX}/messages/${moved.body.id as string}?$select=id,parentFolderId,categories`,
    );
    expect(state.body).toEqual({
      id: moved.body.id,
      parentFolderId: folder.body.id,
      categories: [],
    });
    // The Inbox delta reports the old id removed; the quarantined copy is not in the Inbox.
    const after = await fetch(deltaLink, { headers: { Authorization: `Bearer ${graphToken()}` } });
    const items = ((await after.json()) as { value: Record<string, unknown>[] }).value;
    expect(items).toEqual([
      expect.objectContaining({ id: delivered.messageId, '@removed': expect.anything() }),
    ]);
    expect(messageLocation(sims.script, ALEX, delivered.messageId)).toMatchObject({
      currentId: moved.body.id,
      state: 'present',
      folder: { id: folder.body.id, displayName: FOLDER_NAME, wellKnownName: null, isHidden: true },
    });
    // Back to the Inbox by well-known name: another new id, in the delta as a new item.
    const back = await graph(`/v1.0/users/${ALEX}/messages/${moved.body.id as string}/move`, {
      method: 'POST',
      body: { destinationId: 'inbox' },
    });
    const inboxId = (await graph(`/v1.0/users/${ALEX}/mailFolders/inbox`)).body.id;
    expect(back.body.parentFolderId).toBe(inboxId);
    expect(messageLocation(sims.script, ALEX, delivered.messageId)).toMatchObject({
      currentId: back.body.id,
      folder: { wellKnownName: 'inbox' },
    });
    const again = await fetch(deltaLink, { headers: { Authorization: `Bearer ${graphToken()}` } });
    const later = ((await again.json()) as { value: Record<string, unknown>[] }).value;
    expect(later.map((i) => i.id)).toEqual([delivered.messageId, back.body.id]);
    // Unknown destination → 404; extra body keys → 400.
    expect(
      (
        await graph(`/v1.0/users/${ALEX}/messages/${back.body.id as string}/move`, {
          method: 'POST',
          body: { destinationId: 'AAMkEXAMPLEnope' },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await graph(`/v1.0/users/${ALEX}/messages/${back.body.id as string}/move`, {
          method: 'POST',
          body: { destinationId: 'junkemail', extra: true },
        })
      ).status,
    ).toBe(400);
  });

  it('patches categories only; permanentDelete answers 204 and the message is gone', async () => {
    const { messageId } = await sims.deliver({ user: ALEX, eml: syntheticEml() });
    const path = `/v1.0/users/${ALEX}/messages/${messageId}`;
    const patched = await graph(path, {
      method: 'PATCH',
      body: { categories: ['Blue', 'Email Gateway: Suspicious'] },
    });
    expect(patched.status).toBe(200);
    expect(patched.body.categories).toEqual(['Blue', 'Email Gateway: Suspicious']);
    expect((await graph(path, { method: 'PATCH', body: { subject: 'x' } })).status).toBe(400);
    expect((await graph(path, { method: 'PATCH', body: { categories: 'x' } })).status).toBe(400);
    expect(messageLocation(sims.script, ALEX, messageId)?.categories).toEqual([
      'Blue',
      'Email Gateway: Suspicious',
    ]);
    const deleted = await graph(`${path}/permanentDelete`, { method: 'POST' });
    expect(deleted.status).toBe(204);
    expect((await graph(path)).status).toBe(404);
    expect((await graph(`${path}/permanentDelete`, { method: 'POST' })).status).toBe(404);
    expect(messageLocation(sims.script, ALEX, messageId)).toMatchObject({
      state: 'deleted',
      currentId: null,
    });
  });

  it('enforces Mail.ReadWrite for writes (Mail.Read reads only)', async () => {
    const { messageId } = await sims.deliver({ user: ALEX, eml: syntheticEml() });
    const readOnly = graphToken('m365.read_only');
    expect(
      (await graph(`/v1.0/users/${ALEX}/messages/${messageId}`, { token: readOnly })).status,
    ).toBe(200);
    for (const [path, method, body] of [
      [`/v1.0/users/${ALEX}/messages/${messageId}/move`, 'POST', { destinationId: 'junkemail' }],
      [`/v1.0/users/${ALEX}/messages/${messageId}`, 'PATCH', { categories: [] }],
      [`/v1.0/users/${ALEX}/messages/${messageId}/permanentDelete`, 'POST', undefined],
      [`/v1.0/users/${ALEX}/mailFolders/msgfolderroot/childFolders`, 'POST', { displayName: 'x' }],
    ] as const) {
      const denied = await graph(path, { method, body, token: readOnly });
      expect(denied.status, path).toBe(403);
      expect(errorCode(denied.body)).toBe('ErrorAccessDenied');
    }
    tokens.revokePermission('Mail.ReadWrite', MS_TENANT_ID);
    expect((await graph(locate('<x@mail.example>'))).status).toBe(403);
  });
});

describe('Gmail remediation endpoints', () => {
  it('searches rfc822msgid (brackets optional) and hides SPAM/TRASH without includeSpamTrash', async () => {
    const id = 'gmail-rem-1@mail.example';
    const inbox = await sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml({ messageId: id }) });
    const spam = await sims.deliver({
      user: GMAIL_ALEX,
      eml: syntheticEml({ messageId: id }),
      labelIds: ['SPAM'],
    });
    const q = (value: string, extra = '') =>
      `/messages?q=${encodeURIComponent(`rfc822msgid:${value}`)}${extra}`;
    const all = await gmail(q(id, '&includeSpamTrash=true&maxResults=10'));
    expect((all.body.messages as { id: string }[]).map((m) => m.id).sort()).toEqual(
      [inbox.messageId, spam.messageId].sort(),
    );
    const bracketed = await gmail(q(`<${id}>`));
    expect((bracketed.body.messages as { id: string }[]).map((m) => m.id)).toEqual([
      inbox.messageId,
    ]);
    expect((await gmail(q('none@mail.example'))).body).toEqual({ resultSizeEstimate: 0 });
    expect((await gmail('/messages?q=from:someone')).status).toBe(400);
    expect((await gmail(q(id, '&maxResults=0'))).status).toBe(400);
  });

  it('lists and creates labels (hidden visibility kept; duplicates 409)', async () => {
    const created = await gmail('/labels', {
      method: 'POST',
      body: {
        name: 'Email Gateway/Quarantine',
        labelListVisibility: 'labelHide',
        messageListVisibility: 'hide',
      },
    });
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({
      name: 'Email Gateway/Quarantine',
      type: 'user',
      labelListVisibility: 'labelHide',
      messageListVisibility: 'hide',
    });
    const list = await gmail('/labels');
    const labels = list.body.labels as { id: string; type: string }[];
    expect(labels.some((l) => l.id === 'INBOX' && l.type === 'system')).toBe(true);
    expect(labels.some((l) => l.id === created.body.id)).toBe(true);
    const dup = await gmail('/labels', {
      method: 'POST',
      body: { name: 'email gateway/quarantine' },
    });
    expect(dup.status).toBe(409);
    expect((await gmail('/labels', { method: 'POST', body: { name: 'INBOX' } })).status).toBe(409);
    expect((await gmail('/labels', { method: 'POST', body: { name: '' } })).status).toBe(400);
  });

  it('modifies labels, trashes and untrashes; label changes advance the history id', async () => {
    const { messageId } = await sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() });
    const label = await gmail('/labels', { method: 'POST', body: { name: 'Q' } });
    const before = (await gmail('/profile')).body.historyId as string;
    const modified = await gmail(`/messages/${messageId}/modify`, {
      method: 'POST',
      body: { addLabelIds: [label.body.id], removeLabelIds: ['INBOX'] },
    });
    expect(modified.status).toBe(200);
    expect(modified.body.labelIds).toEqual(['UNREAD', label.body.id]);
    expect(Number((await gmail('/profile')).body.historyId)).toBe(Number(before) + 1);
    expect(
      (
        await gmail(`/messages/${messageId}/modify`, {
          method: 'POST',
          body: { addLabelIds: ['Label_999'] },
        })
      ).status,
    ).toBe(400);
    const minimal = await gmail(`/messages/${messageId}?format=minimal`);
    expect(minimal.body.labelIds).toEqual(['UNREAD', label.body.id]);
    const trashed = await gmail(`/messages/${messageId}/trash`, { method: 'POST' });
    expect(trashed.body.labelIds).toEqual(['UNREAD', label.body.id, 'TRASH']);
    const untrashed = await gmail(`/messages/${messageId}/untrash`, { method: 'POST' });
    expect(untrashed.body.labelIds).toEqual(['UNREAD', label.body.id]);
    expect(messageLocation(sims.script, GMAIL_ALEX, messageId)).toMatchObject({
      provider: 'google',
      state: 'present',
      labelIds: ['UNREAD', label.body.id],
      labelNames: ['Q'],
    });
    expect((await gmail('/messages/ffffffff/trash', { method: 'POST' })).status).toBe(404);
  });

  it('refuses DELETE without the full mail scope (403 insufficientPermissions)', async () => {
    const { messageId } = await sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() });
    const refused = await gmail(`/messages/${messageId}`, { method: 'DELETE' });
    expect(refused.status).toBe(403);
    expect(errorReason(refused.body)).toBe('insufficientPermissions');
    expect(messageLocation(sims.script, GMAIL_ALEX, messageId)?.state).toBe('present');
    const full = gmailToken(GMAIL_ALEX, 'google.full');
    expect((await gmail(`/messages/${messageId}`, { method: 'DELETE', token: full })).status).toBe(
      204,
    );
    expect(messageLocation(sims.script, GMAIL_ALEX, messageId)?.state).toBe('deleted');
  });

  it('enforces gmail.modify for writes (gmail.readonly reads only)', async () => {
    const { messageId } = await sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() });
    const readonly = gmailToken(GMAIL_ALEX, 'google.readonly');
    expect((await gmail('/labels', { token: readonly })).status).toBe(200);
    expect((await gmail('/messages?q=rfc822msgid:x', { token: readonly })).status).toBe(200);
    for (const [path, body] of [
      [`/messages/${messageId}/modify`, { addLabelIds: ['SPAM'] }],
      [`/messages/${messageId}/trash`, undefined],
      [`/messages/${messageId}/untrash`, undefined],
      ['/labels', { name: 'x' }],
    ] as const) {
      const denied = await gmail(path, { method: 'POST', body, token: readonly });
      expect(denied.status, path).toBe(403);
      expect(errorReason(denied.body)).toBe('insufficientPermissions');
    }
  });
});

describe('standalone admin API additions (step API-2)', () => {
  let running: Awaited<ReturnType<typeof runStandalone>>;
  let admin: string;
  let data: string;
  beforeAll(async () => {
    running = await runStandalone({
      IDP_SIM_HOST: '127.0.0.1',
      IDP_SIM_PORT: '0',
      IDP_SIM_ADMIN_PORT: '0',
      IDP_SIM_QUIET: 'true',
    });
    admin = `http://127.0.0.1:${running.adminPort}`;
    data = `http://127.0.0.1:${running.dataPort}`;
  });
  afterAll(async () => {
    await running.stop();
  });
  const call = (method: string, path: string, body?: unknown) =>
    fetch(`${admin}${path}`, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const stack = (path: string, init: { method?: string; body?: unknown } = {}) =>
    fetch(`${data}${path}`, {
      method: init.method ?? 'GET',
      headers: {
        Authorization: 'Bearer EXAMPLE-stack-token',
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });

  it('reports a message location after a move and scripts 429/503 per remediation family', async () => {
    await call('POST', '/admin/dataset', {
      microsoft: { directories: [microsoftDirectory(NOW)] },
    });
    const delivered = (await (
      await call('POST', `/admin/mailboxes/${encodeURIComponent(`alex@${MS_DOMAIN}`)}/messages`, {
        eml: syntheticEml(),
      })
    ).json()) as { messageId: string };
    const moved = await stack(`/graph/v1.0/users/${ALEX}/messages/${delivered.messageId}/move`, {
      method: 'POST',
      body: { destinationId: 'junkemail' },
    });
    const movedId = ((await moved.json()) as { id: string }).id;
    const location = (await (
      await call('GET', `/admin/mailboxes/${ALEX}/messages/${delivered.messageId}`)
    ).json()) as Record<string, unknown>;
    expect(location).toMatchObject({
      provider: 'microsoft',
      messageId: delivered.messageId,
      currentId: movedId,
      state: 'present',
      folder: { wellKnownName: 'junkemail', displayName: 'Junk Email' },
      categories: [],
    });
    expect((await call('GET', `/admin/mailboxes/${ALEX}/messages/unknown`)).status).toBe(404);

    expect(
      (
        await call('POST', '/admin/inject', {
          family: 'graph_messages',
          status: 429,
          retryAfter: '3',
        })
      ).status,
    ).toBe(204);
    // A folder call is another family: not answered by the injection.
    expect((await stack(`/graph/v1.0/users/${ALEX}/mailFolders/inbox`)).status).toBe(200);
    const throttled = await stack(`/graph/v1.0/users/${ALEX}/messages/${movedId}`);
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get('retry-after')).toBe('3');
    await call('POST', '/admin/inject', { family: 'graph_folders', status: 503, retryAfter: '4' });
    const unavailable = await stack(`/graph/v1.0/users/${ALEX}/mailFolders/inbox`);
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get('retry-after')).toBe('4');
    for (const family of ['gmail_messages', 'gmail_labels']) {
      expect((await call('POST', '/admin/inject', { family, status: 429 })).status).toBe(204);
    }
    expect((await call('POST', '/admin/inject', { family: 'nope', status: 429 })).status).toBe(400);
    const calls = (await (await call('GET', '/admin/calls?simulator=graph')).json()) as {
      calls: { method: string; path: string; status: number }[];
    };
    expect(calls.calls.map((c) => [c.method, c.status])).toEqual([
      ['POST', 201],
      ['GET', 200],
      ['GET', 429],
      ['GET', 503],
    ]);
    await call('POST', '/admin/reset', {});
  });
});
