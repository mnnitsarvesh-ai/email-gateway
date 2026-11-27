/* eslint-disable @typescript-eslint/require-await -- the fakes implement async ports */
import { describe, expect, it } from 'vitest';
import { MailboxApiError } from '@email-gateway/mailbox-api';
import {
  executeGmail,
  executeGraph,
  GraphFolderIds,
  type ExecInput,
  type GmailPort,
  type GraphMailPort,
} from './provider-exec';

const NAMES = {
  quarantineFolderName: 'Email Gateway Quarantine',
  quarantineFolderHidden: true,
  gmailQuarantineLabel: 'Email Gateway/Quarantine',
  tagName: 'Email Gateway: Suspicious',
};
const notFound = () => new MailboxApiError('not_found', { status: 404, retryable: false });
const signal = new AbortController().signal;

const input = (over: Partial<ExecInput>): ExecInput => ({
  action: 'move_quarantine',
  user: 'user-1',
  knownIds: [],
  internetMessageId: '<m1@example.test>',
  containers: { quarantineId: null, tagId: null },
  names: NAMES,
  signal,
  ...over,
});

/** An in-memory Graph mailbox (fake port): folders by id, moves return new ids. */
function fakeGraph(
  messages: Array<{
    id: string;
    folder: string;
    mid: string;
    draft?: boolean;
    categories?: string[];
  }>,
) {
  const calls: string[] = [];
  let seq = 0;
  const folders: Record<string, string> = {
    inbox: 'F-inbox',
    junkemail: 'F-junk',
    sentitems: 'F-sent',
    recoverableitemsdeletions: 'F-rid',
    msgfolderroot: 'F-root',
  };
  const children: Array<{ id: string; name: string }> = [];
  const live = new Map(messages.map((m) => [m.id, { ...m, categories: m.categories ?? [] }]));
  const port: GraphMailPort = {
    findMessagesByInternetMessageId: async (_u, mid) => {
      calls.push('find');
      return [...live.values()]
        .filter((m) => m.mid === mid)
        .map((m) => ({ id: m.id, parentFolderId: m.folder, isDraft: m.draft === true }));
    },
    getMessageState: async (_u, id) => {
      calls.push(`state:${id}`);
      const m = live.get(id);
      if (!m) throw notFound();
      return { id: m.id, parentFolderId: m.folder, categories: [...m.categories] };
    },
    wellKnownFolderId: async (_u, name) => {
      calls.push(`wk:${name}`);
      return folders[name]!;
    },
    ensureChildFolder: async (_u, _p, name) => {
      calls.push('ensure');
      const found = children.find((c) => c.name === name);
      if (found) return { id: found.id, created: false };
      const created = { id: `F-q${children.length}`, name };
      children.push(created);
      return { id: created.id, created: true };
    },
    moveMessage: async (_u, id, destination) => {
      calls.push(`move:${id}`);
      const m = live.get(id);
      if (!m) throw notFound();
      if (destination.startsWith('F-q') && !children.some((c) => c.id === destination)) {
        throw notFound();
      }
      live.delete(id);
      const next = { ...m, id: `${m.id.split('~')[0]}~${++seq}`, folder: destination };
      live.set(next.id, next);
      return { id: next.id, parentFolderId: destination };
    },
    setCategories: async (_u, id, categories) => {
      calls.push(`categories:${id}`);
      const m = live.get(id);
      if (!m) throw notFound();
      m.categories = [...categories];
      return [...categories];
    },
    permanentDelete: async (_u, id) => {
      calls.push(`delete:${id}`);
      if (!live.delete(id)) throw notFound();
    },
  };
  return { port, calls, live, children };
}

describe('executeGraph (R3, R5.3, R5.4)', () => {
  it('moves a known id to the hidden quarantine folder (created once) and returns the new id', async () => {
    const g = fakeGraph([{ id: 'A', folder: 'F-inbox', mid: '<m1@example.test>' }]);
    const r = await executeGraph(g.port, new GraphFolderIds(), 'mb1', input({ knownIds: ['A'] }));
    expect(r).toMatchObject({ kind: 'done', before: ['A'], already: false, located: false });
    if (r.kind !== 'done') throw new Error('unreachable');
    expect(r.after).toHaveLength(1);
    expect(r.after[0]).not.toBe('A');
    expect(r.containers.quarantineId).toBe('F-q0');
    expect(g.live.get(r.after[0]!)?.folder).toBe('F-q0');
    // Already in the target: no second move, the cached folder id is reused.
    const again = await executeGraph(
      g.port,
      new GraphFolderIds(),
      'mb1',
      input({ knownIds: r.after, containers: r.containers }),
    );
    expect(again).toMatchObject({ kind: 'done', already: true, before: r.after, after: r.after });
    expect(g.calls.filter((c) => c === 'ensure')).toHaveLength(1);
    expect(g.calls.filter((c) => c.startsWith('move:'))).toHaveLength(1);
  });

  it('re-ensures a cached quarantine folder that answers 404', async () => {
    const g = fakeGraph([{ id: 'A', folder: 'F-inbox', mid: '<m1@example.test>' }]);
    const r = await executeGraph(
      g.port,
      new GraphFolderIds(),
      'mb1',
      input({ knownIds: ['A'], containers: { quarantineId: 'F-q-gone', tagId: null } }),
    );
    expect(r.kind).toBe('done');
    expect(r.containers.quarantineId).toBe('F-q0');
  });

  it('locates by Message-ID when the stored id is gone, ignoring drafts and Sent Items', async () => {
    const g = fakeGraph([
      { id: 'IN', folder: 'F-inbox', mid: '<m1@example.test>' },
      { id: 'SENT', folder: 'F-sent', mid: '<m1@example.test>' },
      { id: 'DRAFT', folder: 'F-inbox', mid: '<m1@example.test>', draft: true },
    ]);
    const r = await executeGraph(
      g.port,
      new GraphFolderIds(),
      'mb1',
      input({ action: 'move_junk', knownIds: ['STALE'] }),
    );
    expect(r).toMatchObject({ kind: 'done', before: ['IN'], located: true });
    expect(g.live.get('SENT')?.folder).toBe('F-sent');
    expect(g.live.get('DRAFT')?.folder).toBe('F-inbox');
  });

  it('reports not found (locatable or not)', async () => {
    const g = fakeGraph([]);
    expect(await executeGraph(g.port, new GraphFolderIds(), 'mb1', input({}))).toMatchObject({
      kind: 'not_found',
      locatable: true,
    });
    expect(
      await executeGraph(g.port, new GraphFolderIds(), 'mb1', input({ internetMessageId: null })),
    ).toMatchObject({ kind: 'not_found', locatable: false });
  });

  it('tags (no-op when present), removes the tag and restores to the Inbox', async () => {
    const g = fakeGraph([
      { id: 'A', folder: 'F-inbox', mid: '<m1@example.test>', categories: ['Blue'] },
    ]);
    const folders = new GraphFolderIds();
    const tagged = await executeGraph(
      g.port,
      folders,
      'mb1',
      input({ action: 'tag', knownIds: ['A'] }),
    );
    expect(tagged).toMatchObject({ kind: 'done', after: ['A'], already: false });
    expect(g.live.get('A')?.categories).toEqual(['Blue', NAMES.tagName]);
    const again = await executeGraph(
      g.port,
      folders,
      'mb1',
      input({ action: 'tag', knownIds: ['A'] }),
    );
    expect(again).toMatchObject({ already: true });
    await executeGraph(g.port, folders, 'mb1', input({ action: 'remove_tag', knownIds: ['A'] }));
    expect(g.live.get('A')?.categories).toEqual(['Blue']);
    const moved = await executeGraph(
      g.port,
      folders,
      'mb1',
      input({ action: 'soft_delete', knownIds: ['A'] }),
    );
    if (moved.kind !== 'done') throw new Error('unreachable');
    expect(g.live.get(moved.after[0]!)?.folder).toBe('F-rid');
    const restored = await executeGraph(
      g.port,
      folders,
      'mb1',
      input({ action: 'restore_inbox', knownIds: moved.after }),
    );
    if (restored.kind !== 'done') throw new Error('unreachable');
    expect(g.live.get(restored.after[0]!)?.folder).toBe('F-inbox');
  });

  it('hard-deletes permanently (no id after)', async () => {
    const g = fakeGraph([{ id: 'A', folder: 'F-inbox', mid: '<m1@example.test>' }]);
    const r = await executeGraph(
      g.port,
      new GraphFolderIds(),
      'mb1',
      input({ action: 'hard_delete', knownIds: ['A'] }),
    );
    expect(r).toMatchObject({ kind: 'done', before: ['A'], after: [] });
    expect(g.live.size).toBe(0);
  });

  it('propagates provider errors other than 404', async () => {
    const g = fakeGraph([{ id: 'A', folder: 'F-inbox', mid: '<m1@example.test>' }]);
    g.port.moveMessage = () =>
      Promise.reject(new MailboxApiError('throttled', { status: 429, retryAfterMs: 2000 }));
    await expect(
      executeGraph(
        g.port,
        new GraphFolderIds(),
        'mb1',
        input({ action: 'move_junk', knownIds: ['A'] }),
      ),
    ).rejects.toMatchObject({ code: 'throttled' });
  });
});

/** An in-memory Gmail mailbox (fake port). */
function fakeGmail(messages: Array<{ id: string; mid: string; labels: string[] }>) {
  const calls: string[] = [];
  const labels: Array<{ id: string; name: string }> = [];
  const live = new Map(messages.map((m) => [m.id, { ...m, labels: [...m.labels] }]));
  const labeled = (id: string) => {
    const m = live.get(id);
    if (!m) throw notFound();
    return { id, threadId: null, labelIds: [...m.labels] };
  };
  const port: GmailPort = {
    findMessagesByRfc822Id: async (_u, mid) => {
      calls.push('find');
      return [...live.values()]
        .filter((m) => m.mid === mid)
        .map((m) => ({ id: m.id, threadId: null }));
    },
    messageLabels: async (_u, id) => labeled(id),
    listLabels: async () => {
      calls.push('labels');
      return labels.map((l) => ({
        id: l.id,
        name: l.name,
        type: 'user',
        labelListVisibility: null,
        messageListVisibility: null,
      }));
    },
    ensureLabel: async (_u, name) => {
      calls.push(`ensure:${name}`);
      const found = labels.find((l) => l.name === name);
      if (found) return { id: found.id, created: false };
      const l = { id: `Label_${labels.length + 1}`, name };
      labels.push(l);
      return { id: l.id, created: true };
    },
    modifyLabels: async (_u, id, add, remove) => {
      calls.push(`modify:${id}`);
      const m = live.get(id);
      if (!m) throw notFound();
      m.labels = [
        ...m.labels.filter((l) => !remove.includes(l)),
        ...add.filter((l) => !m.labels.includes(l)),
      ];
      return labeled(id);
    },
    trash: async (_u, id) => {
      calls.push(`trash:${id}`);
      const m = live.get(id)!;
      m.labels = [...m.labels.filter((l) => l !== 'INBOX' && l !== 'SPAM'), 'TRASH'];
      return labeled(id);
    },
    untrash: async (_u, id) => {
      calls.push(`untrash:${id}`);
      const m = live.get(id)!;
      m.labels = m.labels.filter((l) => l !== 'TRASH');
      return labeled(id);
    },
  };
  return { port, calls, live, labels };
}

describe('executeGmail (R3, R5.3, R5.4)', () => {
  it('ensures the hidden quarantine label, moves out of the Inbox, then restores', async () => {
    const g = fakeGmail([{ id: 'g1', mid: '<m1@example.test>', labels: ['INBOX', 'UNREAD'] }]);
    const r = await executeGmail(g.port, input({ user: 'alex@example.test' }));
    expect(r).toMatchObject({ kind: 'done', before: ['g1'], after: ['g1'], located: true });
    expect(g.live.get('g1')!.labels.sort()).toEqual(['Label_1', 'UNREAD']);
    const restored = await executeGmail(
      g.port,
      input({ action: 'restore_inbox', knownIds: ['g1'], containers: r.containers }),
    );
    expect(restored).toMatchObject({ kind: 'done', already: false });
    expect(g.live.get('g1')!.labels.sort()).toEqual(['INBOX', 'UNREAD']);
  });

  it('drops Sent-only and draft matches when locating', async () => {
    const g = fakeGmail([
      { id: 'sent', mid: '<m1@example.test>', labels: ['SENT'] },
      { id: 'draft', mid: '<m1@example.test>', labels: ['DRAFT'] },
    ]);
    expect(await executeGmail(g.port, input({ action: 'move_junk' }))).toMatchObject({
      kind: 'not_found',
      locatable: true,
    });
  });

  it('runs a hard delete as Trash and restores from Trash', async () => {
    const g = fakeGmail([{ id: 'g1', mid: '<m1@example.test>', labels: ['INBOX'] }]);
    const r = await executeGmail(g.port, input({ action: 'hard_delete', knownIds: ['g1'] }));
    expect(r).toMatchObject({ kind: 'done', already: false });
    expect(g.live.get('g1')!.labels).toEqual(['TRASH']);
    expect(g.calls).toContain('trash:g1');
    await executeGmail(g.port, input({ action: 'restore_inbox', knownIds: ['g1'] }));
    expect(g.live.get('g1')!.labels).toEqual(['INBOX']);
  });

  it('tags with a visible label and removes it without creating labels', async () => {
    const g = fakeGmail([{ id: 'g1', mid: '<m1@example.test>', labels: ['INBOX'] }]);
    const tagged = await executeGmail(g.port, input({ action: 'tag', knownIds: ['g1'] }));
    expect(tagged.containers.tagId).toBe('Label_1');
    const removed = await executeGmail(g.port, input({ action: 'remove_tag', knownIds: ['g1'] }));
    expect(removed).toMatchObject({ kind: 'done' });
    expect(g.live.get('g1')!.labels).toEqual(['INBOX']);
    expect(g.calls.filter((c) => c.startsWith('ensure:'))).toHaveLength(1);
    // A restore with no quarantine label anywhere looks it up and never creates it.
    const fresh = fakeGmail([{ id: 'g2', mid: '<m2@example.test>', labels: ['SPAM'] }]);
    await executeGmail(fresh.port, input({ action: 'restore_inbox', knownIds: ['g2'] }));
    expect(fresh.labels).toHaveLength(0);
    expect(fresh.live.get('g2')!.labels).toEqual(['INBOX']);
  });
});
