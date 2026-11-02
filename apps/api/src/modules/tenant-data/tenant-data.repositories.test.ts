import type { PrismaReadService, PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { DomainsRepository } from './domains.repository';
import { MessagesRepository } from './messages.repository';
import { PoliciesRepository } from './policies.repository';
import { QuarantineRepository } from './quarantine.repository';

interface Call {
  client: 'writer' | 'reader';
  model: string;
  method: string;
  args: { where?: unknown; take?: number; orderBy?: unknown };
}

/** A Prisma stand-in that records every model call and answers with `results` (or defaults). */
function recordingClients(results: Record<string, unknown> = {}) {
  const calls: Call[] = [];
  const make = (client: Call['client']) =>
    new Proxy(
      {},
      {
        get: (_t, model: string) =>
          new Proxy(
            {},
            {
              get: (_m, method: string) => (args: Call['args']) => {
                calls.push({ client, model, method, args });
                const key = `${model}.${method}`;
                if (key in results) return Promise.resolve(results[key]);
                return Promise.resolve(method === 'findMany' ? [] : null);
              },
            },
          ),
      },
    );
  const writer = make('writer') as unknown as PrismaService;
  const reader = { client: make('reader') } as unknown as PrismaReadService;
  return { writer, reader, calls };
}

/** True when `value` contains `organizationId: <id>` at any depth. */
function scopedTo(value: unknown, id: bigint): boolean {
  if (value === null || typeof value !== 'object') return false;
  if ((value as { organizationId?: unknown }).organizationId === id) return true;
  return Object.values(value).some((v) => scopedTo(v, id));
}

const SCOPE = systemScope(42n);
const PUBLIC_ID = '0190a0b0-0000-7000-8000-0000000000f1';

function expectEveryQueryScoped(calls: Call[]): void {
  expect(calls.length).toBeGreaterThan(0);
  for (const call of calls) {
    expect(scopedTo(call.args.where, 42n), `${call.model}.${call.method}`).toBe(true);
  }
}

describe('tenant-scoped repositories (D9)', () => {
  it('domains: by public id with the organization (writer), lists on the reader', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new DomainsRepository(writer, reader);
    await repo.findByPublicId(SCOPE, PUBLIC_ID);
    await repo.list(SCOPE, { take: 26, beforeId: 9n });
    expectEveryQueryScoped(calls);
    expect(calls.map((c) => `${c.client}:${c.method}`)).toEqual([
      'writer:findFirst',
      'reader:findMany',
    ]);
    expect(calls[0]!.args.where).toEqual({ publicId: PUBLIC_ID, organizationId: 42n });
    expect(calls[1]!.args.where).toEqual({ id: { lt: 9n }, organizationId: 42n });
  });

  it('policies: soft-deleted policies are excluded', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new PoliciesRepository(writer, reader);
    await repo.findByPublicId(SCOPE, PUBLIC_ID);
    await repo.list(SCOPE, { take: 500 });
    expectEveryQueryScoped(calls);
    for (const call of calls) expect(call.args.where).toMatchObject({ deletedAt: null });
    expect(calls[1]!.args.take).toBe(101);
  });

  it('quarantine: scoped lookups and lists', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new QuarantineRepository(writer, reader);
    await repo.findByPublicId(SCOPE, PUBLIC_ID);
    await repo.list(SCOPE, { take: 10 });
    expectEveryQueryScoped(calls);
  });

  it('messages: registry and partitioned row both carry the organization', async () => {
    const receivedAt = new Date('2026-11-02T08:00:00Z');
    const { writer, reader, calls } = recordingClients({
      'messageIdentity.findFirst': { id: 77n, publicId: PUBLIC_ID, receivedAt },
      'emailMessage.findFirst': { id: 77n, receivedAt, organizationId: 42n },
    });
    const repo = new MessagesRepository(writer, reader);
    const found = await repo.findByPublicId(SCOPE, PUBLIC_ID);
    expect(found).toMatchObject({ id: 77n, publicId: PUBLIC_ID });
    expectEveryQueryScoped(calls);
    expect(calls[1]!.args.where).toEqual({ id: 77n, receivedAt, organizationId: 42n });
  });

  it('messages: an identity of another organization is never followed', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new MessagesRepository(writer, reader);
    expect(await repo.findByPublicId(SCOPE, PUBLIC_ID)).toBeNull();
    expect(calls.map((c) => c.model)).toEqual(['messageIdentity']);
  });

  it('messages: range list with keyset cursor, scoped identities, rows without identity dropped', async () => {
    const from = new Date('2026-11-01T00:00:00Z');
    const to = new Date('2026-11-02T00:00:00Z');
    const after = { receivedAt: new Date('2026-11-01T12:00:00Z'), id: 5n };
    const { writer, reader, calls } = recordingClients({
      'emailMessage.findMany': [
        { id: 4n, receivedAt: from, organizationId: 42n },
        { id: 3n, receivedAt: from, organizationId: 42n },
      ],
      'messageIdentity.findMany': [{ id: 4n, publicId: PUBLIC_ID }],
    });
    const repo = new MessagesRepository(writer, reader);
    const rows = await repo.listRecent(SCOPE, { from, to }, { take: 26, after });
    expect(rows.map((r) => r.id)).toEqual([4n]);
    expectEveryQueryScoped(calls);
    expect(calls.every((c) => c.client === 'reader')).toBe(true);
    expect(calls[0]!.args.where).toMatchObject({
      organizationId: 42n,
      receivedAt: { gte: from, lt: to },
      OR: [
        { receivedAt: { lt: after.receivedAt } },
        { receivedAt: after.receivedAt, id: { lt: 5n } },
      ],
    });
    expect(calls[0]!.args.orderBy).toEqual([{ receivedAt: 'desc' }, { id: 'desc' }]);
  });
});
