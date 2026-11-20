import type { PrismaReadService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentReadError } from '../../../http/listing/echo-check';
import type { MessageRef } from './message-data.repository';
import { MAX_HEADER_ROWS, MessageHeadersRepository } from './message-headers.repository';
import { MessageRevealRepository } from './message-reveal.repository';

const scope = systemScope(7n);
const at = new Date('2026-11-12T08:00:00.000Z');
const ref: MessageRef = { id: 5n, publicId: 'p-5', receivedAt: at, organizationId: 7n };

function client(models: Record<string, Record<string, unknown>>) {
  return { client: models } as unknown as PrismaReadService;
}

describe('MessageHeadersRepository (step 7.2 §2 E7)', () => {
  const header = (over = {}) => ({
    seq: 0,
    name: 'From',
    value: 'a@x.example',
    organizationId: 7n,
    messageId: 5n,
    receivedAt: at,
    ...over,
  });

  it('reads one partition by (message_id, received_at) in seq order, at most 500 rows', async () => {
    const findMany = vi.fn(() => Promise.resolve([header(), header({ seq: 1, name: 'To' })]));
    const repo = new MessageHeadersRepository(client({ emailHeader: { findMany } }));
    expect(await repo.headers(scope, ref)).toEqual([
      { seq: 0, name: 'From', value: 'a@x.example' },
      { seq: 1, name: 'To', value: 'a@x.example' },
    ]);
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { messageId: 5n, receivedAt: at, organizationId: 7n },
        orderBy: { seq: 'asc' },
        take: MAX_HEADER_ROWS,
      }),
    );
    expect(MAX_HEADER_ROWS).toBe(500);
    await repo.headers(scope, ref, ['To', 'Cc', 'Subject']);
    expect(findMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ name: { in: ['To', 'Cc', 'Subject'] } }),
      }),
    );
  });

  it.each([
    ['organization', { organizationId: 8n }],
    ['message', { messageId: 6n }],
    ['partition key', { receivedAt: new Date('2026-11-12T08:00:00.001Z') }],
  ])('refuses a row that does not echo the query (%s)', async (_what, over) => {
    const repo = new MessageHeadersRepository(
      client({ emailHeader: { findMany: () => Promise.resolve([header(over)]) } }),
    );
    await expect(repo.headers(scope, ref)).rejects.toBeInstanceOf(InconsistentReadError);
  });

  it('the parse status, echo-checked, or null', async () => {
    const parse = (over = {}) => ({
      status: 'parsed',
      organizationId: 7n,
      messageId: 5n,
      receivedAt: at,
      ...over,
    });
    const findFirst = vi.fn(() => Promise.resolve(parse() as unknown));
    const repo = new MessageHeadersRepository(client({ emailMessageParse: { findFirst } }));
    expect(await repo.parseStatus(scope, ref)).toBe('parsed');
    findFirst.mockResolvedValueOnce(null);
    expect(await repo.parseStatus(scope, ref)).toBeNull();
    findFirst.mockResolvedValueOnce(parse({ organizationId: 9n }));
    await expect(repo.parseStatus(scope, ref)).rejects.toBeInstanceOf(InconsistentReadError);
  });
});

describe('MessageRevealRepository (step 7.2 §2 E6)', () => {
  const identity = (publicId: string, over = {}) => ({
    id: 5n,
    publicId,
    receivedAt: at,
    organizationId: 7n,
    ...over,
  });

  const gatewayRows = () =>
    vi.fn(() => Promise.resolve([{ id: 5n, receivedAt: at, organizationId: 7n }]));

  it('finds the scope’s registry rows of the ids and refuses rows of other ids or tenants', async () => {
    const findMany = vi.fn(() => Promise.resolve([identity('p-5')]));
    const repo = new MessageRevealRepository(
      client({ messageIdentity: { findMany }, emailMessage: { findMany: gatewayRows() } }),
    );
    expect(await repo.refs(scope, ['p-5', 'p-6', 'p-5'])).toEqual([identity('p-5')]);
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { publicId: { in: ['p-5', 'p-6'] }, organizationId: 7n } }),
    );
    expect(await repo.refs(scope, [])).toEqual([]);
    findMany.mockResolvedValueOnce([identity('p-9')]);
    await expect(repo.refs(scope, ['p-5'])).rejects.toBeInstanceOf(InconsistentReadError);
    findMany.mockResolvedValueOnce([identity('p-5', { organizationId: 8n })]);
    await expect(repo.refs(scope, ['p-5'])).rejects.toBeInstanceOf(InconsistentReadError);
  });

  it('drops journal intake messages (step 8.6 D5: not gateway messages)', async () => {
    const identities = vi.fn(() => Promise.resolve([identity('p-5'), identity('p-6', { id: 6n })]));
    const gateway = gatewayRows();
    const repo = new MessageRevealRepository(
      client({ messageIdentity: { findMany: identities }, emailMessage: { findMany: gateway } }),
    );
    expect(await repo.refs(scope, ['p-5', 'p-6'])).toEqual([identity('p-5')]);
    expect(gateway).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ ingestSource: 'gateway', organizationId: 7n }),
      }),
    );
  });

  it('reads the subjects by (id, received_at) and checks the exact pairs', async () => {
    const row = (over = {}) => ({
      id: 5n,
      receivedAt: at,
      organizationId: 7n,
      subject: 'S',
      ...over,
    });
    const findMany = vi.fn(() => Promise.resolve([row()]));
    const repo = new MessageRevealRepository(client({ emailMessage: { findMany } }));
    expect(await repo.subjects(scope, [ref])).toEqual([{ ref, subject: 'S' }]);
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { OR: [{ id: 5n, receivedAt: at }], organizationId: 7n },
      }),
    );
    expect(await repo.subjects(scope, [])).toEqual([]);
    // Same id, another partition key: not the requested row.
    findMany.mockResolvedValueOnce([row({ receivedAt: new Date('2026-10-01T00:00:00Z') })]);
    await expect(repo.subjects(scope, [ref])).rejects.toBeInstanceOf(InconsistentReadError);
    findMany.mockResolvedValueOnce([row({ organizationId: 8n })]);
    await expect(repo.subjects(scope, [ref])).rejects.toBeInstanceOf(InconsistentReadError);
    findMany.mockResolvedValueOnce([row({ id: 6n })]);
    await expect(repo.subjects(scope, [ref])).rejects.toBeInstanceOf(InconsistentReadError);
  });
});
