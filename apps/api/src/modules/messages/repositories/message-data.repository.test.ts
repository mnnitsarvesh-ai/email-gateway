import type { PrismaReadService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentReadError } from '../../../http/listing/echo-check';
import type { MessagesRepository } from '../../tenant-data/messages.repository';
import { MessageDataRepository } from './message-data.repository';

const range = { from: new Date('2026-11-11T00:00:00Z'), to: new Date('2026-11-12T00:00:00Z') };
const base = { organizationId: 7n, range, direction: 'desc' as const, take: 26 };
const scope = systemScope(7n);

/** A repository whose replica answers every statement with `rows(nonce)`. */
function repo(rows: (nonce: string) => unknown[] | Promise<unknown[]>) {
  const $queryRaw = vi.fn((sql: { values: unknown[] }) => {
    // The nonce is the first bound value of every driver statement.
    const nonce = String(sql.values[0]);
    return Promise.resolve(rows(nonce));
  });
  return new MessageDataRepository(
    { client: { $queryRaw } } as unknown as PrismaReadService,
    {} as MessagesRepository,
  );
}

const raw = (nonce: string, org = 7n, at = new Date('2026-11-11T10:00:00Z'), over = {}) => ({
  echo_nonce: nonce,
  id: 1n,
  received_at: at,
  organization_id: org,
  domain_id: null,
  direction: 'inbound',
  status: 'delivered',
  status_changed_at: at,
  subject: null,
  envelope_from: 'a@b',
  header_from: null,
  recipient_count: 1,
  attachment_count: 0,
  size_bytes: 1,
  final_verdict: 'spam',
  final_action: null,
  risk_score: null,
  ...over,
});

describe('MessageDataRepository echo checks (6.1 D15, step 7.2 §3.2)', () => {
  it('serves driver rows that echo the nonce, the organization, the verdict and the range', async () => {
    const rows = await repo((n) => [raw(n)]).messagesPage(scope, {
      ...base,
      driver: 'verdict',
      key: 'spam',
    });
    expect(rows[0]).toMatchObject({ id: 1n, organizationId: 7n, finalVerdict: 'spam' });
    // Case-insensitive keys are not re-compared in TypeScript: the nonce binds the rows.
    const sender = await repo((n) => [
      raw(n, 7n, undefined, { envelope_from: 'A@B' }),
    ]).messagesPage(scope, { ...base, driver: 'sender', key: 'a@b' });
    expect(sender).toHaveLength(1);
  });

  it('refuses another statement’s rows (nonce), another organization, verdict or range (503)', async () => {
    const page = (rows: (n: string) => unknown[], driver: 'verdict' | 'scan' = 'verdict') =>
      repo(rows).messagesPage(scope, {
        ...base,
        driver,
        ...(driver === 'verdict' && { key: 'spam' }),
      });
    await expect(page(() => [raw('other-statement')])).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
    await expect(page(() => [{ ...raw('x'), echo_nonce: undefined }])).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
    await expect(page((n) => [raw(n, 8n)])).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(
      page((n) => [raw(n, 7n, undefined, { final_verdict: 'clean' })]),
    ).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(
      page((n) => [raw(n, 7n, new Date('2026-11-12T00:00:00Z'))], 'scan'),
    ).rejects.toBeInstanceOf(InconsistentReadError);
  });

  it('checks boundary keys like rows', async () => {
    const key = (n: string, org = 7n, at = new Date('2026-11-11T05:00:00Z')) => ({
      echo_nonce: n,
      organization_id: org,
      received_at: at,
      id: 9n,
    });
    const input = { ...base, driver: 'scan' as const, budget: 10 };
    expect(await repo((n) => [key(n)]).messagesBoundary(scope, input)).toEqual({
      at: new Date('2026-11-11T05:00:00Z'),
      id: 9n,
    });
    expect(await repo(() => []).messagesBoundary(scope, input)).toBeNull();
    await expect(repo((n) => [key(n, 8n)]).messagesBoundary(scope, input)).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
    await expect(repo(() => [key('x')]).messagesBoundary(scope, input)).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
    await expect(
      repo((n) => [key(n, 7n, new Date('2026-10-01T00:00:00Z'))]).foreignBoundary(scope, {
        ...base,
        driver: 'deliveryStatus',
        key: 'bounced',
        budget: 10,
      }),
    ).rejects.toBeInstanceOf(InconsistentReadError);
  });

  it('foreign keys echo exact states; a recipient domain is bound by the nonce only', async () => {
    const key = (n: string, driverKey: string) => ({
      echo_nonce: n,
      organization_id: 7n,
      driver_key: driverKey,
      received_at: new Date('2026-11-11T05:00:00Z'),
      id: 9n,
    });
    expect(
      await repo((n) => [key(n, 'held')]).foreignKeys(scope, {
        ...base,
        driver: 'quarantineStatus',
        key: 'held',
      }),
    ).toEqual([{ receivedAt: new Date('2026-11-11T05:00:00Z'), id: 9n }]);
    await expect(
      repo((n) => [key(n, 'released')]).foreignKeys(scope, {
        ...base,
        driver: 'quarantineStatus',
        key: 'held',
      }),
    ).rejects.toBeInstanceOf(InconsistentReadError);
    expect(
      await repo((n) => [key(n, 'Partner.Example')]).foreignKeys(scope, {
        ...base,
        driver: 'recipientDomain',
        key: 'partner.example',
      }),
    ).toHaveLength(1);
  });

  it('messages by key: only the requested (id, received_at) pairs', async () => {
    const at = new Date('2026-11-11T10:00:00Z');
    const byKeys = (rows: unknown[]) =>
      new MessageDataRepository(
        {
          client: { $queryRaw: vi.fn(() => Promise.resolve(rows)) },
        } as unknown as PrismaReadService,
        {} as MessagesRepository,
      ).messagesByKeys(scope, range, [{ id: 1n, receivedAt: at }]);
    expect(await byKeys([raw('', 7n, at)])).toHaveLength(1);
    await expect(byKeys([{ ...raw('', 7n, at), id: 2n }])).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
    await expect(byKeys([raw('', 7n, new Date('2026-11-11T11:00:00Z'))])).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
  });

  it('recipient page rows carry their recipient row id', async () => {
    const rows = await repo((n) => [{ ...raw(n), rid: 77n }]).recipientPage(scope, {
      ...base,
      address: 'a@b',
      boundary: null,
      residuals: {},
    });
    expect(rows[0]).toMatchObject({ id: 1n, rid: 77n });
  });

  it('prefix probe: a (cap + 1)-th entry means too broad; a timeout is 503 message_search_timeout', async () => {
    const probe = (rows: (n: string) => unknown[] | Promise<unknown[]>) =>
      repo(rows).prefixProbe(scope, { ...base, pattern: 'abc%', cap: 10, timeoutMs: 1000 });
    const entry = (n: string, org = 7n) => ({
      echo_nonce: n,
      organization_id: org,
      received_at: new Date('2026-11-11T05:00:00Z'),
      id: 3n,
    });
    expect(await probe((n) => [entry(n)])).toBe(true);
    expect(await probe(() => [])).toBe(false);
    await expect(probe((n) => [entry(n), entry(n)])).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(probe(() => [entry('x')])).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(probe((n) => [entry(n, 8n)])).rejects.toBeInstanceOf(InconsistentReadError);
    const timeout = Object.assign(new Error('Raw query failed'), {
      code: 'P2010',
      meta: { code: '3024', message: 'maximum statement execution time exceeded' },
    });
    await expect(probe(() => Promise.reject(timeout))).rejects.toMatchObject({
      code: 'message_search_timeout',
      status: 503,
    });
    const other = new Error('connection lost');
    await expect(
      repo(() => Promise.reject(other)).prefixPage(scope, {
        ...base,
        pattern: 'abc%',
        timeoutMs: 1000,
        residuals: {},
      }),
    ).rejects.toBe(other);
  });
});
