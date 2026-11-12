import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import { systemScope } from '../../auth-contracts/tenant-scope';
import type { ApiConventionMetrics } from '../../http/api-metrics';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import { IdempotencyService } from '../../http/idempotency/idempotency.service';
import type { IdempotencyRepository } from '../../http/idempotency/idempotency.repository';
import type { TransactionRunner } from '../../database/transaction-runner';
import type { OrganizationLimitsService } from '../../tenancy/organization-limits.service';
import type {
  RecipientSuppressionsRepository,
  SuppressionRow,
} from './recipient-suppressions.repository';
import { SuppressionListQuerySchema } from './recipient-suppressions.schemas';
import {
  OPERATIONS,
  parseCreateBody,
  parseSuppressionId,
  RecipientSuppressionsService,
  SUPPRESSION_TX_TIMEOUT_MS,
  toSuppressionView,
} from './recipient-suppressions.service';

const NOW = new Date('2026-11-12T12:00:00.000Z');
const scope = systemScope(7n);
const user: Principal = {
  kind: 'user',
  userId: 10n,
  userPublicId: randomUUID(),
  organizationId: 7n,
  organizationPublicId: randomUUID(),
  organizationKind: 'customer',
  sessionId: randomUUID(),
  mfaAuthenticated: false,
  mfaEnrollmentRequired: false,
  permissions: new Set(['delivery:suppression_manage']),
};

const row = (id: number, over: Partial<SuppressionRow> = {}): SuppressionRow => ({
  id: BigInt(id),
  organizationId: 7n,
  address: 'x@y.example',
  reason: 'manual',
  source: 'api',
  expiresAt: null,
  createdAt: NOW,
  createdBy: { publicId: user.kind === 'user' ? user.userPublicId : '' },
  ...over,
});

function setup(max = 3) {
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const stored = new Map<string, Record<string, unknown>>();
  const records = {
    lock: vi.fn((_tx: unknown, _org: bigint, key: string) =>
      Promise.resolve(stored.get(key) ?? null),
    ),
    delete: vi.fn(() => Promise.resolve()),
    insert: vi.fn((_tx: unknown, r: Record<string, unknown>) => {
      stored.set(r.idempotencyKey as string, { ...r, id: 1n, state: 'completed' });
      return Promise.resolve();
    }),
  };
  const runner = {
    run: vi.fn((fn: (tx: unknown) => Promise<unknown>, _options?: unknown) => fn({ tx: true })),
  };
  const idempotency = new IdempotencyService(
    runner as unknown as TransactionRunner,
    records as unknown as IdempotencyRepository,
  );
  const repo = {
    list: vi.fn<RecipientSuppressionsRepository['list']>(() => Promise.resolve([])),
    boundary: vi.fn<RecipientSuppressionsRepository['boundary']>(() => Promise.resolve(null)),
    find: vi.fn<RecipientSuppressionsRepository['find']>(),
    findByAddress: vi.fn<RecipientSuppressionsRepository['findByAddress']>(() =>
      Promise.resolve(null),
    ),
    countCreatable: vi.fn<RecipientSuppressionsRepository['countCreatable']>(() =>
      Promise.resolve(0),
    ),
    create: vi.fn<RecipientSuppressionsRepository['create']>((_tx, _s, data) =>
      Promise.resolve(row(42, { ...data })),
    ),
    lock: vi.fn<RecipientSuppressionsRepository['lock']>(),
    delete: vi.fn<RecipientSuppressionsRepository['delete']>(() => Promise.resolve(1)),
  };
  const limits = { lockOrganization: vi.fn(() => Promise.resolve()) };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: 'u' })),
  };
  const metrics = { scanBudgetExhausted: { inc: vi.fn() } };
  const service = new RecipientSuppressionsService(
    { RECIPIENT_SUPPRESSIONS_MAX_MANUAL: max, API_LIST_SCAN_BUDGET_ROWS: 1000 },
    repo as unknown as RecipientSuppressionsRepository,
    idempotency,
    limits as unknown as OrganizationLimitsService,
    audit as unknown as AuditService,
    codec,
    metrics as unknown as ApiConventionMetrics,
  );
  service.now = () => NOW;
  idempotency.now = () => NOW;
  return { service, repo, limits, audit, runner, records, metrics };
}

describe('recipient suppressions (step 6.1 WP2)', () => {
  it('parses ids and bodies strictly', () => {
    expect(parseSuppressionId('42')).toBe(42n);
    for (const bad of ['0', '-1', '01', 'x', '1.5', '184467440737095516160']) {
      expect(() => parseSuppressionId(bad)).toThrow(BadRequestException);
    }
    expect(parseCreateBody({ address: '  Bob@Example.COM ' }, NOW)).toEqual({
      address: 'bob@example.com',
      reason: 'manual',
    });
    const bad = [
      {},
      { address: 'no-at-sign' },
      { address: 'a@b.c', reason: 'hard_bounce' },
      { address: 'a@b.c', extra: true },
      { address: `${'a'.repeat(320)}@b.c` },
      { address: 'a@b.c', expiresAt: '2026-11-12T11:00:00Z' },
      { address: 'a@b.c', expiresAt: '2036-12-01T00:00:00Z' },
      { address: 'a@b.c', expiresAt: 'tomorrow' },
    ];
    for (const body of bad)
      expect(() => parseCreateBody(body, NOW), JSON.stringify(body)).toThrow(BadRequestException);
    expect(
      parseCreateBody(
        { address: 'a@b.c', reason: 'unsubscribe', expiresAt: '2027-01-01T00:00:00Z' },
        NOW,
      ),
    ).toMatchObject({
      reason: 'unsubscribe',
    });
  });

  it('active is null-or-future expiry', () => {
    expect(toSuppressionView(row(1), NOW).active).toBe(true);
    expect(toSuppressionView(row(1, { expiresAt: new Date(NOW.getTime() + 1) }), NOW).active).toBe(
      true,
    );
    expect(toSuppressionView(row(1, { expiresAt: NOW }), NOW).active).toBe(false);
    expect(toSuppressionView(row(1, { createdBy: null }), NOW).createdBy).toBeNull();
  });

  it('create: locks the organization, inserts, audits with the address hash, stores 201', async () => {
    const t = setup();
    const result = await t.service.create(
      user,
      scope,
      { idempotencyKey: 'k-1', body: { address: 'Bob@Example.com' } },
      '10.0.0.1',
    );
    expect(result).toMatchObject({
      replayed: false,
      statusCode: 201,
      body: { id: '42', address: 'bob@example.com', source: 'api', active: true },
    });
    expect(t.runner.run.mock.calls[0]![1]).toEqual({ timeoutMs: SUPPRESSION_TX_TIMEOUT_MS });
    expect(t.limits.lockOrganization).toHaveBeenCalledWith({ tx: true }, 7n);
    expect(t.repo.create.mock.calls[0]![2]).toMatchObject({
      reason: 'manual',
      source: 'api',
      createdByUserId: 10n,
      expiresAt: null,
    });
    const entry = (t.audit.record.mock.calls[0] as unknown[])[0] as {
      metadata: Record<string, unknown>;
    };
    expect(entry).toMatchObject({
      action: 'recipient_suppression.created',
      resourceId: '42',
      sourceIp: '10.0.0.1',
    });
    expect(JSON.stringify(entry.metadata)).not.toContain('bob@example.com');
    expect(entry.metadata.addressSha256).toMatch(/^[0-9a-f]{64}$/);
    expect((t.audit.record.mock.calls[0] as unknown[])[1]).toEqual({ tx: true });
    expect(t.records.insert.mock.calls[0]![1]).toMatchObject({
      operation: OPERATIONS.create,
      resourceId: '-',
      statusCode: 201,
    });

    // Replay: the stored response, nothing done again.
    const replay = await t.service.create(
      user,
      scope,
      { idempotencyKey: 'k-1', body: { address: 'bob@example.com', reason: 'manual' } },
      null,
    );
    expect(replay).toMatchObject({ replayed: true, statusCode: 201, body: { id: '42' } });
    expect(t.repo.create).toHaveBeenCalledTimes(1);
    // Reuse with another body.
    await expect(
      t.service.create(
        user,
        scope,
        { idempotencyKey: 'k-1', body: { address: 'other@example.com' } },
        null,
      ),
    ).rejects.toMatchObject({ code: 'idempotency_key_reused' });
  });

  it('create: an API key has no creator; missing key, existing address, limit', async () => {
    const t = setup(2);
    const apiKey: Principal = {
      kind: 'api_key',
      apiKeyId: 3n,
      apiKeyPublicId: randomUUID(),
      organizationId: 7n,
      organizationPublicId: randomUUID(),
      permissions: new Set(),
    };
    await t.service.create(
      apiKey,
      scope,
      { idempotencyKey: 'a', body: { address: 'a@b.c' } },
      null,
    );
    expect(t.repo.create.mock.calls[0]![2].createdByUserId).toBeNull();
    await expect(
      t.service.create(
        user,
        scope,
        { idempotencyKey: undefined, body: { address: 'a@b.c' } },
        null,
      ),
    ).rejects.toMatchObject({
      code: 'idempotency_key_required',
    });
    t.repo.findByAddress.mockResolvedValueOnce({ id: 9n });
    await expect(
      t.service.create(user, scope, { idempotencyKey: 'b', body: { address: 'a@b.c' } }, null),
    ).rejects.toMatchObject({
      code: 'suppression_exists',
      details: { id: '9' },
    });
    t.repo.countCreatable.mockResolvedValueOnce(2);
    await expect(
      t.service.create(user, scope, { idempotencyKey: 'c', body: { address: 'z@b.c' } }, null),
    ).rejects.toMatchObject({
      code: 'suppression_limit_reached',
      details: { limit: 2 },
    });
    // Errors are never stored under their keys.
    expect(t.records.insert).toHaveBeenCalledTimes(1);
  });

  it('delete: locks the row, deletes, audits the former reason and source; 404 otherwise', async () => {
    const t = setup();
    t.repo.lock.mockResolvedValueOnce(row(5, { reason: 'hard_bounce', source: 'bounce' }));
    const result = await t.service.delete(
      user,
      scope,
      { suppressionId: '5', idempotencyKey: 'd-1' },
      null,
    );
    expect(result).toMatchObject({ statusCode: 204, replayed: false });
    expect(t.repo.delete).toHaveBeenCalledWith({ tx: true }, scope, 5n);
    expect((t.audit.record.mock.calls[0] as unknown[])[0]).toMatchObject({
      action: 'recipient_suppression.deleted',
      resourceId: '5',
      metadata: { formerReason: 'hard_bounce', formerSource: 'bounce' },
    });
    const replay = await t.service.delete(
      user,
      scope,
      { suppressionId: '5', idempotencyKey: 'd-1' },
      null,
    );
    expect(replay).toMatchObject({ replayed: true, statusCode: 204 });
    await expect(
      t.service.delete(user, scope, { suppressionId: '6', idempotencyKey: 'd-1' }, null),
    ).rejects.toMatchObject({ code: 'idempotency_key_reused' });
    t.repo.lock.mockResolvedValueOnce(null);
    await expect(
      t.service.delete(user, scope, { suppressionId: '7', idempotencyKey: 'd-2' }, null),
    ).rejects.toMatchObject({ code: 'suppression_not_found' });
    await expect(
      t.service.delete(user, scope, { suppressionId: 'abc', idempotencyKey: 'd-3' }, null),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('list: plain keyset, address via the unique key, reason/active scan-bounded', async () => {
    const t = setup();
    t.repo.list.mockResolvedValueOnce([row(9), row(8)]);
    const page = await t.service.list(
      user,
      scope,
      SuppressionListQuerySchema.parse({ limit: '1' }),
    );
    expect(page.data.map((d) => d.id)).toEqual(['9']);
    expect(t.repo.boundary).not.toHaveBeenCalled();
    t.repo.list.mockResolvedValueOnce([]);
    await t.service.list(
      user,
      scope,
      SuppressionListQuerySchema.parse({ limit: '1', cursor: page.nextCursor! }),
    );
    expect(t.repo.list.mock.calls[1]![1]).toMatchObject({ beforeId: 9n });

    await t.service.list(
      user,
      scope,
      SuppressionListQuerySchema.parse({ address: 'X@Y.example', active: 'true' }),
    );
    expect(t.repo.boundary).not.toHaveBeenCalled();
    expect(t.repo.list.mock.calls[2]![2]).toMatchObject({ address: 'x@y.example', active: true });

    t.repo.boundary.mockResolvedValueOnce(3n);
    t.repo.list.mockResolvedValueOnce([]);
    const scanned = await t.service.list(
      user,
      scope,
      SuppressionListQuerySchema.parse({ reason: 'manual' }),
    );
    expect(t.repo.list.mock.calls[3]![1]).toMatchObject({ boundaryId: 3n });
    expect(scanned.nextCursor).toEqual(expect.any(String));
    expect(t.metrics.scanBudgetExhausted.inc).toHaveBeenCalledWith({
      resource: 'recipient_suppressions',
    });
  });

  it('get: decimal id, 404 suppression_not_found', async () => {
    const t = setup();
    t.repo.find.mockResolvedValueOnce(null);
    await expect(t.service.get(scope, '5')).rejects.toMatchObject({
      code: 'suppression_not_found',
    });
    t.repo.find.mockResolvedValueOnce(row(5));
    await expect(t.service.get(scope, '5')).resolves.toMatchObject({ id: '5' });
    await expect(t.service.get(scope, 'x')).rejects.toBeInstanceOf(BadRequestException);
  });
});
