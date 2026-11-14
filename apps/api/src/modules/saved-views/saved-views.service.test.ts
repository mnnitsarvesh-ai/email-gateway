import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { UserPrincipal } from '../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../database/transaction-runner';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import type { SavedViewRow, SavedViewsRepository } from './saved-views.repository';
import {
  CreateSavedViewBodySchema,
  definitionIssues,
  type SavedViewDefinition,
  SavedViewListQuerySchema,
  UpdateSavedViewBodySchema,
} from './saved-views.schemas';
import { SavedViewsService } from './saved-views.service';

const ORG = randomUUID();
const user = (overrides: Partial<UserPrincipal> = {}): UserPrincipal => ({
  kind: 'user',
  userId: 5n,
  userPublicId: randomUUID(),
  organizationId: 40n,
  organizationPublicId: ORG,
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: false,
  mfaEnrollmentRequired: false,
  permissions: new Set(['message:read']),
  ...overrides,
});
const client = { ip: '198.51.100.9', userAgent: null } as never;

const definition = (over: Partial<SavedViewDefinition> = {}): SavedViewDefinition => ({
  version: 1,
  filters: { verdict: 'phishing,malware', senderDomain: 'example.com' },
  sort: '-receivedAt',
  range: { kind: 'relative', preset: '7d' },
  columns: ['receivedAt', 'subject'],
  ...over,
});

const row = (id: bigint, over: Partial<SavedViewRow> = {}): SavedViewRow => ({
  id,
  publicId: `00000000-0000-7000-8000-${id.toString().padStart(12, '0')}`,
  organizationId: 40n,
  userId: 5n,
  kind: 'message_explorer',
  name: `View ${id}`,
  definition: definition(),
  rowVersion: 1,
  createdAt: new Date('2026-11-14T09:00:00.000Z'),
  updatedAt: new Date('2026-11-14T09:00:00.000Z'),
  ...over,
});

function setup(opts: { max?: number; count?: number } = {}) {
  const tx = { tag: 'tx' };
  const repo = {
    list: vi.fn((_s: unknown, _o: unknown, _k: unknown, page: { take: number }) =>
      Promise.resolve([row(9n), row(8n), row(7n)].slice(0, page.take)),
    ),
    find: vi.fn(() => Promise.resolve(row(9n) as SavedViewRow | null)),
    findWith: vi.fn(() => Promise.resolve(row(9n) as SavedViewRow | null)),
    lockOwner: vi.fn(() => Promise.resolve()),
    count: vi.fn(() => Promise.resolve(opts.count ?? 0)),
    create: vi.fn(() => Promise.resolve(row(10n))),
    update: vi.fn(() => Promise.resolve(true)),
    delete: vi.fn(() => Promise.resolve(true)),
  };
  const runner = {
    run: vi.fn((fn: (t: unknown) => Promise<unknown>) => fn(tx)),
  };
  const audit = {
    record: vi.fn((_entry: Record<string, unknown>, _tx?: unknown) => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: 'u' })),
  };
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const service = new SavedViewsService(
    { SAVED_VIEWS_MAX_PER_USER: opts.max ?? 50, API_MESSAGES_MAX_RANGE_DAYS: 31 },
    repo as unknown as SavedViewsRepository,
    runner as unknown as TransactionRunner,
    audit as unknown as AuditService,
    codec,
  );
  return { service, repo, runner, audit, tx };
}

const createBody = (over: Record<string, unknown> = {}) =>
  CreateSavedViewBodySchema.parse({
    kind: 'message_explorer',
    name: 'Phishing',
    definition: definition(),
    ...over,
  });

describe('saved view definition rules (step 7.2 §3.3)', () => {
  it('accepts a full definition and the absolute range within the bound', () => {
    expect(definitionIssues(definition(), 31)).toEqual([]);
    expect(
      definitionIssues(
        definition({
          filters: {
            subject: 'Re: Hello',
            subjectPrefix: 'Inv',
            'riskScore.gte': '500',
            recipient: 'a@b.example',
            deliveryStatus: 'bounced',
            quarantineStatus: 'held',
          },
          range: { kind: 'absolute', from: '2026-11-01T00:00:00Z', to: '2026-12-02T00:00:00Z' },
          sort: 'receivedAt',
          columns: null,
        }),
        31,
      ),
    ).toEqual([]);
  });

  it('reports filter problems under definition.filters with the real list query schema', () => {
    const paths = (filters: Record<string, string>) =>
      definitionIssues(definition({ filters }), 31).map((i) => i.path);
    expect(paths({ foo: 'x' })).toEqual(['definition.filters']);
    expect(definitionIssues(definition({ filters: { foo: 'x' } }), 31)[0]!.message).toContain(
      'foo',
    );
    // Comma lists report the item index (as GET /messages does).
    expect(paths({ verdict: 'nonsense' })).toEqual(['definition.filters.verdict.0']);
    expect(paths({ subjectPrefix: 'ab' })).toEqual(['definition.filters.subjectPrefix']);
    expect(paths({ senderDomain: 'not a domain' })).toEqual(['definition.filters.senderDomain']);
    expect(paths({ 'riskScore.gte': '2000' })).toEqual(['definition.filters.riskScore.gte']);
    expect(paths({ limit: '5', cursor: 'x' })).toEqual([
      'definition.filters.limit',
      'definition.filters.cursor',
    ]);
    expect(paths({ from: '2026-11-01T00:00:00Z' })).toEqual(['definition.filters.from']);
  });

  it('refuses an unordered or too long absolute range and more than 8 192 bytes', () => {
    expect(
      definitionIssues(
        definition({
          range: { kind: 'absolute', from: '2026-11-02T00:00:00Z', to: '2026-11-01T00:00:00Z' },
        }),
        31,
      ).map((i) => i.path),
    ).toEqual(['definition.range.from']);
    expect(
      definitionIssues(
        definition({
          range: { kind: 'absolute', from: '2026-10-01T00:00:00Z', to: '2026-11-02T00:00:01Z' },
        }),
        31,
      ).map((i) => i.path),
    ).toEqual(['definition.range.to']);
    // Valid values only (3-byte UTF-8 characters), together above 8 192 bytes of JSON.
    const big = definition({
      filters: {
        subject: '中'.repeat(998),
        internetMessageId: '中'.repeat(998),
        subjectPrefix: `${'\u3000'.repeat(990)}abc`,
      },
    });
    expect(Buffer.byteLength(JSON.stringify(big))).toBeGreaterThan(8192);
    expect(definitionIssues(big, 31)).toEqual([
      { path: 'definition', message: 'must be at most 8192 bytes as JSON' },
    ]);
  });

  it('the structural schema is strict and bounded', () => {
    const bad = (value: unknown) =>
      CreateSavedViewBodySchema.safeParse({
        kind: 'message_explorer',
        name: 'x',
        definition: value,
      }).success;
    expect(bad(definition())).toBe(true);
    expect(bad({ ...definition(), extra: 1 })).toBe(false);
    expect(bad({ ...definition(), version: 2 })).toBe(false);
    expect(bad({ ...definition(), sort: '-riskScore' })).toBe(false);
    expect(bad({ ...definition(), range: { kind: 'relative', preset: '90d' } })).toBe(false);
    expect(bad({ ...definition(), columns: ['a', 'a'] })).toBe(false);
    expect(bad({ ...definition(), columns: ['1bad'] })).toBe(false);
    expect(bad({ ...definition(), columns: Array.from({ length: 25 }, (_, i) => `c${i}`) })).toBe(
      false,
    );
    expect(
      bad({
        ...definition(),
        filters: Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`f${i}`, 'x'])),
      }),
    ).toBe(false);
    expect(bad({ ...definition(), filters: { sender: 'x'.repeat(999) } })).toBe(false);
    expect(bad({ ...definition(), filters: { sender: 7 } })).toBe(false);
    for (const name of ['', '   ', 'x'.repeat(81), 'tab\there']) {
      expect(
        CreateSavedViewBodySchema.safeParse({
          kind: 'message_explorer',
          name,
          definition: definition(),
        }).success,
        JSON.stringify(name),
      ).toBe(false);
    }
    expect(
      CreateSavedViewBodySchema.safeParse({ kind: 'other', name: 'x', definition: definition() })
        .success,
    ).toBe(false);
    expect(
      UpdateSavedViewBodySchema.safeParse({
        name: 'x',
        definition: definition(),
        expectedRowVersion: 0,
      }).success,
    ).toBe(false);
    expect(SavedViewListQuerySchema.safeParse({}).success).toBe(false);
    expect(SavedViewListQuerySchema.safeParse({ kind: 'message_explorer' }).success).toBe(true);
    expect(
      SavedViewListQuerySchema.safeParse({ kind: 'message_explorer', sort: 'id' }).success,
    ).toBe(false);
  });
});

describe('SavedViewsService (step 7.2 §2 E4)', () => {
  it('lists the caller’s views newest first with a v1 cursor bound to the caller', async () => {
    const t = setup();
    const p = user();
    const scope = scopeFromPrincipal(p);
    const first = await t.service.list(
      p,
      scope,
      SavedViewListQuerySchema.parse({ kind: 'message_explorer', limit: '2' }),
    );
    expect(first.data.map((v) => v.name)).toEqual(['View 9', 'View 8']);
    expect(t.repo.list.mock.calls[0]!.slice(1, 3)).toEqual([{ userId: 5n }, 'message_explorer']);
    await t.service.list(
      p,
      scope,
      SavedViewListQuerySchema.parse({
        kind: 'message_explorer',
        limit: '2',
        cursor: first.nextCursor!,
      }),
    );
    expect(t.repo.list.mock.calls[1]![3]).toEqual({ take: 3, beforeId: 8n });
    // Another user of another organization presenting the cursor.
    await expect(
      t.service.list(
        user({ organizationPublicId: randomUUID() }),
        scope,
        SavedViewListQuerySchema.parse({ kind: 'message_explorer', cursor: first.nextCursor! }),
      ),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('refuses a platform override session with 403 saved_views_member_only, before any read', async () => {
    const t = setup();
    const p = user({
      organizationKind: 'platform',
      override: {
        id: randomUUID(),
        reason: 'support',
        targetOrganizationId: 77n,
        targetOrganizationPublicId: randomUUID(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const scope = scopeFromPrincipal(p);
    expect(scope.via).toBe('platform_override');
    for (const call of [
      () => t.service.list(p, scope, SavedViewListQuerySchema.parse({ kind: 'message_explorer' })),
      () => t.service.get(p, scope, randomUUID()),
      () => t.service.create(p, scope, createBody(), client),
      () => t.service.remove(p, scope, randomUUID(), client),
    ]) {
      await expect(call()).rejects.toMatchObject({ code: 'saved_views_member_only', status: 403 });
    }
    expect(t.repo.list).not.toHaveBeenCalled();
    expect(t.runner.run).not.toHaveBeenCalled();
  });

  it('get: another user’s or organization’s view is 404 saved_view_not_found', async () => {
    const t = setup();
    t.repo.find.mockResolvedValueOnce(null);
    const p = user();
    await expect(t.service.get(p, scopeFromPrincipal(p), randomUUID())).rejects.toMatchObject({
      code: 'saved_view_not_found',
      status: 404,
    });
  });

  it('create: validates, applies filter permissions, locks the owner, enforces the limit, audits id and kind only', async () => {
    const t = setup({ max: 3, count: 2 });
    const p = user();
    const view = await t.service.create(p, scopeFromPrincipal(p), createBody(), client);
    expect(view).toMatchObject({ id: row(10n).publicId, kind: 'message_explorer', rowVersion: 1 });
    expect(t.repo.lockOwner).toHaveBeenCalledWith(t.tx, expect.anything(), { userId: 5n });
    expect(t.audit.record).toHaveBeenCalledWith(
      {
        organizationId: 40n,
        actor: { type: 'user', id: 'u' },
        action: 'saved_view.created',
        resourceType: 'saved_view',
        resourceId: row(10n).publicId,
        sourceIp: '198.51.100.9',
        metadata: { kind: 'message_explorer' },
      },
      t.tx,
    );

    const full = setup({ max: 3, count: 3 });
    await expect(
      full.service.create(p, scopeFromPrincipal(p), createBody(), client),
    ).rejects.toMatchObject({
      code: 'saved_view_limit_reached',
      status: 409,
      details: { limit: 3 },
    });
    expect(full.repo.create).not.toHaveBeenCalled();
  });

  it('create: 400 for a bad definition, 403 message_filter_forbidden for a gated filter, nothing written', async () => {
    const t = setup();
    const p = user();
    const scope = scopeFromPrincipal(p);
    await expect(
      t.service.create(
        p,
        scope,
        createBody({ definition: definition({ filters: { verdict: 'nope' } }) }),
        client,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      t.service.create(
        p,
        scope,
        createBody({ definition: definition({ filters: { subject: 'Hello' } }) }),
        client,
      ),
    ).rejects.toMatchObject({
      code: 'message_filter_forbidden',
      details: { filter: 'subject', permission: 'message:reveal' },
    });
    await expect(
      t.service.create(
        p,
        scope,
        createBody({ definition: definition({ filters: { quarantineStatus: 'held' } }) }),
        client,
      ),
    ).rejects.toMatchObject({
      code: 'message_filter_forbidden',
      details: { permission: 'quarantine:read' },
    });
    await expect(
      t.service.create(
        p,
        scope,
        createBody({ definition: definition({ filters: { recipient: 'a@b.example' } }) }),
        client,
      ),
    ).rejects.toMatchObject({
      code: 'message_filter_forbidden',
      details: { filter: 'recipient', permission: 'message:reveal' },
    });
    expect(t.runner.run).not.toHaveBeenCalled();
    const revealer = user({ permissions: new Set(['message:read', 'message:reveal']) });
    await t.service.create(
      revealer,
      scope,
      createBody({ definition: definition({ filters: { subject: 'Hello' } }) }),
      client,
    );
    expect(t.repo.create).toHaveBeenCalledTimes(1);
  });

  it('create/update: a duplicate name is 409 saved_view_name_taken', async () => {
    const t = setup();
    const unique = new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
      code: 'P2002',
      clientVersion: 'test',
      meta: { target: 'saved_views_organization_id_user_id_kind_name_key' },
    });
    t.repo.create.mockRejectedValueOnce(unique);
    const p = user();
    await expect(
      t.service.create(p, scopeFromPrincipal(p), createBody(), client),
    ).rejects.toMatchObject({ code: 'saved_view_name_taken', status: 409 });
    t.repo.update.mockRejectedValueOnce(unique);
    await expect(
      t.service.update(
        p,
        scopeFromPrincipal(p),
        row(9n).publicId,
        UpdateSavedViewBodySchema.parse({
          name: 'x',
          definition: definition(),
          expectedRowVersion: 1,
        }),
        client,
      ),
    ).rejects.toMatchObject({ code: 'saved_view_name_taken' });
  });

  it('update: compares rowVersion (409 saved_view_conflict), 404 when missing, reloads and audits', async () => {
    const t = setup();
    const p = user();
    const scope = scopeFromPrincipal(p);
    const body = (expectedRowVersion: number) =>
      UpdateSavedViewBodySchema.parse({
        name: 'Renamed',
        definition: definition(),
        expectedRowVersion,
      });
    t.repo.findWith.mockResolvedValueOnce(row(9n, { rowVersion: 3 }));
    await expect(
      t.service.update(p, scope, row(9n).publicId, body(2), client),
    ).rejects.toMatchObject({
      code: 'saved_view_conflict',
      details: { currentRowVersion: 3 },
    });
    t.repo.findWith.mockResolvedValueOnce(null);
    await expect(
      t.service.update(p, scope, row(9n).publicId, body(1), client),
    ).rejects.toMatchObject({
      code: 'saved_view_not_found',
    });
    t.repo.findWith
      .mockResolvedValueOnce(row(9n))
      .mockResolvedValueOnce(row(9n, { name: 'Renamed', rowVersion: 2 }));
    const updated = await t.service.update(p, scope, row(9n).publicId, body(1), client);
    expect(updated).toMatchObject({ name: 'Renamed', rowVersion: 2 });
    expect(t.repo.update.mock.calls[0]!.slice(3, 6)).toEqual([
      row(9n).publicId,
      1,
      { name: 'Renamed', definition: definition() },
    ]);
    expect(t.audit.record.mock.calls[0]![0]).toMatchObject({
      action: 'saved_view.updated',
      metadata: { kind: 'message_explorer' },
    });
    expect(
      JSON.stringify(t.audit.record.mock.calls[0]![0], (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      ),
    ).not.toMatch(/Renamed|example\.com/);
  });

  it('remove: 404 when missing (or another user’s), audited when deleted', async () => {
    const t = setup();
    const p = user();
    const scope = scopeFromPrincipal(p);
    t.repo.findWith.mockResolvedValueOnce(null);
    await expect(t.service.remove(p, scope, randomUUID(), client)).rejects.toMatchObject({
      code: 'saved_view_not_found',
    });
    await t.service.remove(p, scope, row(9n).publicId, client);
    expect(t.audit.record.mock.calls[0]![0]).toMatchObject({
      action: 'saved_view.deleted',
      resourceId: row(9n).publicId,
    });
  });

  it('never serves a structurally corrupted stored definition (503 inconsistent_read)', async () => {
    const t = setup();
    t.repo.find.mockResolvedValueOnce(row(9n, { definition: { version: 9 } }));
    const p = user();
    await expect(t.service.get(p, scopeFromPrincipal(p), randomUUID())).rejects.toMatchObject({
      code: 'inconsistent_read',
    });
  });
});
