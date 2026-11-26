import { randomBytes } from 'node:crypto';
import type { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal, systemScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { SearchQuerySchema } from '../dto/insights.schemas';
import { SearchTimeoutError } from '../insights.errors';
import type { InsightsMetrics } from '../insights-metrics';
import {
  type SearchInput,
  type SearchOwner,
  SearchRepository,
  type SearchRow,
} from '../repositories/search.repository';
import { AssistantSearchService } from './search.service';

const ORG = 7001n;
const user: UserPrincipal = {
  kind: 'user',
  userId: 501n,
  userPublicId: '0193b000-0000-7000-8000-000000000501',
  organizationId: ORG,
  organizationPublicId: '0193b000-0000-7000-8000-000000007001',
  organizationKind: 'customer',
  sessionId: '0193b000-0000-7000-8000-0000000000aa',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['assistant:use']),
};
const config = { ASSISTANT_SEARCH_SCAN_MAX_MESSAGES: 20_000, ASSISTANT_SEARCH_TIMEOUT_MS: 3000 };
const codec = () =>
  new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
const q = (raw: Record<string, string>) => SearchQuerySchema.parse(raw);

function row(id: number, content: string, userId = user.userId): SearchRow {
  return {
    id: BigInt(id),
    publicId: `m-${id}`,
    organizationId: ORG,
    conversationId: 10n,
    conversationPublicId: 'c-10',
    conversationTitle: 'Quarantine review',
    userId,
    role: id % 2 ? 'user' : 'assistant',
    seq: id,
    createdAt: new Date(Date.UTC(2026, 10, 20, 9, 0, id)),
    content,
  };
}

function harness(rows: SearchRow[]) {
  const calls: Array<{ owner: SearchOwner; input: SearchInput }> = [];
  const repo = {
    search: vi.fn((owner: SearchOwner, input: SearchInput) => {
      calls.push({ owner, input });
      const after = input.beforeId;
      return Promise.resolve(
        rows
          .filter((r) => after === undefined || r.id < after)
          .sort((a, b) => Number(b.id - a.id))
          .slice(0, input.take),
      );
    }),
  };
  const metrics = { searchSeconds: { observe: vi.fn() } };
  const service = new AssistantSearchService(
    config,
    repo as unknown as SearchRepository,
    codec(),
    metrics as unknown as InsightsMetrics,
  );
  return { service, repo, calls, metrics };
}

describe('SearchQuerySchema (D4 bounds)', () => {
  it('trims q, requires 2-200 characters and bounds limit to 1-50 (default 20)', () => {
    expect(q({ q: '  ab  ' })).toMatchObject({ q: 'ab', limit: 20 });
    expect(SearchQuerySchema.safeParse({ q: ' a ' }).success).toBe(false);
    expect(SearchQuerySchema.safeParse({ q: 'x'.repeat(201) }).success).toBe(false);
    expect(SearchQuerySchema.safeParse({ q: `${'x'.repeat(200)}   ` }).success).toBe(true);
    expect(SearchQuerySchema.safeParse({ q: 'ab', limit: '51' }).success).toBe(false);
    expect(SearchQuerySchema.safeParse({ q: 'ab', limit: '0' }).success).toBe(false);
    expect(SearchQuerySchema.safeParse({ q: 'a\u0000b' }).success).toBe(false);
    expect(SearchQuerySchema.safeParse({ q: 'ab', organizationId: '1' }).success).toBe(false);
  });
});

describe('AssistantSearchService (D4)', () => {
  it('searches the caller’s own scope with the escaped pattern and the configured bounds', async () => {
    const h = harness([row(1, 'release 50% of it')]);
    const page = await h.service.search(user, scopeFromPrincipal(user), q({ q: '50%' }));
    expect(page.data).toHaveLength(1);
    expect(h.calls[0]).toMatchObject({
      owner: { userId: user.userId },
      input: { pattern: '%50!%%', scanMax: 20_000, timeoutMs: 3000, take: 21 },
    });
    expect(h.calls[0]!.owner.scope.organizationId).toBe(ORG);
    expect(h.metrics.searchSeconds.observe).toHaveBeenCalledWith(
      { outcome: 'ok' },
      expect.any(Number),
    );
  });

  it('uses the override target organization under a platform override', async () => {
    const h = harness([]);
    const operator: UserPrincipal = {
      ...user,
      organizationKind: 'platform',
      override: {
        id: '0193b000-0000-7000-8000-00000000ab01',
        targetOrganizationId: 8002n,
        targetOrganizationPublicId: '0193b000-0000-7000-8000-000000008002',
        reason: 'support',
        expiresAt: new Date('2026-11-26T12:00:00.000Z'),
      },
    };
    await h.service.search(operator, scopeFromPrincipal(operator), q({ q: 'abc' }));
    expect(h.calls[0]!.owner.scope.organizationId).toBe(8002n);
    expect(h.calls[0]!.owner.userId).toBe(user.userId);
  });

  it('pages newest first with a v1 cursor bound to the query', async () => {
    const rows = [1, 2, 3, 4, 5].map((i) => row(i, `needle ${i}`));
    const h = harness(rows);
    const scope = scopeFromPrincipal(user);
    const first = await h.service.search(user, scope, q({ q: 'needle', limit: '2' }));
    expect(first.data.map((d) => d.messageId)).toEqual(['m-5', 'm-4']);
    expect(first.nextCursor).not.toBeNull();
    const second = await h.service.search(
      user,
      scope,
      q({ q: 'needle', limit: '2', cursor: first.nextCursor! }),
    );
    expect(second.data.map((d) => d.messageId)).toEqual(['m-3', 'm-2']);
    expect(h.calls[1]!.input.beforeId).toBe(4n);
    const last = await h.service.search(
      user,
      scope,
      q({ q: 'needle', limit: '2', cursor: second.nextCursor! }),
    );
    expect(last.data.map((d) => d.messageId)).toEqual(['m-1']);
    expect(last.nextCursor).toBeNull();
    // A cursor of another query is refused.
    await expect(
      h.service.search(user, scope, q({ q: 'other', cursor: first.nextCursor! })),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('returns the documented item with a cut, sanitized snippet', async () => {
    const h = harness([row(2, `${'x'.repeat(300)} the\u202E needle ${'y'.repeat(300)}`)]);
    const page = await h.service.search(user, scopeFromPrincipal(user), q({ q: 'NEEDLE' }));
    const item = page.data[0]!;
    expect(Object.keys(item).sort()).toEqual(
      [
        'conversationId',
        'conversationTitle',
        'createdAt',
        'messageId',
        'role',
        'seq',
        'snippet',
      ].sort(),
    );
    expect(item.snippet).toContain('the needle');
    expect(Array.from(item.snippet).length).toBeLessThanOrEqual(160);
  });

  it('answers 503 assistant_search_timeout when MySQL stops the statement', async () => {
    const h = harness([]);
    h.repo.search.mockRejectedValueOnce(new SearchTimeoutError());
    await expect(
      h.service.search(user, scopeFromPrincipal(user), q({ q: 'abc' })),
    ).rejects.toMatchObject({ code: 'assistant_search_timeout' });
    expect(h.metrics.searchSeconds.observe).toHaveBeenCalledWith(
      { outcome: 'timeout' },
      expect.any(Number),
    );
  });
});

describe('SearchRepository (owner-bounded scan on the replica)', () => {
  function repository(result: unknown) {
    const queries: Prisma.Sql[] = [];
    const reader = {
      client: {
        $queryRaw: vi.fn((sql: Prisma.Sql) => {
          queries.push(sql);
          return result instanceof Error ? Promise.reject(result) : Promise.resolve(result);
        }),
      },
    };
    return { repo: new SearchRepository(reader as unknown as PrismaReadService), queries };
  }
  const owner: SearchOwner = { scope: systemScope(ORG), userId: 501n };
  const input: SearchInput = { pattern: '%a!_b%', scanMax: 1000, timeoutMs: 750, take: 21 };

  it('binds organization, user, scan bound, pattern and keyset; the hint is an integer', async () => {
    const { repo, queries } = repository([]);
    await repo.search(owner, { ...input, beforeId: 99n });
    const sql = queries[0]!;
    expect(sql.sql).toContain('/*+ MAX_EXECUTION_TIME(750) */');
    expect(sql.sql).toMatch(/rc\.organization_id = \? AND rc\.user_id = \?/);
    expect(sql.sql).toContain("rc.status IN ('active', 'archived')");
    expect(sql.sql).toContain('rm.content IS NOT NULL');
    expect(sql.sql).toContain('ORDER BY rm.id DESC');
    expect(sql.sql).toContain("COLLATE utf8mb4_0900_ai_ci LIKE ? ESCAPE '!'");
    expect(sql.sql).toContain('m.id < ?');
    expect(sql.values).toEqual([ORG, 501n, ORG, 1000, '%a!_b%', '%a!_b%', 99n, 21]);
    // Nothing from the input is spliced into the statement text.
    expect(sql.sql).not.toContain('a!_b');
  });

  it('refuses non-integer bounds and maps a 3024 to SearchTimeoutError', async () => {
    await expect(repository([]).repo.search(owner, { ...input, timeoutMs: 1.5 })).rejects.toThrow(
      /positive integer/,
    );
    const timeout = Object.assign(new Error('Query execution was interrupted'), {
      meta: { code: '3024' },
    });
    await expect(repository(timeout).repo.search(owner, input)).rejects.toBeInstanceOf(
      SearchTimeoutError,
    );
  });

  it('never serves a row of another user or organization (echo check)', async () => {
    const raw = {
      id: 5n,
      publicId: 'm-5',
      organizationId: ORG,
      conversationId: 10n,
      conversationPublicId: 'c-10',
      conversationTitle: null,
      userId: 999n,
      role: 'user',
      seq: 1,
      createdAt: new Date(),
      content: 'x',
    };
    await expect(repository([raw]).repo.search(owner, input)).rejects.toMatchObject({
      code: 'inconsistent_read',
    });
    await expect(
      repository([{ ...raw, userId: 501n, organizationId: 8002n }]).repo.search(owner, input),
    ).rejects.toMatchObject({ code: 'inconsistent_read' });
    const ok = await repository([{ ...raw, userId: 501n }]).repo.search(owner, input);
    expect(ok[0]).toMatchObject({ id: 5n, role: 'user', content: 'x' });
  });
});
