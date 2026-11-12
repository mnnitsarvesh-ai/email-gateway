import { randomBytes } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { UserPrincipal } from '../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import type { ApiConventionMetrics } from '../../http/api-metrics';
import { CodedForbiddenException, CodedHttpException } from '../../http/coded-exception';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import type { OrganizationsRepository } from '../organizations/organizations.repository';
import type {
  AuditKey,
  AuditLogRecord,
  AuditLogsRepository,
  AuditSearch,
} from './audit-logs.repository';
import { AuditLogsQuerySchema, PlatformAuditLogsQuerySchema } from './audit-logs.schemas';
import { AuditLogsService } from './audit-logs.service';

const now = new Date('2026-11-12T10:00:00.000Z');
const ORG = '01930c2e-7d1a-7000-8000-00000000000a';

const user = (overrides: Partial<UserPrincipal> = {}): UserPrincipal => ({
  kind: 'user',
  userId: 5n,
  userPublicId: '01930c2e-7d1a-7000-8000-0000000000u5',
  organizationId: 40n,
  organizationPublicId: ORG,
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['audit:read']),
  ...overrides,
});

const record = (
  id: bigint,
  minutesAgo: number,
  organizationId: bigint | null = 40n,
): AuditLogRecord => ({
  id,
  createdAt: new Date(now.getTime() - minutesAgo * 60_000),
  organizationId,
  actorType: 'user',
  actorId: 'actor',
  action: 'quarantine.entry_released',
  resourceType: 'quarantine_entry',
  resourceId: 'r1',
  correlationId: null,
  sourceIp: null,
  metadata: { recipients: 1 },
});

function setup(rows: AuditLogRecord[] = [], boundary: AuditKey | null = null) {
  const repo = {
    page: vi.fn((_s: AuditSearch, take: number) => Promise.resolve(rows.slice(0, take))),
    boundary: vi.fn(() => Promise.resolve(boundary)),
    filtered: vi.fn((_s: AuditSearch, _f: unknown, _b: unknown, take: number) =>
      Promise.resolve(rows.slice(0, take)),
    ),
  };
  const organizations = { findVisibleOnReader: vi.fn(() => Promise.resolve(null as unknown)) };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: 'u' })),
  };
  const metrics = { scanBudgetExhausted: { inc: vi.fn() } };
  const cursors = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const service = new AuditLogsService(
    repo as unknown as AuditLogsRepository,
    organizations as unknown as OrganizationsRepository,
    cursors,
    audit as unknown as AuditService,
    metrics as unknown as ApiConventionMetrics,
    { API_AUDIT_MAX_RANGE_DAYS: 90, API_LIST_SCAN_BUDGET_ROWS: 5000 },
  );
  return { service, repo, organizations, audit, metrics };
}

const q = (raw: Record<string, string>) => AuditLogsQuerySchema.parse(raw);
const pq = (raw: Record<string, string>) => PlatformAuditLogsQuerySchema.parse(raw);
const origin = { ip: '198.51.100.7' };

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof CodedHttpException || err instanceof CodedForbiddenException)
      return err.code;
    if (err instanceof BadRequestException) return 'validation_failed';
    throw err;
  }
  return 'ok';
}

describe('AuditLogsService.search (tenant)', () => {
  it('pages newest first with a v1 cursor, keeps the first window and audits the first page only', async () => {
    const p = user();
    const scope = scopeFromPrincipal(p);
    const { service, repo, audit } = setup([record(9n, 1), record(8n, 2), record(7n, 3)]);
    const first = await service.search(p, scope, q({ limit: '2' }), origin, now);
    expect(first.data.map((r) => r.id)).toEqual(['9', '8']);
    expect(first.data[0]).toMatchObject({
      actor: { type: 'user', id: 'actor' },
      metadata: { recipients: 1 },
    });
    expect(first.nextCursor).toEqual(expect.any(String));
    const search = repo.page.mock.calls[0]![0];
    expect(search).toMatchObject({
      owner: { kind: 'organization', organizationId: 40n },
      direction: 'desc',
    });
    expect(search.to).toEqual(now);
    expect(search.from).toEqual(new Date(now.getTime() - 7 * 86_400_000));
    expect(repo.page.mock.calls[0]![1]).toBe(3);
    expect(audit.record).toHaveBeenCalledTimes(1);
    expect(audit.record.mock.calls[0]).toMatchObject([
      {
        organizationId: 40n,
        action: 'audit.searched',
        resourceType: 'audit_log',
        sourceIp: '198.51.100.7',
        metadata: { filters: [], resultCount: 2, sort: '-createdAt' },
      },
    ]);

    // Page 2, an hour later: same window from the cursor, after the last row; not audited.
    await service.search(
      p,
      scope,
      q({ limit: '2', cursor: first.nextCursor! }),
      origin,
      new Date(now.getTime() + 3_600_000),
    );
    const second = repo.page.mock.calls[1]![0];
    expect(second.to).toEqual(now);
    expect(second.after).toEqual({ createdAt: record(8n, 2).createdAt, id: 8n });
    expect(audit.record).toHaveBeenCalledTimes(1);
  });

  it('uses the scan budget with filters; a page ended by the budget is short and continues at the boundary', async () => {
    const p = user();
    const boundary = { createdAt: new Date(now.getTime() - 3_600_000), id: 100n };
    const { service, repo, metrics, audit } = setup([record(9n, 1)], boundary);
    const page = await service.search(
      p,
      scopeFromPrincipal(p),
      q({ actionPrefix: 'quarantine.', actorId: 'someone', limit: '10' }),
      origin,
      now,
    );
    expect(page.data).toHaveLength(1);
    expect(page.nextCursor).not.toBeNull();
    expect(repo.boundary).toHaveBeenCalledWith(expect.anything(), 5000);
    expect(repo.filtered.mock.calls[0]![1]).toEqual({
      actionPrefix: 'quarantine.',
      actorId: 'someone',
    });
    expect(repo.filtered.mock.calls[0]![2]).toEqual(boundary);
    expect(metrics.scanBudgetExhausted.inc).toHaveBeenCalledWith({ resource: 'audit_logs' });
    const metadata = (
      audit.record.mock.calls[0] as unknown as [{ metadata: Record<string, unknown> }]
    )[0].metadata;
    expect(metadata.filters).toEqual(['actionPrefix', 'actorId']);
    expect(JSON.stringify(metadata)).not.toContain('someone');
    expect(metadata.identifierSha256).toEqual({ actorId: expect.stringMatching(/^[0-9a-f]{64}$/) });
  });

  it('refuses action with actionPrefix, malformed prefixes and foreign or altered cursors', async () => {
    const p = user();
    const scope = scopeFromPrincipal(p);
    const { service } = setup([record(9n, 1), record(8n, 2)]);
    expect(
      await codeOf(service.search(p, scope, q({ action: 'a.b', actionPrefix: 'a.' }), origin, now)),
    ).toBe('validation_failed');
    expect(
      await codeOf(service.search(p, scope, q({ actionPrefix: 'Quarantine.' }), origin, now)),
    ).toBe('validation_failed');
    expect(
      await codeOf(service.search(p, scope, q({ actionPrefix: 'quarantine' }), origin, now)),
    ).toBe('validation_failed');

    const page = await service.search(p, scope, q({ limit: '1' }), origin, now);
    const cursor = page.nextCursor!;
    const other = user({
      organizationId: 41n,
      organizationPublicId: '01930c2e-7d1a-7000-8000-00000000000b',
    });
    expect(
      await codeOf(
        service.search(other, scopeFromPrincipal(other), q({ limit: '1', cursor }), origin, now),
      ),
    ).toBe('cursor_invalid');
    expect(
      await codeOf(service.search(p, scope, q({ limit: '1', cursor, action: 'x.y' }), origin, now)),
    ).toBe('cursor_invalid');
    expect(
      await codeOf(
        service.search(p, scope, q({ limit: '1', cursor, sort: 'createdAt' }), origin, now),
      ),
    ).toBe('cursor_invalid');
    expect(
      await codeOf(
        service.search(
          p,
          scope,
          q({ limit: '1', cursor, from: '2026-11-01T00:00:00Z' }),
          origin,
          now,
        ),
      ),
    ).toBe('cursor_invalid');
    expect(await codeOf(service.search(p, scope, q({ limit: '1', cursor }), origin, now))).toBe(
      'ok',
    );
  });

  it('bounds the window by API_AUDIT_MAX_RANGE_DAYS', async () => {
    const p = user();
    const { service } = setup();
    expect(
      await codeOf(
        service.search(
          p,
          scopeFromPrincipal(p),
          q({ from: '2026-08-01T00:00:00Z', to: '2026-11-12T00:00:00Z' }),
          origin,
          now,
        ),
      ),
    ).toBe('validation_failed');
  });
});

describe('AuditLogsService.searchPlatform', () => {
  const platform = user({
    organizationId: 1n,
    organizationPublicId: '01930c2e-7d1a-7000-8000-000000000001',
    organizationKind: 'platform',
    permissions: new Set(['platform:operations', 'audit:read']),
  });

  it('requires exactly one target and resolves organizations by public id (404 organization_not_found)', async () => {
    const { service, organizations } = setup();
    const scope = scopeFromPrincipal(platform);
    expect(await codeOf(service.searchPlatform(platform, scope, pq({}), origin, now))).toBe(
      'validation_failed',
    );
    expect(
      await codeOf(
        service.searchPlatform(
          platform,
          scope,
          pq({ organizationId: ORG, scope: 'platform' }),
          origin,
          now,
        ),
      ),
    ).toBe('validation_failed');
    expect(
      await codeOf(
        service.searchPlatform(platform, scope, pq({ organizationId: ORG }), origin, now),
      ),
    ).toBe('organization_not_found');
    expect(organizations.findVisibleOnReader).toHaveBeenCalledWith(
      { kind: 'platform', principal: platform },
      ORG,
    );
  });

  it('reads the target organization and audits platform.audit_searched in its trail', async () => {
    const { service, organizations, repo, audit } = setup([record(3n, 1, 40n)]);
    organizations.findVisibleOnReader.mockResolvedValue({ id: 40n, publicId: ORG });
    const page = await service.searchPlatform(
      platform,
      scopeFromPrincipal(platform),
      pq({ organizationId: ORG }),
      origin,
      now,
    );
    expect(page.data.map((r) => r.id)).toEqual(['3']);
    expect(repo.page.mock.calls[0]![0].owner).toEqual({
      kind: 'organization',
      organizationId: 40n,
    });
    expect(audit.record.mock.calls[0]).toMatchObject([
      {
        organizationId: 40n,
        action: 'platform.audit_searched',
        resourceId: ORG,
        metadata: { target: { organization: ORG }, resultCount: 1 },
      },
    ]);
  });

  it('reads platform rows for scope=platform and refuses non-platform principals', async () => {
    const { service, repo, audit } = setup([record(2n, 1, null)]);
    await service.searchPlatform(
      platform,
      scopeFromPrincipal(platform),
      pq({ scope: 'platform' }),
      origin,
      now,
    );
    expect(repo.page.mock.calls[0]![0].owner).toEqual({ kind: 'platform' });
    expect(audit.record.mock.calls[0]).toMatchObject([
      { organizationId: null, resourceId: 'platform' },
    ]);
    const customer = user({ permissions: new Set(['platform:operations', 'audit:read']) });
    expect(
      await codeOf(
        service.searchPlatform(
          customer,
          scopeFromPrincipal(customer),
          pq({ scope: 'platform' }),
          origin,
          now,
        ),
      ),
    ).toBe('forbidden');
  });
});
