import { createHash } from 'node:crypto';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import type {
  ThreatIndicatorRow,
  ThreatIndicatorsRepository,
} from '../repositories/threat-indicators.repository';
import {
  INDICATOR_TX,
  normalizeIndicatorValue,
  THREAT_INDICATOR_AUDIT,
  ThreatIndicatorsService,
} from './threat-indicators.service';

const NOW = new Date('2026-11-06T12:00:00.000Z');
const sha = (value: string) => createHash('sha256').update(value).digest('hex');

const platformUser: UserPrincipal = {
  kind: 'user',
  userId: 3n,
  userPublicId: '0190f0f0-0000-7000-8000-000000000003',
  organizationId: 1n,
  organizationPublicId: '0190f0f0-0000-7000-8000-000000000001',
  organizationKind: 'platform',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['platform:threat_intel_manage']),
};
const client = { ip: '198.51.100.7', userAgent: null } as never;

const stored = (overrides: Partial<ThreatIndicatorRow> = {}): ThreatIndicatorRow => ({
  id: 41n,
  organizationId: null,
  indicatorType: 'domain',
  value: 'evil.example',
  valueSha256: sha('evil.example'),
  severity: 'high',
  category: 'phishing',
  source: 'analyst',
  reason: 'campaign',
  expiresAt: null,
  firstSeenAt: NOW,
  lastSeenAt: NOW,
  createdAt: NOW,
  updatedAt: NOW,
  addedBy: { publicId: platformUser.userPublicId },
  ...overrides,
});

function setup(existing: ThreatIndicatorRow | null = null, byId: ThreatIndicatorRow | null = null) {
  const tx = { marker: 'tx' };
  const repository = {
    list: vi.fn(() => Promise.resolve([stored(), stored({ id: 40n })])),
    findAnalystForUpdate: vi.fn(() => Promise.resolve(existing)),
    findPlatformForUpdate: vi.fn(() => Promise.resolve(byId)),
    create: vi.fn(
      (
        _tx: unknown,
        input: { type: 'url' | 'domain' | 'ip'; value: string; valueSha256: string },
      ) =>
        Promise.resolve(
          stored({ indicatorType: input.type, value: input.value, valueSha256: input.valueSha256 }),
        ),
    ),
    remove: vi.fn(() => Promise.resolve()),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: platformUser.userPublicId })),
  };
  const transactions = {
    run: vi.fn((fn: (t: unknown) => Promise<unknown>, _options?: unknown) => fn(tx)),
  };
  const service = new ThreatIndicatorsService(
    repository as unknown as ThreatIndicatorsRepository,
    transactions as unknown as TransactionRunner,
    audit as unknown as AuditService,
  );
  return { service, repository, audit, transactions, tx };
}

const failure = (promise: Promise<unknown>) =>
  promise.then(
    () => null,
    (error: unknown) => error,
  );
const body = {
  type: 'domain' as const,
  value: 'Evil.Example.',
  severity: 'high' as const,
  category: 'phishing' as const,
  reason: 'campaign',
};

describe('normalizeIndicatorValue (step 4.3 U16)', () => {
  it.each([
    ['url', 'HTTPS://User:pw@Evil.Example:443/a/../b?x=1#frag', 'https://evil.example/b?x=1'],
    ['domain', 'Bücher.Example.', 'xn--bcher-kva.example'],
    ['domain', 'login.evil.co.uk', 'login.evil.co.uk'],
    ['ip', '::FFFF:7F00:1', '::ffff:7f00:1'],
    ['ip', '203.0.113.010', null],
  ] as const)('%s %s → %s', (type, raw, expected) => {
    if (expected === null) {
      expect(() => normalizeIndicatorValue(type, raw)).toThrow(BadRequestException);
      return;
    }
    expect(normalizeIndicatorValue(type, raw)).toEqual({
      value: expected,
      valueSha256: sha(expected),
    });
  });

  it.each([
    ['domain', 'co.uk'],
    ['domain', 'github.io'],
    ['domain', 'localhost'],
    ['domain', '10.0.0.1'],
    ['url', 'ftp://evil.example/'],
    ['url', `https://evil.example/${'a'.repeat(2100)}`],
    ['ip', 'evil.example'],
  ] as const)('refuses %s %s with a value message', (type, raw) => {
    try {
      normalizeIndicatorValue(type, raw);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(BadRequestException);
      expect(JSON.stringify((error as BadRequestException).getResponse())).toContain('value:');
    }
  });
});

describe('ThreatIndicatorsService (step 4.3 U16)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it('adds a normalized analyst indicator with its audit row in one long transaction', async () => {
    const { service, repository, audit, transactions, tx } = setup();
    const view = await service.add(platformUser, body, client);
    expect(repository.findAnalystForUpdate).toHaveBeenCalledWith(tx, 'domain', sha('evil.example'));
    expect(repository.create).toHaveBeenCalledWith(
      tx,
      expect.objectContaining({
        type: 'domain',
        value: 'evil.example',
        valueSha256: sha('evil.example'),
        severity: 'high',
        category: 'phishing',
        addedByUserId: 3n,
        expiresAt: null,
        now: NOW,
      }),
    );
    expect(transactions.run).toHaveBeenCalledWith(expect.any(Function), INDICATOR_TX);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: null,
        action: THREAT_INDICATOR_AUDIT.added,
        resourceType: 'threat_indicator',
        resourceId: '41',
        metadata: expect.objectContaining({ value: 'evil.example', source: 'analyst' }),
      }),
      tx,
    );
    expect(view).toMatchObject({
      id: '41',
      type: 'domain',
      value: 'evil.example',
      source: 'analyst',
    });
  });

  it('409 indicator_exists for a listed value and for the unique-key race', async () => {
    const listed = setup(stored());
    const error = await failure(listed.service.add(platformUser, body, client));
    expect(error).toBeInstanceOf(CodedHttpException);
    expect((error as CodedHttpException).code).toBe('indicator_exists');
    expect(listed.repository.create).not.toHaveBeenCalled();
    expect(listed.audit.record).not.toHaveBeenCalled();

    const raced = setup();
    raced.repository.create.mockRejectedValueOnce(
      new Prisma.PrismaClientKnownRequestError('dup', { code: 'P2002', clientVersion: 'x' }),
    );
    const raceError = await failure(raced.service.add(platformUser, body, client));
    expect((raceError as CodedHttpException).code).toBe('indicator_exists');
  });

  it('refuses a past expiry and an invalid value before any database access', async () => {
    const { service, transactions } = setup();
    await expect(
      service.add(platformUser, { ...body, expiresAt: '2026-11-06T11:59:59.000Z' }, client),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      service.add(platformUser, { ...body, value: 'co.uk' }, client),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(transactions.run).not.toHaveBeenCalled();
  });

  it('removes with the before-image in the audit row, 404 when not a platform indicator', async () => {
    const { service, repository, audit, transactions, tx } = setup(null, stored());
    await service.remove(platformUser, 41n, 'false positive', client);
    expect(repository.remove).toHaveBeenCalledWith(tx, 41n);
    expect(transactions.run).toHaveBeenCalledWith(expect.any(Function), INDICATOR_TX);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: THREAT_INDICATOR_AUDIT.removed,
        resourceId: '41',
        metadata: {
          reason: 'false positive',
          before: expect.objectContaining({ id: '41', value: 'evil.example', severity: 'high' }),
        },
      }),
      tx,
    );
    const missing = setup(null, null);
    const error = await failure(missing.service.remove(platformUser, 9n, 'x', client));
    expect((error as CodedHttpException).code).toBe('threat_indicator_not_found');
    expect(missing.repository.remove).not.toHaveBeenCalled();
  });

  it('lists with filters, normalizing a value filter, and requires type with value', async () => {
    const { service, repository } = setup();
    const page = await service.list(platformUser, {
      limit: 1,
      type: 'url',
      value: 'HTTPS://Evil.Example/x#f',
      source: 'analyst',
    });
    expect(repository.list).toHaveBeenCalledWith({
      take: 2,
      type: 'url',
      source: 'analyst',
      valueSha256: sha('https://evil.example/x'),
    });
    expect(page.data).toHaveLength(1);
    expect(page.nextCursor).not.toBeNull();
    await expect(
      service.list(platformUser, { limit: 5, value: 'x.example' }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('refuses non-platform principals and override sessions', async () => {
    const { service } = setup();
    const tenant = { ...platformUser, organizationKind: 'customer' } as UserPrincipal;
    await expect(service.list(tenant, { limit: 5 })).rejects.toBeInstanceOf(ForbiddenException);
    const override = { ...platformUser, override: {} } as unknown as UserPrincipal;
    await expect(service.add(override, body, client)).rejects.toBeInstanceOf(ForbiddenException);
  });
});
