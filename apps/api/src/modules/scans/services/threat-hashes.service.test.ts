import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import type {
  ThreatHashesRepository,
  ThreatHashRow,
} from '../repositories/threat-hashes.repository';
import { THREAT_HASH_AUDIT, ThreatHashesService } from './threat-hashes.service';

const NOW = new Date('2026-11-05T12:00:00.000Z');
const SHA = 'a'.repeat(64);

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

const stored = (overrides: Partial<ThreatHashRow> = {}): ThreatHashRow => ({
  id: 41n,
  sha256: SHA,
  md5: null,
  severity: 'high',
  family: 'Win.Test',
  source: 'analyst',
  reason: 'seen in a campaign',
  expiresAt: null,
  firstSeenAt: NOW,
  lastSeenAt: NOW,
  createdAt: NOW,
  updatedAt: NOW,
  addedBy: { publicId: platformUser.userPublicId },
  ...overrides,
});

function setup(existing: ThreatHashRow | null = null) {
  const tx = { marker: 'tx' };
  const repository = {
    list: vi.fn(() => Promise.resolve([stored(), stored({ id: 40n, sha256: 'b'.repeat(64) })])),
    findForUpdate: vi.fn(() => Promise.resolve(existing)),
    create: vi.fn((_tx: unknown, input: { sha256: string }) =>
      Promise.resolve(stored({ sha256: input.sha256 })),
    ),
    remove: vi.fn(() => Promise.resolve()),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: platformUser.userPublicId })),
  };
  const transactions = { run: vi.fn((fn: (t: unknown) => Promise<unknown>) => fn(tx)) };
  const service = new ThreatHashesService(
    repository as unknown as ThreatHashesRepository,
    transactions as unknown as TransactionRunner,
    audit as unknown as AuditService,
  );
  return { service, repository, audit, tx };
}

const failure = (promise: Promise<unknown>) =>
  promise.then(
    () => null,
    (error: unknown) => error,
  );

describe('ThreatHashesService (step 4.2 A16, A17)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it('adds an analyst hash with its audit row in the same transaction', async () => {
    const { service, repository, audit, tx } = setup();
    const view = await service.add(
      platformUser,
      { sha256: SHA, severity: 'high', family: 'Win.Test', reason: 'seen in a campaign' },
      client,
    );
    expect(view).toMatchObject({ sha256: SHA, source: 'analyst', severity: 'high' });
    expect(repository.create).toHaveBeenCalledWith(tx, {
      sha256: SHA,
      md5: null,
      severity: 'high',
      family: 'Win.Test',
      reason: 'seen in a campaign',
      expiresAt: null,
      addedByUserId: 3n,
      now: NOW,
    });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: null,
        action: THREAT_HASH_AUDIT.added,
        resourceType: 'malware_signature',
        resourceId: SHA,
        sourceIp: '198.51.100.7',
        metadata: expect.objectContaining({ sha256: SHA, severity: 'high', family: 'Win.Test' }),
      }),
      tx,
    );
  });

  it('refuses a hash that is already listed (409 hash_exists), also on a raced unique key', async () => {
    const listed = setup(stored());
    const error = await failure(
      listed.service.add(platformUser, { sha256: SHA, severity: 'low', reason: 'x' }, client),
    );
    expect(error).toBeInstanceOf(CodedHttpException);
    expect((error as CodedHttpException).getResponse()).toMatchObject({ code: 'hash_exists' });
    expect(listed.repository.create).not.toHaveBeenCalled();
    expect(listed.audit.record).not.toHaveBeenCalled();

    const raced = setup();
    raced.repository.create.mockRejectedValueOnce(
      new Prisma.PrismaClientKnownRequestError('dup', { code: 'P2002', clientVersion: 't' }),
    );
    const racedError = await failure(
      raced.service.add(platformUser, { sha256: SHA, severity: 'low', reason: 'x' }, client),
    );
    expect((racedError as CodedHttpException).getStatus()).toBe(409);
  });

  it('refuses an expiresAt that is not in the future', async () => {
    const { service, repository } = setup();
    const error = await failure(
      service.add(
        platformUser,
        { sha256: SHA, severity: 'low', reason: 'x', expiresAt: NOW.toISOString() },
        client,
      ),
    );
    expect(error).toBeInstanceOf(BadRequestException);
    expect(repository.create).not.toHaveBeenCalled();
  });

  it('removes a hash with the before-image in the audit row', async () => {
    const { service, repository, audit, tx } = setup(stored());
    await service.remove(platformUser, SHA, 'false positive', client);
    expect(repository.remove).toHaveBeenCalledWith(tx, 41n);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: THREAT_HASH_AUDIT.removed,
        resourceId: SHA,
        metadata: {
          reason: 'false positive',
          before: expect.objectContaining({
            sha256: SHA,
            severity: 'high',
            family: 'Win.Test',
            source: 'analyst',
            addedByUserId: platformUser.userPublicId,
          }),
        },
      }),
      tx,
    );
  });

  it('answers 404 threat_hash_not_found when removing an unknown hash', async () => {
    const { service, repository, audit } = setup(null);
    const error = await failure(service.remove(platformUser, SHA, 'x', client));
    expect((error as CodedHttpException).getResponse()).toMatchObject({
      code: 'threat_hash_not_found',
    });
    expect(repository.remove).not.toHaveBeenCalled();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('pages newest first with a cursor', async () => {
    const { service, repository } = setup();
    const page = await service.list(platformUser, { limit: 1, source: 'analyst' });
    expect(repository.list).toHaveBeenCalledWith({ take: 2, source: 'analyst' });
    expect(page.data.map((h) => h.sha256)).toEqual([SHA]);
    expect(page.nextCursor).not.toBeNull();
  });

  it('refuses customer users and override sessions even with the permission', async () => {
    const { service } = setup();
    for (const principal of [
      { ...platformUser, organizationKind: 'customer' as const },
      {
        ...platformUser,
        override: {
          id: 'o',
          reason: 'r',
          targetOrganizationId: 9n,
          targetOrganizationPublicId: 'x',
          expiresAt: NOW,
        },
      },
    ]) {
      expect(await failure(service.list(principal, { limit: 10 }))).toBeInstanceOf(
        ForbiddenException,
      );
    }
  });
});
