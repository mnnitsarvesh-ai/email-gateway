import type { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { runWithContext } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../auth-contracts/principal';
import { AuditService, scrubMetadata, SYSTEM_ACTOR } from './audit.service';

function service() {
  const create = vi
    .fn()
    .mockResolvedValue({ id: 901n, createdAt: new Date('2026-11-18T10:00:00.000Z') });
  const outbox = vi.fn().mockResolvedValue({ id: 1n });
  const prisma: Record<string, unknown> = {
    auditLog: { create },
    messageOutbox: { create: outbox },
  };
  const transaction = vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn(prisma));
  prisma.$transaction = transaction;
  return {
    create,
    outbox,
    transaction,
    audit: new AuditService(prisma as unknown as PrismaService),
  };
}

const user: UserPrincipal = {
  kind: 'user',
  userId: 10n,
  userPublicId: '0190a0b0-0000-7000-8000-000000000010',
  organizationId: 1n,
  organizationPublicId: '0190a0b0-0000-7000-8000-000000000001',
  organizationKind: 'platform',
  sessionId: 'b5f2c4a8-1111-4222-8333-444455556666',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(),
};

describe('AuditService.actorFrom', () => {
  it('uses public ids for users and API keys', () => {
    const { audit } = service();
    expect(audit.actorFrom(user)).toEqual({ type: 'user', id: user.userPublicId });
    const key: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 3n,
      apiKeyPublicId: '0190a0b0-0000-7000-8000-000000000003',
      organizationId: 2n,
      organizationPublicId: '0190a0b0-0000-7000-8000-000000000002',
      permissions: new Set(),
    };
    expect(audit.actorFrom(key)).toEqual({ type: 'api_key', id: key.apiKeyPublicId });
  });

  it('carries the override into the metadata of every row', async () => {
    const { audit, create } = service();
    const actor = audit.actorFrom({
      ...user,
      override: {
        id: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
        reason: 'Ticket 1234: mail flow issue',
        targetOrganizationId: 42n,
        targetOrganizationPublicId: '0190a0b0-0000-7000-8000-000000000042',
        expiresAt: new Date(),
      },
    });
    await audit.record({
      organizationId: 42n,
      actor,
      action: 'organization.updated',
      resourceType: 'organization',
      resourceId: '0190a0b0-0000-7000-8000-000000000042',
      metadata: { changed: ['name'] },
    });
    expect(create.mock.calls[0]![0].data.metadata).toEqual({
      changed: ['name'],
      override: {
        id: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
        reason: 'Ticket 1234: mail flow issue',
      },
    });
  });
});

describe('AuditService.record', () => {
  it('writes the row with the correlation id from the request context', async () => {
    const { audit, create } = service();
    await runWithContext({ correlationId: 'corr-audit-0001' }, () =>
      audit.record({
        organizationId: 7n,
        actor: { type: 'user', id: 'u-1' },
        action: 'user.invited',
        resourceType: 'user',
        resourceId: 'u-2',
        sourceIp: '203.0.113.5',
        metadata: { roleKeys: ['read_only_user'] },
      }),
    );
    expect(create).toHaveBeenCalledWith({
      select: { id: true, createdAt: true },
      data: {
        organizationId: 7n,
        actorType: 'user',
        actorId: 'u-1',
        action: 'user.invited',
        resourceType: 'user',
        resourceId: 'u-2',
        correlationId: 'corr-audit-0001',
        sourceIp: '203.0.113.5',
        metadata: { roleKeys: ['read_only_user'] },
      },
    });
  });

  it('adds the request id of the HTTP request to the metadata (step 6.1 D11)', async () => {
    const { audit, create } = service();
    const requestId = '0b9c6a2e-1111-4222-8333-444455556666';
    await runWithContext({ correlationId: 'corr-audit-0002', requestId }, async () => {
      await audit.record({
        organizationId: 7n,
        actor: { type: 'user', id: 'u-1' },
        action: 'user.invited',
        resourceType: 'user',
        metadata: { roleKeys: ['read_only_user'] },
      });
      // Also when the caller passes no metadata.
      await audit.record({
        organizationId: 7n,
        actor: SYSTEM_ACTOR,
        action: 'x.y',
        resourceType: 'x',
      });
    });
    expect(create.mock.calls[0]![0].data.metadata).toEqual({
      roleKeys: ['read_only_user'],
      requestId,
    });
    expect(create.mock.calls[1]![0].data.metadata).toEqual({ requestId });
  });

  it('writes platform-only and system rows with nulls', async () => {
    const { audit, create } = service();
    await audit.record({
      organizationId: null,
      actor: SYSTEM_ACTOR,
      action: 'user.bootstrap_invited',
      resourceType: 'user',
    });
    expect(create.mock.calls[0]![0].data).toMatchObject({
      organizationId: null,
      actorType: 'system',
      actorId: null,
      resourceId: null,
      correlationId: null,
      sourceIp: null,
      metadata: Prisma.DbNull,
    });
  });

  it('uses the transaction client when given', async () => {
    const { audit, create } = service();
    const txCreate = vi.fn().mockResolvedValue({});
    const tx = { auditLog: { create: txCreate } } as unknown as Prisma.TransactionClient;
    await audit.record(
      { organizationId: 1n, actor: SYSTEM_ACTOR, action: 'x.y', resourceType: 'x' },
      tx,
    );
    expect(txCreate).toHaveBeenCalledTimes(1);
    expect(create).not.toHaveBeenCalled();
  });

  it('writes auth.account.changed.v1 with the audit row for ATO account-change actions (step 8.4 D5)', async () => {
    const { audit, create, outbox, transaction } = service();
    await runWithContext({ correlationId: 'corr-ato-0001' }, () =>
      audit.record({
        organizationId: 7n,
        actor: { type: 'user', id: user.userPublicId },
        action: 'auth.password_changed',
        resourceType: 'user',
        resourceId: user.userPublicId,
        sourceIp: '203.0.113.5',
        metadata: { reason: 'self_service' },
      }),
    );
    // Without a caller transaction both inserts run in a new one.
    expect(transaction).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledTimes(1);
    expect(outbox).toHaveBeenCalledWith({
      data: {
        eventId: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/),
        organizationId: 7n,
        eventType: 'auth.account.changed.v1',
        aggregateType: 'audit',
        aggregateId: '901',
        correlationId: 'corr-ato-0001',
        payload: {
          auditLogId: '901',
          auditCreatedAt: '2026-11-18T10:00:00.000Z',
          action: 'auth.password_changed',
          actorType: 'user',
          actorPublicId: user.userPublicId,
          resourceType: 'user',
          resourcePublicId: user.userPublicId,
        },
      },
      select: { id: true },
    });
  });

  it('uses the caller transaction for both rows; system actors have no public id', async () => {
    const { audit, transaction } = service();
    const txAudit = vi.fn().mockResolvedValue({ id: 5n, createdAt: new Date(0) });
    const txOutbox = vi.fn().mockResolvedValue({ id: 1n });
    const tx = {
      auditLog: { create: txAudit },
      messageOutbox: { create: txOutbox },
    } as unknown as Prisma.TransactionClient;
    await audit.record(
      {
        organizationId: 3n,
        actor: SYSTEM_ACTOR,
        action: 'session.revoked_all',
        resourceType: 'user',
        resourceId: null,
      },
      tx,
    );
    expect(transaction).not.toHaveBeenCalled();
    expect(txOutbox.mock.calls[0]![0].data.payload).toMatchObject({
      actorType: 'system',
      actorPublicId: null,
      resourcePublicId: null,
    });
  });

  it('writes no event for platform-only rows, other actions, or rows outside the contract', async () => {
    const { audit, outbox, transaction } = service();
    await audit.record({
      organizationId: null,
      actor: SYSTEM_ACTOR,
      action: 'auth.password_changed',
      resourceType: 'user',
    });
    await audit.record({
      organizationId: 7n,
      actor: { type: 'user', id: user.userPublicId },
      action: 'domain.created',
      resourceType: 'domain',
    });
    expect(transaction).not.toHaveBeenCalled();
    // A non-UUID actor id: the audit row is still written, the event is skipped.
    await audit.record({
      organizationId: 7n,
      actor: { type: 'user', id: 'not-a-uuid' },
      action: 'auth.mfa_enabled',
      resourceType: 'user',
    });
    expect(outbox).not.toHaveBeenCalled();
  });

  it('propagates write errors', async () => {
    const { audit, create } = service();
    create.mockRejectedValueOnce(new Error('db down'));
    await expect(
      audit.record({ organizationId: 1n, actor: SYSTEM_ACTOR, action: 'x.y', resourceType: 'x' }),
    ).rejects.toThrow('db down');
  });
});

describe('scrubMetadata', () => {
  it('drops credential-like keys at any depth', () => {
    expect(
      scrubMetadata({
        name: 'ok',
        password: 'p',
        newPassword: 'p',
        clientSecret: 's',
        refreshToken: 't',
        code: '123456',
        recoveryCode: 'abcde-fghij',
        key: 'egk_x',
        apiKey: 'egk_y',
        nested: { accessToken: 'a', keep: 1, list: [{ secret: 's', id: 'i' }] },
      }),
    ).toEqual({ name: 'ok', nested: { keep: 1, list: [{ id: 'i' }] } });
  });

  it('keeps identifiers that only look sensitive by name', () => {
    expect(
      scrubMetadata({
        statusCode: 200,
        planCode: 'standard',
        featureKey: 'api_access',
        limitKey: 'max_users',
        roleKeys: ['a'],
        keyPrefix: 'egk_abc',
      }),
    ).toEqual({
      statusCode: 200,
      planCode: 'standard',
      featureKey: 'api_access',
      limitKey: 'max_users',
      roleKeys: ['a'],
      keyPrefix: 'egk_abc',
    });
  });

  it('never leaves bigint or Date values for JSON', () => {
    const out = scrubMetadata({
      id: 12345678901234567890n,
      at: new Date('2026-01-01T00:00:00Z'),
      n: Number.NaN,
      u: undefined,
    });
    expect(out).toEqual({ id: '12345678901234567890', at: '2026-01-01T00:00:00.000Z', n: null });
    expect(() => JSON.stringify(out)).not.toThrow();
  });
});
