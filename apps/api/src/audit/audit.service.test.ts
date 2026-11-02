import type { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { runWithContext } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../auth-contracts/principal';
import { AuditService, scrubMetadata, SYSTEM_ACTOR } from './audit.service';

function service() {
  const create = vi.fn().mockResolvedValue({});
  const prisma = { auditLog: { create } } as unknown as PrismaService;
  return { create, audit: new AuditService(prisma) };
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
