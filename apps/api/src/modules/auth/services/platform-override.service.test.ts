import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type {
  OrganizationAuthRecord,
  OrganizationsAuthRepository,
} from '../repositories/organizations-auth.repository';
import { PlatformOverrideService } from './platform-override.service';
import { TokenService } from './token.service';

const target: OrganizationAuthRecord = {
  id: 42n,
  publicId: randomUUID(),
  slug: 'acme',
  name: 'Acme',
  kind: 'customer',
  status: 'active',
  deletedAt: null,
};

describe('PlatformOverrideService', () => {
  let kv: InMemoryKeyValueStore;
  let orgs: Map<string, OrganizationAuthRecord>;
  let audit: { record: ReturnType<typeof vi.fn> };
  let tokens: TokenService;
  let service: PlatformOverrideService;
  let operator: UserPrincipal;
  const context = { ip: '198.51.100.4', userAgent: null };

  beforeEach(() => {
    kv = new InMemoryKeyValueStore();
    orgs = new Map([[target.publicId, target]]);
    audit = { record: vi.fn() };
    tokens = new TokenService({
      AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
      AUTH_JWT_ISSUER: 'iss',
      AUTH_JWT_AUDIENCE: 'aud',
      AUTH_ACCESS_TOKEN_TTL_SECONDS: 600,
    });
    const repository = {
      findByPublicId: (id: string) => Promise.resolve(orgs.get(id) ?? null),
      findById: (id: bigint) =>
        Promise.resolve([...orgs.values()].find((o) => o.id === id) ?? null),
    };
    service = new PlatformOverrideService(
      { PLATFORM_OVERRIDE_MAX_MINUTES: 60 },
      repository as unknown as OrganizationsAuthRepository,
      kv,
      tokens,
      audit as unknown as AuditService,
    );
    operator = {
      kind: 'user',
      userId: 7n,
      userPublicId: randomUUID(),
      organizationId: 1n,
      organizationPublicId: randomUUID(),
      organizationKind: 'platform',
      sessionId: randomUUID(),
      mfaAuthenticated: true,
      mfaEnrollmentRequired: false,
      permissions: new Set(['platform:tenant_override']),
    };
  });

  const input = {
    organizationId: target.publicId,
    reason: 'Customer ticket 4711',
    durationMinutes: 30,
  };

  it('starts an override: KV entry with TTL, audit row, non-refreshable token', async () => {
    const res = await service.start(operator, input, context);
    expect(res.organization).toEqual({ id: target.publicId, slug: 'acme', name: 'Acme' });
    expect(await kv.ttl(`auth:override:${res.overrideId}`)).toBe(1800);
    const claims = await tokens.verify(res.accessToken);
    expect(claims).toMatchObject({
      ovr: res.overrideId,
      sid: operator.sessionId,
      amr: ['pwd', 'otp'],
    });
    expect(claims!.exp).toBe(Math.floor(new Date(res.expiresAt).getTime() / 1000));
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'platform.override_started',
        organizationId: 42n,
        resourceId: target.publicId,
        metadata: expect.objectContaining({ overrideId: res.overrideId, reason: input.reason }),
      }),
    );
    expect(
      await service.resolve(res.overrideId, { userId: 7n, sessionId: operator.sessionId }),
    ).toMatchObject({
      id: res.overrideId,
      targetOrganizationId: 42n,
      reason: input.reason,
    });
  });

  it('enforces its own rules', async () => {
    await expect(
      service.start({ ...operator, organizationKind: 'customer' }, input, context),
    ).rejects.toThrow(ForbiddenException);
    await expect(
      service.start({ ...operator, mfaAuthenticated: false }, input, context),
    ).rejects.toThrow(ForbiddenException);
    await expect(
      service.start(
        {
          ...operator,
          override: {
            id: randomUUID(),
            reason: 'x',
            targetOrganizationId: 42n,
            targetOrganizationPublicId: target.publicId,
            expiresAt: new Date(),
          },
        },
        input,
        context,
      ),
    ).rejects.toThrow(ForbiddenException);
    await expect(
      service.start(operator, { ...input, durationMinutes: 61 }, context),
    ).rejects.toThrow(BadRequestException);
    await expect(
      service.start(operator, { ...input, organizationId: randomUUID() }, context),
    ).rejects.toThrow(NotFoundException);
    orgs.set(target.publicId, { ...target, kind: 'platform' });
    await expect(service.start(operator, input, context)).rejects.toThrow(NotFoundException);
    orgs.set(target.publicId, { ...target, status: 'deleted', deletedAt: new Date() });
    await expect(service.start(operator, input, context)).rejects.toThrow(NotFoundException);
  });

  it('resolve: only for the same user and session, and while the target qualifies', async () => {
    const { overrideId } = await service.start(operator, input, context);
    expect(
      await service.resolve(overrideId, { userId: 8n, sessionId: operator.sessionId }),
    ).toBeNull();
    expect(await service.resolve(overrideId, { userId: 7n, sessionId: randomUUID() })).toBeNull();
    orgs.set(target.publicId, { ...target, status: 'deleted', deletedAt: new Date() });
    expect(
      await service.resolve(overrideId, { userId: 7n, sessionId: operator.sessionId }),
    ).toBeNull();
    expect(
      await service.resolve(randomUUID(), { userId: 7n, sessionId: operator.sessionId }),
    ).toBeNull();
  });

  it('end: owner only, removes the entry and audits', async () => {
    const { overrideId } = await service.start(operator, input, context);
    await expect(service.end({ ...operator, userId: 8n }, overrideId, context)).rejects.toThrow(
      NotFoundException,
    );
    await service.end(operator, overrideId, context);
    expect(await kv.get(`auth:override:${overrideId}`)).toBeNull();
    expect(audit.record).toHaveBeenLastCalledWith(
      expect.objectContaining({ action: 'platform.override_ended' }),
    );
    await expect(service.end(operator, overrideId, context)).rejects.toThrow(NotFoundException);
  });
});
