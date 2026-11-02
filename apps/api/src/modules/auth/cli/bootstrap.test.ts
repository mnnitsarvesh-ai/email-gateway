import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type {
  BootstrapRepository,
  BootstrapUserRecord,
} from '../repositories/bootstrap.repository';
import type {
  OrganizationAuthRecord,
  OrganizationsAuthRepository,
} from '../repositories/organizations-auth.repository';
import { BootstrapAdminService, BootstrapRefusedError } from '../services/bootstrap-admin.service';
import type { InvitationService } from '../services/invitation.service';
import type { PrincipalCacheService } from '../services/principal-cache.service';
import { BootstrapUsageError, parseBootstrapArgs } from './bootstrap-args';

describe('parseBootstrapArgs', () => {
  it('parses flags in both forms and ignores the pnpm separator', () => {
    expect(
      parseBootstrapArgs(['--', '--email', ' Ops@Example.COM ', '--display-name', 'Ops Team']),
    ).toEqual({
      email: 'ops@example.com',
      displayName: 'Ops Team',
      additional: false,
    });
    expect(parseBootstrapArgs(['--email=ops@example.com', '--additional'])).toEqual({
      email: 'ops@example.com',
      displayName: 'ops',
      additional: true,
    });
  });

  it.each([
    [[], '--email is required'],
    [['--email'], '--email needs a value'],
    [['--email', '--additional'], '--email needs a value'],
    [['--email', 'not-an-email'], 'valid email'],
    [['--email', 'a@example.com', '--admin'], 'Unknown argument: --admin'],
    [['--email', 'a@example.com', 'extra'], 'Unknown argument: (positional)'],
    [['--email', 'a@example.com', '--additional=yes'], 'takes no value'],
    [['--email', 'a@example.com', '--display-name', ' '], '--display-name'],
  ])('rejects %j', (argv, message) => {
    expect(() => parseBootstrapArgs(argv)).toThrow(BootstrapUsageError);
    expect(() => parseBootstrapArgs(argv)).toThrow(message);
  });
});

describe('BootstrapAdminService', () => {
  const platform: OrganizationAuthRecord = {
    id: 1n,
    publicId: randomUUID(),
    slug: 'platform',
    name: 'Platform operations',
    kind: 'platform',
    status: 'active',
    deletedAt: null,
  };
  let org: OrganizationAuthRecord | null;
  let activeAdmins: number;
  let existing: BootstrapUserRecord | null;
  let repo: Record<string, ReturnType<typeof vi.fn>>;
  let audit: { record: ReturnType<typeof vi.fn> };
  let service: BootstrapAdminService;

  beforeEach(() => {
    org = platform;
    activeAdmins = 0;
    existing = null;
    repo = {
      findSystemRoleId: vi.fn(() => Promise.resolve(9n)),
      countActiveWithRole: vi.fn(() => Promise.resolve(activeAdmins)),
      findUser: vi.fn(() => Promise.resolve(existing)),
      createInvitedUser: vi.fn(() =>
        Promise.resolve({ id: 5n, publicId: randomUUID(), status: 'invited', deletedAt: null }),
      ),
      resetToInvited: vi.fn(),
      ensureRole: vi.fn(),
    };
    audit = { record: vi.fn() };
    const expiresAt = new Date('2026-11-09T00:00:00Z');
    service = new BootstrapAdminService(
      { findBySlug: () => Promise.resolve(org) } as unknown as OrganizationsAuthRepository,
      repo as unknown as BootstrapRepository,
      { run: (fn: (tx: object) => Promise<unknown>) => fn({}) } as unknown as TransactionRunner,
      {
        createToken: vi.fn(() => Promise.resolve({ token: 'egt_secret', expiresAt })),
        link: (t: string) => `https://portal.example/auth/accept-invitation#token=${t}`,
      } as unknown as InvitationService,
      audit as unknown as AuditService,
      { invalidateUserByPublicId: vi.fn() } as unknown as PrincipalCacheService,
    );
  });

  const input = { email: 'ops@example.com', displayName: 'Ops', additional: false };

  it('refuses without the seeded platform organization', async () => {
    org = null;
    await expect(service.invite(input)).rejects.toThrow(/pnpm db:seed/);
  });

  it('refuses when an active super admin exists, unless --additional', async () => {
    activeAdmins = 1;
    await expect(service.invite(input)).rejects.toThrow(BootstrapRefusedError);
    await expect(service.invite({ ...input, additional: true })).resolves.toMatchObject({
      reused: false,
    });
  });

  it('refuses for an existing active or disabled user', async () => {
    existing = { id: 5n, publicId: randomUUID(), status: 'active', deletedAt: null };
    await expect(service.invite(input)).rejects.toThrow(BootstrapRefusedError);
    existing = { ...existing, status: 'disabled' };
    await expect(service.invite(input)).rejects.toThrow(BootstrapRefusedError);
  });

  it('creates an invited super admin, audits with the system actor and returns the link', async () => {
    const result = await service.invite(input);
    expect(result.link).toBe('https://portal.example/auth/accept-invitation#token=egt_secret');
    expect(repo.ensureRole).toHaveBeenCalledWith(
      {},
      { userId: 5n, roleId: 9n, organizationId: 1n },
    );
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'user.bootstrap_invited',
        actor: { type: 'system', id: null },
      }),
      {},
    );
    expect(
      JSON.stringify(audit.record.mock.calls, (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      ),
    ).not.toContain('egt_secret');
  });

  it('reuses an invited or soft-deleted user', async () => {
    existing = { id: 6n, publicId: randomUUID(), status: 'disabled', deletedAt: new Date() };
    const result = await service.invite(input);
    expect(result.reused).toBe(true);
    expect(repo.resetToInvited).toHaveBeenCalledWith(
      {},
      6n,
      expect.objectContaining({ displayName: 'Ops' }),
    );
    expect(repo.createInvitedUser).not.toHaveBeenCalled();
  });
});
