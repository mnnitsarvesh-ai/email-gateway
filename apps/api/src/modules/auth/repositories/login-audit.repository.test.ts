import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { type LoginAuditEntry, LoginAuditRepository } from './login-audit.repository';

function harness(platform: { id: bigint } | null) {
  const loginCreate = vi.fn((_: unknown) =>
    Promise.resolve({ id: 41n, createdAt: new Date('2026-11-18T10:00:00.000Z') }),
  );
  const outboxCreate = vi.fn((_: { data: Record<string, unknown> }) => Promise.resolve({ id: 1n }));
  const tx = { loginAuditLog: { create: loginCreate }, messageOutbox: { create: outboxCreate } };
  const findFirst = vi.fn(() => Promise.resolve(platform));
  const prisma = {
    organization: { findFirst },
    $transaction: vi.fn((fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
  } as unknown as PrismaService;
  return { repository: new LoginAuditRepository(prisma), loginCreate, outboxCreate, findFirst };
}

const entry = (overrides: Partial<LoginAuditEntry> = {}): LoginAuditEntry => ({
  organizationId: 7n,
  userId: 9n,
  emailAttempted: 'Alice@Tenant.test',
  outcome: 'success',
  failureReason: null,
  ipAddress: '203.0.113.5',
  userAgent: 'Mozilla/5.0',
  ...overrides,
});

describe('LoginAuditRepository (step 8.4 D5)', () => {
  it('writes the row and auth.login.recorded.v1 in one transaction (user organization, channel)', async () => {
    const h = harness({ id: 1n });
    await h.repository.insert(entry({ channel: 'portal' }));
    expect(h.loginCreate.mock.calls[0]![0]).toMatchObject({
      data: { emailAttempted: 'alice@tenant.test', organizationId: 7n, userId: 9n },
    });
    // The channel is never stored in the row.
    expect(
      JSON.stringify(h.loginCreate.mock.calls[0]![0], (_, v: unknown) =>
        typeof v === 'bigint' ? String(v) : v,
      ),
    ).not.toContain('portal');
    const data = h.outboxCreate.mock.calls[0]![0].data;
    expect(data).toMatchObject({
      organizationId: 7n,
      eventType: 'auth.login.recorded.v1',
      aggregateType: 'login',
      aggregateId: '41',
      correlationId: 'login:41',
      payload: {
        loginAuditId: '41',
        occurredAt: '2026-11-18T10:00:00.000Z',
        outcome: 'success',
        failureReason: null,
        accountKnown: true,
        userId: '9',
        channel: 'portal',
      },
    });
    expect(h.findFirst).not.toHaveBeenCalled();
  });

  it('routes unknown accounts to the platform organization, resolved once', async () => {
    const h = harness({ id: 1n });
    const unknown = entry({
      organizationId: 5n,
      userId: null,
      outcome: 'failure',
      failureReason: 'unknown_account',
    });
    await h.repository.insert(unknown);
    await h.repository.insert(unknown);
    expect(h.findFirst).toHaveBeenCalledTimes(1);
    expect(h.outboxCreate.mock.calls[0]![0].data).toMatchObject({
      organizationId: 1n,
      payload: { accountKnown: false, userId: null, channel: 'api' },
    });
  });

  it('still writes the row when no platform organization exists (event skipped)', async () => {
    const h = harness(null);
    await h.repository.insert(
      entry({ userId: null, outcome: 'failure', failureReason: 'unknown_account' }),
    );
    expect(h.loginCreate).toHaveBeenCalledTimes(1);
    expect(h.outboxCreate).not.toHaveBeenCalled();
  });
});
