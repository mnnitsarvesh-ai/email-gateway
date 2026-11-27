import { describe, expect, it, vi } from 'vitest';
import { InconsistentNotificationReadError } from './notification-reads';
import { ReportFeedbackReads } from './report-feedback-reads';

/** Writer reads of the reporter feedback (step API-3 C12): organization scope and echo checks. */
const REPORT = '0192f0c4-eeee-7fff-8aaa-0000000000d1';
const reads = new ReportFeedbackReads();

describe('ReportFeedbackReads.report', () => {
  const row = {
    publicId: REPORT,
    organizationId: 7n,
    status: 'resolved',
    reporterAddress: ' Pat@Acme.example ',
    analystVerdict: 'clean',
    reportedAt: new Date('2026-11-26T08:15:00.000Z'),
  };

  it('scopes to the organization, lower-cases the address and selects no content', async () => {
    const findFirst = vi.fn((_args: { select: Record<string, boolean> }) => Promise.resolve(row));
    const tx = { apiUserReport: { findFirst } } as never;
    expect(await reads.report(tx, 7n, REPORT)).toMatchObject({
      reporterAddress: 'pat@acme.example',
      analystVerdict: 'clean',
    });
    const args = findFirst.mock.calls[0]![0] as {
      where: unknown;
      select: Record<string, boolean>;
    };
    expect(args.where).toEqual({ publicId: REPORT, organizationId: 7n });
    expect(Object.keys(args.select)).not.toEqual(
      expect.arrayContaining(['original', 'analystNote']),
    );
    expect(args.select.original).toBeUndefined();
    expect(args.select.analystNote).toBeUndefined();
  });

  it('null when absent; a foreign echo is an inconsistent read', async () => {
    const none = { apiUserReport: { findFirst: () => Promise.resolve(null) } } as never;
    expect(await reads.report(none, 7n, REPORT)).toBeNull();
    const foreign = {
      apiUserReport: { findFirst: () => Promise.resolve({ ...row, organizationId: 8n }) },
    } as never;
    await expect(reads.report(foreign, 7n, REPORT)).rejects.toBeInstanceOf(
      InconsistentNotificationReadError,
    );
  });
});

describe('ReportFeedbackReads.ownDomain', () => {
  it('verified or active, non-deleted domains of the organization only', async () => {
    const findFirst = vi.fn(() => Promise.resolve({ organizationId: 7n, name: 'acme.example' }));
    const tx = { domain: { findFirst } } as never;
    expect(await reads.ownDomain(tx, 7n, 'acme.example')).toBe(true);
    expect(findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          organizationId: 7n,
          name: 'acme.example',
          status: { in: ['verified', 'active'] },
          deletedAt: null,
        },
      }),
    );
    const none = { domain: { findFirst: () => Promise.resolve(null) } } as never;
    expect(await reads.ownDomain(none, 7n, 'outside.example')).toBe(false);
  });
});

describe('ReportFeedbackReads.reporterResolves', () => {
  const txOf = (mailbox: unknown, user: unknown) =>
    ({
      apiMailboxAddress: { findFirst: vi.fn(() => Promise.resolve(mailbox)) },
      user: { findFirst: vi.fn(() => Promise.resolve(user)) },
    }) as never;
  const address = 'pat@acme.example';
  const mailboxRow = (over: Record<string, unknown> = {}) => ({
    organizationId: 7n,
    address,
    mailbox: { organizationId: 7n, status: 'active', deletedAt: null, ...over },
  });

  it('an organization mailbox address that is not deleted resolves', async () => {
    expect(await reads.reporterResolves(txOf(mailboxRow(), null), 7n, address)).toBe(true);
  });

  it('a deleted mailbox falls back to an active user; neither → false', async () => {
    const user = { organizationId: 7n, email: 'Pat@Acme.example', status: 'active' };
    expect(
      await reads.reporterResolves(txOf(mailboxRow({ status: 'deleted' }), user), 7n, address),
    ).toBe(true);
    expect(
      await reads.reporterResolves(txOf(mailboxRow({ deletedAt: new Date() }), null), 7n, address),
    ).toBe(false);
    expect(await reads.reporterResolves(txOf(null, null), 7n, address)).toBe(false);
  });

  it('a foreign mailbox or user echo is an inconsistent read', async () => {
    await expect(
      reads.reporterResolves(txOf(mailboxRow({ organizationId: 8n }), null), 7n, address),
    ).rejects.toBeInstanceOf(InconsistentNotificationReadError);
    await expect(
      reads.reporterResolves(
        txOf(null, { organizationId: 8n, email: address, status: 'active' }),
        7n,
        address,
      ),
    ).rejects.toBeInstanceOf(InconsistentNotificationReadError);
  });
});
