import { HttpException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type {
  ScanSettingsRepository,
  ScanSettingsRow,
} from '../repositories/scan-settings.repository';
import { ScanSettingsService } from './scan-settings.service';

const scope = systemScope(7n);
const client = { ip: '198.51.100.9', userAgent: null };
const user: Principal = {
  kind: 'user',
  userId: 42n,
  userPublicId: '0190f0f0-0000-7000-8000-000000000042',
  organizationId: 7n,
  organizationPublicId: '0190f0f0-0000-7000-8000-000000000007',
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['scan:settings_manage']),
};
const apiKey: Principal = {
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: '0190f0f0-0000-7000-8000-000000000005',
  organizationId: 7n,
  organizationPublicId: user.organizationPublicId,
  permissions: new Set(['scan:settings_manage']),
};

const config = {
  SCAN_RSPAMD_SPAM_SCORE: 6,
  SCAN_RSPAMD_SUSPICIOUS_SCORE: 4,
  SCAN_RSPAMD_SCORE_MIN: 1,
  SCAN_RSPAMD_SCORE_MAX: 15,
  SCAN_RSPAMD_PHISHING_VERDICT: 'suspicious',
  SCAN_RSPAMD_DMARC_REJECT_VERDICT: 'suspicious',
  SCAN_RSPAMD_AUTH_FAILURE_VERDICT: 'reason_only',
};

/** An in-memory scan_engine_settings table with the repository's compare-and-set. */
function fakeStore(initial?: ScanSettingsRow) {
  let row: (ScanSettingsRow & { updatedByUserId: bigint | null }) | null = initial
    ? { ...initial, updatedByUserId: null }
    : null;
  const repository = {
    list: vi.fn(() => Promise.resolve(row ? [row] : [])),
    find: vi.fn((): Promise<ScanSettingsRow | null> => Promise.resolve(row)),
    create: vi.fn((_tx: unknown, _scope: unknown, input: Record<string, unknown>) => {
      if (row) {
        return Promise.reject(
          new Prisma.PrismaClientKnownRequestError('dup', { code: 'P2002', clientVersion: 't' }),
        );
      }
      row = {
        engine: input.engine as string,
        settings: input.settings as Prisma.JsonValue,
        version: 1,
        updatedAt: new Date(),
        updatedByUserId: input.updatedByUserId as bigint | null,
      };
      return Promise.resolve(row);
    }),
    replaceIfVersion: vi.fn(
      (
        _tx: unknown,
        _scope: unknown,
        input: Record<string, unknown> & { expectedVersion: number },
      ) => {
        if (!row || row.version !== input.expectedVersion) return Promise.resolve(false);
        row = {
          ...row,
          settings: input.settings as Prisma.JsonValue,
          version: row.version + 1,
          updatedByUserId: input.updatedByUserId as bigint | null,
        };
        return Promise.resolve(true);
      },
    ),
  };
  const audits: Record<string, unknown>[] = [];
  const audit = {
    actorFrom: (p: Principal) => new AuditService({} as never).actorFrom(p),
    record: vi.fn((entry: Record<string, unknown>, tx: unknown) => {
      expect(tx).toBe(TX);
      audits.push(entry);
      return Promise.resolve();
    }),
  };
  const transactions = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn(TX)) };
  const service = new ScanSettingsService(
    config,
    repository as unknown as ScanSettingsRepository,
    transactions as unknown as TransactionRunner,
    audit as unknown as AuditService,
  );
  return { service, repository, audits, row: () => row };
}
const TX = { tx: true };

const codeOf = async (promise: Promise<unknown>) => {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const body = (error as HttpException).getResponse() as { code: string };
  return { status: (error as HttpException).getStatus(), code: body.code, error };
};

describe('ScanSettingsService (step 4.1 S8, S16)', () => {
  it('creates the first override at expectedVersion 0, audited with before/after', async () => {
    const { service, audits, row } = fakeStore();
    const view = await service.replace(
      user,
      scope,
      'rspamd',
      { expectedVersion: 0, settings: { spamScore: 7.5, authFailureVerdict: 'suspicious' } },
      client,
    );
    expect(view).toMatchObject({
      engine: 'rspamd',
      version: 1,
      override: { spamScore: 7.5, authFailureVerdict: 'suspicious' },
      effective: { spamScore: 7.5, authFailureVerdict: 'suspicious' },
      overrideApplied: true,
    });
    expect(view.note).toContain('SCAN_SETTINGS_CACHE_TTL_MS');
    expect(row()?.updatedByUserId).toBe(42n);
    expect(audits).toEqual([
      {
        organizationId: 7n,
        actor: { type: 'user', id: user.kind === 'user' ? user.userPublicId : '' },
        action: 'scan_settings.updated',
        resourceType: 'scan_engine_settings',
        resourceId: 'rspamd',
        sourceIp: '198.51.100.9',
        metadata: {
          engine: 'rspamd',
          fromVersion: 0,
          toVersion: 1,
          before: null,
          after: { spamScore: 7.5, authFailureVerdict: 'suspicious' },
        },
      },
    ]);
  });

  it('replaces at the current version (API key: no user id) and refuses a stale version', async () => {
    const { service, audits, row } = fakeStore({
      engine: 'rspamd',
      settings: { spamScore: 7 },
      version: 2,
      updatedAt: new Date(),
    });
    const view = await service.replace(
      apiKey,
      scope,
      'rspamd',
      { expectedVersion: 2, settings: { suspiciousScore: 3 } },
      client,
    );
    expect(view).toMatchObject({ version: 3, override: { suspiciousScore: 3 } });
    expect(row()?.updatedByUserId).toBeNull();
    expect(audits[0]).toMatchObject({
      actor: { type: 'api_key' },
      metadata: {
        fromVersion: 2,
        toVersion: 3,
        before: { spamScore: 7 },
        after: { suspiciousScore: 3 },
      },
    });
    const stale = await codeOf(
      service.replace(user, scope, 'rspamd', { expectedVersion: 2, settings: {} }, client),
    );
    expect(stale).toMatchObject({ status: 409, code: 'version_conflict' });
    expect((stale.error as { details: unknown }).details).toEqual({ currentVersion: 3 });
    expect(audits).toHaveLength(1);
  });

  it('a lost compare-and-set (concurrent change) is 409 with the version now', async () => {
    const store = fakeStore({ engine: 'rspamd', settings: {}, version: 1, updatedAt: new Date() });
    store.repository.replaceIfVersion.mockResolvedValueOnce(false);
    store.repository.find
      .mockResolvedValueOnce({ engine: 'rspamd', settings: {}, version: 1, updatedAt: new Date() })
      .mockResolvedValueOnce({ engine: 'rspamd', settings: {}, version: 2, updatedAt: new Date() });
    const lost = await codeOf(
      store.service.replace(user, scope, 'rspamd', { expectedVersion: 1, settings: {} }, client),
    );
    expect(lost).toMatchObject({ status: 409, code: 'version_conflict' });
    expect((lost.error as { details: unknown }).details).toEqual({ currentVersion: 2 });
    expect(store.audits).toHaveLength(0);
  });

  it('two first writes racing on the unique key: the loser is a 409', async () => {
    const store = fakeStore({ engine: 'rspamd', settings: {}, version: 1, updatedAt: new Date() });
    store.repository.find.mockResolvedValueOnce(null); // the loser read before the winner committed
    const lost = await codeOf(
      store.service.replace(user, scope, 'rspamd', { expectedVersion: 0, settings: {} }, client),
    );
    expect(lost).toMatchObject({ status: 409, code: 'version_conflict' });
    expect((lost.error as { details: unknown }).details).toEqual({ currentVersion: 1 });
  });

  it('refuses an unknown engine (404) and invalid settings (422) before any transaction', async () => {
    const { service, repository } = fakeStore();
    expect(
      await codeOf(
        service.replace(user, scope, 'clamav', { expectedVersion: 0, settings: {} }, client),
      ),
    ).toMatchObject({ status: 404, code: 'scan_engine_not_found' });
    expect(await codeOf(service.reset(user, scope, 'yara', 0, client))).toMatchObject({
      status: 404,
      code: 'scan_engine_not_found',
    });
    const invalid = await codeOf(
      service.replace(
        user,
        scope,
        'rspamd',
        { expectedVersion: 0, settings: { spamScore: 3, dmarcRejectVerdict: 'suspicious' } },
        client,
      ),
    );
    expect(invalid).toMatchObject({ status: 422, code: 'scan_settings_invalid' });
    expect((invalid.error as { details: { violations: unknown[] } }).details.violations).toEqual([
      { path: 'spamScore', code: 'threshold_order', message: expect.any(String) },
    ]);
    expect(repository.find).not.toHaveBeenCalled();
  });

  it('resets to the platform settings with a new version, audited; nothing to reset is a no-op', async () => {
    const { service, audits, row } = fakeStore({
      engine: 'rspamd',
      settings: { spamScore: 9 },
      version: 4,
      updatedAt: new Date(),
    });
    expect(await codeOf(service.reset(user, scope, 'rspamd', 3, client))).toMatchObject({
      status: 409,
      code: 'version_conflict',
    });
    const view = await service.reset(user, scope, 'rspamd', 4, client);
    expect(view).toMatchObject({ version: 5, override: null, overrideApplied: false });
    expect(view.engine === 'rspamd' && view.effective.spamScore).toBe(6);
    expect(row()?.settings).toEqual({});
    expect(audits).toEqual([
      expect.objectContaining({
        action: 'scan_settings.reset',
        metadata: {
          engine: 'rspamd',
          fromVersion: 4,
          toVersion: 5,
          before: { spamScore: 9 },
          after: null,
        },
      }),
    ]);
    const again = await service.reset(user, scope, 'rspamd', 5, client);
    expect(again.version).toBe(5);
    expect(audits).toHaveLength(1);
    // The version never repeats: an old expectedVersion cannot overwrite a newer override.
    expect(
      await codeOf(
        service.replace(user, scope, 'rspamd', { expectedVersion: 4, settings: {} }, client),
      ),
    ).toMatchObject({ status: 409 });
  });

  it('lists every catalog engine with the organization override', async () => {
    const { service } = fakeStore({
      engine: 'rspamd',
      settings: { phishingVerdict: 'malicious' },
      version: 2,
      updatedAt: new Date('2026-11-05T09:00:00Z'),
    });
    const list = await service.list(scope);
    expect(list.data.map((view) => view.engine)).toEqual(['rspamd', 'attachment', 'url']);
    expect(list.data[0]).toMatchObject({
      engine: 'rspamd',
      version: 2,
      override: { phishingVerdict: 'malicious' },
      effective: { phishingVerdict: 'malicious', spamScore: 6 },
      updatedAt: '2026-11-05T09:00:00.000Z',
    });
    expect(list.data[1]).toMatchObject({ engine: 'attachment', version: 0, override: null });
  });

  it('replaces the attachment override within the platform bounds, audited (step 4.2 A8)', async () => {
    const { service, audits, row } = fakeStore();
    const view = await service.replace(
      user,
      scope,
      'attachment',
      { expectedVersion: 0, settings: { deniedTypes: ['zip'], deniedTypeVerdict: 'malicious' } },
      client,
    );
    expect(view).toMatchObject({
      engine: 'attachment',
      version: 1,
      overrideApplied: true,
      effective: { deniedTypeVerdict: 'malicious' },
    });
    expect(row()?.settings).toEqual({ deniedTypes: ['zip'], deniedTypeVerdict: 'malicious' });
    expect(audits).toEqual([
      expect.objectContaining({
        action: 'scan_settings.updated',
        resourceId: 'attachment',
        metadata: expect.objectContaining({ engine: 'attachment', fromVersion: 0, toVersion: 1 }),
      }),
    ]);
  });

  it('refuses an attachment override that allows a platform-denied type (422)', async () => {
    const { service, row } = fakeStore();
    expect(
      await codeOf(
        service.replace(
          user,
          scope,
          'attachment',
          { expectedVersion: 0, settings: { allowedTypes: ['pe_executable'] } },
          client,
        ),
      ),
    ).toMatchObject({ status: 422, code: 'scan_settings_invalid' });
    expect(row()).toBeNull();
  });

  it('replaces the url override with normalized domains, audited (step 4.3 U13)', async () => {
    const { service, audits, row } = fakeStore();
    const view = await service.replace(
      user,
      scope,
      'url',
      {
        expectedVersion: 0,
        settings: {
          allowedDomains: ['Partner.Example.'],
          blockedDomains: ['bücher.example'],
          click: { suspicious: 'block' },
        },
      },
      client,
    );
    expect(view).toMatchObject({
      engine: 'url',
      version: 1,
      overrideApplied: true,
      effective: {
        allowedDomains: ['partner.example'],
        blockedDomains: ['xn--bcher-kva.example'],
        click: { suspicious: 'block', unknown: 'warn' },
      },
    });
    expect(row()?.settings).toEqual({
      allowedDomains: ['partner.example'],
      blockedDomains: ['xn--bcher-kva.example'],
      click: { suspicious: 'block' },
    });
    expect(audits).toEqual([
      expect.objectContaining({
        action: 'scan_settings.updated',
        resourceId: 'url',
        metadata: expect.objectContaining({
          engine: 'url',
          after: expect.objectContaining({ allowedDomains: ['partner.example'] }),
        }),
      }),
    ]);
  });

  it('refuses a url override with a public suffix (422) before any transaction', async () => {
    const { service, row } = fakeStore();
    const result = await codeOf(
      service.replace(
        user,
        scope,
        'url',
        { expectedVersion: 0, settings: { blockedDomains: ['co.uk'] } },
        client,
      ),
    );
    expect(result).toMatchObject({ status: 422, code: 'scan_settings_invalid' });
    expect((result.error as { details: { violations: unknown[] } }).details.violations).toEqual([
      expect.objectContaining({ path: 'blockedDomains.0', code: 'invalid' }),
    ]);
    expect(row()).toBeNull();
  });
});
