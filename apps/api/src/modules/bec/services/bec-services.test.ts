import { BadRequestException } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import { InconsistentBecReadError } from '../bec.errors';
import { BecFeedbackCreateSchema } from '../dto/bec.schemas';
import type { BecFeedbackRepository } from '../repositories/bec-feedback.repository';
import type { BecProfilesRepository, ExecutiveRow } from '../repositories/bec-profiles.repository';
import { BecFeedbackService } from './bec-feedback.service';
import { BecProfilesService } from './bec-profiles.service';
import { BecTrustedSendersService } from './bec-trusted-senders.service';
import { BEC_AUDIT, BEC_TX, BecMetrics, BecWriter } from './bec-writer';

const NOW = new Date('2026-11-06T12:00:00.000Z');
const scope = systemScope(7n);
const user: UserPrincipal = {
  kind: 'user',
  userId: 3n,
  userPublicId: '0190f0f0-0000-7000-8000-000000000003',
  organizationId: 7n,
  organizationPublicId: '0190f0f0-0000-7000-8000-000000000007',
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['bec:manage', 'bec:feedback']),
};
const client = { ip: '198.51.100.7', userAgent: null } as never;
const EXEC_ID = '0190f0f0-0000-7000-8000-0000000000e1';

const codeOf = async (promise: Promise<unknown>): Promise<string> => {
  try {
    await promise;
    return 'resolved';
  } catch (error) {
    if (error instanceof CodedHttpException) return error.code;
    if (error instanceof BadRequestException) return 'bad_request';
    throw error;
  }
};

function writerWith() {
  const tx = { marker: 'tx' };
  const transactions = {
    run: vi.fn((fn: (t: unknown) => Promise<unknown>, _options?: unknown) => fn(tx)),
  };
  const audit = {
    actorFrom: () => ({ type: 'user', id: user.userPublicId }),
    record: vi.fn((_entry: Record<string, unknown>, _tx?: unknown) => Promise.resolve()),
  };
  return {
    tx,
    transactions,
    audit,
    writer: new BecWriter(transactions as unknown as TransactionRunner),
  };
}

const executive = (overrides: Partial<ExecutiveRow> = {}): ExecutiveRow => ({
  id: 11n,
  publicId: EXEC_ID,
  organizationId: 7n,
  displayName: 'Anita Sharma',
  normalizedName: 'anita sharma',
  aliases: [],
  knownAddresses: ['anita@acme.example'],
  title: 'CEO',
  enabled: true,
  version: 1,
  createdAt: NOW,
  updatedAt: NOW,
  createdBy: { publicId: user.userPublicId },
  updatedBy: null,
  ...overrides,
});

function profilesSetup(
  options: { byName?: ExecutiveRow | null; count?: number; current?: ExecutiveRow | null } = {},
) {
  const w = writerWith();
  const repository = {
    lockOrganization: vi.fn(() => Promise.resolve()),
    findExecutiveByName: vi.fn(() => Promise.resolve(options.byName ?? null)),
    countExecutives: vi.fn(() => Promise.resolve(options.count ?? 0)),
    createExecutive: vi.fn(
      (_tx: unknown, _scope: unknown, publicId: string, data: Record<string, unknown>) =>
        Promise.resolve(executive({ ...data, publicId })),
    ),
    findExecutiveForUpdate: vi.fn(() =>
      Promise.resolve(options.current === undefined ? executive() : options.current),
    ),
    updateExecutive: vi.fn(() => Promise.resolve(true)),
    executiveById: vi.fn(() =>
      Promise.resolve(executive({ version: 2, displayName: 'Anita R. Sharma' })),
    ),
    deleteExecutive: vi.fn(() => Promise.resolve()),
  };
  const service = new BecProfilesService(
    { BEC_MAX_EXECUTIVES: 2, BEC_MAX_VENDORS: 2 },
    repository as unknown as BecProfilesRepository,
    w.writer,
    w.audit as unknown as AuditService,
  );
  return { ...w, repository, service };
}

describe('BecProfilesService (step 4.4 B18)', () => {
  it('creates a normalized executive under the organization lock, audited in the transaction', async () => {
    const s = profilesSetup();
    const view = await s.service.createExecutive(
      user,
      scope,
      {
        displayName: ' Anita  Sharma ',
        aliases: ['A. Sharma'],
        knownAddresses: ['Anita@ACME.example', 'anita@acme.example'],
        enabled: true,
      },
      client,
    );
    expect(s.transactions.run).toHaveBeenCalledWith(expect.any(Function), BEC_TX);
    expect(BEC_TX).toEqual({ timeoutMs: 120_000, maxWaitMs: 10_000 });
    expect(s.repository.lockOrganization).toHaveBeenCalledWith(s.tx, scope);
    expect(s.repository.createExecutive.mock.calls[0]![3]).toEqual({
      displayName: 'Anita  Sharma',
      normalizedName: 'anita sharma',
      aliases: ['A. Sharma'],
      knownAddresses: ['anita@acme.example'],
      title: null,
      enabled: true,
    });
    expect(view.knownAddresses).toEqual(['anita@acme.example']);
    expect(s.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: 7n,
        action: BEC_AUDIT.executiveCreated,
        resourceType: 'bec_executive_profile',
        resourceId: view.id,
      }),
      s.tx,
    );
  });

  it('409 executive_exists on the normalized name, 409 bec_limit_reached at the cap', async () => {
    expect(
      await codeOf(
        profilesSetup({ byName: executive() }).service.createExecutive(
          user,
          scope,
          { displayName: 'ANITA sharma', aliases: [], knownAddresses: [], enabled: true },
          client,
        ),
      ),
    ).toBe('executive_exists');
    expect(
      await codeOf(
        profilesSetup({ count: 2 }).service.createExecutive(
          user,
          scope,
          { displayName: 'Ravi Kumar', aliases: [], knownAddresses: [], enabled: true },
          client,
        ),
      ),
    ).toBe('bec_limit_reached');
    const race = profilesSetup();
    race.repository.createExecutive.mockRejectedValueOnce(
      new Prisma.PrismaClientKnownRequestError('dup', { code: 'P2002', clientVersion: 'x' }),
    );
    expect(
      await codeOf(
        race.service.createExecutive(
          user,
          scope,
          { displayName: 'Ravi Kumar', aliases: [], knownAddresses: [], enabled: true },
          client,
        ),
      ),
    ).toBe('executive_exists');
  });

  it('updates with the version compare-and-set and audits the before-image', async () => {
    const s = profilesSetup();
    const view = await s.service.updateExecutive(
      user,
      scope,
      EXEC_ID,
      { version: 1, displayName: 'Anita R. Sharma' },
      client,
    );
    expect(view.version).toBe(2);
    expect(s.repository.updateExecutive).toHaveBeenCalledWith(
      s.tx,
      scope,
      11n,
      1,
      expect.objectContaining({ normalizedName: 'anita r sharma' }),
      3n,
    );
    expect(s.audit.record.mock.calls[0]![0]).toMatchObject({
      action: BEC_AUDIT.executiveUpdated,
      metadata: {
        before: { displayName: 'Anita Sharma', version: 1 },
        after: { displayName: 'Anita R. Sharma', version: 2 },
      },
    });
    expect(
      await codeOf(
        profilesSetup().service.updateExecutive(user, scope, EXEC_ID, { version: 3 }, client),
      ),
    ).toBe('version_conflict');
    expect(
      await codeOf(
        profilesSetup({ current: null }).service.updateExecutive(
          user,
          scope,
          EXEC_ID,
          { version: 1 },
          client,
        ),
      ),
    ).toBe('bec_executive_not_found');
  });

  it('deletes with the before-image; another tenant’s id is a 404', async () => {
    const s = profilesSetup();
    await s.service.deleteExecutive(user, scope, EXEC_ID, undefined, client);
    expect(s.repository.deleteExecutive).toHaveBeenCalledWith(s.tx, scope, 11n);
    expect(s.audit.record.mock.calls[0]![0]).toMatchObject({
      action: BEC_AUDIT.executiveDeleted,
      metadata: { before: { displayName: 'Anita Sharma' } },
    });
    expect(
      await codeOf(
        profilesSetup({ current: null }).service.deleteExecutive(
          user,
          scope,
          EXEC_ID,
          undefined,
          client,
        ),
      ),
    ).toBe('bec_executive_not_found');
  });

  it('retries an inconsistent writer read once, then answers 503 inconsistent_read', async () => {
    const s = profilesSetup();
    s.repository.findExecutiveForUpdate
      .mockRejectedValueOnce(new InconsistentBecReadError('executive'))
      .mockResolvedValueOnce(executive());
    await s.service.deleteExecutive(user, scope, EXEC_ID, undefined, client);
    expect(s.transactions.run).toHaveBeenCalledTimes(2);
    const t = profilesSetup();
    t.repository.findExecutiveForUpdate.mockRejectedValue(
      new InconsistentBecReadError('executive'),
    );
    expect(await codeOf(t.service.deleteExecutive(user, scope, EXEC_ID, undefined, client))).toBe(
      'inconsistent_read',
    );
    expect(t.transactions.run).toHaveBeenCalledTimes(2);
  });

  it('refuses a free-mail vendor domain with 422 vendor_domain_freemail before any write', async () => {
    const s = profilesSetup();
    expect(
      await codeOf(
        s.service.createVendor(
          user,
          scope,
          {
            name: 'Globex',
            aliases: [],
            domains: ['globex.example', 'outlook.com'],
            knownSenders: [],
            paymentChangeSensitive: true,
            enabled: true,
          },
          client,
        ),
      ),
    ).toBe('vendor_domain_freemail');
    expect(s.transactions.run).not.toHaveBeenCalled();
  });
});

describe('BecTrustedSendersService (step 4.4 B7)', () => {
  it('refuses free-mail domains and bad expiries before any write', async () => {
    const w = writerWith();
    const service = new BecTrustedSendersService(
      { BEC_MAX_TRUSTED_SENDERS: 10 },
      {} as BecProfilesRepository,
      w.writer,
      w.audit as unknown as AuditService,
    );
    expect(
      await codeOf(
        service.create(user, scope, { kind: 'domain', value: 'gmail.com', reason: 'x' }, client),
      ),
    ).toBe('trusted_domain_freemail');
    expect(
      await codeOf(
        service.create(
          user,
          scope,
          { kind: 'address', value: 'a@b.example', reason: 'x', expiresAt: '2020-01-01T00:00:00Z' },
          client,
        ),
      ),
    ).toBe('bad_request');
    expect(w.transactions.run).not.toHaveBeenCalled();
  });
});

const FEEDBACK_ID = '0190f0f0-0000-7000-8000-0000000000fb';
const message = { id: 100n, publicId: '0190f0f0-0000-7000-8000-0000000000a1', receivedAt: NOW };

function feedbackSetup(options: { active?: number; existing?: unknown; own?: boolean } = {}) {
  const w = writerWith();
  const metricsService = new MetricsService({ service: 't' });
  const suppressionRow = (code: string, id = 1n) => ({
    id,
    publicId: `0190f0f0-0000-7000-8000-00000000050${id}`,
    organizationId: 7n,
    reasonCode: code,
    senderScope: 'domain' as const,
    senderValue: 'partner.example',
    feedbackId: 900n,
    expiresAt: new Date('2026-12-06T12:00:00.000Z'),
    createdAt: NOW,
    createdBy: { publicId: user.userPublicId },
  });
  const repository = {
    lockOrganization: vi.fn(() => Promise.resolve()),
    findMessage: vi.fn(() => Promise.resolve(message)),
    scanExists: vi.fn(() => Promise.resolve(true)),
    findResult: vi.fn(() =>
      Promise.resolve({
        id: 55n,
        organizationId: 7n,
        messageId: 100n,
        receivedAt: NOW,
        scanId: 900n,
        verdict: 'suspicious',
        rules: [
          {
            id: 'R2',
            code: 'bec.reply_to.freemail',
            category: 'identity',
            severity: 'medium',
            weight: 20,
            suppressed: null,
            evidence: [],
          },
        ],
        identity: {
          from: { address: 'billing@partner.example', registrableDomain: 'partner.example' },
        },
      }),
    ),
    finalReasonCodes: vi.fn(() => Promise.resolve(['bec.reply_to.freemail', 'bec.ai.flagged'])),
    findOwnFeedback: vi.fn(() => Promise.resolve(options.own ? { id: 1n } : null)),
    createFeedback: vi.fn(() =>
      Promise.resolve({
        id: 900n,
        publicId: FEEDBACK_ID,
        organizationId: 7n,
        messageId: 100n,
        messageReceivedAt: NOW,
        scanId: 900n,
        becResultId: 55n,
        kind: 'false_positive' as const,
        reasonCodes: ['bec.reply_to.freemail'],
        note: null,
        createdAt: NOW,
        createdBy: { publicId: user.userPublicId },
      }),
    ),
    countActiveSuppressions: vi.fn(() => Promise.resolve(options.active ?? 0)),
    findSuppressionByKey: vi.fn(() => Promise.resolve(options.existing ?? null)),
    createSuppression: vi.fn((_tx: unknown, _s: unknown, input: { reasonCode: string }) =>
      Promise.resolve(suppressionRow(input.reasonCode)),
    ),
    renewSuppression: vi.fn(() => Promise.resolve(suppressionRow('bec.reply_to.freemail', 2n))),
    purgeHistoryBatch: vi.fn(),
    exportIds: vi.fn(),
    exportFeedback: vi.fn(),
    exportResults: vi.fn(),
  };
  const service = new BecFeedbackService(
    { BEC_SUPPRESSIONS_MAX_PER_TENANT: 2 },
    repository as unknown as BecFeedbackRepository,
    w.writer,
    w.audit as unknown as AuditService,
    new BecMetrics(metricsService),
  );
  return { ...w, repository, service, metricsService, suppressionRow };
}

const fp = BecFeedbackCreateSchema.parse({
  kind: 'false_positive',
  reasonCodes: ['bec.reply_to.freemail', 'bec.ai.flagged'],
  suppress: { codes: ['bec.reply_to.freemail'], scope: 'domain', days: 30 },
});

describe('BecFeedbackService (step 4.4 B11)', () => {
  it('records feedback with a domain suppression, audited, counted', async () => {
    const s = feedbackSetup();
    const created = await s.service.record(user, scope, message.publicId, 900n, fp, client);
    expect(created).toMatchObject({
      id: FEEDBACK_ID,
      kind: 'false_positive',
      messageId: message.publicId,
      scanId: '900',
      suppressions: [
        {
          reasonCode: 'bec.reply_to.freemail',
          senderScope: 'domain',
          senderValue: 'partner.example',
          feedbackId: FEEDBACK_ID,
          expired: false,
        },
      ],
    });
    expect(s.repository.createSuppression.mock.calls[0]![2]).toMatchObject({
      reasonCode: 'bec.reply_to.freemail',
      senderScope: 'domain',
      senderValue: 'partner.example',
      feedbackId: 900n,
      userId: 3n,
    });
    expect(s.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: BEC_AUDIT.feedbackRecorded, resourceId: FEEDBACK_ID }),
      s.tx,
    );
    expect(await s.metricsService.metrics()).toContain(
      'bec_feedback_total{kind="false_positive",service="t"} 1',
    );
  });

  it('renews an existing rule and enforces the active-rule cap', async () => {
    vi.useFakeTimers({ now: NOW, toFake: ['Date'] });
    const renew = feedbackSetup({
      active: 2,
      existing: { id: 2n, expiresAt: new Date('2026-11-20T00:00:00.000Z') },
    });
    const created = await renew.service.record(user, scope, message.publicId, 900n, fp, client);
    expect(renew.repository.renewSuppression).toHaveBeenCalledWith(
      renew.tx,
      scope,
      2n,
      new Date('2026-12-06T12:00:00.000Z'),
      900n,
    );
    expect(created.suppressions).toHaveLength(1);
    const full = feedbackSetup({ active: 2 });
    expect(await codeOf(full.service.record(user, scope, message.publicId, 900n, fp, client))).toBe(
      'bec_limit_reached',
    );
    vi.useRealTimers();
  });

  it('404s and 409 feedback_exists', async () => {
    const missing = feedbackSetup();
    missing.repository.findMessage.mockResolvedValueOnce(null as never);
    expect(
      await codeOf(missing.service.record(user, scope, message.publicId, 900n, fp, client)),
    ).toBe('message_not_found');
    const noScan = feedbackSetup();
    noScan.repository.scanExists.mockResolvedValueOnce(false);
    expect(
      await codeOf(noScan.service.record(user, scope, message.publicId, 900n, fp, client)),
    ).toBe('scan_not_found');
    const noResult = feedbackSetup();
    noResult.repository.findResult.mockResolvedValueOnce(null as never);
    expect(
      await codeOf(noResult.service.record(user, scope, message.publicId, 900n, fp, client)),
    ).toBe('bec_result_not_found');
    expect(
      await codeOf(
        feedbackSetup({ own: true }).service.record(
          user,
          scope,
          message.publicId,
          900n,
          fp,
          client,
        ),
      ),
    ).toBe('feedback_exists');
  });

  it('locks the organization row before any read (serialized suppression keys and cap)', async () => {
    const s = feedbackSetup();
    await s.service.record(user, scope, message.publicId, 900n, fp, client);
    expect(s.repository.lockOrganization).toHaveBeenCalledWith(s.tx, scope);
    const lockOrder = s.repository.lockOrganization.mock.invocationCallOrder[0]!;
    for (const later of [
      s.repository.findMessage,
      s.repository.countActiveSuppressions,
      s.repository.findSuppressionByKey,
      s.repository.createSuppression,
    ]) {
      expect(later.mock.invocationCallOrder[0]!).toBeGreaterThan(lockOrder);
    }
  });

  it('maps only the (scan, user, kind) unique key to feedback_exists', async () => {
    const violation = (target: unknown) =>
      new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
        code: 'P2002',
        clientVersion: 't',
        meta: { target },
      });
    const own = feedbackSetup();
    own.repository.createFeedback.mockRejectedValueOnce(
      violation('bec_feedback_scan_id_created_by_user_id_kind_key'),
    );
    expect(await codeOf(own.service.record(user, scope, message.publicId, 900n, fp, client))).toBe(
      'feedback_exists',
    );
    const fields = feedbackSetup();
    fields.repository.createFeedback.mockRejectedValueOnce(
      violation(['scan_id', 'created_by_user_id', 'kind']),
    );
    expect(
      await codeOf(fields.service.record(user, scope, message.publicId, 900n, fp, client)),
    ).toBe('feedback_exists');
    const rule = feedbackSetup();
    const ruleError = violation('bec_suppression_rules_organization_id_reason_code_sender_sco_key');
    rule.repository.createSuppression.mockRejectedValueOnce(ruleError);
    await expect(rule.service.record(user, scope, message.publicId, 900n, fp, client)).rejects.toBe(
      ruleError,
    );
  });

  it('purges the history in batches and audits the total once', async () => {
    const s = feedbackSetup();
    s.repository.purgeHistoryBatch.mockResolvedValueOnce(5000).mockResolvedValueOnce(12);
    expect(await s.service.purgeHistory(user, scope, client)).toEqual({ deleted: 5012 });
    expect(s.repository.purgeHistoryBatch).toHaveBeenCalledTimes(2);
    expect(s.audit.record).toHaveBeenCalledTimes(1);
    expect(s.audit.record.mock.calls[0]![0]).toMatchObject({
      action: BEC_AUDIT.historyPurged,
      metadata: { deleted: 5012, batches: 2 },
    });
  });

  it('exports NDJSON lines of this page, audited first, with the next cursor', async () => {
    const s = feedbackSetup();
    s.repository.exportIds.mockResolvedValue([1n, 2n, 3n]);
    s.repository.exportFeedback.mockResolvedValue([
      {
        id: 1n,
        publicId: FEEDBACK_ID,
        kind: 'false_positive',
        createdAt: NOW,
        becResultId: 55n,
        messageReceivedAt: NOW,
      },
      {
        id: 2n,
        publicId: FEEDBACK_ID,
        kind: 'false_negative',
        createdAt: NOW,
        becResultId: 56n,
        messageReceivedAt: NOW,
      },
    ]);
    s.repository.exportResults.mockResolvedValue([
      {
        id: 55n,
        receivedAt: NOW,
        rulesVersion: 'bec-map/1',
        engineVersion: 'bec/1',
        deterministicScore: 45,
        score: 45,
        verdict: 'suspicious',
        deterministicVerdict: 'suspicious',
        rules: [],
        features: { rule_r2: 1 },
        ai: null,
        aiShadow: null,
      },
    ]);
    const stream = await s.service.export(user, scope, { limit: 2 }, client);
    expect(s.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: BEC_AUDIT.feedbackExported,
        metadata: expect.objectContaining({ records: 2, more: true }),
      }),
    );
    expect(stream.nextCursor).not.toBeNull();
    const lines: string[] = [];
    for await (const line of stream.lines) lines.push(line);
    // The second feedback's result row is missing: skipped, never invented.
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toMatchObject({
      feedbackId: FEEDBACK_ID,
      firedCodes: [],
      features: { rule_r2: 1 },
    });
    expect(lines[0]!.endsWith('\n')).toBe(true);
    expect(s.repository.exportFeedback).toHaveBeenCalledWith(scope, [1n, 2n]);
  });
});
