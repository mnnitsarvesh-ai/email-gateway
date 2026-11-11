import { HttpException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import {
  buildScoringInput,
  platformProfile,
  resolveProfile,
  type RiskResult,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryRiskProfiles } from '../../../../test/support/in-memory-risk-profiles';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import type { ClientContext } from '../../auth/services/session.service';
import { roundRowsOf } from '../domain/risk-dry-run';
import type {
  DryRunMessageRow,
  DryRunRows,
  DryRunScanRow,
  RiskDryRunRepository,
} from '../repositories/risk-dry-run.repository';
import { RiskDryRunService } from './risk-dry-run.service';
import { RiskProfilesService } from './risk-profiles.service';
import type { RiskAuditor, RiskMetrics } from './risk-writer';
import { RiskWriter } from './risk-writer';

const ORG = systemScope(5n);
const PLATFORM = 'rsk-default/1';
const MESSAGE_ID = '0190f0f0-0000-7000-8000-000000000077';
const RECEIVED = new Date('2026-11-10T10:00:00.000Z');
const COMPLETED = new Date('2026-11-10T10:00:05.000Z');

const message: DryRunMessageRow = {
  id: 77n,
  publicId: MESSAGE_ID,
  receivedAt: RECEIVED,
  organizationId: 5n,
  direction: 'inbound',
  attachmentCount: 0,
  recipientCount: 2,
};

const scanRow = (patch: Partial<DryRunScanRow> = {}): DryRunScanRow => ({
  id: 900n,
  messageId: 77n,
  receivedAt: RECEIVED,
  organizationId: 5n,
  lifecycleRound: 0,
  scanKind: 'initial',
  status: 'completed',
  requiredEngines: ['rspamd', 'dlp'],
  riskProfileVersionId: null,
  ...patch,
});

const final = (engine: string, outcome: string, reasonCodes: string[], score: string | null) => ({
  engine,
  outcome: outcome as DryRunRows['finals'][number]['outcome'],
  errorCode: null,
  reasonCodes,
  score: score === null ? null : new Prisma.Decimal(score),
  engineVersion: `${engine}/1`,
  settingsVersion: `${engine}-map/1;p=000000000000;t=none`,
  attempt: 1,
  completedAt: COMPLETED,
});

const roundRows = (withSandbox = false): DryRunRows => ({
  finals: [
    final('dlp', 'suspicious', ['dlp.action.alert', 'dlp.payment_card.number'], null),
    final('rspamd', 'spam', ['spam.suspicious_score'], '7.25'),
    ...(withSandbox ? [final('sandbox', 'suspicious', ['sandbox.behavior.suspicious'], null)] : []),
  ],
  auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
  bec: null,
  dlp: {
    action: 'alert',
    verdict: 'suspicious',
    coverage: 'complete',
    categories: [{ category: 'payment_card', count: 1, maxSeverity: 'high', maxConfidence: 0.9 }],
  },
});

const storedOf = (result: RiskResult, revision: 0 | 1) => ({
  revision,
  score: result.score,
  level: result.level,
  recommendedAction: result.recommendedAction,
  inputSha256: result.inputSha256,
  profileSha256: result.versions.profile.sha256,
});

const principal = { kind: 'user', userId: 1n } as unknown as Principal;
const client = { ip: '203.0.113.9' } as ClientContext;

function setup(scan: DryRunScanRow = scanRow(), rows: DryRunRows = roundRows()) {
  const store = new InMemoryRiskProfiles();
  const results: string[] = [];
  const metrics = {
    profileChanges: { inc: vi.fn() },
    dryRuns: { inc: vi.fn(({ result }: { result: string }) => results.push(result)) },
  } as unknown as RiskMetrics;
  const reads = {
    message: vi.fn((_s: unknown, id: string) =>
      Promise.resolve(id === MESSAGE_ID ? message : null),
    ),
    scan: vi.fn((_s: unknown, _m: unknown, id: bigint) =>
      Promise.resolve(id === scan.id ? scan : null),
    ),
    roundRows: vi.fn(() => Promise.resolve(rows)),
    storedScore: vi.fn((..._args: unknown[]) => Promise.resolve(null as unknown)),
  };
  const settings = { RISK_PLATFORM_PROFILE: PLATFORM, RISK_PROFILE_MAX_VERSIONS: 200 };
  const service = new RiskDryRunService(
    settings,
    reads as unknown as RiskDryRunRepository,
    store.repository,
    metrics,
  );
  const profiles = new RiskProfilesService(
    settings,
    store.repository,
    new RiskWriter(store.transactions as unknown as TransactionRunner),
    { record: () => Promise.resolve() } as unknown as RiskAuditor,
    metrics,
  );
  return { service, profiles, store, reads, results };
}

async function refusal(promise: Promise<unknown>): Promise<{ status: number; code?: string }> {
  const error: unknown = await promise.then(
    () => expect.fail('expected a refusal'),
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  return {
    status: (error as HttpException).getStatus(),
    ...(error instanceof CodedHttpException && { code: error.code }),
  };
}

const WRITE_METHODS = [
  'lockOrganization',
  'profileForUpdate',
  'createProfile',
  'versionForUpdate',
  'versionByIdTx',
  'createVersion',
  'updateDraft',
  'deleteDraft',
  'publishDraft',
  'movePointer',
];

describe('roundRowsOf (R12: the rows exactly as the email-worker passes them)', () => {
  it('carries the Decimal score as toString() and JSON columns as read', () => {
    const rows = roundRowsOf(message, scanRow(), roundRows());
    expect(rows.scan).toEqual({
      requiredEngines: ['rspamd', 'dlp'],
      scanKind: 'initial',
      lifecycleRound: 0,
      status: 'completed',
    });
    expect(rows.message).toEqual({ direction: 'inbound', attachmentCount: 0, recipientCount: 2 });
    expect(rows.finals.find((f) => f.engine === 'rspamd')!.score).toBe('7.25');
    expect(rows.dlp!.categories).toEqual(roundRows().dlp!.categories);
  });
});

describe('RiskDryRunService (R15)', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('reproduces the stored score with profile active (platform snapshot) and writes nothing', async () => {
    const expected = scoreRisk(
      buildScoringInput(roundRowsOf(message, scanRow(), roundRows()), 0),
      platformProfile(PLATFORM),
    );
    t.reads.storedScore.mockResolvedValue(storedOf(expected, 0));
    const response = await t.service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: 'active',
      revision: 0,
    });
    expect(response.result).toEqual({ ...expected, revision: 0 });
    expect(response.stored).toEqual(storedOf(expected, 0));
    expect(response.reproducible).toBe(true);
    expect(t.reads.storedScore).toHaveBeenCalledWith(ORG, message, 900n, 0);
    // No write of any kind: no writer transaction, no write repository method.
    expect(t.store.txOptions).toEqual([]);
    expect(t.store.calls.filter((c) => WRITE_METHODS.includes(c))).toEqual([]);
    expect(t.results).toEqual(['ok']);
  });

  it('uses the round’s snapshot version for profile active (and reproduces its score)', async () => {
    const draft = await t.profiles.createDraft(
      principal,
      ORG,
      { overrides: { actions: { medium: 'quarantine' }, thresholds: { medium: 250 } } },
      client,
    );
    await t.profiles.publish(
      principal,
      ORG,
      draft.id,
      { activate: true, expectedRowVersion: 1 },
      client,
    );
    const versionId = t.store.versions[0]!.id;
    const scan = scanRow({ riskProfileVersionId: versionId });
    const s = setup(scan);
    // Share the store state: re-use the first store's repository.
    const service = new RiskDryRunService(
      { RISK_PLATFORM_PROFILE: PLATFORM },
      s.reads as unknown as RiskDryRunRepository,
      t.store.repository,
      { dryRuns: { inc: vi.fn() } } as unknown as RiskMetrics,
    );
    const resolved = resolveProfile(PLATFORM, {
      publicId: draft.id,
      versionNo: 1,
      baseProfile: PLATFORM,
      overrides: { actions: { medium: 'quarantine' }, thresholds: { medium: 250 } },
    });
    const expected = scoreRisk(
      buildScoringInput(roundRowsOf(message, scan, roundRows()), 0),
      resolved,
    );
    s.reads.storedScore.mockResolvedValue(storedOf(expected, 0));
    const calls = t.store.calls.length;
    const response = await service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: 'active',
      revision: 0,
    });
    expect(response.result.versions.profile).toEqual({
      source: 'tenant',
      id: resolved.id,
      versionNo: 1,
      sha256: resolved.sha256,
    });
    expect(response.result).toEqual({ ...expected, revision: 0 });
    expect(response.reproducible).toBe(true);
    expect(t.store.calls.slice(calls)).toEqual(['versionById']);
  });

  it('scores against the platform, a draft version and an inline document', async () => {
    const platform = await t.service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: 'platform',
      revision: 0,
    });
    expect(platform.result.versions.profile.source).toBe('platform');
    expect(platform.stored).toBeNull();
    expect(platform.reproducible).toBe(false);

    const draft = await t.profiles.createDraft(
      principal,
      ORG,
      { overrides: { thresholds: { low: 50, medium: 200 } } },
      client,
    );
    const byVersion = await t.service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: { versionId: draft.id },
      revision: 0,
    });
    expect(byVersion.result.versions.profile).toMatchObject({ source: 'tenant', versionNo: 1 });

    const inline = await t.service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: { overrides: { thresholds: { low: 50, medium: 200 } } },
      revision: 0,
    });
    expect(inline.result.versions.profile).toMatchObject({
      source: 'tenant',
      id: `${PLATFORM}+t:inline`,
      versionNo: null,
      sha256: byVersion.result.versions.profile.sha256,
    });
    expect(inline.result.score).toBe(byVersion.result.score);
    // The input does not depend on the profile.
    expect(inline.result.inputSha256).toBe(platform.result.inputSha256);
  });

  it('refuses an invalid inline document (400, before any database read) and a foreign version (404)', async () => {
    const invalid = await refusal(
      t.service.dryRun(ORG, MESSAGE_ID, 900n, {
        profile: { overrides: { thresholds: { critical: 990 } } },
        revision: 0,
      }),
    );
    expect(invalid).toEqual({ status: 400, code: 'risk_profile_invalid' });
    expect(t.reads.message).not.toHaveBeenCalled();
    const other = await t.profiles.createDraft(principal, systemScope(6n), {}, client);
    const foreign = await refusal(
      t.service.dryRun(ORG, MESSAGE_ID, 900n, { profile: { versionId: other.id }, revision: 0 }),
    );
    expect(foreign).toEqual({ status: 404, code: 'risk_profile_version_not_found' });
    expect(t.results).toEqual(['invalid_profile', 'not_found']);
  });

  it('is 404 for an unknown or foreign message or scan', async () => {
    const noMessage = await refusal(
      t.service.dryRun(ORG, '0190f0f0-0000-7000-8000-000000000999', 900n, {
        profile: 'platform',
        revision: 0,
      }),
    );
    expect(noMessage).toEqual({ status: 404, code: 'message_not_found' });
    const noScan = await refusal(
      t.service.dryRun(ORG, MESSAGE_ID, 901n, { profile: 'platform', revision: 0 }),
    );
    expect(noScan).toEqual({ status: 404, code: 'scan_not_found' });
    expect(t.reads.message).toHaveBeenCalledWith(ORG, expect.any(String));
  });

  it('is 409 scan_round_not_complete while pending or running', async () => {
    for (const status of ['pending', 'running'] as const) {
      const s = setup(scanRow({ status }));
      const error = await refusal(
        s.service.dryRun(ORG, MESSAGE_ID, 900n, { profile: 'platform', revision: 0 }),
      );
      expect(error).toEqual({ status: 409, code: 'scan_round_not_complete' });
      expect(s.reads.roundRows).not.toHaveBeenCalled();
      expect(s.results).toEqual(['not_complete']);
    }
  });

  it('scores revision 1 only with a non-skipped sandbox final', async () => {
    const missing = await refusal(
      t.service.dryRun(ORG, MESSAGE_ID, 900n, { profile: 'platform', revision: 1 }),
    );
    expect(missing).toEqual({ status: 409, code: 'risk_revision_unavailable' });
    const s = setup(scanRow(), roundRows(true));
    const response = await s.service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: 'platform',
      revision: 1,
    });
    expect(response.result.revision).toBe(1);
    expect(response.result.evidence.sandbox).toEqual({ outcome: 'suspicious' });
    expect(s.reads.storedScore).toHaveBeenCalledWith(ORG, message, 900n, 1);
  });

  it('returns the fail-safe error result for malformed round rows, as the worker stores it', async () => {
    const s = setup(scanRow({ requiredEngines: null }));
    const response = await s.service.dryRun(ORG, MESSAGE_ID, 900n, {
      profile: 'platform',
      revision: 0,
    });
    expect(response.result).toMatchObject({
      status: 'error',
      level: 'high',
      verdict: 'unknown',
      recommendedAction: 'quarantine',
    });
    expect(response.result.reasonCodes).toContain('risk.scoring_error');
  });
});
