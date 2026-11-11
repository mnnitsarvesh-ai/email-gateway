import { HttpException } from '@nestjs/common';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  type RoundRows,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import { describe, expect, it, vi } from 'vitest';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { NO_DLP_IDS } from '../../dlp/domain/dlp-result';
import { encodeScanCursor } from '../domain/message-scans';
import type {
  LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../repositories/message-lifecycle-read.repository';
import type {
  MessageScansReadRepository,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';
import { MessageScansReadService } from './message-scans-read.service';

const scope = systemScope(3n);
/** A caller with message:read only (the D20 permission split: no dlp section). */
const reader = { permissions: new Set(['message:read']) } as unknown as Principal;
const message: LifecycleMessageRow = {
  id: 10n,
  publicId: '0190f0f0-0000-7000-8000-000000000010',
  receivedAt: new Date('2026-11-05T08:00:00Z'),
  direction: 'inbound',
  status: 'scanned',
  statusReason: null,
  version: 6,
  lifecycleRound: 2,
  statusChangedAt: new Date('2026-11-05T08:00:00Z'),
};
const round = (id: bigint, lifecycleRound: number): ScanRoundRow => ({
  id,
  lifecycleRound,
  scanKind: lifecycleRound === 0 ? 'initial' : 'rescan',
  status: 'completed',
  scanVerdict: 'clean',
  reasonCodes: [],
  requiredEngines: ['rspamd'],
  startedAt: null,
  completedAt: null,
  deadlineAt: null,
});

function setup(rows: ScanRoundRow[], found = true) {
  const lifecycle = { findMessage: vi.fn(() => Promise.resolve(found ? message : null)) };
  const scans = {
    rounds: vi.fn(() => Promise.resolve(rows)),
    engineResults: vi.fn(() => Promise.resolve([] as unknown[])),
    authResults: vi.fn(() => Promise.resolve([])),
    attachmentResults: vi.fn(() => Promise.resolve([] as unknown[])),
    attachmentParts: vi.fn((..._args: unknown[]) => Promise.resolve([] as unknown[])),
    sandboxSubmissions: vi.fn(() => Promise.resolve([] as unknown[])),
    sandboxAnalyses: vi.fn((..._args: unknown[]) => Promise.resolve([] as unknown[])),
    sandboxArtifacts: vi.fn((..._args: unknown[]) => Promise.resolve([] as unknown[])),
    messageUrls: vi.fn(() => Promise.resolve([] as unknown[])),
    urlResults: vi.fn(() => Promise.resolve([] as unknown[])),
    urlRewrites: vi.fn(() => Promise.resolve([] as unknown[])),
    urlInspections: vi.fn(() => Promise.resolve([] as unknown[])),
    urlClicks: vi.fn(() => Promise.resolve([] as unknown[])),
    dlpResults: vi.fn(() => Promise.resolve([] as unknown[])),
    dlpEvidence: vi.fn(() => Promise.resolve([] as unknown[])),
    dlpPublicIds: vi.fn(() => Promise.resolve(NO_DLP_IDS)),
    riskScores: vi.fn(() => Promise.resolve([] as unknown[])),
  };
  const service = new MessageScansReadService(
    lifecycle as unknown as MessageLifecycleReadRepository,
    scans as unknown as MessageScansReadRepository,
  );
  return { service, lifecycle, scans };
}

describe('MessageScansReadService (step 4.1 S16)', () => {
  it('pages newest round first with a round cursor, reading only the page’s scans', async () => {
    const { service, scans } = setup([round(30n, 2), round(20n, 1), round(10n, 0)]);
    const page = await service.list(reader, scope, message.publicId, { limit: 2 });
    expect(page.messageId).toBe(message.publicId);
    expect(page.data.map((r) => r.round)).toEqual([2, 1]);
    expect(page.nextCursor).toBe(encodeScanCursor(1));
    expect(scans.rounds).toHaveBeenCalledWith(scope, message, { take: 3 });
    expect(scans.engineResults).toHaveBeenCalledWith(scope, message, [30n, 20n]);
    expect(scans.authResults).toHaveBeenCalledWith(scope, message, [30n, 20n]);

    const next = setup([round(10n, 0)]);
    const last = await next.service.list(reader, scope, message.publicId, {
      limit: 2,
      cursor: encodeScanCursor(1),
    });
    expect(next.scans.rounds).toHaveBeenCalledWith(scope, message, { take: 3, beforeRound: 1 });
    expect(last.nextCursor).toBeNull();
  });

  it('is 404 message_not_found for an unknown or foreign message (looked up in the scope)', async () => {
    const { service, lifecycle, scans } = setup([], false);
    const error: unknown = await service
      .list(reader, scope, message.publicId, { limit: 10 })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpException);
    expect((error as HttpException).getStatus()).toBe(404);
    expect(lifecycle.findMessage).toHaveBeenCalledWith(scope, message.publicId);
    expect(scans.rounds).not.toHaveBeenCalled();
  });

  it('adds the per-attachment results to the attachment engine entry (step 4.2 A16)', async () => {
    const { service, scans } = setup([round(30n, 2)]);
    const completedAt = new Date('2026-11-05T08:00:05Z');
    scans.engineResults.mockResolvedValue([
      {
        scanId: 30n,
        engine: 'attachment',
        engineVersion: 'clamav/1.4.6/28173;yara-x/0.10.0/462fab6e5cc4',
        outcome: 'malicious',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['malware.clamav'],
        errorCode: null,
        settingsVersion: 'attachment-map/1;p=abc;t=none',
        durationMs: 40,
        evidence: { signals: [] },
        attempt: 1,
        isFinal: true,
        completedAt,
      },
    ]);
    scans.attachmentResults.mockResolvedValue([
      {
        scanId: 30n,
        attachmentId: 900n,
        partIndex: 1,
        sha256: 'a'.repeat(64),
        sizeBytes: 68,
        detectedType: 'text',
        typeFamily: 'text',
        typeMismatch: false,
        verdict: 'malicious',
        reasonCodes: ['malware.clamav'],
        clamavSignature: 'Eicar-Test-Signature',
        clamavEngineVersion: '1.4.6',
        clamavDbVersion: 28173,
        yaraBundleId: null,
        yaraMatches: null,
        archive: null,
        knownHashSeverity: null,
        cacheResult: 'miss',
        durationMs: 12,
      },
    ]);
    scans.attachmentParts.mockResolvedValue([
      { partIndex: 1, filename: 'eicar.txt', declaredContentType: 'text/plain' },
    ]);
    const page = await service.list(reader, scope, message.publicId, { limit: 10 });
    expect(scans.attachmentParts).toHaveBeenCalledWith(scope, message, [1]);
    expect(scans.attachmentResults).toHaveBeenCalledWith(scope, message, [30n]);
    expect(scans.sandboxSubmissions).toHaveBeenCalledWith(scope, message, [30n]);
    expect(page.data[0]!.engines[0]).toMatchObject({
      engine: 'attachment',
      outcome: 'malicious',
      attachments: [
        {
          partIndex: 1,
          filename: 'eicar.txt',
          declaredContentType: 'text/plain',
          verdict: 'malicious',
          reasonCodes: ['malware.clamav'],
          clamav: { signature: 'Eicar-Test-Signature', engineVersion: '1.4.6', dbVersion: 28173 },
          sandbox: null,
        },
      ],
    });
  });

  it('reads the URL rows only when a page round has a url engine row (step 4.3 U16)', async () => {
    const without = setup([round(30n, 2)]);
    await without.service.list(reader, scope, message.publicId, { limit: 10 });
    expect(without.scans.messageUrls).not.toHaveBeenCalled();
    expect(without.scans.urlClicks).not.toHaveBeenCalled();

    const { service, scans } = setup([round(30n, 2)]);
    scans.engineResults.mockResolvedValue([
      {
        scanId: 30n,
        engine: 'url',
        engineVersion: 'url/1;url-fetch/1;aaaaaaaa;bbbbbbbb',
        outcome: 'skipped',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['url.none'],
        errorCode: null,
        settingsVersion: 'url-map/1;p=abc;t=none',
        durationMs: 40,
        evidence: { signals: [] },
        attempt: 1,
        isFinal: true,
        completedAt: new Date('2026-11-05T08:00:05.500Z'),
      },
    ]);
    scans.urlRewrites.mockResolvedValue([
      {
        scanId: 30n,
        lifecycleRound: 2,
        status: 'skipped',
        skipReason: 'no_urls',
        linksRewritten: 0,
        partsRewritten: 0,
        dkimSigned: false,
        expiresAt: null,
      },
    ]);
    const page = await service.list(reader, scope, message.publicId, { limit: 10 });
    expect(scans.messageUrls).toHaveBeenCalledWith(scope, message);
    expect(scans.urlResults).toHaveBeenCalledWith(scope, message, [30n]);
    expect(scans.urlRewrites).toHaveBeenCalledWith(scope, message, [30n]);
    expect(scans.urlInspections).toHaveBeenCalledWith(scope, message, [30n]);
    expect(scans.urlClicks).toHaveBeenCalledWith(scope, message);
    expect(page.data[0]!.engines[0]).toMatchObject({
      engine: 'url',
      outcome: 'skipped',
      durationMs: null,
      completedAt: '2026-11-05T08:00:05.000Z',
      urls: [],
      rewrite: { status: 'skipped', skipReason: 'no_urls' },
    });
  });

  it('shows the masked dlp section only to dlp:read holders (step 4.5 D20 permission split)', async () => {
    const dlpEngineRow = {
      scanId: 30n,
      engine: 'dlp',
      engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
      outcome: 'suspicious',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['dlp.action.alert', 'dlp.payment_card.number'],
      errorCode: null,
      settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
      durationMs: 812,
      evidence: { signals: [{ name: 'LEAK', score: 1, options: ['4532015112830366'] }] },
      attempt: 1,
      isFinal: true,
      completedAt: new Date('2026-11-05T08:00:05.700Z'),
    };
    const stored = {
      scanId: 30n,
      engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
      rulesVersion: 'dlp-map/1',
      settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
      policyVersion: 'pol/1;h=0123456789ab',
      extractorVersion: 'dlp-extract/1',
      verdict: 'suspicious',
      action: 'alert',
      actionSource: 'default_policy',
      matchedPolicyId: null,
      matchedRuleId: null,
      coverage: 'complete',
      coverageDetail: [
        { source: 'body_text', format: 'text', status: 'scanned', reasons: [], chars: 40 },
      ],
      categories: [
        { category: 'payment_card', count: 1, maxSeverity: 'high', maxConfidence: 0.95 },
      ],
      findings: [
        {
          detector: 'PC1',
          code: 'dlp.payment_card.number',
          category: 'payment_card',
          severity: 'high',
          confidence: 0.95,
          count: 1,
          capped: false,
          sources: [{ kind: 'body_text' }],
          masked: ['************0366'],
        },
      ],
      policy: { winner: null, matched: [], exceptionsApplied: [] },
      evidenceStatus: 'disabled',
    };
    const hidden = setup([round(30n, 2)]);
    hidden.scans.engineResults.mockResolvedValue([dlpEngineRow]);
    const withheld = await hidden.service.list(reader, scope, message.publicId, { limit: 10 });
    expect(hidden.scans.dlpResults).not.toHaveBeenCalled();
    expect(withheld.data[0]!.engines[0]).toMatchObject({
      engine: 'dlp',
      outcome: 'suspicious',
      reasonCodes: ['dlp.action.alert', 'dlp.payment_card.number'],
      symbols: [],
      dlp: null,
      durationMs: null,
      completedAt: '2026-11-05T08:00:05.000Z',
    });
    expect(JSON.stringify(withheld)).not.toContain('0366');

    const analyst = {
      permissions: new Set(['message:read', 'dlp:read']),
    } as unknown as Principal;
    const shown = setup([round(30n, 2)]);
    shown.scans.engineResults.mockResolvedValue([dlpEngineRow]);
    shown.scans.dlpResults.mockResolvedValue([stored]);
    const page = await shown.service.list(analyst, scope, message.publicId, { limit: 10 });
    expect(shown.scans.dlpResults).toHaveBeenCalledWith(scope, message, [30n]);
    expect(shown.scans.dlpEvidence).toHaveBeenCalledWith(scope, message, [30n]);
    expect(page.data[0]!.engines[0]).toMatchObject({
      engine: 'dlp',
      symbols: [],
      dlp: {
        verdict: 'suspicious',
        action: 'alert',
        actionSource: 'default_policy',
        findings: [{ detector: 'PC1', masked: ['************0366'] }],
        evidence: { status: 'disabled', expiresAt: null, purged: false },
      },
    });
    expect(JSON.stringify(page)).not.toContain('4532015112830366');
  });
});

describe('MessageScansReadService: sandbox (step 4.6 X18)', () => {
  const TASK = '0193a7c0-0000-7000-8000-00000000abcd';
  const sub = (overrides: Record<string, unknown>) => ({
    id: 501n,
    scanId: 30n,
    attachmentId: 900n,
    partIndex: 1,
    sha256: 'a'.repeat(64),
    status: 'completed',
    skipReason: null,
    sandboxVerdict: 'unknown',
    sandboxReasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
    completedAt: new Date('2026-11-08T08:00:05.600Z'),
    analysisId: 40n,
    externalRef: TASK,
    ...overrides,
  });

  it('reads analyses and artifacts only by the ids of the organization’s terminal submissions', async () => {
    const { service, scans } = setup([round(30n, 2)]);
    scans.engineResults.mockResolvedValue([
      {
        scanId: 30n,
        engine: 'sandbox',
        engineVersion: '0.1.0+disabled/disabled/1',
        outcome: 'unknown',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['sandbox.not_executed'],
        errorCode: null,
        settingsVersion: null,
        durationMs: 0,
        evidence: { submissions: 2, executed: 0, isolation: ['none'] },
        attempt: 1,
        isFinal: true,
        completedAt: new Date('2026-11-08T08:00:06.900Z'),
      },
    ]);
    scans.sandboxSubmissions.mockResolvedValue([
      sub({}),
      sub({
        id: 502n,
        attachmentId: 901n,
        partIndex: 2,
        status: 'skipped',
        skipReason: 'type_excluded',
        sandboxVerdict: null,
        sandboxReasonCodes: ['sandbox.type_excluded'],
        analysisId: null,
        externalRef: null,
      }),
      sub({ id: 503n, attachmentId: 902n, partIndex: 3, status: 'submitted', externalRef: null }),
    ]);
    scans.sandboxAnalyses.mockResolvedValue([
      {
        id: 40n,
        publicId: TASK,
        report: null,
        backend: 'disabled',
        backendVersion: 'disabled/1',
        isolation: 'none',
        executed: false,
        controllerVersion: '0.1.0',
        analyzerVersion: null,
        mapVersion: 'sandbox-map/1',
      },
    ]);
    const page = await service.list(reader, scope, message.publicId, { limit: 10 });
    expect(scans.sandboxAnalyses).toHaveBeenCalledWith([40n]);
    expect(scans.sandboxArtifacts).toHaveBeenCalledWith([40n]);
    const entry = page.data[0]!.engines.find((e) => e.engine === 'sandbox')!;
    expect(entry).toMatchObject({ outcome: 'unknown', durationMs: null, symbols: [] });
    expect(entry.submissions).toEqual([
      expect.objectContaining({
        submissionId: '501',
        status: 'completed',
        executed: false,
        isolation: 'none',
        backend: 'disabled',
        completedAt: '2026-11-08T08:00:05.000Z',
      }),
      expect.objectContaining({
        submissionId: '502',
        status: 'skipped',
        skipReason: 'type_excluded',
      }),
      expect.objectContaining({ submissionId: '503', status: 'submitted', executed: null }),
    ]);
  });
});

/** A stored score row as the email-worker writes it (the library's own mapping). */
function storedRisk(scanId: bigint, revision: 0 | 1, rspamdCodes: string[]) {
  const rows: RoundRows = {
    scan: {
      requiredEngines: ['rspamd'],
      scanKind: 'initial',
      lifecycleRound: 0,
      status: 'completed',
    },
    message: { direction: 'inbound', attachmentCount: 0, recipientCount: 1 },
    finals: [
      {
        engine: 'rspamd',
        outcome: rspamdCodes.length > 0 ? 'spam' : 'clean',
        errorCode: null,
        reasonCodes: rspamdCodes.length > 0 ? rspamdCodes : ['clean.below_threshold'],
        score: '9.5',
        engineVersion: 'rspamd/3.13.2',
        settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
        attempt: 1,
        completedAt: new Date('2026-11-05T08:00:05Z'),
      },
      ...(revision === 1
        ? [
            {
              engine: 'sandbox',
              outcome: 'clean' as const,
              errorCode: null,
              reasonCodes: ['sandbox.clean'],
              score: null,
              engineVersion: 'sandbox/1',
              settingsVersion: null,
              attempt: 1,
              completedAt: new Date('2026-11-05T08:01:00Z'),
            },
          ]
        : []),
    ],
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
    bec: null,
    dlp: null,
  };
  const result = scoreRisk(buildScoringInput(rows, revision), platformProfile('rsk-default/1'));
  return {
    scanId,
    revision,
    ...riskResultToRowJson(result),
    createdAt: new Date('2026-11-05T08:00:06Z'),
  };
}

describe('MessageScansReadService: risk scores (step 5.1 R15)', () => {
  it("lists each round's stored scores, revisions ascending, [] for rounds without one", async () => {
    const { service, scans } = setup([round(30n, 1), round(20n, 0)]);
    scans.riskScores.mockResolvedValue([
      storedRisk(30n, 1, ['spam.gtube']),
      storedRisk(30n, 0, ['spam.gtube']),
    ]);
    const page = await service.list(reader, scope, message.publicId, { limit: 10 });
    expect(scans.riskScores).toHaveBeenCalledWith(scope, message, [30n, 20n]);
    const [newest, oldest] = page.data;
    expect(newest!.risk.map((r) => r.revision)).toEqual([0, 1]);
    expect(newest!.risk[0]).toMatchObject({
      status: 'scored',
      level: 'high',
      verdict: 'spam',
      recommendedAction: 'quarantine',
      versions: { scorer: 'risk-score/1', profile: { source: 'platform', id: 'rsk-default/1' } },
      createdAt: '2026-11-05T08:00:06.000Z',
    });
    expect(newest!.risk[0]!.reasonCodes).toContain('risk.signal.spam_gtube');
    expect(oldest!.risk).toEqual([]);
    // Never an internal id: the row's scan id and profile version id are not in the view.
    expect(JSON.stringify(newest!.risk)).not.toContain('profileVersionId');
    expect(newest!.risk[0]).not.toHaveProperty('scanId');
  });

  it('leaves out a stored row whose JSON does not form a valid view', async () => {
    const { service, scans } = setup([round(30n, 0)]);
    scans.riskScores.mockResolvedValue([{ ...storedRisk(30n, 0, []), contributions: 'broken' }]);
    const page = await service.list(reader, scope, message.publicId, { limit: 10 });
    expect(page.data[0]!.risk).toEqual([]);
  });
});
