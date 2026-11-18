import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  attachmentPartSelect,
  type AttachmentPartRow,
  attachmentResultSelect,
  type AttachmentResultRow,
  authSelect,
  type AuthResultRow,
  becResultSelect,
  type BecResultRow,
  type DlpResultRow as ReadModelDlpResultRow,
  dlpEvidenceStateSelect,
  dlpResultSelect,
  engineResultSelect,
  type EngineResultRow,
  type EvaluationRow,
  evaluationSelect,
  messageUrlSelect,
  type MessageUrlRow,
  riskScoreSelect,
  type RiskScoreRow,
  sandboxAnalysisSelect,
  type SandboxAnalysisRow,
  sandboxArtifactSelect,
  type SandboxArtifactRow,
  sandboxSubmissionSelect,
  type SandboxSubmissionRow,
  scanSelect,
  type ScanRoundRow,
  urlInspectionSelect,
  type UrlInspectionRow,
  urlResultSelect,
  type UrlResultRow,
  urlRewriteSelect,
  type UrlRewriteRow,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type {
  DlpEvidenceStateInput,
  DlpIdMaps,
  DlpRefs,
  DlpResultRowInput,
} from '../../dlp/domain/dlp-result';
import { resolveDlpIds } from '../../dlp/repositories/dlp-results.repository';
import type { LifecycleMessageRow } from './message-lifecycle-read.repository';

/**
 * The scan read-model selects and row types live in `@email-gateway/database`
 * (`src/read-models/scan-read-model.ts`, step 8.1 A5) so the archive-worker freezes exactly the
 * columns this view maps; re-exported here for the existing importers. `DlpResultRow` adds the
 * DLP mapper's input type.
 */
export {
  attachmentResultSelect,
  messageUrlSelect,
  urlResultSelect,
  urlRewriteSelect,
  type AttachmentPartRow,
  type AttachmentResultRow,
  type AuthResultRow,
  type BecResultRow,
  type EngineResultRow,
  type MessageUrlRow,
  type RiskScoreRow,
  type SandboxAnalysisRow,
  type SandboxArtifactRow,
  type SandboxSubmissionRow,
  type ScanRoundRow,
  type UrlInspectionRow,
  type UrlResultRow,
  type UrlRewriteRow,
};

/** Most engine rows one page reads: ≤ 20 rounds × (attempts of every engine). */
const MAX_ENGINE_ROWS = 2_000;

/** Most artifact rows one page reads: ≤ 20 rounds × 5 submissions × 16 artifacts. */
const MAX_SANDBOX_ARTIFACT_ROWS = 2_000;

/**
 * Most per-attachment rows one page reads: ≤ 20 rounds × ATTACHMENT_MAX_PER_MESSAGE (100, the
 * engine scans at most that many attachments per round, step 4.2 A3).
 */
const MAX_ATTACHMENT_ROWS = 2_000;

/** The click summary of one URL of a message (`url_click_events`, every round). */
export interface UrlClickSummaryRow {
  urlSeq: number;
  total: number;
  lastDecision: 'allowed' | 'warned' | 'blocked' | 'continued' | 'expired' | 'not_found' | null;
  lastAt: Date | null;
}

/** Most URL rows a message has (U4 `URL_MAX_PER_MESSAGE` ≤ 200, the seq space is stable). */
const MAX_MESSAGE_URLS = 1_000;
/** Most per-URL result / inspection rows one page reads: ≤ 20 rounds × 200 URLs. */
const MAX_URL_RESULT_ROWS = 4_000;

export interface BecFeedbackRefRow {
  scanId: bigint;
  publicId: string;
  kind: 'false_positive' | 'false_negative';
  createdAt: Date;
}

/** Most feedback references one page reads: ≤ 20 rounds × BEC_MAX_FEEDBACK_REFS (50). */
const MAX_BEC_FEEDBACK_ROWS = 1_000;

export type DlpResultRow = ReadModelDlpResultRow & DlpResultRowInput;

/** Most score rows one page reads: ≤ 20 rounds × 2 revisions. */
const MAX_RISK_SCORE_ROWS = 64;

/**
 * Read-only, tenant-scoped scan reads (step 4.1 S16; 4.2 attachments; 4.3 URLs; 4.4 BEC; 4.5 DLP;
 * 4.6 sandbox submissions and the analyses/artifacts they reference; 5.1 risk scores) on the replica (`PrismaReadService`, with
 * the writer fallback above the lag threshold; ADR-0014, §2.0 invariant 6). Every query matches
 * the organization of the caller's scope and the message's `(message_id, received_at)`, so the
 * partitioned tables are pruned and another tenant's rows are never read.
 */
@Injectable()
export class MessageScansReadRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** Rounds newest first, below `beforeRound` when given (`(message_id, lifecycle_round)` key). */
  rounds(
    scope: TenantScope,
    message: LifecycleMessageRow,
    page: { take: number; beforeRound?: number },
  ): Promise<ScanRoundRow[]> {
    return this.db.emailScan.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.beforeRound !== undefined && { lifecycleRound: { lt: page.beforeRound } }),
      }),
      select: scanSelect,
      orderBy: [{ lifecycleRound: 'desc' }, { id: 'desc' }],
      take: page.take,
    });
  }

  /** Every engine row (attempts and finals) of the given scans, by engine and attempt. */
  engineResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<EngineResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.scanEngineResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: engineResultSelect,
      orderBy: [{ scanId: 'desc' }, { engine: 'asc' }, { attempt: 'asc' }],
      take: MAX_ENGINE_ROWS,
    });
  }

  /**
   * The per-attachment results of the given scans (step 4.2 A16, A18), by round and part index.
   * File contents and entry names are never stored there.
   */
  attachmentResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<AttachmentResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.attachmentScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: attachmentResultSelect,
      orderBy: [{ scanId: 'desc' }, { partIndex: 'asc' }],
      take: MAX_ATTACHMENT_ROWS,
    });
  }

  /**
   * Display metadata of the message's attachments by part index (`email_attachments`, joined on
   * `(message_id, part_index, received_at)`): the sanitized filename and the declared type.
   */
  attachmentParts(
    scope: TenantScope,
    message: LifecycleMessageRow,
    partIndexes: readonly number[],
  ): Promise<AttachmentPartRow[]> {
    if (partIndexes.length === 0) return Promise.resolve([]);
    return this.db.emailAttachment.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        partIndex: { in: [...new Set(partIndexes)] },
      }),
      select: attachmentPartSelect,
      take: MAX_ATTACHMENT_ROWS,
    });
  }

  /**
   * The sandbox submissions of the given scans (step 4.2 A11; step 4.6 X18 outcome columns), one
   * per scan and attachment.
   */
  sandboxSubmissions(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<SandboxSubmissionRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.sandboxSubmission.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: sandboxSubmissionSelect,
      orderBy: [{ scanId: 'desc' }, { partIndex: 'asc' }],
      take: MAX_ATTACHMENT_ROWS,
    });
  }

  /**
   * The analyses that completed the given submissions (step 4.6 X18). `sandbox_analyses` is a
   * platform table (content-addressed, shared by every organization that submitted the same
   * file), so it is never queried on its own: the ids come only from this organization's
   * completed submissions (tenant-scoped above), and the caller additionally matches each row's
   * public id with the submission's `external_ref`.
   */
  sandboxAnalyses(analysisIds: readonly bigint[]): Promise<SandboxAnalysisRow[]> {
    if (analysisIds.length === 0) return Promise.resolve([]);
    const ids = [...new Set(analysisIds)];
    return this.db.sandboxAnalysis.findMany({
      where: { id: { in: ids } },
      select: sandboxAnalysisSelect,
      take: ids.length,
    });
  }

  /** Artifact metadata of the given analyses (ids from the tenant's own submissions only). */
  sandboxArtifacts(analysisIds: readonly bigint[]): Promise<SandboxArtifactRow[]> {
    if (analysisIds.length === 0) return Promise.resolve([]);
    return this.db.sandboxArtifact.findMany({
      where: { analysisId: { in: [...new Set(analysisIds)] } },
      select: sandboxArtifactSelect,
      orderBy: [{ analysisId: 'asc' }, { seq: 'asc' }],
      take: MAX_SANDBOX_ARTIFACT_ROWS,
    });
  }

  /** The authentication results of the given scans (one per scan and engine). */
  authResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<AuthResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.emailAuthResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: authSelect,
      orderBy: [{ scanId: 'desc' }, { engine: 'asc' }],
    });
  }

  /** The URLs of the message (`message_urls`, seqs stable across rounds, step 4.3 U3/U16). */
  messageUrls(scope: TenantScope, message: LifecycleMessageRow): Promise<MessageUrlRow[]> {
    return this.db.messageUrl.findMany({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: messageUrlSelect,
      orderBy: { urlSeq: 'asc' },
      take: MAX_MESSAGE_URLS,
    });
  }

  /** The per-URL results of the given scans (`url_scan_results`), by round and seq. */
  urlResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<UrlResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.urlScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: urlResultSelect,
      orderBy: [{ scanId: 'desc' }, { urlSeq: 'asc' }],
      take: MAX_URL_RESULT_ROWS,
    });
  }

  /** The rewrite rows of the given scans (`url_rewrites`, one per round). */
  urlRewrites(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<UrlRewriteRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.urlRewrite.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: urlRewriteSelect,
      take: MAX_URL_RESULT_ROWS,
    });
  }

  /** The dynamic inspections of the given scans (`url_dynamic_inspections`, ≤ 3 per round). */
  urlInspections(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<UrlInspectionRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.urlDynamicInspection.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: urlInspectionSelect,
      take: MAX_URL_RESULT_ROWS,
    });
  }

  /** The BEC results of the given scans (`bec_scan_results`, one per scan, step 4.4 B15). */
  becResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<BecResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.becScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: becResultSelect,
      orderBy: { scanId: 'desc' },
      take: scanIds.length,
    });
  }

  /** The feedback references of the given scans (`bec_feedback`), newest first. */
  becFeedback(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<BecFeedbackRefRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.becFeedback.findMany({
      where: tenantWhere(scope, { messageId: message.id, scanId: { in: [...scanIds] } }),
      select: { scanId: true, publicId: true, kind: true, createdAt: true },
      orderBy: { id: 'desc' },
      take: MAX_BEC_FEEDBACK_ROWS,
    });
  }

  /**
   * Public ids of the organization's BEC profiles, trusted senders and suppressions referenced
   * by internal id in stored evidence (only queried when a result references internal ids).
   */
  async becPublicIds(
    scope: TenantScope,
    ids: { executive: bigint[]; vendor: bigint[]; trusted: bigint[]; suppression: bigint[] },
  ): Promise<{
    executive: Map<string, string>;
    vendor: Map<string, string>;
    trusted: Map<string, string>;
    suppression: Map<string, string>;
  }> {
    const select = { id: true, publicId: true } as const;
    const toMap = (rows: Array<{ id: bigint; publicId: string }>) =>
      new Map(rows.map((row) => [row.id.toString(), row.publicId]));
    const [executive, vendor, trusted, suppression] = await Promise.all([
      ids.executive.length === 0
        ? []
        : this.db.becExecutiveProfile.findMany({
            where: tenantWhere(scope, { id: { in: ids.executive } }),
            select,
          }),
      ids.vendor.length === 0
        ? []
        : this.db.becVendorProfile.findMany({
            where: tenantWhere(scope, { id: { in: ids.vendor } }),
            select,
          }),
      ids.trusted.length === 0
        ? []
        : this.db.becTrustedSender.findMany({
            where: tenantWhere(scope, { id: { in: ids.trusted } }),
            select,
          }),
      ids.suppression.length === 0
        ? []
        : this.db.becSuppressionRule.findMany({
            where: tenantWhere(scope, { id: { in: ids.suppression } }),
            select,
          }),
    ]);
    return {
      executive: toMap(executive),
      vendor: toMap(vendor),
      trusted: toMap(trusted),
      suppression: toMap(suppression),
    };
  }

  /** The DLP results of the given scans (`dlp_scan_results`, one per scan, step 4.5 D20). */
  dlpResults(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<DlpResultRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.dlpScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: dlpResultSelect,
      orderBy: { scanId: 'desc' },
      take: scanIds.length,
    });
  }

  /**
   * The evidence state of the given scans (`dlp_evidence`: expiry and purge time only; never
   * the object key, hash or wrapped key).
   */
  dlpEvidence(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<DlpEvidenceStateInput[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.dlpEvidence.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: dlpEvidenceStateSelect,
      take: scanIds.length,
    });
  }

  /**
   * The risk scores of the given scans (`message_risk_scores`, partitioned by `received_at`;
   * one row per scan and revision, step 5.1 R14), by round and revision.
   */
  riskScores(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<RiskScoreRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.messageRiskScore.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: riskScoreSelect,
      orderBy: [{ scanId: 'desc' }, { revision: 'asc' }],
      take: MAX_RISK_SCORE_ROWS,
    });
  }

  /**
   * The policy evaluations of the given scans (`policy_execution_logs`, partitioned by
   * `received_at`; one per round, step 5.2 P16): the columns of the api view, never internal ids.
   */
  policyEvaluations(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<EvaluationRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.policyExecutionLog.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
      }),
      select: evaluationSelect,
      orderBy: [{ evaluationSeq: 'desc' }, { id: 'desc' }],
      take: MAX_RISK_SCORE_ROWS,
    });
  }

  /** This organization's public ids of the DLP rows the stored results reference. */
  dlpPublicIds(scope: TenantScope, refs: DlpRefs): Promise<DlpIdMaps> {
    return resolveDlpIds(this.db, scope, refs);
  }

  /**
   * The click summary per URL of the message (`url_click_events`, partitioned by `clicked_at`;
   * matched on the `(message_id, message_received_at)` index and the scope's organization): the
   * count, the newest click's decision and time. Two queries: the per-seq count and newest time,
   * then the decisions of those newest clicks.
   */
  async urlClicks(scope: TenantScope, message: LifecycleMessageRow): Promise<UrlClickSummaryRow[]> {
    const where = tenantWhere(scope, {
      messageId: message.id,
      messageReceivedAt: message.receivedAt,
    });
    const groups = await this.db.urlClickEvent.groupBy({
      by: ['urlSeq'],
      where,
      _count: { _all: true },
      _max: { clickedAt: true },
      orderBy: { urlSeq: 'asc' },
      take: MAX_MESSAGE_URLS,
    });
    if (groups.length === 0) return [];
    const newest = groups.flatMap((g) =>
      g._max.clickedAt ? [{ urlSeq: g.urlSeq, clickedAt: g._max.clickedAt }] : [],
    );
    const last =
      newest.length === 0
        ? []
        : await this.db.urlClickEvent.findMany({
            where: { AND: [where, { OR: newest }] },
            select: { urlSeq: true, clickedAt: true, decision: true, id: true },
            orderBy: [{ clickedAt: 'desc' }, { id: 'desc' }],
            take: MAX_MESSAGE_URLS * 4,
          });
    const decisionOf = new Map<number, UrlClickSummaryRow['lastDecision']>();
    for (const row of last) {
      if (!decisionOf.has(row.urlSeq)) decisionOf.set(row.urlSeq, row.decision);
    }
    return groups.map((g) => ({
      urlSeq: g.urlSeq,
      total: g._count._all,
      lastDecision: decisionOf.get(g.urlSeq) ?? null,
      lastAt: g._max.clickedAt ?? null,
    }));
  }
}
