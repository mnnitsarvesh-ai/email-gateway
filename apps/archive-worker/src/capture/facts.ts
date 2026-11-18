import {
  type ArchiveParties,
  canonicalJson,
  type MessageDirection,
  type MessageStatus,
  type RecipientStatus,
  type ScanSnapshotRows,
} from '@email-gateway/archive';
import type {
  MessageAction as DbMessageAction,
  MessageVerdict as DbMessageVerdict,
} from '@email-gateway/database';
import {
  Prisma,
  attachmentPartSelect,
  attachmentResultSelect,
  authSelect,
  becResultSelect,
  dlpResultSelect,
  engineResultSelect,
  evaluationSelect,
  messageUrlSelect,
  riskScoreSelect,
  sandboxAnalysisSelect,
  sandboxArtifactSelect,
  sandboxSubmissionSelect,
  scanSelect,
  urlInspectionSelect,
  urlResultSelect,
  urlRewriteSelect,
} from '@email-gateway/database';
import type { Db } from '../shared/db';
import type { JournalInputs } from './journal';
import { InconsistentReadError } from '../shared/errors';

/** Rounds whose scan reached a terminal state can be frozen (A5 step 5). */
export const TERMINAL_SCAN_STATUSES = ['completed', 'failed', 'timed_out'] as const;

export interface MessageRow {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  publicId: string;
  direction: MessageDirection;
  status: MessageStatus;
  statusReason: string | null;
  statusChangedAt: Date;
  lifecycleRound: number;
  internetMessageId: string | null;
  envelopeFrom: string;
  headerFrom: string | null;
  subject: string | null;
  sizeBytes: number;
  attachmentCount: number;
  emlObjectKey: string;
  emlSha256: string;
  clientIp: string | null;
  clientHelo: string | null;
  clientName: string | null;
  finalVerdict: DbMessageVerdict | null;
  finalAction: DbMessageAction | null;
  riskScore: number | null;
}

export interface RecipientRow {
  id: bigint;
  seq: number;
  address: string;
  direction: MessageDirection;
  status: RecipientStatus;
  finalAction: string | null;
}

/** A terminal scan round and its newest risk revision (the link key of A5/A7). */
export interface RoundRef {
  scanId: bigint;
  round: number;
  revision: number;
}

/** The writer facts of one capture or refresh (A5 step 1). */
export interface MessageFacts {
  message: MessageRow;
  recipients: RecipientRow[];
}

const MAX_RECIPIENTS = 65_535;
const MAX_ROWS = 4_000;

/**
 * Reads the facts of a capture on the **writer** (A5 step 1), every query scoped to the
 * message's organization and partition key `(message_id, received_at)`, every row echo-checked.
 * Scan rounds are read with the shared selects of `packages/database/src/read-models/
 * scan-read-model.ts`, exactly as the api's scans view reads them, so a frozen round maps through
 * the same mapper.
 */
export class FactsReader {
  /** The message row (+ its public id from the registry) or null when gone. */
  async message(
    db: Db,
    key: { organizationId: bigint; messageId: bigint; receivedAt: Date },
  ): Promise<MessageFacts | null> {
    const [row, identity] = await Promise.all([
      db.emailMessage.findUnique({
        where: { id_receivedAt: { id: key.messageId, receivedAt: key.receivedAt } },
        select: {
          id: true,
          receivedAt: true,
          organizationId: true,
          direction: true,
          status: true,
          statusReason: true,
          statusChangedAt: true,
          lifecycleRound: true,
          internetMessageId: true,
          envelopeFrom: true,
          headerFrom: true,
          subject: true,
          sizeBytes: true,
          attachmentCount: true,
          emlObjectKey: true,
          emlSha256: true,
          clientIp: true,
          clientHelo: true,
          clientName: true,
          finalVerdict: true,
          finalAction: true,
          riskScore: true,
        },
      }),
      db.messageIdentity.findUnique({
        where: { id: key.messageId },
        select: { id: true, organizationId: true, publicId: true },
      }),
    ]);
    if (row === null || identity === null) return null;
    if (
      row.organizationId !== key.organizationId ||
      identity.organizationId !== key.organizationId ||
      row.id !== key.messageId ||
      row.receivedAt.getTime() !== key.receivedAt.getTime()
    ) {
      throw new InconsistentReadError('message_echo');
    }
    const recipients = await db.emailRecipient.findMany({
      where: {
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
      },
      select: {
        id: true,
        messageId: true,
        organizationId: true,
        rcptSeq: true,
        address: true,
        direction: true,
        status: true,
        finalAction: true,
      },
      orderBy: { rcptSeq: 'asc' },
      take: MAX_RECIPIENTS,
    });
    if (recipients.some((r) => r.organizationId !== key.organizationId)) {
      throw new InconsistentReadError('recipient_echo');
    }
    return {
      message: { ...row, publicId: identity.publicId },
      recipients: recipients.map((r) => ({
        id: r.id,
        seq: r.rcptSeq,
        address: r.address,
        direction: r.direction ?? row.direction,
        status: r.status,
        finalAction: r.finalAction,
      })),
    };
  }

  /** The journal inputs: parse row, header allow-list, attachments, deliveries at this instant. */
  async journalInputs(db: Db, facts: MessageFacts): Promise<JournalInputs> {
    const m = facts.message;
    const where = { messageId: m.id, receivedAt: m.receivedAt, organizationId: m.organizationId };
    const [parse, headers, attachments, deliveries] = await Promise.all([
      db.emailMessageParse.findUnique({
        where: { messageId_receivedAt: { messageId: m.id, receivedAt: m.receivedAt } },
        select: {
          organizationId: true,
          status: true,
          failureReason: true,
          limitsExceeded: true,
          defects: true,
          textBodyObjectKey: true,
          htmlBodyObjectKey: true,
        },
      }),
      db.emailHeader.findMany({
        where,
        select: { organizationId: true, seq: true, name: true, value: true },
        orderBy: { seq: 'asc' },
        take: 10_000,
      }),
      db.emailAttachment.findMany({
        where,
        select: {
          organizationId: true,
          partIndex: true,
          filename: true,
          declaredContentType: true,
          detectedContentType: true,
          sizeBytes: true,
          sha256: true,
        },
        orderBy: { partIndex: 'asc' },
        take: 10_000,
      }),
      db.emailDelivery.findMany({
        where,
        select: {
          organizationId: true,
          recipientId: true,
          status: true,
          deliveredAt: true,
          statusChangedAt: true,
        },
        orderBy: [{ recipientId: 'asc' }, { deliverySeq: 'asc' }],
        take: MAX_ROWS,
      }),
    ]);
    const foreign = [parse, ...headers, ...attachments, ...deliveries].some(
      (r) => r !== null && r.organizationId !== m.organizationId,
    );
    if (foreign) throw new InconsistentReadError('journal_input_echo');
    return { parse, headers, attachments, deliveries };
  }

  /**
   * Terminal rounds of the message newest first, each with its newest risk revision (0 when the
   * round has no risk row). A round still `pending`/`running` is not frozen yet (A5).
   */
  async terminalRounds(db: Db, m: MessageRow): Promise<RoundRef[]> {
    const scans = await db.emailScan.findMany({
      where: {
        messageId: m.id,
        receivedAt: m.receivedAt,
        organizationId: m.organizationId,
        status: { in: [...TERMINAL_SCAN_STATUSES] },
      },
      select: { id: true, organizationId: true, lifecycleRound: true },
      orderBy: [{ lifecycleRound: 'desc' }, { id: 'desc' }],
      take: 32,
    });
    if (scans.some((s) => s.organizationId !== m.organizationId)) {
      throw new InconsistentReadError('scan_echo');
    }
    if (scans.length === 0) return [];
    const risks = await db.messageRiskScore.groupBy({
      by: ['scanId'],
      where: {
        messageId: m.id,
        receivedAt: m.receivedAt,
        organizationId: m.organizationId,
        scanId: { in: scans.map((s) => s.id) },
      },
      _max: { revision: true },
    });
    const revisionOf = new Map(risks.map((r) => [r.scanId.toString(), r._max.revision ?? 0]));
    return scans.map((s) => ({
      scanId: s.id,
      round: s.lifecycleRound,
      revision: revisionOf.get(s.id.toString()) ?? 0,
    }));
  }

  /**
   * The read-model rows of one round (the `archive-scan/1` `rows`), with the shared selects.
   * `sandbox_analyses` / `sandbox_artifacts` are platform tables: their ids come only from this
   * organization's submissions, and an analysis is kept only when its public id is the
   * submission's `external_ref` (the api's rule, step 4.6 X18).
   */
  async roundRows(db: Db, m: MessageRow, round: RoundRef): Promise<ScanSnapshotRows> {
    const where = {
      messageId: m.id,
      receivedAt: m.receivedAt,
      organizationId: m.organizationId,
    };
    const byScan = { ...where, scanId: round.scanId };
    const [
      scan,
      engines,
      auth,
      attachments,
      submissions,
      urls,
      urlResults,
      urlRewrites,
      urlInspections,
      bec,
      dlp,
      risk,
      policy,
    ] = await Promise.all([
      db.emailScan.findFirst({ where: { ...where, id: round.scanId }, select: scanSelect }),
      db.scanEngineResult.findMany({
        where: byScan,
        select: engineResultSelect,
        orderBy: [{ engine: 'asc' }, { attempt: 'asc' }],
        take: MAX_ROWS,
      }),
      db.emailAuthResult.findMany({
        where: byScan,
        select: authSelect,
        orderBy: { engine: 'asc' },
      }),
      db.attachmentScanResult.findMany({
        where: byScan,
        select: attachmentResultSelect,
        orderBy: { partIndex: 'asc' },
        take: MAX_ROWS,
      }),
      db.sandboxSubmission.findMany({
        where: byScan,
        select: sandboxSubmissionSelect,
        orderBy: { partIndex: 'asc' },
        take: MAX_ROWS,
      }),
      db.messageUrl.findMany({
        where,
        select: messageUrlSelect,
        orderBy: { urlSeq: 'asc' },
        take: MAX_ROWS,
      }),
      db.urlScanResult.findMany({
        where: byScan,
        select: urlResultSelect,
        orderBy: { urlSeq: 'asc' },
        take: MAX_ROWS,
      }),
      db.urlRewrite.findMany({ where: byScan, select: urlRewriteSelect, take: MAX_ROWS }),
      db.urlDynamicInspection.findMany({
        where: byScan,
        select: urlInspectionSelect,
        take: MAX_ROWS,
      }),
      db.becScanResult.findMany({ where: byScan, select: becResultSelect, take: 1 }),
      db.dlpScanResult.findMany({ where: byScan, select: dlpResultSelect, take: 1 }),
      db.messageRiskScore.findMany({
        where: byScan,
        select: riskScoreSelect,
        orderBy: { revision: 'asc' },
        take: MAX_ROWS,
      }),
      db.policyExecutionLog.findFirst({
        where: byScan,
        select: evaluationSelect,
        orderBy: [{ evaluationSeq: 'desc' }, { id: 'desc' }],
      }),
    ]);
    if (scan === null) throw new InconsistentReadError('scan_missing');
    const partIndexes = [...new Set(attachments.map((a) => a.partIndex))];
    const attachmentParts =
      partIndexes.length === 0
        ? []
        : await db.emailAttachment.findMany({
            where: { ...where, partIndex: { in: partIndexes } },
            select: attachmentPartSelect,
            take: MAX_ROWS,
          });
    const analysisIds = [
      ...new Set(submissions.map((s) => s.analysisId).filter((id): id is bigint => id !== null)),
    ];
    const analysesAll =
      analysisIds.length === 0
        ? []
        : await db.sandboxAnalysis.findMany({
            where: { id: { in: analysisIds } },
            select: sandboxAnalysisSelect,
            take: analysisIds.length,
          });
    const refs = new Set(submissions.map((s) => s.externalRef).filter((r) => r !== null));
    const analyses = analysesAll.filter((a) => refs.has(a.publicId));
    const artifacts =
      analyses.length === 0
        ? []
        : await db.sandboxArtifact.findMany({
            where: { analysisId: { in: analyses.map((a) => a.id) } },
            select: sandboxArtifactSelect,
            orderBy: [{ analysisId: 'asc' }, { seq: 'asc' }],
            take: MAX_ROWS,
          });
    return {
      scan: scan as unknown as Record<string, unknown>,
      engines: engines.map(decimalsToStrings),
      auth: auth as unknown as Record<string, unknown>[],
      attachments: attachments as unknown as Record<string, unknown>[],
      attachmentParts: attachmentParts as unknown as Record<string, unknown>[],
      sandboxSubmissions: submissions as unknown as Record<string, unknown>[],
      sandboxAnalyses: analyses as unknown as Record<string, unknown>[],
      sandboxArtifacts: artifacts as unknown as Record<string, unknown>[],
      urls: urls as unknown as Record<string, unknown>[],
      urlResults: urlResults as unknown as Record<string, unknown>[],
      urlRewrites: urlRewrites as unknown as Record<string, unknown>[],
      urlInspections: urlInspections as unknown as Record<string, unknown>[],
      bec: bec as unknown as Record<string, unknown>[],
      dlp: dlp as unknown as Record<string, unknown>[],
      risk: risk.filter((r) => Number(r.revision) <= round.revision) as unknown as Record<
        string,
        unknown
      >[],
      policy: (policy ?? null) as unknown as Record<string, unknown> | null,
    };
  }
}

/**
 * `scan_engine_results.score` / `required_score` are `DECIMAL(8,3)` (Prisma `Decimal`), which
 * the `archive-scan/1` tagged codec refuses (only BigInt and Date are tagged). They are frozen as
 * their exact decimal strings; a reader restores them with `new Prisma.Decimal(value)` before the
 * api mapper (`.toNumber()`), WP3 deviation D2.
 */
export function decimalsToStrings<T extends object>(row: T): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = Prisma.Decimal.isDecimal(v) ? v.toString() : v;
  }
  return out;
}

/** `archive-parties/1` of a message (A5 step 6; addresses as stored). */
export function partiesOf(facts: MessageFacts): ArchiveParties {
  return {
    v: 1,
    from: facts.message.envelopeFrom.slice(0, 320),
    headerFrom: facts.message.headerFrom?.slice(0, 320) ?? null,
    recipients: facts.recipients.map((r) => ({
      seq: r.seq,
      address: r.address.slice(0, 320),
      direction: r.direction,
      status: r.status,
      finalAction: r.finalAction,
    })),
  };
}

/**
 * Whether the stored `email_archives.parties` equals `next` regardless of object key order: MySQL
 * normalizes JSON object keys (by length, then bytes), so a stored document never round-trips in
 * `partiesOf` order and a plain `JSON.stringify` comparison always reports a change (review
 * finding of step 8.1). Compared as canonical JSON (sorted keys; array order kept).
 */
export function sameParties(stored: unknown, next: ArchiveParties): boolean {
  try {
    const value: unknown = typeof stored === 'string' ? JSON.parse(stored) : stored;
    return canonicalJson(value) === canonicalJson(next);
  } catch {
    return false;
  }
}

/**
 * Whether the record is malicious (exports place it under `malicious/`, downloads are refused):
 * a malware or phishing verdict, or a malicious attachment or URL in the linked round.
 */
export function isMalicious(
  message: Pick<MessageRow, 'finalVerdict'>,
  rows: Pick<ScanSnapshotRows, 'attachments' | 'urlResults'> | null,
): boolean {
  if (message.finalVerdict === 'malware' || message.finalVerdict === 'phishing') return true;
  if (rows === null) return false;
  return (
    rows.attachments.some((a) => a.verdict === 'malicious') ||
    rows.urlResults.some((u) => u.verdict === 'malicious')
  );
}

/** Every direction of the message: its own and its recipients' (retention and holds). */
export function directionsOf(facts: MessageFacts): MessageDirection[] {
  return [...new Set([facts.message.direction, ...facts.recipients.map((r) => r.direction)])];
}
