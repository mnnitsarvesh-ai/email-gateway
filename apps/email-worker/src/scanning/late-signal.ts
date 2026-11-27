import {
  type Counter,
  type MetricsService,
  NonRetryableError,
  uuidv7,
} from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import {
  EventTypes,
  LATE_SIGNAL_KIND_VALUES,
  LATE_SIGNAL_LEVEL_VALUES,
  LATE_SIGNAL_MAX_HARD_BLOCKS,
  LATE_SIGNAL_MAX_HASHES,
  threatLateSignalV1,
  type ThreatLateSignalV1,
} from '@email-gateway/event-contracts';

/**
 * Late verdicts of the email-worker (step API-3 C2.1, ADR-0103, contracts §38): a sandbox risk
 * revision that raised the round's level or reached a different threat verdict, and a URL dynamic
 * inspection verdict `malicious` / `suspicious` that arrived after the round finished. Both write
 * one content-free `mail.threat.late_signal.v1` outbox row (`aggregate_type = 'message'`,
 * `aggregate_id` = the decimal message id) in the transaction that stores the revision or the
 * inspection verdict, for every ingest source; the mailbox-worker `copies` role turns it into at
 * most one clawback per organization and signal key.
 *
 * The decisions are pure (`sandboxRevisionSignal`, `urlDynamicSignal`); the writer validates the
 * payload against the strict contract first, so a violation (a defect of this code) rolls the
 * caller's transaction back instead of committing half a finalization.
 */

/** The risk verdicts that count as a threat for a late signal (C2.1). */
export const LATE_SIGNAL_THREAT_VERDICTS = ['malware', 'phishing', 'suspicious', 'bec'] as const;

/** Sandbox submission verdicts whose hashes a sandbox revision signal carries (C2.1). */
const SIGNAL_SANDBOX_VERDICTS: ReadonlySet<string> = new Set(['malicious', 'suspicious']);

/** The hard-block id a malicious URL dynamic verdict synthesizes (C3.1). */
export const URL_CLAWBACK_HARD_BLOCK = 'hb.clawback.url';

type Level = ThreatLateSignalV1['level'];
type Verdict = ThreatLateSignalV1['verdict'];

const isThreat = (verdict: string | null): boolean =>
  verdict !== null && (LATE_SIGNAL_THREAT_VERDICTS as readonly string[]).includes(verdict);

/** Rank of a risk level (`none` 0 … `critical` 4); an unknown value ranks lowest. */
export function levelRank(level: string | null): number {
  return level === null ? -1 : (LATE_SIGNAL_LEVEL_VALUES as readonly string[]).indexOf(level);
}

/** Distinct values in first-seen order, at most `max`. */
function distinct(values: readonly string[], max: number): string[] {
  return [...new Set(values)].slice(0, max);
}

/** Revision 0 of a round as the comparison needs it (level and verdict only). */
export interface RevisionFacts {
  level: string;
  verdict: string;
}

export interface SandboxRevisionInput {
  messageId: bigint;
  receivedAt: Date;
  scanId: bigint;
  /** The revision just written (1). */
  revision: number;
  /** The written revision's facts. */
  written: { level: string; verdict: string; hardBlocks: readonly string[] };
  /** Revision 0 of the same round; null when the round has none (treated as level `none`). */
  base: RevisionFacts | null;
  /** The round's sandbox submissions (`sha256`, terminal `sandboxVerdict`). */
  submissions: readonly { sha256: string; sandboxVerdict: string | null }[];
  signalAt: Date;
}

/**
 * C2.1 sandbox revision: a signal when the written revision's level is higher than revision 0's,
 * or its verdict is a threat verdict different from revision 0's; else null.
 */
export function sandboxRevisionSignal(input: SandboxRevisionInput): ThreatLateSignalV1 | null {
  const { written, base } = input;
  const raised = levelRank(written.level) > levelRank(base?.level ?? 'none');
  const newThreat = isThreat(written.verdict) && written.verdict !== (base?.verdict ?? null);
  if (!raised && !newThreat) return null;
  return {
    kind: 'sandbox_revision',
    messageId: input.messageId.toString(),
    receivedAt: input.receivedAt.toISOString(),
    scanId: input.scanId.toString(),
    revision: input.revision,
    verdict: written.verdict as Verdict,
    level: written.level as Level,
    hardBlocks: distinct(written.hardBlocks, LATE_SIGNAL_MAX_HARD_BLOCKS),
    attachmentSha256: distinct(
      input.submissions
        .filter((s) => s.sandboxVerdict !== null && SIGNAL_SANDBOX_VERDICTS.has(s.sandboxVerdict))
        .map((s) => s.sha256.toLowerCase()),
      LATE_SIGNAL_MAX_HASHES,
    ),
    urlSha256: [],
    signalAt: input.signalAt.toISOString(),
  };
}

export interface UrlDynamicInput {
  messageId: bigint;
  receivedAt: Date;
  scanId: bigint;
  /** The inspection's dynamic verdict (`url-map/1`). */
  verdict: string;
  reasonCodes: readonly string[];
  /** The inspected URL's identity hash (`url_dynamic_inspections.url_sha256`). */
  urlSha256: string;
  /** `email_scans.status` of the round under a locking read. */
  roundStatus: string;
  signalAt: Date;
}

/**
 * C2.1 URL dynamic verdict: a signal for `malicious` / `suspicious` when the round is no longer
 * `running` (a running round decides with its own engines); else null. `malicious` (or the
 * dynamic phishing rule) is a phishing verdict; the level is `critical` with the synthesized
 * hard block `hb.clawback.url` for `malicious`, `high` without one for `suspicious` (C3.1).
 */
export function urlDynamicSignal(input: UrlDynamicInput): ThreatLateSignalV1 | null {
  if (input.verdict !== 'malicious' && input.verdict !== 'suspicious') return null;
  if (input.roundStatus === 'running') return null;
  const malicious = input.verdict === 'malicious';
  const phishing = malicious || input.reasonCodes.includes('url.dynamic_phishing');
  return {
    kind: 'url_dynamic',
    messageId: input.messageId.toString(),
    receivedAt: input.receivedAt.toISOString(),
    scanId: input.scanId.toString(),
    revision: null,
    verdict: phishing ? 'phishing' : 'suspicious',
    level: malicious ? 'critical' : 'high',
    hardBlocks: malicious ? [URL_CLAWBACK_HARD_BLOCK] : [],
    attachmentSha256: [],
    urlSha256: [input.urlSha256.toLowerCase()],
    signalAt: input.signalAt.toISOString(),
  };
}

/**
 * Writes one `mail.threat.late_signal.v1` outbox row in the caller's transaction after validating
 * the payload with the strict contract (`NonRetryableError` on a violation). Returns the event id
 * (uuidv7 at `signalAt`).
 */
export async function writeLateSignalOutbox(
  tx: Prisma.TransactionClient,
  input: { organizationId: bigint; payload: ThreatLateSignalV1; correlationId: string },
): Promise<string> {
  const parsed = threatLateSignalV1.safeParse(input.payload);
  if (!parsed.success) throw new NonRetryableError('late_signal_payload_invalid');
  const eventId = uuidv7(new Date(parsed.data.signalAt).getTime());
  await tx.messageOutbox.create({
    data: {
      eventId,
      organizationId: input.organizationId,
      eventType: EventTypes.ThreatLateSignal,
      aggregateType: 'message',
      aggregateId: parsed.data.messageId,
      correlationId: input.correlationId,
      payload: parsed.data,
    },
    select: { id: true },
  });
  return eventId;
}

/** A locking read of the round returned a row of another round (retried). */
export class InconsistentLateSignalReadError extends Error {
  override readonly name = 'InconsistentLateSignalReadError';

  constructor(readonly check: string) {
    super(`inconsistent late-signal read: ${check}`);
  }
}

/**
 * Revision 0 of a round (`message_risk_scores`), read `FOR SHARE` so the latest committed row is
 * seen whatever the transaction's REPEATABLE READ snapshot is (the completion that wrote it may
 * have committed after the snapshot). Echo-checked. Null when the round has no revision 0.
 */
export async function readRevisionZero(
  tx: Prisma.TransactionClient,
  round: { scanId: bigint; receivedAt: Date; organizationId: bigint },
): Promise<RevisionFacts | null> {
  const rows = await tx.$queryRaw<Array<Record<string, unknown>>>(Prisma.sql`
    SELECT scan_id, received_at, organization_id, revision, level, verdict
    FROM message_risk_scores
    WHERE scan_id = ${round.scanId} AND received_at = ${round.receivedAt} AND revision = 0
    FOR SHARE`);
  const row = rows[0];
  if (!row) return null;
  const receivedAt = row.received_at instanceof Date ? row.received_at : null;
  if (
    rows.length > 1 ||
    BigInt(row.scan_id as bigint) !== round.scanId ||
    receivedAt?.getTime() !== round.receivedAt.getTime() ||
    BigInt(row.organization_id as bigint) !== round.organizationId ||
    Number(row.revision) !== 0
  ) {
    throw new InconsistentLateSignalReadError('risk revision echo');
  }
  return { level: String(row.level), verdict: String(row.verdict) };
}

/**
 * The status of a round (`email_scans`), read `FOR SHARE` (latest committed; waits for a
 * completion holding the row). Echo-checked; null when the row is gone.
 */
export async function readRoundStatus(
  tx: Prisma.TransactionClient,
  round: { scanId: bigint; receivedAt: Date; organizationId: bigint; messageId: bigint },
): Promise<string | null> {
  const rows = await tx.$queryRaw<Array<Record<string, unknown>>>(Prisma.sql`
    SELECT id, received_at, organization_id, message_id, status
    FROM email_scans WHERE id = ${round.scanId} AND received_at = ${round.receivedAt}
    FOR SHARE`);
  const row = rows[0];
  if (!row) return null;
  const receivedAt = row.received_at instanceof Date ? row.received_at : null;
  if (
    rows.length > 1 ||
    BigInt(row.id as bigint) !== round.scanId ||
    receivedAt?.getTime() !== round.receivedAt.getTime() ||
    BigInt(row.organization_id as bigint) !== round.organizationId ||
    BigInt(row.message_id as bigint) !== round.messageId
  ) {
    throw new InconsistentLateSignalReadError('scan echo');
  }
  return String(row.status);
}

const metricRegistries = new WeakMap<MetricsService, LateSignalMetrics>();

/**
 * `scan_late_signals_total{kind}` (step API-3 C2.1): late-signal outbox rows committed, by kind
 * (`sandbox_revision`, `url_dynamic`). One instance per registry, shared by the risk metrics
 * (sandbox path) and the URL metrics (results consumer). Bounded labels only.
 */
export class LateSignalMetrics {
  private readonly signals: Counter<'kind'>;

  static for(registry: MetricsService): LateSignalMetrics {
    let metrics = metricRegistries.get(registry);
    if (!metrics) {
      metrics = new LateSignalMetrics(registry);
      metricRegistries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(registry: MetricsService) {
    this.signals = registry.counter(
      'scan_late_signals_total',
      'mail.threat.late_signal.v1 outbox rows committed by the email-worker (step API-3 C2.1), by kind (sandbox_revision, url_dynamic)',
      ['kind'],
    );
    for (const kind of LATE_SIGNAL_KIND_VALUES) this.signals.inc({ kind }, 0);
  }

  signal(kind: ThreatLateSignalV1['kind']): void {
    this.signals.inc({ kind });
  }
}
