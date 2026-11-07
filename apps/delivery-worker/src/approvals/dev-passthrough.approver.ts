import { processOnceHandler, uuidv7 } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  type MessageScannedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { transitionMessage } from '@email-gateway/message-lifecycle';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { SOURCE_SERVICE } from '../planning/delivery-planner';
import type { ApprovalFeed } from './approval-feed';

/**
 * `message_idempotency.consumer` and outbox cursor of the development pass-through (step 4.1
 * S15). New in step 4.1: the step 2.3 consumer `delivery-worker.dev-passthrough` read
 * `mail.message.received.v1`; this one reads `mail.message.scanned.v1` and starts at the latest
 * outbox row (never replays old mail).
 */
export const DEV_PASSTHROUGH_CONSUMER = 'delivery-worker.dev-passthrough-scanned';

export const DEV_PASSTHROUGH_WARNING =
  'DEV PASS-THROUGH ENABLED: mail is delivered after scanning without policy; malicious verdicts are held in scanned, and so are suspicious or malicious BEC results and DLP actions require_approval, quarantine and block (not production behaviour)';

/** The phishing/BEC engine (step 4.4 B1); its result is held by the pass-through (B17). */
export const BEC_ENGINE = 'bec';
/** BEC outcomes the pass-through never approves (step 4.4 B17). */
const HELD_BEC_OUTCOMES: ReadonlySet<string> = new Set(['suspicious', 'malicious']);

/** The outcome of the `bec` engine in a `scanned.v1` payload when it is held, else null. */
export function heldBecOutcome(payload: Pick<MessageScannedV1, 'engines'>): string | null {
  const bec = payload.engines.find((entry) => entry.engine === BEC_ENGINE);
  return bec !== undefined && HELD_BEC_OUTCOMES.has(bec.outcome) ? bec.outcome : null;
}

/**
 * A writer read of `bec_scan_results` returned a row other than the one asked for (Prisma 6
 * wrong read, step 4.2 §6). Thrown inside the ledger transaction: nothing is approved, the event
 * is redelivered.
 */
export class InconsistentBecResultReadError extends Error {
  constructor() {
    super('inconsistent read of bec_scan_results');
    this.name = 'InconsistentBecResultReadError';
  }
}

/** The deterministic and final verdicts of the round's `bec_scan_results` row (B14). */
export interface BecRoundVerdicts {
  deterministicVerdict: string;
  verdict: string;
}

/**
 * Whether a held bec outcome stays held (step 4.4 B17 with ADR-0034 "an LLM never alone
 * authorizes or rejects delivery", review round 1): held when the round's **deterministic**
 * verdict is `suspicious` or `malicious`, and fail-safe when the result row is missing. A
 * result raised to `suspicious` by the AI layer alone (deterministic `clean` or `unknown`) is
 * not held: the AI assessment is evidence for policy (5.2), never the reason mail is held.
 */
export function becHoldDecision(row: BecRoundVerdicts | null): 'held' | 'ai_only' | 'missing' {
  if (row === null) return 'missing';
  return HELD_BEC_OUTCOMES.has(row.deterministicVerdict) ? 'held' : 'ai_only';
}

/** The data loss prevention engine (step 4.5 D1); its policy action is applied here (D13). */
export const DLP_ENGINE = 'dlp';
/** Engine outcomes that are not a definite DLP result (a failed or skipped engine). */
const NON_DEFINITE_DLP_OUTCOMES: ReadonlySet<string> = new Set(['skipped', 'timeout', 'error']);
/** DLP actions the pass-through never approves (step 4.5 D13); weaker ones are approved. */
const HELD_DLP_ACTIONS: ReadonlySet<string> = new Set(['require_approval', 'quarantine', 'block']);

/**
 * Whether the `scanned.v1` engines entry for `dlp` carries a definite outcome other than
 * `skipped` (then the round's `dlp_scan_results` row decides, D13). An absent entry (a round
 * without the dlp engine) and `skipped` (inbound not scanned) are not checked.
 */
export function dlpResultApplies(payload: Pick<MessageScannedV1, 'engines'>): boolean {
  const dlp = payload.engines.find((entry) => entry.engine === DLP_ENGINE);
  return dlp !== undefined && !NON_DEFINITE_DLP_OUTCOMES.has(dlp.outcome);
}

/**
 * The pass-through decision for the round's DLP action (D13): `allow` → approve, `alert` →
 * approve (counted), `require_approval` / `quarantine` / `block` → held, a missing row → held
 * (fail-safe: policy 5.2 treats it as a block-equivalent hold, contracts.md).
 */
export function dlpHoldDecision(action: string | null): 'approve' | 'alert' | 'held' | 'missing' {
  if (action === null) return 'missing';
  if (HELD_DLP_ACTIONS.has(action)) return 'held';
  return action === 'alert' ? 'alert' : 'approve';
}

/**
 * A writer read of `dlp_scan_results` returned a row other than the one asked for (Prisma 6
 * wrong read, step 4.2 §6). Thrown inside the ledger transaction: nothing is approved, the event
 * is redelivered.
 */
export class InconsistentDlpResultReadError extends Error {
  constructor() {
    super('inconsistent read of dlp_scan_results');
    this.name = 'InconsistentDlpResultReadError';
  }
}

/**
 * A writer read of `url_rewrites` returned a row other than the one asked for (Prisma 6 wrong
 * read, step 4.2 §6). Thrown inside the ledger transaction: nothing is approved, the event is
 * redelivered.
 */
export class InconsistentRewriteReadError extends Error {
  constructor() {
    super('inconsistent read of url_rewrites');
    this.name = 'InconsistentRewriteReadError';
  }
}

/** The object an approval delivers (step 4.3 U20). */
export type ApprovalObject = 'rewritten' | 'original';

/** True when `key` is a rewritten copy of `organizationId` (`org/<org>/rewrite/…`, no `..`). */
export function isRewriteKeyOf(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/rewrite/`) &&
    !key.split('/').some((segment) => segment === '..' || segment === '.' || segment === '')
  );
}

/** `mail.delivery.approved.v1` carries at most 1000 recipients. */
const MAX_APPROVAL_RECIPIENTS = 1000;

export interface PassThroughResult {
  approvals: string[];
  recipients: number;
}

/**
 * DEVELOPMENT ONLY (step 2.3 R5, step 4.1 S15): turns every `mail.message.scanned.v1` with
 * `outcome = scanned` into `mail.delivery.approved.v1` (`source = dev_passthrough`) for every
 * recipient of the message whose `email_recipients.status` is `pending`, so the stack can be
 * tested end to end before policy (5.2) exists. **This is not production behaviour: it delivers
 * every scanned message without policy, except a `malicious` verdict.** Config validation refuses it
 * unless `APP_ENV` is `local` or `ci`; it starts from the outbox position at its first start
 * (never replays old mail). Step 5.2 replaces it with the policy engine's approvals.
 *
 * In the consumer's idempotency transaction (`processOnceHandler`, budget `txTimeoutMs`) it
 * first moves the message `scanned → approved` (edge E27, role `dev_passthrough`, key
 * `evt:<scannedEventId>:approved`, expected round = the event's `lifecycleRound`) through
 * @email-gateway/message-lifecycle, then writes the approval outbox row(s) with that
 * `lifecycleRound` and one `email_events` row `delivery.approved` per approval
 * (`details.source = dev_passthrough`). `clean`, `spam`, `suspicious` and `unknown` verdicts are
 * approved as in step 4.1 (logged).
 *
 * Never approved:
 * - `outcome = scan_failed` (a required engine timed out or failed): ledger row only,
 *   `delivery_approvals_skipped_total{reason="scan_failed"}`; the message waits for policy's
 *   fail-safe (5.2) or its deadline;
 * - `outcome = scanned` with `verdict = malicious` (step 4.2 A15): ledger row only,
 *   `delivery_approvals_skipped_total{reason="malicious_verdict"}`, an info log with the ids and
 *   the verdict. The message stays `scanned` until policy (5.2) or the `scanned` lifecycle
 *   deadline (`LIFECYCLE_DEADLINE_SCANNED_HOURS`, then `expired`). Quarantine is a policy action
 *   (5.3); the pass-through does not invent one, but it never delivers malware either;
 * - `outcome = scanned` whose `engines` entry for `bec` has outcome `suspicious` or `malicious`
 *   **and** whose round's `bec_scan_results.deterministic_verdict` is `suspicious` or
 *   `malicious` (step 4.4 B17), or whose result row is missing (fail-safe): ledger row only,
 *   `delivery_approvals_skipped_total{reason="bec_verdict"}`, an info log with the ids and the
 *   bec outcome; held in `scanned` like a malicious verdict. A result raised to `suspicious` by
 *   the AI layer alone (deterministic `clean`/`unknown`) is **not** held (ADR-0034: an LLM never
 *   alone authorizes or rejects delivery): approved, `delivery_bec_ai_only_not_held_total`. A
 *   `suspicious` URL or Rspamd result, and a bec `clean`, `unknown` or `skipped` result, are
 *   still approved (policy, 5.2, must treat the bec result explicitly);
 * - `outcome = scanned` whose `engines` entry for `dlp` has a definite outcome other than
 *   `skipped` (step 4.5 D13, checked after the three cases above, whose reasons are unchanged)
 *   and whose round's `dlp_scan_results.action` is `require_approval`, `quarantine` or `block`,
 *   or whose result row is missing (fail-safe): ledger row only,
 *   `delivery_approvals_skipped_total{reason="dlp_action"}`,
 *   `delivery_dlp_holds_total{action}` (`missing` for the missing row), an info log (warn for the
 *   missing row) with the ids and the action; held in `scanned`. `allow` and `alert` are approved
 *   (`alert` counted in `delivery_dlp_alerts_approved_total` and logged: the incident already
 *   exists). The row is read in this transaction and echo-checked (organization, message,
 *   `received_at`, scan, round; a shifted read throws `InconsistentDlpResultReadError`,
 *   `delivery_inconsistent_reads_total{read="dlp_result"}`, the event is redelivered);
 * - a message that is not `scanned` in that round (another stage or an operator moved it, a
 *   rescan superseded the round) or that does not exist for the envelope's organization
 *   (`delivery_approvals_skipped_total{reason="lifecycle_<result>"}`);
 * - `parse_failed` messages: they never produce `scanned.v1` (they stay `persisted`).
 *
 * The message and its EML key come from the writer row of the envelope's organization, never
 * from the event payload alone.
 *
 * **Which object is delivered (step 4.3 U11 "Delivery", U20):** when the URL engine produced a
 * rewritten copy for this round (`url_rewrites` row with `status = rewritten` for the message,
 * organization, `lifecycle_round` and scan of the event), `emlS3Key` is that copy's
 * `object_key`; otherwise the original `email_messages.eml_object_key`. The rewrite row is read in
 * this transaction and echo-checked (message, organization, `received_at`, round, scan, status;
 * a shifted read throws `InconsistentRewriteReadError` and the event is redelivered, 4.2 §6); its
 * key must start with `org/<org>/rewrite/` and contain no `..` segment, else the original is
 * delivered and a warning logged (never another tenant's or an unexpected object). The planner
 * counts `delivery_approvals_total{source, object}`. Policy (5.2) and the quarantine release
 * (5.3) follow the same rule (docs/architecture/contracts.md).
 */
export class DevPassThroughApprover {
  private readonly logger: Logger;

  constructor(
    private readonly feed: ApprovalFeed<MessageScannedV1>,
    private readonly prisma: PrismaClient,
    private readonly txTimeoutMs: number,
    logger: Logger,
    private readonly metrics: DeliveryMetrics,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.logger = logger.child({ component: 'dev-passthrough' });
  }

  start(): void {
    this.logger.warn(DEV_PASSTHROUGH_WARNING);
    this.feed.start(
      processOnceHandler<MessageScannedV1>(
        this.prisma,
        DEV_PASSTHROUGH_CONSUMER,
        async (event, tx) => {
          await this.approve(event, tx);
        },
        { txTimeoutMs: this.txTimeoutMs },
      ),
    );
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }

  async approve(
    event: EventEnvelope<MessageScannedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<PassThroughResult> {
    const organizationId = BigInt(event.organizationId);
    const payload = event.payload;
    const messageId = BigInt(payload.messageId);
    const receivedAt = new Date(payload.receivedAt);
    const round = payload.lifecycleRound;
    const ids = {
      eventId: event.eventId,
      messageId: payload.messageId,
      scanId: payload.scanId,
      round,
    };
    if (payload.outcome === 'scan_failed') {
      // Invariant 1 of step 4.1: a failed scan is never delivered by the pass-through.
      this.metrics.approvalsSkipped.inc({ reason: 'scan_failed' });
      this.logger.info(
        { ...ids, outcome: payload.outcome, verdict: payload.verdict },
        'scan failed; the dev pass-through does not approve it (waits for policy or its deadline)',
      );
      return { approvals: [], recipients: 0 };
    }
    if (payload.verdict === 'malicious') {
      // Step 4.2 A15: the pass-through never delivers a malicious verdict; the message is held.
      this.metrics.approvalsSkipped.inc({ reason: 'malicious_verdict' });
      this.logger.info(
        { ...ids, outcome: payload.outcome, verdict: payload.verdict },
        'malicious verdict; the dev pass-through does not approve it (held in scanned until ' +
          'policy or its deadline)',
      );
      return { approvals: [], recipients: 0 };
    }
    const becOutcome = heldBecOutcome(payload);
    if (becOutcome !== null) {
      const becRow = await this.becVerdicts(tx, {
        messageId,
        receivedAt,
        organizationId,
        round,
        scanId: BigInt(payload.scanId),
      });
      const decision = becHoldDecision(becRow);
      if (decision === 'ai_only') {
        // ADR-0034: the AI layer alone never holds (or releases) mail; approved and counted.
        this.metrics.becAiOnlyNotHeld.inc();
        this.logger.info(
          {
            ...ids,
            outcome: payload.outcome,
            verdict: payload.verdict,
            becOutcome,
            deterministicVerdict: becRow!.deterministicVerdict,
          },
          'BEC result raised by the AI layer only; not held by the dev pass-through (the ' +
            'deterministic verdict is below suspicious)',
        );
      } else {
        // Step 4.4 B17: a deterministic suspicious or malicious BEC result is held like a
        // malicious verdict; a missing result row is held too (fail-safe).
        this.metrics.approvalsSkipped.inc({ reason: 'bec_verdict' });
        const log = { ...ids, outcome: payload.outcome, verdict: payload.verdict, becOutcome };
        if (decision === 'missing') {
          this.logger.warn(
            log,
            'BEC result row of the round not found; held by the dev pass-through (fail-safe)',
          );
        } else {
          this.logger.info(
            log,
            'suspicious or malicious BEC result; the dev pass-through does not approve it (held ' +
              'in scanned until policy or its deadline)',
          );
        }
        return { approvals: [], recipients: 0 };
      }
    }
    if (dlpResultApplies(payload)) {
      // Step 4.5 D13: the round's DLP action, after the scan_failed, malicious and BEC checks.
      const action = await this.dlpAction(tx, {
        messageId,
        receivedAt,
        organizationId,
        round,
        scanId: BigInt(payload.scanId),
      });
      const decision = dlpHoldDecision(action);
      if (decision === 'held' || decision === 'missing') {
        this.metrics.approvalsSkipped.inc({ reason: 'dlp_action' });
        this.metrics.dlpHolds.inc({ action: action ?? 'missing' });
        if (decision === 'missing') {
          this.logger.warn(
            { ...ids, outcome: payload.outcome, verdict: payload.verdict },
            'DLP result row of the round not found; held by the dev pass-through (fail-safe)',
          );
        } else {
          this.logger.info(
            { ...ids, outcome: payload.outcome, verdict: payload.verdict, dlpAction: action },
            'DLP action holds the message; the dev pass-through does not approve it (held in ' +
              'scanned until policy or its deadline)',
          );
        }
        return { approvals: [], recipients: 0 };
      }
      if (decision === 'alert') {
        this.metrics.dlpAlertsApproved.inc();
        this.logger.info(
          { ...ids, outcome: payload.outcome, verdict: payload.verdict, dlpAction: action },
          'DLP alert (incident recorded); the dev pass-through approves the message',
        );
      }
    }
    // E27 first, in the same transaction as the approvals: they exist iff the message is approved.
    const lifecycle = await transitionMessage(
      tx,
      {
        message: { id: messageId, receivedAt, organizationId },
        to: 'approved',
        reason: 'dev_passthrough',
        actor: { role: 'dev_passthrough', service: SOURCE_SERVICE, type: 'system' },
        transitionKey: `evt:${event.eventId}:approved`,
        causationEventId: event.eventId,
        correlationId: event.correlationId,
        expectedRound: round,
        expectedFrom: ['scanned'],
      },
      { metrics: this.metrics.lifecycle, logger: this.logger },
    );
    if (lifecycle.result === 'duplicate') {
      // Already approved by an earlier run of this event (cannot happen inside one ledger
      // transaction; kept for safety): its approvals were committed with it.
      this.logger.info(
        { ...ids, result: lifecycle.result, why: lifecycle.why, state: lifecycle.snapshot.state },
        'message already approved; nothing more to approve',
      );
      return { approvals: [], recipients: 0 };
    }
    if (lifecycle.result !== 'applied') {
      const why = lifecycle.result === 'not_found' ? null : lifecycle.why;
      const state = lifecycle.result === 'not_found' ? null : lifecycle.snapshot.state;
      this.metrics.approvalsSkipped.inc({ reason: `lifecycle_${lifecycle.result}` });
      this.logger.info(
        { ...ids, result: lifecycle.result, why, state },
        'message is not scanned in this round for the organization (lifecycle); not approved',
      );
      return { approvals: [], recipients: 0 };
    }
    const delivered = await this.deliveryObject(tx, {
      messageId,
      receivedAt,
      organizationId,
      round,
      scanId: BigInt(payload.scanId),
      original: lifecycle.snapshot.emlObjectKey,
      ids,
    });
    const emlObjectKey = delivered.key;
    const recipients = await tx.emailRecipient.findMany({
      where: { messageId, receivedAt, organizationId, status: 'pending' },
      orderBy: { rcptSeq: 'asc' },
      select: { id: true, rcptSeq: true },
    });
    // 0 for the first delivery (what step 2.3 always wrote); after a rescan of a message that
    // already has deliveries (e.g. expired while delivering), the next sequence, so the planner
    // never mistakes the new approval for a duplicate of the old one.
    const deliverySeq = await this.nextDeliverySeq(tx, { messageId, receivedAt, organizationId });
    const approvals: string[] = [];
    const now = this.now();
    for (let i = 0; i < recipients.length; i += MAX_APPROVAL_RECIPIENTS) {
      const chunk = recipients.slice(i, i + MAX_APPROVAL_RECIPIENTS);
      const approvalId = uuidv7(now.getTime());
      const approval = deliveryApprovedV1.parse({
        messageId: messageId.toString(),
        receivedAt: receivedAt.toISOString(),
        deliverySeq,
        lifecycleRound: round,
        source: 'dev_passthrough',
        emlS3Key: emlObjectKey,
        recipients: chunk.map((r) => ({ recipientId: r.id.toString(), rcptSeq: r.rcptSeq })),
        approvedAt: now.toISOString(),
      });
      await tx.messageOutbox.create({
        data: {
          eventId: approvalId,
          organizationId,
          eventType: EventTypes.DeliveryApproved,
          aggregateType: 'message',
          aggregateId: messageId.toString(),
          correlationId: event.correlationId,
          payload: approval,
        },
        select: { id: true },
      });
      await tx.emailEvent.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          eventType: 'delivery.approved',
          occurredAt: now,
          sourceService: SOURCE_SERVICE,
          eventId: approvalId,
          details: {
            source: 'dev_passthrough',
            approvalEventId: approvalId,
            deliverySeq,
            lifecycleRound: round,
            recipientCount: chunk.length,
          },
        },
        select: { id: true },
      });
      approvals.push(approvalId);
    }
    if (approvals.length === 0) {
      this.logger.info(
        { ...ids, verdict: payload.verdict },
        'no pending recipients; nothing approved',
      );
    } else {
      this.logger.info(
        {
          ...ids,
          verdict: payload.verdict,
          object: delivered.object,
          deliverySeq,
          approvals: approvals.length,
          recipients: recipients.length,
        },
        'dev pass-through approved the scanned message (no policy)',
      );
    }
    return { approvals, recipients: recipients.length };
  }

  /**
   * The object to deliver for this round (U11 "Delivery", U20): the round's rewritten copy when
   * the URL engine wrote one, else the original EML. Echo-checked writer read in the ledger
   * transaction.
   */
  private async deliveryObject(
    tx: Prisma.TransactionClient,
    input: {
      messageId: bigint;
      receivedAt: Date;
      organizationId: bigint;
      round: number;
      scanId: bigint;
      original: string;
      ids: Record<string, unknown>;
    },
  ): Promise<{ key: string; object: ApprovalObject }> {
    const row = await tx.urlRewrite.findFirst({
      where: {
        messageId: input.messageId,
        receivedAt: input.receivedAt,
        organizationId: input.organizationId,
        lifecycleRound: input.round,
        scanId: input.scanId,
        status: 'rewritten',
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        lifecycleRound: true,
        scanId: true,
        status: true,
        objectKey: true,
      },
      orderBy: { id: 'desc' },
    });
    if (row === null) return { key: input.original, object: 'original' };
    if (
      row.messageId !== input.messageId ||
      row.organizationId !== input.organizationId ||
      row.receivedAt.getTime() !== input.receivedAt.getTime() ||
      row.lifecycleRound !== input.round ||
      row.scanId !== input.scanId ||
      row.status !== 'rewritten'
    ) {
      this.metrics.inconsistentReads.inc({ read: 'url_rewrite' });
      throw new InconsistentRewriteReadError();
    }
    if (row.objectKey === null || !isRewriteKeyOf(row.objectKey, input.organizationId)) {
      this.logger.warn(
        { ...input.ids, reason: row.objectKey === null ? 'missing_key' : 'key_prefix' },
        'rewritten copy of the round is not usable; delivering the original message',
      );
      return { key: input.original, object: 'original' };
    }
    return { key: row.objectKey, object: 'rewritten' };
  }

  /**
   * The round's `bec_scan_results` verdicts (written in the same transaction as the bec final),
   * or null. Echo-checked writer read in the ledger transaction (step 4.2 §6).
   */
  private async becVerdicts(
    tx: Prisma.TransactionClient,
    input: {
      messageId: bigint;
      receivedAt: Date;
      organizationId: bigint;
      round: number;
      scanId: bigint;
    },
  ): Promise<BecRoundVerdicts | null> {
    const row = await tx.becScanResult.findFirst({
      where: {
        scanId: input.scanId,
        receivedAt: input.receivedAt,
        messageId: input.messageId,
        organizationId: input.organizationId,
        lifecycleRound: input.round,
      },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        deterministicVerdict: true,
        verdict: true,
      },
    });
    if (row === null) return null;
    if (
      row.scanId !== input.scanId ||
      row.messageId !== input.messageId ||
      row.organizationId !== input.organizationId ||
      row.receivedAt.getTime() !== input.receivedAt.getTime() ||
      row.lifecycleRound !== input.round
    ) {
      this.metrics.inconsistentReads.inc({ read: 'bec_result' });
      throw new InconsistentBecResultReadError();
    }
    return { deterministicVerdict: row.deterministicVerdict, verdict: row.verdict };
  }

  /**
   * The `action` of the round's `dlp_scan_results` row (written in the same transaction as the
   * dlp final, D19), or null. Echo-checked writer read in the ledger transaction (step 4.2 §6).
   */
  private async dlpAction(
    tx: Prisma.TransactionClient,
    input: {
      messageId: bigint;
      receivedAt: Date;
      organizationId: bigint;
      round: number;
      scanId: bigint;
    },
  ): Promise<string | null> {
    const row = await tx.dlpScanResult.findFirst({
      where: {
        scanId: input.scanId,
        receivedAt: input.receivedAt,
        messageId: input.messageId,
        organizationId: input.organizationId,
        lifecycleRound: input.round,
      },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        action: true,
      },
    });
    if (row === null) return null;
    if (
      row.scanId !== input.scanId ||
      row.messageId !== input.messageId ||
      row.organizationId !== input.organizationId ||
      row.receivedAt.getTime() !== input.receivedAt.getTime() ||
      row.lifecycleRound !== input.round
    ) {
      this.metrics.inconsistentReads.inc({ read: 'dlp_result' });
      throw new InconsistentDlpResultReadError();
    }
    return row.action;
  }

  private async nextDeliverySeq(
    tx: Prisma.TransactionClient,
    message: { messageId: bigint; receivedAt: Date; organizationId: bigint },
  ): Promise<number> {
    const result = await tx.emailDelivery.aggregate({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
      },
      _max: { deliverySeq: true },
    });
    const max = result._max.deliverySeq;
    return max === null || max === undefined ? 0 : max + 1;
  }
}
