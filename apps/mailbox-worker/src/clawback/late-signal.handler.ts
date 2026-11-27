import {
  NonRetryableError,
  withTransactionDefaults,
  type HandleOutcome,
} from '@email-gateway/common';
import {
  Prisma,
  processOnce,
  type MessageVerdict,
  type PrismaClient,
} from '@email-gateway/database';
import {
  threatLateSignalV1,
  type EventEnvelope,
  type ThreatLateSignalV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  CLAWBACK_HARD_BLOCKS,
  clawbackSignalKey,
  copyMessageIdHash,
  signalFacts,
  type ClawbackSignalFacts,
} from '@email-gateway/mailbox-api';
import { loadOrgApiModeState } from '../domain/api-mode-state';
import { loadOrgSettings } from '../domain/org-settings';
import type { LateSignalResult, MailboxMetrics } from '../metrics/mailbox-metrics';
import { TX_MAX_WAIT_MS, TX_TIMEOUT_MS } from '../shared/db';
import { automaticCriteria, automaticWindow, insertAutomaticClawback } from './clawback-rows';

/** The ledger consumer shared with the copies role (C1: same queue, same consumer). */
export const LATE_SIGNAL_CONSUMER = 'mailbox-worker.copies';

/** Severity order of stored verdicts (C3.3: a late verdict only raises a copy's verdict). */
const VERDICT_RANK: Readonly<Record<MessageVerdict, number>> = Object.freeze({
  clean: 0,
  unknown: 0,
  bulk: 1,
  spam: 2,
  dlp_violation: 2,
  suspicious: 3,
  bec: 4,
  phishing: 4,
  malware: 5,
});

export const verdictRank = (verdict: MessageVerdict | null): number =>
  verdict === null ? -1 : VERDICT_RANK[verdict];

export interface LateSignalDeps {
  prisma: PrismaClient;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  /** TEST SEAM: only these organizations are handled (others are acked untouched). */
  organizationIds?: readonly bigint[];
}

/**
 * Whether a URL dynamic late signal reports a `malicious` URL. The email-worker
 * (`urlDynamicSignal`) sets level `critical` and the `hb.clawback.url` hard block only for a
 * malicious inspection; a `suspicious` inspection with the `url.dynamic_phishing` reason arrives
 * as verdict `phishing` at level `high` without a hard block and stays suspicious (C3.1).
 */
export function isMaliciousUrlSignal(payload: ThreatLateSignalV1): boolean {
  return payload.level === 'critical' || payload.hardBlocks.includes(CLAWBACK_HARD_BLOCKS.url);
}

/** The facts of a late signal (C3.1 rows "Sandbox revision" and "URL dynamic"). */
export function lateSignalFacts(payload: ThreatLateSignalV1): ClawbackSignalFacts {
  if (payload.kind === 'url_dynamic') {
    return signalFacts({
      kind: 'url_dynamic',
      urlVerdict: isMaliciousUrlSignal(payload) ? 'malicious' : 'suspicious',
    });
  }
  return signalFacts({
    kind: 'sandbox_revision',
    verdict: payload.verdict,
    level: payload.level,
    hardBlocks: payload.hardBlocks,
  });
}

/**
 * Step API-3 C2.1 (ADR-0103): `mail.threat.late_signal.v1` on `email.mailbox`, consumed by the
 * copies role with the same ledger consumer (`processOnce`, reconciled queue: every event writes
 * its ledger row, also the ones only acked). Organization not API-active → ack
 * (`not_active`); `auto_clawback = off` → ack (`skipped_off`); else an `api_clawbacks` row
 * (`trigger = late_verdict`, signal key C2.5, `decision_mode = policy`, the signal facts, criteria
 * from the message's Message-ID hash plus the payload hashes over `[receivedAt − lookback, now]`,
 * status `searching`) — `INSERT IGNORE`, so a redelivery or a replay creates nothing new. When it
 * is created, copies of the signal's own message have their stored verdict raised (C3.3,
 * `verdict_revision + 1`). The tenant comes from the envelope and every read is echo-checked.
 */
export class LateSignalHandler {
  private readonly txPrisma: PrismaClient;

  constructor(private readonly deps: LateSignalDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    const parsed = threatLateSignalV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('late_signal payload invalid');
    if (!/^[1-9][0-9]{0,19}$/.test(event.organizationId)) {
      throw new NonRetryableError('organization id invalid');
    }
    const organizationId = BigInt(event.organizationId);
    if (this.deps.organizationIds && !this.deps.organizationIds.includes(organizationId)) {
      return 'handled';
    }
    const payload = parsed.data;
    let result = 'not_active' as LateSignalResult;
    const outcome = await processOnce(
      this.txPrisma,
      LATE_SIGNAL_CONSUMER,
      event.eventId,
      async (tx) => {
        const messageId = BigInt(payload.messageId);
        const receivedAt = new Date(payload.receivedAt);
        const message = await tx.emailMessage.findUnique({
          where: { id_receivedAt: { id: messageId, receivedAt } },
          select: { organizationId: true, internetMessageId: true },
        });
        if (!message || message.organizationId !== organizationId) {
          result = 'no_message';
          return;
        }
        const state = await loadOrgApiModeState(tx, organizationId);
        if (!state?.active) {
          result = 'not_active';
          return;
        }
        const settings = await loadOrgSettings(tx, organizationId);
        if (settings.autoClawback === 'off') {
          result = 'skipped_off';
          return;
        }
        const now = this.deps.now();
        const facts = lateSignalFacts(payload);
        const messageIdHash = copyMessageIdHash(organizationId, message.internetMessageId);
        const criteria = automaticCriteria({
          window: automaticWindow(receivedAt, settings.clawbackLookbackDays, now),
          keys: {
            ...(messageIdHash !== null ? { messageIdHashes: [messageIdHash] } : {}),
            attachmentSha256: payload.attachmentSha256,
            urlSha256: payload.urlSha256,
          },
        });
        if (criteria === null) {
          result = 'no_message';
          return;
        }
        const signalKey = clawbackSignalKey(organizationId, {
          source: 'late',
          messageId,
          receivedAt,
          kind: payload.kind,
          revision: payload.revision,
          urlSha256: payload.urlSha256[0] ?? null,
        });
        const created = await insertAutomaticClawback(tx, {
          organizationId,
          trigger: 'late_verdict',
          signalKey,
          signal: {
            v: 1,
            kind: payload.kind,
            refs: {
              messageId: payload.messageId,
              receivedAt: receivedAt.toISOString(),
              scanId: payload.scanId,
              ...(payload.revision !== null ? { revision: payload.revision } : {}),
            },
            facts,
            signalAt: new Date(payload.signalAt).toISOString(),
          },
          criteria,
          facts,
          signalAt: new Date(payload.signalAt),
          now,
        });
        result = created ? 'created' : 'duplicate';
        if (!created) return;
        // C3.3: the signal's own message — its copies show the late verdict when it is worse.
        const worse = Object.entries(VERDICT_RANK)
          .filter(([, rank]) => rank < verdictRank(payload.verdict))
          .map(([verdict]) => verdict);
        if (worse.length > 0) {
          await tx.$executeRaw`
          UPDATE api_message_copies
          SET verdict = ${payload.verdict}, verdict_revision = LEAST(verdict_revision + 1, 255),
              updated_at = ${now}
          WHERE message_id = ${messageId} AND received_at = ${receivedAt}
            AND organization_id = ${organizationId} AND status = 'scanned'
            AND (verdict IS NULL OR verdict IN (${Prisma.join(worse)}))`;
        }
      },
    );
    if (outcome.status === 'duplicate') return 'duplicate';
    this.deps.metrics?.lateSignal(payload.kind, result);
    if (result === 'created') {
      this.deps.metrics?.clawback('late_verdict', 'created');
      this.deps.logger.info(
        { messageId: payload.messageId, kind: payload.kind, result },
        'late signal recorded as a clawback',
      );
    }
    return 'handled';
  };
}
