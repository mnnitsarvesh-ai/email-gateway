import {
  NonRetryableError,
  uuidv7,
  withTransactionDefaults,
  type HandleOutcome,
} from '@email-gateway/common';
import {
  processOnce,
  type ApiCopyDeliveredBasis,
  type ApiCopyStatus,
  type MessageVerdict,
  type Prisma,
  type PrismaClient,
} from '@email-gateway/database';
import {
  EventTypes,
  messageCopyScannedV1,
  type EventEnvelope,
  type MessageCopyScannedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  classifyRecipientDirection,
  copyMessageIdHash,
  extractCopyHeaders,
} from '@email-gateway/mailbox-api';
import {
  domainForAddress,
  isApiSide,
  loadOrgApiModeState,
  type OrgApiModeState,
} from '../domain/api-mode-state';
import { ensureApiConnection } from '../domain/connections';
import {
  findInlineMessage,
  resolveOrDiscoverMailbox,
  type InlineLink,
  type MailboxRef,
} from '../domain/mailboxes';
import type { CopyResult, MailboxMetrics, RemediationResult } from '../metrics/mailbox-metrics';
import {
  loadDecisionCopy,
  newDecisionMemo,
  type DecisionMemo,
  type RemediationDecider,
} from '../remediation/decide';
import type { CounterDelta, CounterStore } from '../runtime/redis-stores';
import { TX_MAX_WAIT_MS, TX_TIMEOUT_MS, big, bigOrNull, type Db } from '../shared/db';
import { domainOf, errorFields } from '../shared/errors';
import type { HeaderReader } from './header-reader';
import {
  STATUS_OF_OUTCOME,
  journalDelivery,
  lagDelta,
  lagOf,
  mergeDelta,
  storedVerdict,
} from './copy-plan';

/** Queue, ledger consumer and accepted event of the copies role (topology v17). */
export const COPIES_QUEUE = 'email.mailbox' as const;
export const COPIES_CONSUMER = 'mailbox-worker.copies';
export const COPIES_EVENT_TYPES = [EventTypes.MessageCopyScanned] as const;

export interface CopiesConfig {
  hybridLinkWindowHours: number;
  headerMaxBytes: number;
}

export interface CopiesDeps {
  prisma: PrismaClient;
  headers: HeaderReader;
  counters: CounterStore;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: CopiesConfig;
  /** Step API-2 R4: the remediation decision taken in the copies transaction (null: off). */
  decider: RemediationDecider | null;
  /** TEST SEAM: only these organizations are handled (others are acked untouched). */
  organizationIds?: readonly bigint[];
}

/** One mailbox a journal copy is recorded for (resolved before the ledger transaction). */
interface JournalTarget {
  mailbox: MailboxRef;
  address: string;
  inline: InlineLink | null;
}

interface CopyMessage {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  ingestSource: 'gateway' | 'journal_intake' | 'mailbox_api';
  internetMessageId: string | null;
  messageIdKey: string | null;
  envelopeFrom: string;
  headerFrom: string | null;
  domainId: bigint | null;
  emlObjectKey: string;
}

/** What one event did (applied to counters and metrics after the commit). */
interface Outcome {
  source: 'journal' | 'graph' | 'gmail';
  results: Map<CopyResult, number>;
  counters: Map<bigint, CounterDelta>;
  lags: number[];
  /** Remediation decisions written (`api_mode_remediations_total` after the commit). */
  remediations: Array<{ provider: string; action: string; result: RemediationResult }>;
}

const tally = (o: Outcome, result: CopyResult, n = 1) =>
  o.results.set(result, (o.results.get(result) ?? 0) + n);
const count = (o: Outcome, apiConnectionId: bigint, delta: CounterDelta) =>
  o.counters.set(apiConnectionId, mergeDelta(o.counters.get(apiConnectionId) ?? {}, delta));

/**
 * The copies role (design D7; queue `email.mailbox`, ledger `mailbox-worker.copies`, retry `hold`).
 * For every `mail.message.copy_scanned.v1`:
 *
 * - **journal copies** (`journal_intake`): the intake source's provider connection gives the API
 *   connection (created lazily); every recipient on an organization domain whose effective mode is
 *   `api`/`hybrid` resolves to a mailbox (`discovered` when unknown); internal recipients only
 *   count `skipped_internal` (API-1 records inbound only); per mailbox the Message-ID dedupe
 *   (`api_copy_dedupe_keys`, UNIQUE (mailbox, hash)) either records the copy (`INSERT … ON DUPLICATE
 *   KEY UPDATE` on UNIQUE (message, received_at, mailbox)), takes over an in-flight feed claim, or
 *   marks the feed copy already recorded `seen_journal` (no second row); hybrid copies link to the
 *   inline gateway message (verdict authority `inline`); lag from the topmost `Received:` header
 *   (bounded range GET) else the ingest time;
 * - **feed copies** (`mailbox_api`): the pending row written at ingest (D10.3) is finalized.
 *
 * Every write of an event — and the ledger row, also for skipped events (the queue is reconciled)
 * — commits in one writer transaction (`processOnce`), so a redelivery is a `duplicate` with no
 * effect. Mailbox discovery, the header read and the inline lookup happen before it (idempotent
 * reads and inserts). Counters and metrics follow the commit. Logs carry public ids, codes and
 * recipient domains only.
 */
export class CopiesHandler {
  private readonly txPrisma: PrismaClient;

  constructor(private readonly deps: CopiesDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    const parsed = messageCopyScannedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('copy_scanned payload invalid');
    if (!/^[1-9][0-9]{0,19}$/.test(event.organizationId)) {
      throw new NonRetryableError('organization id invalid');
    }
    const organizationId = BigInt(event.organizationId);
    if (this.deps.organizationIds && !this.deps.organizationIds.includes(organizationId)) {
      return 'handled';
    }
    const payload = parsed.data;
    const outcome: Outcome = {
      source: payload.ingestSource === 'journal_intake' ? 'journal' : 'graph',
      results: new Map(),
      counters: new Map(),
      lags: [],
      remediations: [],
    };
    const prepared = await this.prepare(organizationId, payload, outcome);
    const result = await processOnce(this.txPrisma, COPIES_CONSUMER, event.eventId, (tx) =>
      prepared(tx),
    );
    if (result.status === 'duplicate') return 'duplicate';
    for (const [apiConnectionId, delta] of outcome.counters) {
      await this.deps.counters.add(apiConnectionId, delta);
    }
    for (const [name, n] of outcome.results) this.deps.metrics?.copy(outcome.source, name, n);
    for (const lag of outcome.lags)
      this.deps.metrics?.lag.observe({ source: outcome.source }, lag / 1000);
    for (const r of outcome.remediations) {
      this.deps.metrics?.remediation(r.provider, r.action, r.result);
    }
    return 'handled';
  };

  /**
   * Everything before the ledger transaction; returns the transaction body. Throws on transient
   * failures (database, S3): the queue retries the event.
   */
  private async prepare(
    organizationId: bigint,
    payload: MessageCopyScannedV1,
    outcome: Outcome,
  ): Promise<(tx: Prisma.TransactionClient) => Promise<void>> {
    const noop = () => Promise.resolve();
    const message = await this.loadMessage(organizationId, payload);
    if (!message || message.ingestSource === 'gateway') {
      tally(outcome, 'no_copy');
      return noop;
    }
    if (message.ingestSource === 'mailbox_api') {
      return (tx) => this.finalizeFeedCopies(tx, message, payload, outcome);
    }
    const state = await loadOrgApiModeState(this.deps.prisma, organizationId);
    if (!state?.active) {
      tally(outcome, 'not_active');
      return noop;
    }
    const providerConnectionId = await this.intakeConnectionOf(message);
    if (providerConnectionId === null) {
      tally(outcome, 'no_connection');
      return noop;
    }
    const connection = await ensureApiConnection(
      this.deps.prisma,
      providerConnectionId,
      organizationId,
    );
    if (!connection) {
      tally(outcome, 'no_connection');
      return noop;
    }
    const targets = await this.journalTargets(message, state, connection.id, outcome);
    if (targets.length === 0) {
      if (!outcome.results.has('skipped_internal')) tally(outcome, 'no_recipient');
      return noop;
    }
    const delivery = journalDelivery(await this.topReceivedAt(message), message.receivedAt);
    return (tx) => this.recordJournalCopies(tx, message, payload, targets, delivery, outcome);
  }

  private async loadMessage(
    organizationId: bigint,
    payload: MessageCopyScannedV1,
  ): Promise<CopyMessage | null> {
    const row = await this.deps.prisma.emailMessage.findUnique({
      where: {
        id_receivedAt: { id: BigInt(payload.messageId), receivedAt: new Date(payload.receivedAt) },
      },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        ingestSource: true,
        internetMessageId: true,
        messageIdKey: true,
        envelopeFrom: true,
        headerFrom: true,
        domainId: true,
        emlObjectKey: true,
      },
    });
    if (!row || row.organizationId !== organizationId) return null;
    return row;
  }

  /** The 8.2 connection of the message's journal intake source (D6); null for none. */
  private async intakeConnectionOf(message: CopyMessage): Promise<bigint | null> {
    const intake = await this.deps.prisma.journalIntakeMessage.findUnique({
      where: { messageId_receivedAt: { messageId: message.id, receivedAt: message.receivedAt } },
      select: { organizationId: true, sourceId: true },
    });
    if (!intake || intake.organizationId !== message.organizationId) return null;
    const source = await this.deps.prisma.journalIntakeSource.findUnique({
      where: { id: intake.sourceId },
      select: { organizationId: true, providerConnectionId: true },
    });
    if (!source || source.organizationId !== message.organizationId) return null;
    return source.providerConnectionId;
  }

  /** D7 steps 3–5: the in-scope, inbound recipients as mailboxes (discovering unknown ones). */
  private async journalTargets(
    message: CopyMessage,
    state: OrgApiModeState,
    apiConnectionId: bigint,
    outcome: Outcome,
  ): Promise<JournalTarget[]> {
    const recipients = await this.deps.prisma.emailRecipient.findMany({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
      },
      select: { address: true },
      orderBy: { rcptSeq: 'asc' },
    });
    const sender = message.headerFrom ?? message.envelopeFrom;
    const orgDomains = state.domains.map((d) => d.name);
    const seen = new Set<string>();
    const targets: JournalTarget[] = [];
    const now = this.deps.now();
    for (const { address: raw } of recipients) {
      const address = raw.trim().toLowerCase();
      if (seen.has(address)) continue;
      seen.add(address);
      const domain = domainForAddress(state.domains, address);
      if (!domain || !isApiSide(domain.effectiveMode)) continue;
      if (classifyRecipientDirection(sender, address, orgDomains) === 'internal') {
        tally(outcome, 'skipped_internal');
        count(outcome, apiConnectionId, { skipped_internal: 1 });
        continue;
      }
      const mailbox = await resolveOrDiscoverMailbox(this.deps.prisma, {
        organizationId: message.organizationId,
        apiConnectionId,
        address,
        domainId: domain.id,
        now,
      });
      const inline =
        domain.effectiveMode === 'hybrid' && message.messageIdKey
          ? await findInlineMessage(this.deps.prisma, {
              organizationId: message.organizationId,
              messageIdKey: message.messageIdKey,
              address,
              around: message.receivedAt,
              windowHours: this.deps.config.hybridLinkWindowHours,
            })
          : null;
      targets.push({ mailbox, address, inline });
    }
    return targets;
  }

  /** The topmost `Received:` date of the stored copy (bounded range GET); null when unavailable. */
  private async topReceivedAt(message: CopyMessage): Promise<Date | null> {
    try {
      const bytes = await this.deps.headers.read(
        message.emlObjectKey,
        this.deps.config.headerMaxBytes,
        AbortSignal.timeout(60_000),
      );
      if (!bytes) return null;
      return extractCopyHeaders(bytes, { maxBytes: this.deps.config.headerMaxBytes }).topReceivedAt;
    } catch (error) {
      // The lag falls back to the ingest time (basis `ingest`); the copy is still recorded.
      this.deps.logger.warn(
        { messageId: message.id.toString(), ...errorFields(error) },
        'copy header read failed; lag uses the ingest time',
      );
      return null;
    }
  }

  /** D7 steps 6 and 8 for every target mailbox, inside the ledger transaction. */
  private async recordJournalCopies(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    targets: readonly JournalTarget[],
    delivery: { at: Date; basis: ApiCopyDeliveredBasis },
    outcome: Outcome,
  ): Promise<void> {
    const now = this.deps.now();
    const verdictAt = new Date(payload.completedAt);
    const status = STATUS_OF_OUTCOME[payload.outcome];
    const hash = copyMessageIdHash(message.organizationId, message.internetMessageId);
    const memo = newDecisionMemo();
    for (const target of targets) {
      const { mailbox } = target;
      const lag = lagOf(payload.outcome, delivery.at, verdictAt);
      const { verdict, authority } = storedVerdict(payload.verdict, target.inline);
      const write = {
        message,
        mailbox,
        status,
        verdict,
        authority,
        riskScore: payload.riskScore,
        verdictAt,
        lag,
        delivery,
        hash,
        inline: target.inline,
        now,
      };
      const copy =
        hash === null
          ? await upsertJournalCopy(tx, write)
          : await this.dedupeJournal(tx, write, hash);
      const recorded = copy !== null;
      await tx.$executeRaw`
        UPDATE api_mailboxes
        SET journal_last_seen_at = GREATEST(COALESCE(journal_last_seen_at, ${message.receivedAt}),
                                            ${message.receivedAt}),
            updated_at = ${now}
        WHERE id = ${mailbox.id} AND organization_id = ${message.organizationId}`;
      if (recorded) {
        tally(outcome, 'recorded');
        count(outcome, mailbox.apiConnectionId, {
          journal_copies: 1,
          ...(lag !== null ? lagDelta(lag) : {}),
        });
        if (lag !== null) outcome.lags.push(lag);
        await this.decideRemediation(tx, message, copy, payload.scanId, now, outcome, memo);
      } else {
        tally(outcome, 'duplicate');
        count(outcome, mailbox.apiConnectionId, { duplicates: 1 });
      }
      this.deps.logger.debug(
        {
          messageId: message.id.toString(),
          mailboxId: mailbox.publicId,
          recipientDomain: domainOf(target.address),
          result: recorded ? 'recorded' : 'duplicate',
          authority,
        },
        'journal copy recorded for mailbox',
      );
    }
  }

  /**
   * D7 step 6 with a Message-ID: claims (mailbox, hash) for this journal copy. The copy key when
   * the copy row was written (first sighting or a feed claim still in flight, which is taken
   * over); null when another copy of the same Message-ID is already recorded for the mailbox
   * (that copy is marked `seen_journal`, no second row).
   */
  private async dedupeJournal(
    tx: Prisma.TransactionClient,
    write: CopyWrite,
    hash: string,
  ): Promise<{ id: bigint; receivedAt: Date } | null> {
    const { message, mailbox, now } = write;
    const inserted = await tx.$executeRaw`
      INSERT IGNORE INTO api_copy_dedupe_keys
        (organization_id, mailbox_id, message_id_hash, claimed_by, copy_id, copy_received_at,
         claim_expires_at, created_at)
      VALUES (${message.organizationId}, ${mailbox.id}, ${hash}, 'journal', NULL, NULL, NULL,
              ${now})`;
    const rows = await tx.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        copy_id: bigint | number | null;
        copy_received_at: Date | null;
      }>
    >`
      SELECT id, organization_id, copy_id, copy_received_at FROM api_copy_dedupe_keys
      WHERE mailbox_id = ${mailbox.id} AND message_id_hash = ${hash}
      FOR UPDATE`;
    const claim = rows[0];
    if (!claim || big(claim.organization_id) !== message.organizationId) {
      throw new Error('api_copy_dedupe_keys read inconsistent');
    }
    const copyId = bigOrNull(claim.copy_id);
    if (inserted !== 1 && copyId !== null && claim.copy_received_at !== null) {
      const existing = await tx.$queryRaw<Array<{ message_id: bigint | number }>>`
        SELECT message_id FROM api_message_copies
        WHERE id = ${copyId} AND received_at = ${claim.copy_received_at}
          AND organization_id = ${message.organizationId}`;
      const existingMessage = existing[0] ? big(existing[0].message_id) : null;
      if (existingMessage !== null && existingMessage !== message.id) {
        await tx.$executeRaw`
          UPDATE api_message_copies SET seen_journal = 1, updated_at = ${now}
          WHERE id = ${copyId} AND received_at = ${claim.copy_received_at}
            AND organization_id = ${message.organizationId}`;
        return null;
      }
    }
    // First sighting, our own earlier row, or a feed claim in flight (taken over).
    const copy = await upsertJournalCopy(tx, write);
    await tx.$executeRaw`
      UPDATE api_copy_dedupe_keys
      SET claimed_by = 'journal', copy_id = ${copy.id}, copy_received_at = ${copy.receivedAt},
          claim_expires_at = NULL
      WHERE id = ${big(claim.id)}`;
    return copy;
  }

  /**
   * Step API-2 R4: the remediation decision of a recorded or finalized copy, in this transaction
   * (never for a duplicate). Counters and metrics are applied after the commit.
   */
  private async decideRemediation(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    key: { id: bigint; receivedAt: Date },
    scanId: string | null,
    now: Date,
    outcome: Outcome,
    memo: DecisionMemo,
  ): Promise<void> {
    if (!this.deps.decider) return;
    const copy = await loadDecisionCopy(tx, { ...key, organizationId: message.organizationId });
    if (!copy) throw new Error('api_message_copies row not visible for the decision');
    const result = await this.deps.decider.decide(tx, copy, scanId, now, memo);
    if (result.kind === 'none' || result.kind === 'unchanged' || !result.inserted) return;
    count(outcome, result.apiConnectionId, result.counters);
    if (result.kind !== 'pending') {
      outcome.remediations.push({
        provider: result.provider,
        action: result.action,
        result: result.kind,
      });
    }
  }

  /** D7 step 7 (+ 5, 8): the pending copy row(s) written at ingest are finalized. */
  private async finalizeFeedCopies(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    outcome: Outcome,
  ): Promise<void> {
    const copies = await tx.apiMessageCopy.findMany({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
      },
      select: {
        id: true,
        receivedAt: true,
        apiConnectionId: true,
        mailboxId: true,
        source: true,
        providerDeliveredAt: true,
      },
    });
    if (copies.length === 0) {
      tally(outcome, 'no_copy');
      return;
    }
    const now = this.deps.now();
    const verdictAt = new Date(payload.completedAt);
    const status = STATUS_OF_OUTCOME[payload.outcome];
    const memo = newDecisionMemo();
    for (const copy of copies) {
      outcome.source = copy.source;
      const inline = await this.feedInlineLink(tx, message, copy.mailboxId);
      const { verdict, authority } = storedVerdict(payload.verdict, inline);
      const lag = lagOf(payload.outcome, copy.providerDeliveredAt, verdictAt);
      await tx.$executeRaw`
        UPDATE api_message_copies
        SET status = ${status}, verdict = ${verdict}, risk_score = ${payload.riskScore},
            verdict_at = ${verdictAt}, lag_ms = ${lag}, seen_api = 1,
            verdict_authority = ${authority}, inline_message_id = ${inline?.messageId ?? null},
            inline_received_at = ${inline?.receivedAt ?? null}, updated_at = ${now}
        WHERE id = ${copy.id} AND received_at = ${copy.receivedAt}
          AND organization_id = ${message.organizationId}`;
      tally(outcome, 'recorded');
      if (lag !== null) {
        outcome.lags.push(lag);
        count(outcome, copy.apiConnectionId, lagDelta(lag));
      }
      await this.decideRemediation(tx, message, copy, payload.scanId, now, outcome, memo);
    }
  }

  /** The hybrid inline link of a feed copy (the mailbox's domain effective `hybrid`). */
  private async feedInlineLink(
    tx: Db,
    message: CopyMessage,
    mailboxId: bigint,
  ): Promise<InlineLink | null> {
    if (!message.messageIdKey) return null;
    const mailbox = await tx.apiMailbox.findUnique({
      where: { id: mailboxId },
      select: { organizationId: true, primaryAddress: true, domainId: true },
    });
    if (!mailbox || mailbox.organizationId !== message.organizationId || !mailbox.domainId) {
      return null;
    }
    const domain = await tx.domain.findUnique({
      where: { id: mailbox.domainId },
      select: {
        organizationId: true,
        protectionMode: true,
        deletedAt: true,
        organization: { select: { protectionMode: true } },
      },
    });
    if (
      !domain ||
      domain.organizationId !== message.organizationId ||
      domain.deletedAt !== null ||
      (domain.protectionMode ?? domain.organization.protectionMode) !== 'hybrid'
    ) {
      return null;
    }
    return findInlineMessage(tx, {
      organizationId: message.organizationId,
      messageIdKey: message.messageIdKey,
      address: mailbox.primaryAddress,
      around: message.receivedAt,
      windowHours: this.deps.config.hybridLinkWindowHours,
    });
  }
}

interface CopyWrite {
  message: CopyMessage;
  mailbox: MailboxRef;
  status: ApiCopyStatus;
  verdict: MessageVerdict | null;
  authority: 'copy' | 'inline';
  riskScore: number | null;
  verdictAt: Date;
  lag: number | null;
  delivery: { at: Date; basis: ApiCopyDeliveredBasis };
  hash: string | null;
  inline: InlineLink | null;
  now: Date;
}

/**
 * The journal copy row of (message, mailbox): `INSERT … ON DUPLICATE KEY UPDATE` on UNIQUE
 * (message_id, received_at, mailbox_id) (D7 step 6), `seen_journal = 1`, direction `inbound`.
 */
async function upsertJournalCopy(
  tx: Prisma.TransactionClient,
  w: CopyWrite,
): Promise<{ id: bigint; receivedAt: Date }> {
  const { message, mailbox } = w;
  await tx.$executeRaw`
    INSERT INTO api_message_copies
      (received_at, public_id, organization_id, api_connection_id, mailbox_id, message_id, source,
       seen_journal, seen_api, direction, message_id_hash, provider_delivered_at, delivered_basis,
       status, verdict, risk_score, verdict_at, lag_ms, verdict_authority, inline_message_id,
       inline_received_at, created_at, updated_at)
    VALUES (${message.receivedAt}, ${uuidv7(w.now.getTime())}, ${message.organizationId},
            ${mailbox.apiConnectionId}, ${mailbox.id}, ${message.id}, 'journal', 1, 0, 'inbound',
            ${w.hash}, ${w.delivery.at}, ${w.delivery.basis}, ${w.status}, ${w.verdict},
            ${w.riskScore}, ${w.verdictAt}, ${w.lag}, ${w.authority},
            ${w.inline?.messageId ?? null}, ${w.inline?.receivedAt ?? null}, ${w.now}, ${w.now})
    ON DUPLICATE KEY UPDATE
      seen_journal = 1, status = VALUES(status), verdict = VALUES(verdict),
      risk_score = VALUES(risk_score), verdict_at = VALUES(verdict_at), lag_ms = VALUES(lag_ms),
      provider_delivered_at = VALUES(provider_delivered_at),
      delivered_basis = VALUES(delivered_basis), verdict_authority = VALUES(verdict_authority),
      inline_message_id = VALUES(inline_message_id),
      inline_received_at = VALUES(inline_received_at), updated_at = VALUES(updated_at)`;
  const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
    SELECT id FROM api_message_copies
    WHERE message_id = ${message.id} AND received_at = ${message.receivedAt}
      AND mailbox_id = ${mailbox.id}`;
  if (!rows[0]) throw new Error('api_message_copies upsert not visible');
  return { id: big(rows[0].id), receivedAt: message.receivedAt };
}
