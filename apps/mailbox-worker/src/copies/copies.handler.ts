import {
  NonRetryableError,
  uuidv7,
  withTransactionDefaults,
  type HandleOutcome,
} from '@email-gateway/common';
import {
  Prisma,
  processOnce,
  type ApiCopyDeliveredBasis,
  type ApiCopyStatus,
  type MessageVerdict,
  type PrismaClient,
} from '@email-gateway/database';
import {
  EventTypes,
  messageCopyScannedV1,
  policyNotificationRequestedV1,
  type EventEnvelope,
  type MessageCopyScannedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  assessReport,
  classifyRecipientDirection,
  copyDetectionOf,
  copyMessageIdHash,
  extractCopyHeaders,
  reportGroupKey,
  reportOriginalSchema,
  type PolicyOutcomeFacts,
  type ResolvedOrgSettings,
} from '@email-gateway/mailbox-api';
import {
  domainForAddress,
  isApiSide,
  loadOrgApiModeState,
  type OrgApiModeState,
} from '../domain/api-mode-state';
import { ensureApiConnection } from '../domain/connections';
import {
  discoverMailboxIn,
  findInlineMessage,
  findMailboxByAddress,
  hasGatewayOutboundMessage,
  resolveOrDiscoverMailbox,
  type InlineLink,
  type MailboxRef,
} from '../domain/mailboxes';
import { loadOrgSettings } from '../domain/org-settings';
import { mailboxScope } from '../domain/scope';
import type { LateSignalHandler } from '../clawback/late-signal.handler';
import {
  addrSpecOf,
  latestRiskFacts,
  recordUserReport,
  REPORT_SCAN_TIMEOUT_CODE,
  reporterAddressOf,
  requestReportAlert,
} from '../reports/report-intake';
import type {
  CopyResult,
  MailboxMetrics,
  PolicyEvaluationResult,
  RemediationResult,
} from '../metrics/mailbox-metrics';
import {
  DISABLED_RESULT,
  inlineDispositionOf,
  loadCopyDlpFacts,
  recipientSeqOf,
  type CopyDlpFacts,
  type CopyPolicyEvaluator,
  type MessagePolicyResult,
} from '../policy/copy-policy';
import {
  domainMode,
  loadDecisionCopy,
  newDecisionMemo,
  type DecisionMemo,
  type DecisionResult,
  type RemediationDecider,
} from '../remediation/decide';
import type { CounterDelta, CounterStore } from '../runtime/redis-stores';
import { TX_MAX_WAIT_MS, TX_TIMEOUT_MS, big, bigOrNull, type Db } from '../shared/db';
import { domainOf, errorFields, InconsistentReadError } from '../shared/errors';
import type { HeaderReader } from './header-reader';
import {
  STATUS_OF_OUTCOME,
  journalDelivery,
  lagDelta,
  lagOf,
  mergeDelta,
  storedVerdict,
} from './copy-plan';
import {
  copyDetectedPayload,
  copyPolicyStateOf,
  detectionDirection,
  detectionKinds,
  type CountedCopy,
  type MessagePolicyState,
} from './detection';

/**
 * Queue, ledger consumer and accepted events of the copies role (topology v18: step API-3 adds
 * `mail.threat.late_signal.v1` on the same queue and ledger consumer, C1, C2.1).
 */
export const COPIES_QUEUE = 'email.mailbox' as const;
export const COPIES_CONSUMER = 'mailbox-worker.copies';
export const COPIES_EVENT_TYPES = [
  EventTypes.MessageCopyScanned,
  EventTypes.ThreatLateSignal,
] as const;

export interface CopiesConfig {
  hybridLinkWindowHours: number;
  headerMaxBytes: number;
  /** `API_MODE_REPORT_ALERT_MIN_INTERVAL_MINUTES` (C13): an ingested original reaching triage. */
  reportAlertMinIntervalMinutes: number;
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
  /** Step API-3 C2.1: the handler of `mail.threat.late_signal.v1` (same queue and ledger). */
  lateSignals: LateSignalHandler;
  /**
   * Step API-4 A1–A3: the detect-mode policy evaluation of copy messages (null: never evaluated,
   * every copy `disabled`).
   */
  policy: CopyPolicyEvaluator | null;
  /** TEST SEAM: only these organizations are handled (others are acked untouched). */
  organizationIds?: readonly bigint[];
}

/** One mailbox a journal copy is recorded for (resolved before the ledger transaction). */
interface JournalTarget {
  mailbox: MailboxRef;
  address: string;
  inline: InlineLink | null;
  /** Step API-3 C8.1: `internal` when sender and recipient are org-side (D7.4). */
  direction: 'inbound' | 'internal';
  /** Step API-3 C9.2: the mailbox is a report mailbox (recorded, never decided, a report). */
  reportMailbox: boolean;
  /** The recipient's organization domain (step API-4 B8 first copy). */
  domainId: bigint;
}

/** A copy row written for this event (journal or feed), before the policy and decision steps. */
interface RecordedCopy {
  key: { id: bigint; receivedAt: Date };
  mailbox: Pick<MailboxRef, 'id' | 'apiConnectionId'>;
  direction: 'inbound' | 'internal' | 'outbound';
  authority: 'copy' | 'inline';
  inline: InlineLink | null;
  reportMailbox: boolean;
}

/** Step API-4 A6.2: the sender of an outbound-only journal message (an API-side domain). */
interface OutboundSender {
  address: string;
  domainId: bigint;
  apiConnectionId: bigint;
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
  /** Step API-3: reports that reached `pending_triage` (seconds since reported). */
  triaged: number[];
  /** Step API-4: the message's detect evaluation (metric after the commit). */
  policy: { result: PolicyEvaluationResult; seconds: number | null } | null;
  /** Step API-4 A8: detections (metric labels) of the event. */
  detections: Array<{ kinds: string[]; direction: string }>;
  outboundDetections: number;
  /** Step API-4 B8: domains whose first copy is set by this event (memo after the commit). */
  firstCopyDomains: bigint[];
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
 *   `api`/`hybrid` resolves to a mailbox (`discovered` when unknown); internal recipients are
 *   recorded with `direction = internal` when the organization's internal-mail setting is on
 *   (step API-3 C8, ADR-0104; otherwise they count `skipped_internal`), outbound-only messages
 *   end `outbound_only` without discovery; per mailbox the Message-ID dedupe
 *   (`api_copy_dedupe_keys`, UNIQUE (mailbox, hash)) either records the copy (`INSERT … ON DUPLICATE
 *   KEY UPDATE` on UNIQUE (message, received_at, mailbox)), takes over an in-flight feed claim, or
 *   marks the feed copy already recorded `seen_journal` (no second row); hybrid copies link to the
 *   inline gateway message (verdict authority `inline`); lag from the topmost `Received:` header
 *   (bounded range GET) else the ingest time;
 * - **feed copies** (`mailbox_api`): the pending row written at ingest (D10.3) is finalized; a
 *   `mailbox_api` message without a copy row is a report original ingested by the `reports` role
 *   (C10.4): its scan facts go to the report (`pending_triage`).
 *
 * Step API-3: a copy recorded for a **report mailbox** (C9.2) gets no remediation decision and an
 * `api_user_reports` row instead; `mail.threat.late_signal.v1` on the same queue is handed to the
 * `LateSignalHandler` (same ledger consumer, C2.1).
 *
 * Every write of an event — and the ledger row, also for skipped events (the queue is reconciled)
 * — commits in one writer transaction (`processOnce`), so a redelivery is a `duplicate` with no
 * effect. Mailbox discovery, the header read and the inline lookup happen before it (idempotent
 * reads and inserts). Counters and metrics follow the commit. Logs carry public ids, codes and
 * recipient domains only.
 */
export class CopiesHandler {
  private readonly txPrisma: PrismaClient;
  /** Step API-4 B8: domains known to have their first copy recorded (the common path writes nothing). */
  private readonly firstCopyKnown = new Set<string>();

  constructor(private readonly deps: CopiesDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    if (event.eventType === EventTypes.ThreatLateSignal) {
      return this.deps.lateSignals.handle(event);
    }
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
      triaged: [],
      policy: null,
      detections: [],
      outboundDetections: 0,
      firstCopyDomains: [],
    };
    const prepared = await this.prepare(organizationId, payload, outcome, event.correlationId);
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
    for (const seconds of outcome.triaged) {
      this.deps.metrics?.report('pending_triage');
      this.deps.metrics?.reportTriage.observe(seconds);
    }
    if (outcome.policy) {
      this.deps.metrics?.policyEvaluation(outcome.policy.result, outcome.policy.seconds);
    }
    for (const d of outcome.detections) {
      for (const kind of d.kinds) {
        this.deps.metrics?.copyDetection(kind as 'threat' | 'dlp' | 'policy', d.direction);
      }
    }
    if (outcome.outboundDetections > 0) {
      this.deps.metrics?.outboundDetections.inc(outcome.outboundDetections);
    }
    if (this.firstCopyKnown.size > 100_000) this.firstCopyKnown.clear();
    for (const domainId of outcome.firstCopyDomains) this.firstCopyKnown.add(domainId.toString());
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
    correlationId: string,
  ): Promise<(tx: Prisma.TransactionClient) => Promise<void>> {
    const noop = () => Promise.resolve();
    const message = await this.loadMessage(organizationId, payload);
    if (!message || message.ingestSource === 'gateway') {
      tally(outcome, 'no_copy');
      return noop;
    }
    if (message.ingestSource === 'mailbox_api') {
      return (tx) => this.finalizeFeedCopies(tx, message, payload, outcome, correlationId);
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
    const settings = await loadOrgSettings(this.deps.prisma, organizationId);
    const { targets, apiSideRecipients } = await this.journalTargets(
      message,
      state,
      connection.id,
      settings,
      outcome,
    );
    if (targets.length === 0) {
      if (!outcome.results.has('skipped_internal')) {
        // C8.2: no recipient on an API-side domain and an org-side sender → outbound-only.
        // Step API-4 A6.2: evaluated, and recorded on the sender's mailbox when a detection.
        const sender = addrSpecOf(message.headerFrom) ?? addrSpecOf(message.envelopeFrom);
        const senderDomain =
          apiSideRecipients === 0 && sender !== null
            ? domainForAddress(state.domains, sender)
            : null;
        if (!senderDomain) {
          tally(outcome, 'no_recipient');
          return noop;
        }
        if (
          !settings.outboundDetectionEnabled ||
          !isApiSide(senderDomain.effectiveMode) ||
          payload.outcome === 'parse_failed' ||
          (message.messageIdKey !== null &&
            (await hasGatewayOutboundMessage(this.deps.prisma, {
              organizationId,
              messageIdKey: message.messageIdKey,
              around: message.receivedAt,
              windowHours: this.deps.config.hybridLinkWindowHours,
            })))
        ) {
          // A6.3 (P-I3): the gateway enforced outbound policy inline; or detections are off.
          tally(outcome, 'outbound_only');
          return noop;
        }
        const outboundSender: OutboundSender = {
          address: sender!,
          domainId: senderDomain.id,
          apiConnectionId: connection.id,
        };
        return (tx) =>
          this.recordOutboundDetection(
            tx,
            message,
            payload,
            outboundSender,
            settings,
            outcome,
            correlationId,
          );
      }
      return noop;
    }
    const delivery = journalDelivery(await this.topReceivedAt(message), message.receivedAt);
    return (tx) =>
      this.recordJournalCopies(tx, message, payload, targets, delivery, outcome, correlationId);
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

  /**
   * D7 steps 3–5: the in-scope recipients as mailboxes (discovering unknown ones). Step API-3
   * (C8.1, ADR-0104): internal recipients are recorded (`direction = internal`) when the
   * organization's internal-mail setting is on, otherwise counted `skipped_internal` without
   * discovery — except a known report mailbox, which is recorded whatever the direction and
   * setting (C9.2). `apiSideRecipients` counts recipients on API-side domains (C8.2).
   */
  private async journalTargets(
    message: CopyMessage,
    state: OrgApiModeState,
    apiConnectionId: bigint,
    settings: ResolvedOrgSettings,
    outcome: Outcome,
  ): Promise<{ targets: JournalTarget[]; apiSideRecipients: number }> {
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
    let apiSideRecipients = 0;
    for (const { address: raw } of recipients) {
      const address = raw.trim().toLowerCase();
      if (seen.has(address)) continue;
      seen.add(address);
      const domain = domainForAddress(state.domains, address);
      if (!domain || !isApiSide(domain.effectiveMode)) continue;
      apiSideRecipients += 1;
      const direction = classifyRecipientDirection(sender, address, orgDomains);
      let mailbox: MailboxRef | null = null;
      if (direction === 'internal' && !settings.internalMailEnabled) {
        const known = await findMailboxByAddress(this.deps.prisma, message.organizationId, address);
        if (!known || !(await this.isReportMailbox(known))) {
          tally(outcome, 'skipped_internal');
          count(outcome, apiConnectionId, { skipped_internal: 1 });
          continue;
        }
        mailbox = known;
      }
      mailbox ??= await resolveOrDiscoverMailbox(this.deps.prisma, {
        organizationId: message.organizationId,
        apiConnectionId,
        address,
        domainId: domain.id,
        now,
      });
      const reportMailbox = await this.isReportMailbox(mailbox);
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
      targets.push({ mailbox, address, inline, direction, reportMailbox, domainId: domain.id });
    }
    return { targets, apiSideRecipients };
  }

  /** `api_mailboxes.report_mailbox` of a mailbox (organization echo-checked). */
  private async isReportMailbox(mailbox: MailboxRef, db: Db = this.deps.prisma): Promise<boolean> {
    const row = await db.apiMailbox.findUnique({
      where: { id: mailbox.id },
      select: { organizationId: true, reportMailbox: true },
    });
    if (!row || row.organizationId !== mailbox.organizationId) return false;
    return row.reportMailbox;
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

  /**
   * D7 steps 6 and 8 for every target mailbox, inside the ledger transaction; then (step API-4)
   * the message's detect evaluation and, per recorded copy, the policy columns and the
   * remediation decision, the ALERT request and the detection event (`applyPolicy`).
   */
  private async recordJournalCopies(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    targets: readonly JournalTarget[],
    delivery: { at: Date; basis: ApiCopyDeliveredBasis },
    outcome: Outcome,
    correlationId: string,
  ): Promise<void> {
    const now = this.deps.now();
    const verdictAt = new Date(payload.completedAt);
    const status = STATUS_OF_OUTCOME[payload.outcome];
    const hash = copyMessageIdHash(message.organizationId, message.internetMessageId);
    const recorded: RecordedCopy[] = [];
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
        direction: target.direction,
        now,
      };
      const copy =
        hash === null
          ? await upsertJournalCopy(tx, write)
          : await this.dedupeJournal(tx, write, hash);
      const isRecorded = copy !== null;
      await tx.$executeRaw`
        UPDATE api_mailboxes
        SET journal_last_seen_at = GREATEST(COALESCE(journal_last_seen_at, ${message.receivedAt}),
                                            ${message.receivedAt}),
            updated_at = ${now}
        WHERE id = ${mailbox.id} AND organization_id = ${message.organizationId}`;
      if (isRecorded) {
        const internal = target.direction === 'internal';
        tally(outcome, internal ? 'recorded_internal' : 'recorded');
        count(outcome, mailbox.apiConnectionId, {
          journal_copies: 1,
          ...(internal ? { internal_copies: 1 } : {}),
          ...(lag !== null ? lagDelta(lag) : {}),
        });
        if (lag !== null) outcome.lags.push(lag);
        if (target.reportMailbox) {
          // C9.2 / C-I5: a report-mailbox copy is never decided; it becomes a user report.
          await this.intakeReport(tx, message, mailbox, copy, now, outcome);
        }
        recorded.push({
          key: copy,
          mailbox,
          direction: target.direction,
          authority,
          inline: target.inline,
          reportMailbox: target.reportMailbox,
        });
      } else {
        tally(outcome, 'duplicate');
        count(outcome, mailbox.apiConnectionId, { duplicates: 1 });
      }
      this.deps.logger.debug(
        {
          messageId: message.id.toString(),
          mailboxId: mailbox.publicId,
          recipientDomain: domainOf(target.address),
          result: isRecorded ? 'recorded' : 'duplicate',
          direction: target.direction,
          authority,
        },
        'journal copy recorded for mailbox',
      );
    }
    if (recorded.length === 0) return;
    const policy = await this.messagePolicy(tx, message, payload, recorded, now, outcome);
    await this.applyPolicy(tx, {
      message,
      payload,
      copies: recorded,
      policy,
      copySource: 'journal',
      now,
      outcome,
      correlationId,
    });
  }

  /**
   * Step API-4 A6.2: an outbound-only journal message of an API-active organization with outbound
   * detection on. The message is evaluated (A3, message level); only a detection (A8.1) is
   * recorded — one `api_message_copies` row for the sender's mailbox (header-From addr-spec, else
   * the envelope sender; unknown → a `discovered` mailbox under the intake source's connection),
   * `direction = outbound`, no delivery time or lag, `seen_journal = 1`, never a coverage sighting
   * and no dedupe claim. When an inbound/internal copy of the same message already exists for
   * that mailbox (the sender was also a recipient), nothing is recorded. Its decision is always
   * `skip outbound_not_remediable` (P-I5).
   */
  private async recordOutboundDetection(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    sender: OutboundSender,
    settings: ResolvedOrgSettings,
    outcome: Outcome,
    correlationId: string,
  ): Promise<void> {
    const now = this.deps.now();
    // The message level is evaluated before any row exists (a non-detection records nothing).
    const policy = await this.messagePolicy(
      tx,
      message,
      payload,
      [
        {
          authority: 'copy',
          reportMailbox: false,
          mailbox: { id: 0n, apiConnectionId: sender.apiConnectionId },
        },
      ],
      now,
      outcome,
      settings,
    );
    const messageOutcome = policy.result?.outcomeFor(null) ?? null;
    const detection = copyDetectionOf({
      verdict: payload.verdict,
      policyOutcome: messageOutcome,
      dlpAction: policy.dlp?.action ?? null,
    });
    if (!detection.isDetection) {
      tally(outcome, 'outbound_only');
      return;
    }
    const mailbox = await discoverMailboxIn(tx, {
      organizationId: message.organizationId,
      apiConnectionId: sender.apiConnectionId,
      address: sender.address,
      domainId: sender.domainId,
      now,
    });
    const hash = copyMessageIdHash(message.organizationId, message.internetMessageId);
    const also = await tx.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT id FROM api_message_copies
      WHERE organization_id = ${message.organizationId} AND mailbox_id = ${mailbox.id}
        AND direction IN ('inbound', 'internal')
        AND ((message_id = ${message.id} AND received_at = ${message.receivedAt})
             ${hash === null ? Prisma.empty : Prisma.sql`OR message_id_hash = ${hash}`})
      LIMIT 1`;
    if (also.length > 0) {
      // The sender was also a recipient: its inbound/internal copy is the record.
      tally(outcome, 'outbound_only');
      return;
    }
    const status = STATUS_OF_OUTCOME[payload.outcome];
    await tx.$executeRaw`
      INSERT INTO api_message_copies
        (received_at, public_id, organization_id, api_connection_id, mailbox_id, message_id, source,
         seen_journal, seen_api, direction, message_id_hash, provider_delivered_at, delivered_basis,
         status, verdict, risk_score, verdict_at, lag_ms, verdict_authority, created_at, updated_at)
      VALUES (${message.receivedAt}, ${uuidv7(now.getTime())}, ${message.organizationId},
              ${mailbox.apiConnectionId}, ${mailbox.id}, ${message.id}, 'journal', 1, 0, 'outbound',
              ${hash}, NULL, NULL, ${status}, ${payload.verdict}, ${payload.riskScore},
              ${new Date(payload.completedAt)}, NULL, 'copy', ${now}, ${now})
      ON DUPLICATE KEY UPDATE seen_journal = 1, updated_at = VALUES(updated_at)`;
    const rows = await tx.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number; direction: string }>
    >`
      SELECT id, organization_id, direction FROM api_message_copies
      WHERE message_id = ${message.id} AND received_at = ${message.receivedAt}
        AND mailbox_id = ${mailbox.id}`;
    const row = rows[0];
    if (!row || big(row.organization_id) !== message.organizationId) {
      throw new InconsistentReadError('api_message_copies');
    }
    if (row.direction !== 'outbound') {
      tally(outcome, 'outbound_only');
      return;
    }
    tally(outcome, 'outbound_detection');
    count(outcome, mailbox.apiConnectionId, { outbound_detections: 1 });
    outcome.outboundDetections += 1;
    await this.applyPolicy(tx, {
      message,
      payload,
      copies: [
        {
          key: { id: big(row.id), receivedAt: message.receivedAt },
          mailbox,
          direction: 'outbound',
          authority: 'copy',
          inline: null,
          reportMailbox: false,
        },
      ],
      policy,
      copySource: 'journal',
      now,
      outcome,
      correlationId,
    });
  }

  /**
   * A1: the message-level detect evaluation of a registry copy message — none when no recorded
   * copy has copy authority outside a report mailbox (all-inline hybrid, report mailboxes);
   * `not_applicable` for a parse failure; `disabled` by the platform switch or the organization
   * setting; else `evaluateCopyRound` once (detect row inserted, or reused on a replay). A failed
   * evaluation is counted, logged and never dead-letters the event. Plus the round's DLP facts.
   */
  private async messagePolicy(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    copies: ReadonlyArray<Pick<RecordedCopy, 'authority' | 'reportMailbox' | 'mailbox'>>,
    now: Date,
    outcome: Outcome,
    settings?: ResolvedOrgSettings,
  ): Promise<MessageEvaluation> {
    const evaluable = copies.filter((c) => c.authority === 'copy' && !c.reportMailbox);
    if (evaluable.length === 0) {
      if (copies.some((c) => c.authority === 'inline')) {
        outcome.policy = { result: 'inline', seconds: null };
      }
      return { state: null, result: null, dlp: null };
    }
    if (payload.outcome === 'parse_failed' || payload.scanId === null) {
      outcome.policy = { result: 'not_applicable', seconds: null };
      return { state: 'not_applicable', result: null, dlp: null };
    }
    const scanId = BigInt(payload.scanId);
    const dlp = await loadCopyDlpFacts(tx, {
      messageId: message.id,
      receivedAt: message.receivedAt,
      organizationId: message.organizationId,
      scanId,
    });
    const resolved = settings ?? (await loadOrgSettings(tx, message.organizationId));
    const evaluator = this.deps.policy;
    if (!evaluator?.enabled || !resolved.policyEvaluationEnabled) {
      outcome.policy = { result: 'disabled', seconds: null };
      return { state: 'disabled', result: DISABLED_RESULT, dlp };
    }
    const result = await evaluator.evaluate(
      tx,
      {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        round: payload.lifecycleRound,
        trigger: payload.outcome === 'scan_failed' ? 'scan_failed' : 'scanned',
        scanId,
      },
      now,
    );
    const connectionId = evaluable[0]!.mailbox.apiConnectionId;
    if (result.state === 'failed') {
      count(outcome, connectionId, { policy_errors: 1 });
      outcome.policy = { result: 'failed', seconds: null };
      this.deps.logger.error(
        {
          messageId: payload.messagePublicId,
          code: result.failureCode,
          ingestSource: payload.ingestSource,
        },
        'detect policy evaluation of a copy message failed; the verdict lane decides alone',
      );
    } else {
      if (result.fresh) count(outcome, connectionId, { policy_evaluations: 1 });
      outcome.policy = { result: 'evaluated', seconds: result.durationSeconds };
    }
    return { state: result.state, result, dlp };
  }

  /**
   * Step API-4 per recorded copy (A3): the policy columns (`policy_state`, `policy_disposition`,
   * `policy_tagged`, `dlp_action`; written once — a copy whose state is already set is a replay)
   * and the remediation decision with the copy's policy outcome (R9.1 recipient row →
   * `policyOutcomeOf`) and scope; then the first-copy tracking (B8), the ALERT request (A7) and
   * the detection event (A8) of the message. Report-mailbox copies are never decided.
   */
  private async applyPolicy(
    tx: Prisma.TransactionClient,
    input: {
      message: CopyMessage;
      payload: MessageCopyScannedV1;
      copies: readonly RecordedCopy[];
      policy: MessageEvaluation;
      copySource: 'journal' | 'graph' | 'gmail';
      now: Date;
      outcome: Outcome;
      correlationId: string;
    },
  ): Promise<void> {
    const { message, payload, policy, now, outcome } = input;
    const memo = newDecisionMemo();
    const counted: CountedCopy[] = [];
    let fresh = false;
    for (const copy of input.copies) {
      const state = copyPolicyStateOf({
        reportMailbox: copy.reportMailbox,
        authority: copy.authority,
        messageState: policy.state,
      });
      let copyOutcome: PolicyOutcomeFacts | null = null;
      if (state === 'evaluated' && policy.result) {
        const rcptSeq =
          copy.direction === 'outbound'
            ? null
            : await recipientSeqOf(tx, {
                organizationId: message.organizationId,
                messageId: message.id,
                receivedAt: message.receivedAt,
                mailboxId: copy.mailbox.id,
              });
        copyOutcome = policy.result.outcomeFor(rcptSeq);
      }
      const disposition =
        state === 'inline' && copy.inline
          ? await inlineDispositionOf(tx, message.organizationId, copy.inline)
          : (copyOutcome?.disposition ?? null);
      const dlpAction =
        copy.authority === 'copy' && !copy.reportMailbox ? policy.dlp?.action : null;
      const written = await tx.$executeRaw`
        UPDATE api_message_copies
        SET policy_state = ${state}, policy_disposition = ${disposition},
            policy_tagged = ${copyOutcome?.tagged ?? false}, dlp_action = ${dlpAction ?? null},
            updated_at = ${now}
        WHERE id = ${copy.key.id} AND received_at = ${copy.key.receivedAt}
          AND organization_id = ${message.organizationId} AND policy_state = 'none'`;
      const copyFresh = written === 1;
      fresh ||= copyFresh;
      if (copy.reportMailbox) continue;
      const decided = await this.decideRemediation(
        tx,
        message,
        copy.key,
        payload.scanId,
        now,
        outcome,
        memo,
        copyOutcome,
      );
      const scope = await this.copyScope(tx, message.organizationId, copy.mailbox.id, memo);
      if (copy.direction !== 'outbound' && scope.inScope && scope.domainId !== null) {
        await this.firstCopy(tx, message, scope.domainId, copy.key, payload, now, outcome);
      }
      if (copy.authority !== 'copy' || !scope.inScope) continue;
      const mode = await domainMode(tx, message.organizationId, scope.domainId, memo);
      counted.push({
        publicId: decided.publicId,
        direction: copy.direction,
        domainMode: mode,
        remediation: remediationOf(decided.result),
        detection: copyDetectionOf({
          verdict: payload.verdict,
          policyOutcome: copyOutcome,
          dlpAction: policy.dlp?.action ?? null,
        }),
      });
    }
    // Events only for a first processing of the copies (a manual replay writes nothing again).
    if (!fresh || policy.state === null) return;
    if (policy.result?.fresh && policy.result.alert) {
      await this.requestPolicyAlert(tx, message, payload, policy.result, now, input.correlationId);
    }
    const detected = copyDetectedPayload({
      message: {
        id: message.id,
        publicId: payload.messagePublicId,
        receivedAt: message.receivedAt,
        ingestSource: message.ingestSource === 'mailbox_api' ? 'mailbox_api' : 'journal_intake',
      },
      copySource: input.copySource,
      verdict: payload.verdict,
      riskScore: payload.riskScore,
      policyState: policy.state,
      messageOutcome: policy.result?.messageOutcome ?? null,
      dlp: policy.dlp,
      counted,
      decidedAt: now,
    });
    if (!detected) return;
    await tx.messageOutbox.create({
      data: {
        eventId: uuidv7(now.getTime()),
        organizationId: message.organizationId,
        eventType: EventTypes.MessageCopyDetected,
        aggregateType: 'message',
        aggregateId: payload.messagePublicId,
        correlationId: input.correlationId.slice(0, 128),
        payload: detected,
      },
      select: { id: true },
    });
    const first = input.copies.find((c) => !c.reportMailbox) ?? input.copies[0]!;
    count(outcome, first.mailbox.apiConnectionId, { copy_detections: 1 });
    const messageOutcome = policy.result?.messageOutcome ?? null;
    const kinds = new Set<string>();
    for (const c of counted) {
      if (!c.detection.isDetection) continue;
      for (const k of detectionKinds(c.detection, messageOutcome)) kinds.add(k);
    }
    outcome.detections.push({ kinds: [...kinds], direction: detectionDirection(counted) });
  }

  /** A7: one `mail.policy.notification_requested.v1` (`policy_alert`, detect) per message. */
  private async requestPolicyAlert(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    result: MessagePolicyResult,
    now: Date,
    correlationId: string,
  ): Promise<void> {
    const alert = result.alert!;
    const notification = policyNotificationRequestedV1.parse({
      messageId: message.id.toString(),
      receivedAt: message.receivedAt.toISOString(),
      direction: alert.direction,
      lifecycleRound: payload.lifecycleRound,
      kind: 'policy_alert',
      severity: alert.severity,
      disposition: alert.disposition,
      decisive: alert.decisive,
      ruleRefs: alert.ruleRefs,
      requestedAt: now.toISOString(),
      evaluationMode: 'detect',
    });
    await tx.messageOutbox.create({
      data: {
        eventId: uuidv7(now.getTime()),
        organizationId: message.organizationId,
        eventType: EventTypes.PolicyNotificationRequested,
        aggregateType: 'message',
        aggregateId: message.id.toString(),
        correlationId: correlationId.slice(0, 128),
        payload: notification,
      },
      select: { id: true },
    });
  }

  /** B6: the copy's mailbox scope (organization echo-checked). */
  private async copyScope(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    mailboxId: bigint,
    memo: DecisionMemo,
  ): Promise<{ domainId: bigint | null; inScope: boolean }> {
    const mailbox = await tx.apiMailbox.findUnique({
      where: { id: mailboxId },
      select: { organizationId: true, domainId: true, scopeState: true, scopeSelected: true },
    });
    if (!mailbox || mailbox.organizationId !== organizationId) {
      throw new InconsistentReadError('api_mailboxes');
    }
    return mailboxScope(tx, organizationId, mailbox, memo.scopeKinds);
  }

  /**
   * B8: the domain's first in-scope copy (`api_mode_domain_settings.first_copy_*` when NULL;
   * `INSERT … ON DUPLICATE KEY UPDATE` with COALESCE). An in-process memo per domain keeps the
   * common path free of writes.
   */
  private async firstCopy(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    domainId: bigint,
    key: { id: bigint; receivedAt: Date },
    payload: MessageCopyScannedV1,
    now: Date,
    outcome: Outcome,
  ): Promise<void> {
    if (this.firstCopyKnown.has(domainId.toString())) return;
    if (outcome.firstCopyDomains.includes(domainId)) return;
    const verdictAt = new Date(payload.completedAt);
    await tx.$executeRaw`
      INSERT INTO api_mode_domain_settings
        (public_id, organization_id, domain_id, scope_kind, first_copy_id, first_copy_received_at,
         first_copy_at, row_version, created_at, updated_at)
      VALUES (${uuidv7(now.getTime())}, ${message.organizationId}, ${domainId}, 'all', ${key.id},
              ${key.receivedAt}, ${verdictAt}, 1, ${now}, ${now})
      ON DUPLICATE KEY UPDATE
        first_copy_received_at =
          IF(first_copy_id IS NULL, VALUES(first_copy_received_at), first_copy_received_at),
        first_copy_at = IF(first_copy_id IS NULL, VALUES(first_copy_at), first_copy_at),
        first_copy_id = COALESCE(first_copy_id, VALUES(first_copy_id))`;
    outcome.firstCopyDomains.push(domainId);
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
    policyOutcome: PolicyOutcomeFacts | null,
  ): Promise<{ publicId: string; result: DecisionResult | null }> {
    const copy = await loadDecisionCopy(tx, { ...key, organizationId: message.organizationId });
    if (!copy) throw new Error('api_message_copies row not visible for the decision');
    if (!this.deps.decider) return { publicId: copy.publicId, result: null };
    const result = await this.deps.decider.decide(tx, copy, scanId, now, memo, policyOutcome);
    const done = { publicId: copy.publicId, result };
    if (result.kind === 'none' || result.kind === 'unchanged' || !result.inserted) return done;
    count(outcome, result.apiConnectionId, result.counters);
    if (result.kind !== 'pending') {
      outcome.remediations.push({
        provider: result.provider,
        action: result.action,
        result: result.kind,
      });
    }
    return done;
  }

  /** C9.2: the `api_user_reports` row of a copy recorded in a report mailbox (same transaction). */
  private async intakeReport(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    mailbox: Pick<MailboxRef, 'id' | 'apiConnectionId'>,
    copy: { id: bigint; receivedAt: Date },
    now: Date,
    outcome: Outcome,
  ): Promise<void> {
    const created = await recordUserReport(tx, {
      organizationId: message.organizationId,
      apiConnectionId: mailbox.apiConnectionId,
      mailboxId: mailbox.id,
      copy,
      messageId: message.id,
      reporterAddress: reporterAddressOf(message.headerFrom, message.envelopeFrom),
      now,
    });
    if (!created) return;
    tally(outcome, 'report_received');
    count(outcome, mailbox.apiConnectionId, { reports_received: 1 });
  }

  /**
   * C10.4: the detect-mode scan of a report original ingested by the `reports` role (a
   * `mailbox_api` message without a copy row) — its scan facts, assessment and group key on the
   * report, which moves `scanning → pending_triage` in this ledger transaction. A report the
   * reports role already moved to triage because this scan was overdue (`last_error_code =
   * original_scan_timeout`, still open) gets the late scan's facts and assessment instead (no new
   * alert). False when no report references the message (the event stays `no_copy`).
   */
  private async scanOfReportOriginal(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    outcome: Outcome,
  ): Promise<boolean> {
    const report = await tx.apiUserReport.findFirst({
      where: {
        originalMessageId: message.id,
        originalReceivedAt: message.receivedAt,
        organizationId: message.organizationId,
      },
      select: {
        id: true,
        organizationId: true,
        apiConnectionId: true,
        status: true,
        original: true,
        groupKey: true,
        reportedAt: true,
        rowVersion: true,
        lastErrorCode: true,
      },
    });
    if (!report) return false;
    if (report.organizationId !== message.organizationId) {
      throw new InconsistentReadError('api_user_reports');
    }
    tally(outcome, 'report_scanned');
    const overdue =
      report.lastErrorCode === REPORT_SCAN_TIMEOUT_CODE &&
      (report.status === 'pending_triage' || report.status === 'in_review');
    if (report.status !== 'scanning' && !overdue) return true;
    const now = this.deps.now();
    const scanId =
      payload.scanId !== null && /^[1-9][0-9]{0,19}$/.test(payload.scanId)
        ? BigInt(payload.scanId)
        : null;
    const risk = scanId === null ? null : await latestRiskFacts(tx, message, scanId);
    const verdict = payload.verdict ?? risk?.verdict ?? null;
    const score = payload.riskScore ?? risk?.score ?? null;
    const level = risk?.level ?? null;
    const assessment = assessReport(
      verdict === null ? null : { verdict, level, hardBlocks: risk?.hardBlocks ?? [] },
    );
    const parsedOriginal = reportOriginalSchema.safeParse(report.original);
    const groupKey =
      report.groupKey ?? (parsedOriginal.success ? reportGroupKey(parsedOriginal.data) : null);
    if (overdue) {
      await tx.$executeRaw`
        UPDATE api_user_reports
        SET scan_verdict = ${verdict},
            scan_risk_score = ${score === null ? null : Math.min(65_535, Math.max(0, score))},
            scan_level = ${level}, assessment = ${assessment}, group_key = ${groupKey},
            last_error_code = NULL, row_version = row_version + 1, updated_at = ${now}
        WHERE id = ${report.id} AND organization_id = ${message.organizationId}
          AND status = ${report.status} AND row_version = ${report.rowVersion}
          AND last_error_code = ${REPORT_SCAN_TIMEOUT_CODE}`;
      return true;
    }
    const moved = await tx.$executeRaw`
      UPDATE api_user_reports
      SET status = 'pending_triage', scan_verdict = ${verdict},
          scan_risk_score = ${score === null ? null : Math.min(65_535, Math.max(0, score))},
          scan_level = ${level}, assessment = ${assessment}, group_key = ${groupKey},
          next_attempt_at = NULL, row_version = row_version + 1, updated_at = ${now}
      WHERE id = ${report.id} AND organization_id = ${message.organizationId}
        AND status = 'scanning' AND row_version = ${report.rowVersion}`;
    if (moved !== 1) return true;
    await requestReportAlert(tx, {
      organizationId: message.organizationId,
      windowMinutes: this.deps.config.reportAlertMinIntervalMinutes,
      now,
    });
    outcome.triaged.push(Math.max(0, (now.getTime() - report.reportedAt.getTime()) / 1000));
    return true;
  }

  /** D7 step 7 (+ 5, 8): the pending copy row(s) written at ingest are finalized. */
  private async finalizeFeedCopies(
    tx: Prisma.TransactionClient,
    message: CopyMessage,
    payload: MessageCopyScannedV1,
    outcome: Outcome,
    correlationId: string,
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
        direction: true,
      },
    });
    if (copies.length === 0) {
      if (!(await this.scanOfReportOriginal(tx, message, payload, outcome))) {
        tally(outcome, 'no_copy');
      }
      return;
    }
    const now = this.deps.now();
    const verdictAt = new Date(payload.completedAt);
    const status = STATUS_OF_OUTCOME[payload.outcome];
    const recorded: RecordedCopy[] = [];
    let copySource: 'journal' | 'graph' | 'gmail' = 'graph';
    for (const copy of copies) {
      outcome.source = copy.source;
      copySource = copy.source;
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
      const mailbox: MailboxRef = {
        id: copy.mailboxId,
        publicId: '',
        organizationId: message.organizationId,
        apiConnectionId: copy.apiConnectionId,
      };
      const reportMailbox = await this.isReportMailbox(mailbox, tx);
      if (reportMailbox) {
        // C9.2: feed copies of a report mailbox become reports too (never decided).
        await this.intakeReport(tx, message, mailbox, copy, now, outcome);
      }
      recorded.push({
        key: { id: copy.id, receivedAt: copy.receivedAt },
        mailbox,
        direction: copy.direction,
        authority,
        inline,
        reportMailbox,
      });
    }
    const policy = await this.messagePolicy(tx, message, payload, recorded, now, outcome);
    await this.applyPolicy(tx, {
      message,
      payload,
      copies: recorded,
      policy,
      copySource,
      now,
      outcome,
      correlationId,
    });
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

/** The message-level evaluation and the round's DLP facts (state null: nothing to evaluate). */
interface MessageEvaluation {
  state: MessagePolicyState | null;
  result: MessagePolicyResult | null;
  dlp: CopyDlpFacts | null;
}

/** A8.2 `copies.remediation` bucket of a decision. */
function remediationOf(result: DecisionResult | null): CountedCopy['remediation'] {
  if (
    result &&
    (result.kind === 'pending' || result.kind === 'simulated' || result.kind === 'skipped')
  ) {
    return result.kind;
  }
  return 'none';
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
  /** Step API-3 C8.1: written to `api_message_copies.direction`. */
  direction: 'inbound' | 'internal';
  now: Date;
}

/**
 * The journal copy row of (message, mailbox): `INSERT … ON DUPLICATE KEY UPDATE` on UNIQUE
 * (message_id, received_at, mailbox_id) (D7 step 6), `seen_journal = 1`, the recipient's
 * direction (`inbound`, or `internal` since step API-3 C8.1).
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
            ${mailbox.apiConnectionId}, ${mailbox.id}, ${message.id}, 'journal', 1, 0, ${w.direction},
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
