import { isIP } from 'node:net';
import type { S3Client } from '@aws-sdk/client-s3';
import { buildGatewayTrace, GATEWAY_TRACE_HEADER } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  bindReinjectionQueueId,
  classifyDeliveryError,
  type DeliveryErrorClass,
  type DeliverySignal,
  type DeliveryStatus,
  deliveryPathFor,
  evaluateHops,
  loadDomainViews,
  rateLimitSignalKey,
  recipientDomain,
  recordDeliverySignal,
  reinjectionSignalKey,
  reinjectionToken,
} from '@email-gateway/mail-routing';
import type { DeliveryMetrics, ReinjectionOutcome } from '../metrics/delivery-metrics';
import { SOURCE_SERVICE } from '../planning/delivery-planner';
import { maxChunk, type OutboundRateLimiter } from '../rate-limit/outbound-rate-limiter';
import { nextWindowStart, retryDelayMs } from '../shared/backoff';
import { ContentMissingError, type EmlStream, ForeignObjectKeyError, openEml } from './eml-source';
import type {
  ActiveDelivery,
  ClaimedReinjection,
  ReinjectionContext,
  ReinjectionStore,
} from './reinjection-store';
import { isAmbiguousSmtpError, SmtpClient, SmtpClientError, type SmtpReply } from './smtp-client';

export interface ReinjectorConfig {
  DELIVERY_REINJECT_HOST: string;
  DELIVERY_REINJECT_INBOUND_PORT: number;
  DELIVERY_REINJECT_OUTBOUND_PORT: number;
  DELIVERY_REINJECT_HELO: string;
  DELIVERY_REINJECT_COMMAND_TIMEOUT_MS: number;
  DELIVERY_REINJECT_DATA_TIMEOUT_MS: number;
  DELIVERY_REINJECT_RETRY_BASE_SECONDS: number;
  DELIVERY_REINJECT_RETRY_MAX_SECONDS: number;
  DELIVERY_REINJECT_MAX_AGE_SECONDS: number;
  ROUTING_MAX_RECEIVED_HEADERS: number;
  ROUTING_MAX_GATEWAY_PASSES: number;
  GATEWAY_TRACE_SECRET: string;
  GATEWAY_TRACE_ID: string;
  INGEST_HEADER_MAX_BYTES: number;
}

export interface ReinjectorDeps {
  prisma: PrismaClient;
  store: ReinjectionStore;
  s3: Pick<S3Client, 'send'>;
  bucket: string;
  limiter: OutboundRateLimiter;
  metrics: DeliveryMetrics;
  logger: Logger;
  config: ReinjectorConfig;
  /** Interactive transaction timeout of result commits. */
  txTimeoutMs: number;
  now?: () => Date;
  random?: () => number;
}

/** Final RCPT classification of one recipient in a session. */
interface RcptResult {
  delivery: ActiveDelivery;
  reply: SmtpReply;
}

type SessionResult =
  | { stage: 'pre_rcpt'; reply: SmtpReply; command: string }
  | { stage: 'config'; message: string }
  | {
      stage: 'rcpt' | 'data';
      accepted: RcptResult[];
      deferred: RcptResult[];
      refused: RcptResult[];
      data?: { start: SmtpReply; final?: SmtpReply };
    };

const QUEUED_AS = /\bqueued as ([A-Za-z0-9]{1,32})\b/;
const NON_ASCII = /[^\x20-\x7e]/;
const MAX_DETAIL = 1024;

/**
 * Error class of a temporary refusal by the reinjection listener. postfix-outbound's 10026
 * resolves the recipient through the transport map at RCPT and answers a tenant domain without
 * a usable destination with `450 4.4.1 … Destination not configured` (docs/deployment/
 * mail-routing.md V5, WP2 deviation), so that reply is classified `no_destination` (R9.2, §9
 * item 4) instead of the generic `reinjection_4xx`; every other 4xx stays `reinjection_4xx`.
 */
export function reinjectionDeferralClass(reply: SmtpReply | undefined): DeliveryErrorClass {
  return reply !== undefined &&
    classifyDeliveryError(reply.text, reply.enhancedStatus) === 'no_destination'
    ? 'no_destination'
    : 'reinjection_4xx';
}

/**
 * The worker's own hop into postfix-outbound for one claimed reinjection (step 2.3 R8), step by
 * step: max age → inbound hold re-check → outbound rate limits (10027 only, R11) → EML stream
 * from S3 (org-prefix check, header block only) → hop check (R10) → SMTP session (EHLO,
 * XFORWARD with the original client and the token, MAIL with SIZE/RET/ENVID, RCPT with
 * NOTIFY/ORCPT, DATA with exactly one prepended `X-Gateway-Trace`) → result commit. Every
 * per-recipient result goes through the shared recorder (audit, email_events, outbox).
 *
 * Fail closed: S3, Redis, DB and connection trouble defers the row (worker backoff); nothing is
 * dropped or sent without the checks. A timeout or connection loss **after** the final dot is
 * ambiguous: the row stays `in_progress` for the reconciler (R12), which resolves it from the
 * Postfix log binding.
 */
export class Reinjector {
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly random: () => number;

  constructor(private readonly deps: ReinjectorDeps) {
    this.logger = deps.logger.child({ component: 'reinjector' });
    this.now = deps.now ?? (() => new Date());
    this.random = deps.random ?? Math.random;
  }

  async process(row: ClaimedReinjection, signal?: AbortSignal): Promise<ReinjectionOutcome> {
    const started = process.hrtime.bigint();
    const listener = row.listener;
    try {
      const outcome = await this.run(row, signal);
      this.deps.metrics.reinjections.inc({ listener, outcome });
      return outcome;
    } finally {
      const seconds = Number(process.hrtime.bigint() - started) / 1e9;
      this.deps.metrics.reinjectionSeconds.observe({ listener }, seconds);
    }
  }

  private ids(row: ClaimedReinjection): Record<string, string | number> {
    return {
      reinjectionId: row.id.toString(),
      messageId: row.messageId.toString(),
      organizationId: row.organizationId.toString(),
      listener: row.listener,
      attempt: row.attempts,
    };
  }

  private async run(row: ClaimedReinjection, signal?: AbortSignal): Promise<ReinjectionOutcome> {
    const ids = this.ids(row);
    const context = await this.deps.store.context(row);
    if (!context) {
      this.logger.error(ids, 'message of the reinjection not found; reinjection failed');
      await this.deps.store.markFailed(row, 'other', 'message not found');
      return 'failed';
    }
    let active = context.deliveries;
    if (active.length === 0) {
      this.logger.info(ids, 'no recipient of the reinjection still needs the hop');
      await this.deps.store.markFailed(row, row.lastErrorClass, 'no active recipients');
      return 'failed';
    }

    // R8 step 4: max age since the approval.
    const approvalAt = await this.deps.store.approvalTime(row);
    if (
      this.now().getTime() - approvalAt.getTime() >=
      this.deps.config.DELIVERY_REINJECT_MAX_AGE_SECONDS * 1000
    ) {
      this.logger.error(ids, 'reinjection max age reached; deliveries expired');
      await this.commitTerminal(row, active, {
        status: 'expired',
        outcome: 'expired',
        failureReason: 'reinjection_expired',
        errorClass: (row.lastErrorClass as DeliveryErrorClass | null) ?? null,
        detail: 'the gateway could not hand the message to postfix-outbound before the max age',
        rowErrorClass: row.lastErrorClass,
        rowError: 'max age reached',
      });
      return 'failed';
    }

    // R1: an inbound/internal tenant group is re-checked at each attempt.
    if (row.listener === 'reinject_inbound') {
      const checked = await this.recheckTenantDomain(row, active);
      if (checked.refused.length > 0) {
        await this.commitTerminal(row, checked.refused, {
          status: 'failed',
          outcome: 'domain_inactive',
          failureReason: 'recipient_domain_inactive',
          errorClass: null,
          detail: 'recipient domain is no longer an active domain of the organization',
          rowErrorClass: null,
          rowError: 'recipient domain inactive',
          finishRow: checked.refused.length === active.length,
        });
        if (checked.refused.length === active.length) return 'refused';
        active = active.filter((d) => !checked.refused.includes(d));
      }
      if (checked.held) {
        await this.retry(row, active, {
          errorClass: 'gateway_hold',
          error: 'recipient domain or organization suspended',
          outcome: 'hold',
        });
        return 'retry';
      }
    }

    // R11: outbound rate limits.
    if (row.listener === 'reinject_outbound') {
      const limited = await this.applyRateLimits(row, active);
      if (limited.outcome) return limited.outcome;
      active = limited.active;
    }

    // R8 step 2: the EML stream and the header block, before connecting.
    let eml: EmlStream;
    try {
      eml = await openEml(
        this.deps.s3,
        this.deps.bucket,
        row.emlObjectKey,
        row.organizationId,
        this.deps.config.INGEST_HEADER_MAX_BYTES,
      );
    } catch (err) {
      if (err instanceof ContentMissingError || err instanceof ForeignObjectKeyError) {
        this.logger.error(
          { ...ids, err: err.name },
          'EML object missing; recipients failed (content_missing)',
        );
        await this.commitTerminal(row, active, {
          status: 'failed',
          outcome: 'content_missing',
          failureReason: 'content_missing',
          errorClass: 'other',
          detail: 'the stored message content is missing',
          rowErrorClass: 'other',
          rowError: 'content missing',
        });
        return 'failed';
      }
      this.logger.warn({ ...ids, err }, 'EML read failed; retried');
      await this.retry(row, active, {
        errorClass: 'reinjection_error',
        error: 'object storage error',
        outcome: 'retry',
      });
      return 'retry';
    }

    try {
      // R10: hop enforcement over the stored headers.
      const hops = evaluateHops({
        receivedHeaderCount: eml.header.receivedCount,
        traceValues: eml.header.traces,
        organizationId: row.organizationId,
        secret: this.deps.config.GATEWAY_TRACE_SECRET,
        gatewayId: this.deps.config.GATEWAY_TRACE_ID,
        maxReceived: this.deps.config.ROUTING_MAX_RECEIVED_HEADERS,
        maxPasses: this.deps.config.ROUTING_MAX_GATEWAY_PASSES,
      });
      if (!hops.ok) {
        this.logger.error(
          { ...ids, reason: hops.reason, passes: hops.passes, received: eml.header.receivedCount },
          'mail loop detected at reinjection; recipients failed (loop_detected)',
        );
        await this.commitTerminal(row, active, {
          status: 'failed',
          outcome: 'loop',
          failureReason: 'loop_detected',
          errorClass: 'loop',
          detail:
            hops.reason === 'received_limit'
              ? 'too many Received headers'
              : 'too many gateway passes',
          rowErrorClass: 'loop',
          rowError: hops.reason,
        });
        return 'loop';
      }
      return await this.session(row, context, active, eml, signal);
    } finally {
      eml.destroy();
    }
  }

  // --- R1 hold re-check ------------------------------------------------------------------------

  private async recheckTenantDomain(
    row: ClaimedReinjection,
    active: ActiveDelivery[],
  ): Promise<{ refused: ActiveDelivery[]; held: boolean }> {
    const domains = [
      ...new Set(
        active.map((d) => recipientDomain(d.address)).filter((d): d is string => d !== null),
      ),
    ];
    const views = await loadDomainViews(this.deps.prisma, domains);
    const refused: ActiveDelivery[] = [];
    let held = false;
    for (const delivery of active) {
      const domain = recipientDomain(delivery.address);
      const view = domain === null ? undefined : views.get(domain);
      if (!view || view.ownerOrganizationId !== row.organizationId || view.ownerStatus === 'none') {
        refused.push(delivery);
      } else if (view.ownerStatus === 'suspended') {
        held = true;
      }
    }
    return { refused, held };
  }

  // --- R11 rate limits -------------------------------------------------------------------------

  private async applyRateLimits(
    row: ClaimedReinjection,
    active: ActiveDelivery[],
  ): Promise<{ active: ActiveDelivery[]; outcome?: ReinjectionOutcome }> {
    const ids = this.ids(row);
    const domain = row.destinationKey.startsWith('mx:')
      ? row.destinationKey.slice(3)
      : row.destinationKey;
    let limits;
    try {
      limits = await this.deps.limiter.limits(row.organizationId);
    } catch (err) {
      this.logger.warn({ ...ids, err }, 'organization limits unavailable; retried');
      await this.retry(row, active, {
        errorClass: 'reinjection_error',
        error: 'limits unavailable',
        outcome: 'retry',
      });
      return { active, outcome: 'retry' };
    }
    const chunk = maxChunk(limits);
    let kept = active;
    if (chunk > 0 && active.length > chunk) {
      // A group larger than a limit is split into chunks that fit (new reinjection rows).
      kept = active.slice(0, chunk);
      const rest = active.slice(chunk);
      const chunks: ActiveDelivery[][] = [];
      for (let i = 0; i < rest.length; i += chunk) chunks.push(rest.slice(i, i + chunk));
      const now = this.now();
      const owned = await this.deps.prisma.$transaction(
        async (tx) => {
          if (!this.ownsClaim(await this.deps.store.lockForResult(tx, row), row)) return false;
          await this.deps.store.split(tx, row, kept, chunks, {
            nextAttemptAt: now,
            errorClass: null,
            error: null,
            now,
          });
          return true;
        },
        { timeout: this.deps.txTimeoutMs, maxWait: this.deps.txTimeoutMs },
      );
      if (!owned) {
        this.claimLost(row, 'rate-limit split');
        return { active, outcome: 'retry' };
      }
      this.logger.info(
        { ...ids, chunks: chunks.length + 1, chunk },
        'outbound group split to fit the rate limits',
      );
    }

    const now = this.now();
    let result;
    try {
      result = await this.deps.limiter.admit(row.organizationId, domain, kept.length, limits, now);
    } catch (err) {
      this.deps.metrics.rateLimited.inc({ scope: 'unavailable' });
      this.logger.warn({ ...ids, err }, 'rate limiter unavailable (Redis); deferred, never sent');
      await this.retry(row, kept, {
        errorClass: 'gateway_rate_limit_unavailable',
        error: 'rate limiter unavailable',
        outcome: 'rate_limit_unavailable',
      });
      return { active: kept, outcome: 'rate_limited' };
    }
    if (result.admitted) return { active: kept };

    this.deps.metrics.rateLimited.inc({ scope: result.scope });
    const nextAttemptAt = nextWindowStart(now, this.random);
    await this.commitSignals(
      row,
      kept.map((delivery) => ({
        delivery,
        signal: {
          status: 'deferred' as const,
          errorClass: 'gateway_rate_limited' as const,
          detail: `outbound rate limit (${result.scope}) reached`,
          signalKey: rateLimitSignalKey({ reinjectionId: row.id, windowStart: result.windowStart }),
        },
      })),
      async (tx) => {
        await this.deps.store.reschedule(
          row,
          {
            nextAttemptAt,
            errorClass: 'gateway_rate_limited',
            error: `rate limit ${result.scope}`,
            refundAttempt: true,
          },
          tx,
        );
      },
    );
    this.logger.info(
      { ...ids, scope: result.scope, limit: result.limit },
      'outbound rate limit reached; deferred',
    );
    return { active: kept, outcome: 'rate_limited' };
  }

  // --- R8 step 3: the SMTP session -------------------------------------------------------------

  private async session(
    row: ClaimedReinjection,
    context: ReinjectionContext,
    active: ActiveDelivery[],
    eml: EmlStream,
    signal: AbortSignal | undefined,
  ): Promise<ReinjectionOutcome> {
    const ids = this.ids(row);
    const config = this.deps.config;
    const token = reinjectionToken(row.publicId);
    const path = deliveryPathFor(row.direction);
    const trace = buildGatewayTrace({
      secret: config.GATEWAY_TRACE_SECRET,
      gatewayId: config.GATEWAY_TRACE_ID,
      organizationId: row.organizationId,
      direction: path.traceDirection,
      now: this.now(),
    });
    const prefix = `${GATEWAY_TRACE_HEADER}: ${trace}\r\n`;
    let result: SessionResult;
    try {
      const { client, greeting } = await SmtpClient.connect({
        host: config.DELIVERY_REINJECT_HOST,
        port:
          row.listener === 'reinject_inbound'
            ? config.DELIVERY_REINJECT_INBOUND_PORT
            : config.DELIVERY_REINJECT_OUTBOUND_PORT,
        commandTimeoutMs: config.DELIVERY_REINJECT_COMMAND_TIMEOUT_MS,
        dataTimeoutMs: config.DELIVERY_REINJECT_DATA_TIMEOUT_MS,
        ...(signal ? { signal } : {}),
      });
      try {
        result = await this.converse(client, greeting, context, active, eml, {
          token,
          notify: path.notify,
          prefix,
        });
      } finally {
        await client.quit();
      }
    } catch (err) {
      if (isAmbiguousSmtpError(err)) {
        // The server may have queued the message: never re-send blindly (R8, R12).
        this.logger.warn(
          { ...ids, err: (err as Error).message },
          'reinjection outcome unknown after the final dot; left in_progress for the reconciler',
        );
        return 'retry';
      }
      if (signal?.aborted) {
        await this.deps.store.reschedule(row, {
          nextAttemptAt: this.now(),
          errorClass: row.lastErrorClass,
          error: 'released at shutdown',
          refundAttempt: true,
        });
        return 'retry';
      }
      const message =
        err instanceof SmtpClientError ? `${err.kind}: ${err.message}` : 'session error';
      this.logger.warn(
        { ...ids, err: message },
        'reinjection session failed before the final dot; retried',
      );
      await this.retry(row, active, {
        errorClass: 'reinjection_error',
        error: message,
        outcome: 'retry',
      });
      return 'retry';
    }

    try {
      return await this.commitSession(row, active, result);
    } catch (err) {
      if (result.stage === 'data' && result.data?.final && result.data.final.code < 300) {
        // Postfix has the message; the reconciler resolves the row from the log binding.
        this.logger.error(
          { ...ids, err },
          'commit after the 250 failed; left in_progress for the reconciler',
        );
        return 'retry';
      }
      throw err;
    }
  }

  private async converse(
    client: SmtpClient,
    greeting: SmtpReply,
    context: ReinjectionContext,
    active: ActiveDelivery[],
    eml: EmlStream,
    options: { token: string; notify: 'NEVER' | 'FAILURE,DELAY'; prefix: string },
  ): Promise<SessionResult> {
    if (greeting.code !== 220) return { stage: 'pre_rcpt', reply: greeting, command: 'greeting' };
    const ehlo = await client.ehlo(this.deps.config.DELIVERY_REINJECT_HELO);
    if (ehlo.code !== 250) return { stage: 'pre_rcpt', reply: ehlo, command: 'EHLO' };
    if (!client.has('XFORWARD')) {
      return {
        stage: 'config',
        message: 'XFORWARD is not advertised to the worker (smtpd_authorized_xforward_hosts)',
      };
    }
    const clientIp =
      context.clientIp !== null && isIP(context.clientIp) !== 0
        ? context.clientIp
        : '[UNAVAILABLE]';
    const helo =
      context.clientHelo !== null && context.clientHelo.length > 0
        ? context.clientHelo
        : '[UNAVAILABLE]';
    const forward = await client.xforward([
      ['NAME', '[UNAVAILABLE]'],
      ['ADDR', clientIp],
      ['HELO', helo],
      ['PROTO', 'ESMTP'],
    ]);
    if (forward.code !== 250) return { stage: 'pre_rcpt', reply: forward, command: 'XFORWARD' };
    const ident = await client.xforward([
      ['IDENT', options.token],
      ['SOURCE', 'REMOTE'],
    ]);
    if (ident.code !== 250) return { stage: 'pre_rcpt', reply: ident, command: 'XFORWARD' };

    const smtputf8 =
      NON_ASCII.test(context.envelopeFrom) || active.some((d) => NON_ASCII.test(d.address));
    if (smtputf8 && !client.has('SMTPUTF8')) {
      return { stage: 'config', message: 'SMTPUTF8 is required but not advertised' };
    }
    const dsn = client.has('DSN');
    const size =
      eml.size === null ? undefined : eml.size + Buffer.byteLength(options.prefix, 'utf8');
    const mail = await client.mail(context.envelopeFrom, {
      ...(client.has('SIZE') && size !== undefined ? { size } : {}),
      ...(dsn ? { ret: 'HDRS' as const, envid: options.token } : {}),
      smtputf8,
    });
    if (mail.code !== 250) return { stage: 'pre_rcpt', reply: mail, command: 'MAIL' };

    const accepted: RcptResult[] = [];
    const deferred: RcptResult[] = [];
    const refused: RcptResult[] = [];
    for (const delivery of active) {
      const reply = await client.rcpt(
        delivery.address,
        dsn ? { notify: options.notify, orcpt: delivery.address } : {},
      );
      const entry = { delivery, reply };
      if (reply.code >= 200 && reply.code < 300) accepted.push(entry);
      else if (reply.code >= 400 && reply.code < 500) deferred.push(entry);
      else refused.push(entry);
    }
    if (accepted.length === 0) return { stage: 'rcpt', accepted, deferred, refused };
    const data = await client.data(options.prefix, eml.body);
    return { stage: 'data', accepted, deferred, refused, data };
  }

  // --- Result commits --------------------------------------------------------------------------

  private async commitSession(
    row: ClaimedReinjection,
    active: ActiveDelivery[],
    result: SessionResult,
  ): Promise<ReinjectionOutcome> {
    const ids = this.ids(row);
    if (result.stage === 'config') {
      this.logger.error(
        { ...ids, reason: result.message },
        'reinjection listener misconfigured; retried',
      );
      await this.retry(row, active, {
        errorClass: 'reinjection_error',
        error: result.message,
        outcome: 'retry',
      });
      return 'retry';
    }
    if (result.stage === 'pre_rcpt') {
      const reply = result.reply;
      if (reply.code >= 500) {
        this.logger.warn(
          { ...ids, command: result.command, smtpCode: reply.code },
          'reinjection refused',
        );
        await this.commitTerminal(row, active, {
          status: 'failed',
          outcome: 'refused',
          failureReason: 'reinjection_refused',
          errorClass: null,
          reply,
          rowErrorClass: null,
          rowError: reply.text,
        });
        return 'refused';
      }
      await this.retry(row, active, {
        errorClass: 'reinjection_4xx',
        error: reply.text,
        outcome: 'retry',
        reply,
      });
      return 'retry';
    }

    const { accepted, deferred, refused } = result;
    const now = this.now();
    const final = result.data?.final;
    const start = result.data?.start;
    const dataRefused = start !== undefined && start.code !== 354 ? start : undefined;
    const finalReply = dataRefused ?? final;
    const queued = finalReply !== undefined && finalReply.code >= 200 && finalReply.code < 300;
    const groupTempFail =
      finalReply !== undefined && finalReply.code >= 400 && finalReply.code < 500;
    const groupRefused = finalReply !== undefined && finalReply.code >= 500;
    const queueId = queued ? (QUEUED_AS.exec(finalReply.text)?.[1] ?? null) : null;
    const backoff = new Date(
      now.getTime() +
        retryDelayMs(
          row.attempts,
          {
            baseSeconds: this.deps.config.DELIVERY_REINJECT_RETRY_BASE_SECONDS,
            maxSeconds: this.deps.config.DELIVERY_REINJECT_RETRY_MAX_SECONDS,
          },
          this.random,
        ),
    );
    const signals: { delivery: ActiveDelivery; signal: SignalPart }[] = [];
    for (const { delivery, reply } of refused) {
      signals.push({
        delivery,
        signal: this.replySignal(row, delivery, 'failed', 'refused', reply, 'reinjection_refused'),
      });
    }
    for (const { delivery, reply } of deferred) {
      signals.push({
        delivery,
        signal: this.replySignal(row, delivery, 'deferred', 'rcpt_4xx', reply),
      });
    }
    for (const { delivery } of accepted) {
      if (queued) {
        signals.push({
          delivery,
          signal: {
            status: 'queued',
            signalKey: reinjectionSignalKey({
              reinjectionId: row.id,
              attempt: row.attempts,
              address: delivery.address,
              outcome: 'queued',
            }),
            smtpCode: finalReply.code,
            enhancedStatus: finalReply.enhancedStatus,
            queueId,
            detail: finalReply.text,
          },
        });
      } else if (groupRefused) {
        signals.push({
          delivery,
          signal: this.replySignal(
            row,
            delivery,
            'failed',
            'data_refused',
            finalReply,
            'reinjection_refused',
          ),
        });
      } else if (groupTempFail) {
        signals.push({
          delivery,
          signal: this.replySignal(row, delivery, 'deferred', 'data_4xx', finalReply),
        });
      }
    }

    const keepCurrent: ActiveDelivery[] =
      accepted.length > 0 ? accepted.map((r) => r.delivery) : deferred.map((r) => r.delivery);
    const moveToNew = accepted.length > 0 ? deferred.map((r) => r.delivery) : [];

    await this.commitSignals(
      row,
      signals,
      async (tx) => {
        if (moveToNew.length > 0) {
          await this.deps.store.split(tx, row, keepCurrent, [moveToNew], {
            nextAttemptAt: backoff,
            errorClass: reinjectionDeferralClass(deferred[0]?.reply),
            error: deferred[0]?.reply.text ?? null,
            now,
          });
        }
        if (queued && queueId !== null) {
          const bound = await bindReinjectionQueueId(tx, reinjectionToken(row.publicId), queueId);
          if (bound.result === 'conflict') {
            this.logger.warn(
              ids,
              'reinjection already bound to another queue id; reply queue id ignored',
            );
          }
        }
      },
      async (tx) => {
        if (queued) {
          await this.deps.store.markQueued(row, now, tx);
        } else if (groupTempFail || (accepted.length === 0 && deferred.length > 0)) {
          await this.deps.store.reschedule(
            row,
            {
              nextAttemptAt: backoff,
              errorClass: reinjectionDeferralClass(finalReply ?? deferred[0]?.reply),
              error: (finalReply ?? deferred[0]?.reply)?.text ?? null,
            },
            tx,
          );
        } else {
          const reply = finalReply ?? refused[0]?.reply;
          await this.deps.store.markFailed(row, null, reply?.text ?? 'refused', tx);
        }
      },
      // postfix-outbound holds the message: a row the reconciler released meanwhile (and nobody
      // has claimed again) is still recorded as queued instead of being sent a second time.
      { allowReleased: queued },
    );

    if (queued) {
      this.logger.info(
        {
          ...ids,
          accepted: accepted.length,
          deferred: deferred.length,
          refused: refused.length,
          queueIdKnown: queueId !== null,
        },
        'reinjected (queued in postfix-outbound)',
      );
      return deferred.length > 0 || refused.length > 0 ? 'partial' : 'queued';
    }
    if (groupTempFail || (accepted.length === 0 && deferred.length > 0)) return 'retry';
    return groupRefused ? 'failed' : 'refused';
  }

  private replySignal(
    row: ClaimedReinjection,
    delivery: ActiveDelivery,
    status: 'failed' | 'deferred',
    outcome: string,
    reply: SmtpReply,
    failureReason?: string,
  ): SignalPart {
    return {
      status,
      signalKey: reinjectionSignalKey({
        reinjectionId: row.id,
        attempt: row.attempts,
        address: delivery.address,
        outcome,
      }),
      smtpCode: reply.code,
      enhancedStatus: reply.enhancedStatus,
      errorClass: status === 'deferred' ? reinjectionDeferralClass(reply) : null,
      detail: reply.text,
      ...(failureReason ? { failureReason } : {}),
    };
  }

  /** Worker retry with backoff (R8 step 4) and one `deferred` signal per recipient and attempt. */
  private async retry(
    row: ClaimedReinjection,
    active: readonly ActiveDelivery[],
    options: { errorClass: DeliveryErrorClass; error: string; outcome: string; reply?: SmtpReply },
  ): Promise<void> {
    const nextAttemptAt = new Date(
      this.now().getTime() +
        retryDelayMs(
          row.attempts,
          {
            baseSeconds: this.deps.config.DELIVERY_REINJECT_RETRY_BASE_SECONDS,
            maxSeconds: this.deps.config.DELIVERY_REINJECT_RETRY_MAX_SECONDS,
          },
          this.random,
        ),
    );
    await this.commitSignals(
      row,
      active.map((delivery) => ({
        delivery,
        signal: {
          status: 'deferred' as const,
          errorClass: options.errorClass,
          signalKey: reinjectionSignalKey({
            reinjectionId: row.id,
            attempt: row.attempts,
            address: delivery.address,
            outcome: options.outcome,
          }),
          smtpCode: options.reply?.code ?? null,
          enhancedStatus: options.reply?.enhancedStatus ?? null,
          detail: options.reply?.text ?? options.error,
        },
      })),
      async (tx) => {
        await this.deps.store.reschedule(
          row,
          { nextAttemptAt, errorClass: options.errorClass, error: options.error },
          tx,
        );
      },
    );
  }

  /** Terminal outcome for `deliveries`; the row fails unless `finishRow` is false. */
  private async commitTerminal(
    row: ClaimedReinjection,
    deliveries: readonly ActiveDelivery[],
    options: {
      status: 'failed' | 'expired';
      outcome: string;
      failureReason: string;
      errorClass: DeliveryErrorClass | null;
      detail?: string;
      reply?: SmtpReply;
      rowErrorClass: string | null;
      rowError: string;
      finishRow?: boolean;
    },
  ): Promise<void> {
    await this.commitSignals(
      row,
      deliveries.map((delivery) => ({
        delivery,
        signal: {
          status: options.status,
          signalKey: reinjectionSignalKey({
            reinjectionId: row.id,
            attempt: row.attempts,
            address: delivery.address,
            outcome: options.outcome,
          }),
          errorClass: options.errorClass,
          failureReason: options.failureReason,
          smtpCode: options.reply?.code ?? null,
          enhancedStatus: options.reply?.enhancedStatus ?? null,
          detail: options.reply?.text ?? options.detail ?? null,
        },
      })),
      async (tx) => {
        if (options.finishRow !== false) {
          await this.deps.store.markFailed(row, options.rowErrorClass, options.rowError, tx);
        }
      },
    );
  }

  /**
   * True while this worker still owns the claim: the locked row is `in_progress` with the
   * claimed `attempts` (or, with `allowReleased`, back to `pending` with them: the reconciler
   * released an expired lease and no other worker has claimed it since).
   */
  private ownsClaim(
    locked: { status: string; attempts: number } | null,
    row: ClaimedReinjection,
    allowReleased = false,
  ): boolean {
    if (locked === null || locked.attempts !== row.attempts) return false;
    return locked.status === 'in_progress' || (allowReleased && locked.status === 'pending');
  }

  private claimLost(row: ClaimedReinjection, stage: string): void {
    this.deps.metrics.reconcilerActions.inc({ action: 'claim_lost' });
    this.logger.warn(
      { ...this.ids(row), stage },
      'reinjection claim lost (lease expired and the row was released or re-claimed); ' +
        'nothing recorded by this worker',
    );
  }

  /**
   * One writer transaction: lock the reinjection and the message (recorder lock order), check
   * that this worker still owns the claim (else nothing is recorded or split: the current owner
   * or the reconciler decides; review fix), run `before`, record every signal, run `after`.
   * Returns false when the claim was lost.
   */
  private async commitSignals(
    row: ClaimedReinjection,
    signals: readonly { delivery: ActiveDelivery; signal: SignalPart }[],
    before: (tx: Prisma.TransactionClient) => Promise<void>,
    after?: (tx: Prisma.TransactionClient) => Promise<void>,
    options: { allowReleased?: boolean } = {},
  ): Promise<boolean> {
    const occurredAt = this.now();
    const results = await this.deps.prisma.$transaction(
      async (tx) => {
        const locked = await this.deps.store.lockForResult(tx, row);
        if (!this.ownsClaim(locked, row, options.allowReleased)) return null;
        await before(tx);
        const out: { result: string; status: DeliveryStatus | undefined }[] = [];
        for (const { delivery, signal } of signals) {
          const full: DeliverySignal = {
            match: { deliveryId: delivery.id, receivedAt: delivery.receivedAt },
            occurredAt,
            source: 'reinjection',
            ...signal,
            detail: signal.detail?.slice(0, MAX_DETAIL) ?? null,
          };
          const recorded = await recordDeliverySignal(tx, full, {
            sourceService: SOURCE_SERVICE,
            timeoutMs: this.deps.txTimeoutMs,
            eventId: row.approvalEventId,
            logger: this.logger,
            lifecycleMetrics: this.deps.metrics.lifecycle,
          });
          out.push({ result: recorded.result, status: recorded.status });
        }
        if (after) await after(tx);
        return out;
      },
      { timeout: this.deps.txTimeoutMs, maxWait: this.deps.txTimeoutMs },
    );
    if (results === null) {
      this.claimLost(row, 'result commit');
      return false;
    }
    for (const r of results) {
      this.deps.metrics.signal(
        'reinjection',
        r.result as Parameters<DeliveryMetrics['signal']>[1],
        {
          direction: row.direction,
          status: r.status,
        },
      );
    }
    return true;
  }
}

type SignalPart = Omit<DeliverySignal, 'match' | 'occurredAt' | 'source'>;
