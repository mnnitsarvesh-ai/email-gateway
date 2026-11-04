import {
  ConflictException,
  HttpException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import {
  type Counter,
  errorFields,
  MetricsService,
  PublishFailedError,
  uuidv7,
} from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import { KeyValueStore } from '../../../kv/key-value-store';
import type { ClientContext } from '../../auth/services/session.service';
import {
  DeadLetterBroker,
  type DeadLetterSession,
  REPLAY_UNAVAILABLE,
} from '../broker/dead-letter-broker';
import { DeadLettersRepository } from '../dead-letters.repository';
import {
  AUDIT_EVENT_IDS_MAX,
  DEAD_LETTER_QUEUE,
  type DeadLetterMessage,
  decodeForReplay,
  eventTypeOf,
  failureReasonOf,
  matchesFilters,
  organizationIdOf,
  REPLAY_LOCK_KEY,
  REPLAY_LOCK_TTL_SECONDS,
  type ReplayFilters,
  replayHeaders,
  replayTarget,
} from '../domain/dead-letter-replay';
import type {
  DeadLetterStats,
  ReplayItem,
  ReplayRequest,
  ReplayResponse,
} from '../dto/dead-letters.schemas';

/** Stable `message` of the 409 while another replay holds the platform-wide lock. */
export const REPLAY_IN_PROGRESS = 'replay_in_progress';
/** `audit_logs.action` of a replay (`<resource>.<verb>`, D14). */
export const REPLAY_AUDIT_ACTION = 'platform.dead_letters_replayed';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type ReplayOutcome = 'complete' | 'partial';

interface WorkingItem {
  eventId: string | null;
  eventType: string | null;
  organizationId: string | null;
  failureReason: string | null;
  replayed: boolean;
}

/**
 * Dead-letter replay (step 3.2 Q9). One replay at a time platform-wide (Redis lock
 * `dlq:replay:lock`), a broker session per request (`RABBITMQ_OPS_URL`, the `eg-ops` user), and:
 *
 * 1. `basic.get` from `email.dead-letter` with manual acks, holding every fetched message, until
 *    `limit` matched, the queue is empty or `DEAD_LETTER_REPLAY_SCAN_MAX` were scanned;
 * 2. match on the source queue (`x-eg-source-queue`, else the broker's first death) and the
 *    optional event type, organization and failure reason;
 * 3. a match is decoded (registry schema, schema version, tenant agreement) and guarded; an
 *    invalid one stays. A valid one (not a dry run) is republished unchanged to
 *    `retry.<sourceQueue>.org.<id>.<type>` on the source queue's home exchange with fresh retry
 *    headers and the replay headers, and acked **only after the broker confirmed the copy**;
 * 4. every message not replayed is nacked with requeue at the end, also on errors and dry runs;
 * 5. one `audit_logs` row, also when nothing matched or the broker failed half-way (`partial`).
 *
 * A replayed event keeps its `eventId`: a consumer that already applied it records a ledger
 * duplicate, so a replay is safe to repeat. Series `dead_letter_replay_total{source_queue,outcome}`.
 */
@Injectable()
export class DeadLetterReplayService {
  private readonly logger = new Logger(DeadLetterReplayService.name);
  private readonly replays: Counter<'source_queue' | 'outcome'>;

  constructor(
    @Inject(API_CONFIG) private readonly config: Readonly<ApiConfig>,
    private readonly broker: DeadLetterBroker,
    private readonly kv: KeyValueStore,
    private readonly audit: AuditService,
    private readonly repository: DeadLettersRepository,
    metrics: MetricsService,
  ) {
    this.replays = metrics.counter(
      'dead_letter_replay_total',
      'Dead-letter replays by source queue and outcome (complete, partial, dry_run)',
      ['source_queue', 'outcome'],
    );
  }

  /** Depth and consumers of `email.dead-letter` (passive `checkQueue`). */
  async stats(): Promise<DeadLetterStats> {
    if (!this.broker.configured) throw new ServiceUnavailableException(REPLAY_UNAVAILABLE);
    const session = await this.broker.open();
    try {
      const stats = await session.stats();
      return { queue: DEAD_LETTER_QUEUE, ...stats };
    } catch {
      throw new ServiceUnavailableException(REPLAY_UNAVAILABLE);
    } finally {
      await session.close().catch(() => undefined);
    }
  }

  async replay(
    principal: UserPrincipal,
    body: ReplayRequest,
    client: ClientContext,
  ): Promise<ReplayResponse> {
    if (!this.broker.configured) throw new ServiceUnavailableException(REPLAY_UNAVAILABLE);
    let organizationId: string | undefined;
    if (body.organizationId !== undefined) {
      const resolved = await this.repository.organizationIdOf(body.organizationId);
      if (resolved === null) throw new NotFoundException('Organization not found');
      organizationId = resolved;
    }
    const filters: ReplayFilters = {
      sourceQueue: body.sourceQueue,
      ...(body.eventType !== undefined && { eventType: body.eventType }),
      ...(organizationId !== undefined && { organizationId }),
      ...(body.failureReason !== undefined && { failureReason: body.failureReason }),
    };

    const replayId = uuidv7();
    if (!(await this.kv.setIfAbsent(REPLAY_LOCK_KEY, replayId, REPLAY_LOCK_TTL_SECONDS))) {
      throw new ConflictException(REPLAY_IN_PROGRESS);
    }

    const counts = { scanned: 0, matched: 0, replayed: 0, invalid: 0, notMatching: 0 };
    const items: WorkingItem[] = [];
    const replayedEventIds: string[] = [];
    let outcome: ReplayOutcome = 'complete';
    let failure: unknown;
    let session: DeadLetterSession | undefined;
    try {
      session = await this.broker.open();
      await this.scan(session, body, filters, replayId, counts, items, replayedEventIds);
    } catch (error) {
      outcome = 'partial';
      failure = error;
      this.logger.warn(
        `Dead-letter replay ${replayId} stopped early (${JSON.stringify(errorFields(error))})`,
      );
    } finally {
      await session?.close().catch(() => undefined);
      await this.releaseLock(replayId);
    }

    const publicIds = await this.repository.publicIdsOf(
      items.flatMap((i) => (i.organizationId === null ? [] : [i.organizationId])),
    );
    const response: ReplayResponse = {
      replayId,
      dryRun: body.dryRun,
      scanned: counts.scanned,
      matched: counts.matched,
      replayed: counts.replayed,
      skipped: { invalid: counts.invalid, notMatching: counts.notMatching },
      items: items.map((i): ReplayItem => ({
        eventId: i.eventId,
        eventType: i.eventType,
        organizationId:
          i.organizationId === null ? null : (publicIds.get(i.organizationId) ?? null),
        sourceQueue: body.sourceQueue,
        failureReason: i.failureReason,
        replayed: i.replayed,
      })),
    };

    await this.audit.record({
      organizationId: null,
      actor: this.audit.actorFrom(principal),
      action: REPLAY_AUDIT_ACTION,
      resourceType: 'queue',
      resourceId: body.sourceQueue,
      sourceIp: client.ip,
      metadata: {
        replayId,
        dryRun: body.dryRun,
        filters: {
          sourceQueue: body.sourceQueue,
          limit: body.limit,
          eventType: body.eventType ?? null,
          organizationId: body.organizationId ?? null,
          failureReason: body.failureReason ?? null,
        },
        scanned: counts.scanned,
        matched: counts.matched,
        replayed: counts.replayed,
        skipped: response.skipped,
        reason: body.reason,
        outcome,
        eventIds: replayedEventIds.slice(0, AUDIT_EVENT_IDS_MAX),
      },
    });
    this.replays.inc({
      source_queue: body.sourceQueue,
      outcome: body.dryRun && outcome === 'complete' ? 'dry_run' : outcome,
    });

    if (failure !== undefined) {
      if (failure instanceof HttpException) throw failure;
      throw new ServiceUnavailableException(REPLAY_UNAVAILABLE);
    }
    return response;
  }

  /** Steps 1-4; every fetched message that was not replayed is requeued before returning. */
  private async scan(
    session: DeadLetterSession,
    body: ReplayRequest,
    filters: ReplayFilters,
    replayId: string,
    counts: {
      scanned: number;
      matched: number;
      replayed: number;
      invalid: number;
      notMatching: number;
    },
    items: WorkingItem[],
    replayedEventIds: string[],
  ): Promise<void> {
    const held = new Set<DeadLetterMessage>();
    const scanMax = this.config.DEAD_LETTER_REPLAY_SCAN_MAX;
    try {
      while (counts.matched < body.limit && counts.scanned < scanMax) {
        const msg = await session.get();
        if (msg === null) break;
        counts.scanned += 1;
        held.add(msg);
        if (!matchesFilters(msg, filters)) {
          counts.notMatching += 1;
          continue;
        }
        counts.matched += 1;
        const envelope = decodeForReplay(msg, body.sourceQueue);
        const messageId = msg.properties.messageId;
        const item: WorkingItem = {
          eventId:
            envelope?.eventId ??
            (typeof messageId === 'string' && UUID.test(messageId) ? messageId : null),
          eventType: envelope?.eventType ?? eventTypeOf(msg) ?? null,
          organizationId: envelope?.organizationId ?? organizationIdOf(msg) ?? null,
          failureReason: failureReasonOf(msg) ?? null,
          replayed: false,
        };
        items.push(item);
        if (envelope === null) {
          counts.invalid += 1;
          continue;
        }
        if (body.dryRun) continue;
        // Confirm before ack: a crash in between leaves a copy in both queues (a duplicate).
        try {
          await session.republish(msg, {
            ...replayTarget(body.sourceQueue, envelope),
            headers: replayHeaders(msg, envelope, { replayId, replayedAt: new Date() }),
          });
        } catch (error) {
          // The publisher's own guard or size limit refused this message: it stays, the replay
          // goes on. Anything else (broker down, nack, timeout) ends the replay as partial.
          if (error instanceof PublishFailedError && error.outcome === 'refused') {
            counts.invalid += 1;
            continue;
          }
          throw error;
        }
        session.ack(msg);
        held.delete(msg);
        counts.replayed += 1;
        item.replayed = true;
        replayedEventIds.push(envelope.eventId);
      }
    } finally {
      for (const msg of held) {
        try {
          session.requeue(msg);
        } catch {
          // The channel is gone: the broker requeues every unacked delivery itself.
        }
      }
    }
  }

  private async releaseLock(replayId: string): Promise<void> {
    try {
      if ((await this.kv.get(REPLAY_LOCK_KEY)) === replayId) await this.kv.del(REPLAY_LOCK_KEY);
    } catch {
      // The lock expires after REPLAY_LOCK_TTL_SECONDS.
    }
  }
}
