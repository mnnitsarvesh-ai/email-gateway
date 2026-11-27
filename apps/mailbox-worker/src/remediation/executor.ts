import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  classifyRemediationError,
  executionResultCode,
  isMailboxApiError,
  isReversal,
  isRemediationAction,
  type MailboxApiFamily,
  type RemediationProvider,
  type ThrottleGate,
} from '@email-gateway/mailbox-api';
import type { QuarantinePlatformBounds } from '@email-gateway/quarantine';
import {
  connectionUsable,
  grantActive,
  loadConnectionContext,
  type ConnectionContext,
} from '../domain/connections';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import type { ProviderRuntime } from '../runtime/provider-runtime';
import type { CounterStore } from '../runtime/redis-stores';
import { bool } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';
import { mapLimit } from '../shared/loops';
import { claimDueActions, recordLastError, renewLease, type ClaimedAction } from './claims';
import {
  executeGmail,
  executeGraph,
  GraphFolderIds,
  type CachedContainers,
  type ContainerNames,
  type ExecResult,
} from './provider-exec';
import {
  lockEntry,
  loadReleaseLog,
  recheckApprovedRestore,
  resolveOrganizationQuarantineSettings,
} from './quarantine-entries';
import {
  providerRefsOf,
  RemediationOutcomes,
  type ActionRow,
  type HeldClaim,
  type OutcomeContext,
} from './outcomes';

/** Policy actions of a paused connection wait this long before the next look (R5.1). */
export const PAUSED_RECHECK_MS = 300_000;
/** First locate back-off (R5.3): 60 s × 2^(locate_attempts − 1). */
export const LOCATE_BASE_MS = 60_000;
/** Retry back-off base (R5.6): 30 s × 2^attempts, capped. */
export const RETRY_BASE_MS = 30_000;
/** One provider call budget inside an execution (the HTTP client has its own 30 s timeout). */
const EXECUTION_TIMEOUT_MS = 10 * 60_000;

export interface RemediationConfig extends ContainerNames {
  batch: number;
  leaseSeconds: number;
  concurrency: number;
  perConnection: number;
  maxAttempts: number;
  locateAttempts: number;
  backoffMaxSeconds: number;
  /** `API_MODE_HARD_DELETE_ENABLED`, re-checked at execution (R-I2). */
  hardDeleteEnabled: boolean;
  bounds: QuarantinePlatformBounds;
}

export interface RemediationDeps {
  prisma: PrismaClient;
  runtime: ProviderRuntime;
  throttle: ThrottleGate;
  counters: CounterStore;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: RemediationConfig;
  /** TEST SEAM: only actions of these organizations. */
  organizationIds?: readonly bigint[];
}

/** What one execution did (tests and the tick report). */
export type ActionReport =
  'succeeded' | 'failed' | 'retry' | 'throttled' | 'deferred' | 'cancelled' | 'lost';

/** The locate back-off of R5.3 after `locateAttempts` misses (1-based). */
export function locateBackoffMs(locateAttempts: number): number {
  return LOCATE_BASE_MS * 2 ** Math.max(0, locateAttempts - 1);
}

/** The retry back-off of R5.6 after `attemptsBefore` counted attempts. */
export function retryBackoffMs(attemptsBefore: number, maxSeconds: number): number {
  return Math.min(maxSeconds * 1000, RETRY_BASE_MS * 2 ** Math.max(0, attemptsBefore));
}

const familyOf = (provider: RemediationProvider): MailboxApiFamily =>
  provider === 'microsoft_365' ? 'graph' : 'gmail';

/** Codes that mean the provider itself throttled (counted `remediation_throttled`). */
const PROVIDER_THROTTLE_CODES = new Set(['throttled', 'quota_exhausted', 'provider_unavailable']);

interface Loaded {
  action: ActionRow;
  ctx: OutcomeContext;
  connection: ConnectionContext;
  paused: boolean;
  copy: {
    status: string;
    remediationState: string;
    remediationGeneration: number;
    lastActionId: bigint | null;
    providerMessageId: string | null;
  };
  mailbox: {
    providerUserId: string | null;
    primaryAddress: string;
    quarantineContainerId: string | null;
    tagContainerId: string | null;
  };
  internetMessageId: string | null;
}

/**
 * The `remediate` role (step API-2 R1, R5; ADR-0101): every `API_MODE_REMEDIATION_TICK_MS` it
 * claims due actions (`claimDueActions`: `FOR UPDATE SKIP LOCKED`, lease, per-connection cap
 * across replicas) and executes them with at most `API_MODE_REMEDIATION_CONCURRENCY` in flight.
 * Per action, before any provider call (R5.1): the action, copy, mailbox and connection must
 * belong to one organization (else `failed integrity_mismatch`), the connection must be active and
 * bound with an active mailbox-access grant (else `failed mailbox_access_revoked`), a paused
 * connection sends policy actions back for 5 minutes, a paused provider family (shared throttle
 * gate) defers without counting an attempt, a policy action whose copy moved on and a restore
 * whose entry left `releasing` are cancelled, and an approved restore is re-checked
 * (`decideMailboxRestore`). Then the provider plan runs (state read first, locate by Message-ID,
 * already-in-target, Graph/Gmail steps; `provider-exec.ts`) through the API-1 clients with the
 * connection's budget and throttle gate, and the outcome is written (`outcomes.ts`). Errors:
 * throttled → wait (no attempt), retryable → back-off until `API_MODE_REMEDIATION_MAX_ATTEMPTS`,
 * 401/403 → `provider_forbidden`, 400 → `provider_rejected`, missing message → locate back-off
 * then `message_not_found`. Logs carry public ids, codes, HTTP status and provider only.
 */
export class RemediationRunner {
  readonly outcomes: RemediationOutcomes;
  private readonly folders = new GraphFolderIds();

  constructor(private readonly deps: RemediationDeps) {
    this.outcomes = new RemediationOutcomes({
      prisma: deps.prisma,
      counters: deps.counters,
      metrics: deps.metrics,
      logger: deps.logger,
      bounds: deps.config.bounds,
    });
  }

  /** One claim-and-execute pass; true when the batch was full (more work is due). */
  async tick(): Promise<boolean> {
    const cfg = this.deps.config;
    const claimed = await claimDueActions(this.deps.prisma, {
      now: this.deps.now(),
      batch: cfg.batch,
      leaseSeconds: cfg.leaseSeconds,
      perConnection: cfg.perConnection,
      ...(this.deps.organizationIds ? { organizationIds: this.deps.organizationIds } : {}),
    });
    if (claimed.length === 0) return false;
    await mapLimit(claimed, cfg.concurrency, async (claim) => {
      try {
        await this.execute(claim);
      } catch (error) {
        // The row keeps its lease and is claimed again after it expires; the re-claim counts an
        // attempt, so a failure that repeats ends `failed internal_error` at the attempt budget.
        this.deps.logger.warn(
          { actionId: claim.id.toString(), ...errorFields(error) },
          'remediation action not completed; retried after the lease',
        );
        await recordLastError(this.deps.prisma, claim, errorCode(error, 'internal_error')).catch(
          () => undefined,
        );
      }
    });
    return claimed.length >= cfg.batch;
  }

  /** Executes one claimed action (exported for tests: lease expiry, re-claim). */
  async execute(claim: ClaimedAction): Promise<ActionReport> {
    const held: HeldClaim = { id: claim.id, rowVersion: claim.rowVersion };
    const loaded = await this.load(claim);
    if (loaded === 'lost') return 'lost';
    const now = this.deps.now();
    if (loaded.kind === 'integrity') {
      const ctx = loaded.ctx;
      this.deps.logger.error(
        { actionId: ctx.action.publicId, what: loaded.what },
        'remediation action does not match its copy, mailbox or connection; not executed',
      );
      return this.report(
        await this.outcomes.fail(
          ctx,
          held,
          { code: 'integrity_mismatch', counted: false, errorCode: null, httpStatus: null },
          now,
        ),
        'failed',
      );
    }
    const l = loaded.value;
    const a = l.action;

    // Attempts exhausted by executions that never wrote an outcome (an outcome write that threw,
    // a crashed replica): each re-claim of an expired lease counted one (`claimDueActions`).
    if (a.attempts >= this.deps.config.maxAttempts) {
      this.deps.logger.error(
        { actionId: a.publicId, action: a.action, attempts: a.attempts, errCode: a.lastErrorCode },
        'remediation action never completed within the attempt budget; failed',
      );
      return this.report(
        await this.outcomes.fail(
          l.ctx,
          held,
          {
            code: 'internal_error',
            counted: false,
            errorCode: a.lastErrorCode ?? 'lease_expired',
            httpStatus: null,
          },
          now,
        ),
        'failed',
      );
    }

    // Cancellations (R5.2) and the release pre-checks (R10.3).
    const cancel = await this.precheck(l, held, now);
    if (cancel !== null) return cancel;

    if (!connectionUsable(l.connection) || !grantActive(l.connection)) {
      return this.report(
        await this.outcomes.fail(
          l.ctx,
          held,
          { code: 'mailbox_access_revoked', counted: false, errorCode: null, httpStatus: null },
          now,
        ),
        'failed',
      );
    }
    // R5.1 / C5.7: automatic rows (policy, clawback) wait while the connection is paused; admin
    // requests and admin purges proceed.
    if (l.paused && (a.trigger === 'policy' || a.trigger === 'clawback')) {
      return this.report(
        await this.outcomes.defer(l.ctx, held, new Date(now.getTime() + PAUSED_RECHECK_MS), now),
        'deferred',
      );
    }
    const family = familyOf(l.ctx.provider);
    const pausedMs = await this.deps.throttle.remainingMs(l.connection.publicId, family);
    if (pausedMs > 0) {
      return this.report(
        await this.outcomes.defer(l.ctx, held, new Date(now.getTime() + pausedMs), now),
        'deferred',
      );
    }

    let result: ExecResult;
    try {
      result = await this.run(l, claim);
    } catch (error) {
      return this.onError(l, held, error);
    }
    const done = this.deps.now();
    if (
      result.containers.quarantineId !== l.mailbox.quarantineContainerId ||
      result.containers.tagId !== l.mailbox.tagContainerId
    ) {
      await this.cacheContainers(l, result.containers, done);
    }
    if (result.kind === 'not_found') return this.onNotFound(l, held, result.locatable, done);
    const resultCode =
      executionResultCode(a.action, l.ctx.provider) ??
      (result.already ? 'already_in_target' : null);
    return this.report(
      await this.outcomes.succeed(
        l.ctx,
        held,
        {
          refs: providerRefsOf(a.action, l.ctx.provider, result.before, result.after),
          reasonCode: resultCode,
          already: result.already,
        },
        done,
      ),
      'succeeded',
    );
  }

  private report(outcome: 'ok' | 'lost', report: ActionReport): ActionReport {
    return outcome === 'lost' ? 'lost' : report;
  }

  /** Reads and cross-checks the action, copy, mailbox and connection (writer, R-I5). */
  private async load(
    claim: ClaimedAction,
  ): Promise<
    | 'lost'
    | { kind: 'ok'; value: Loaded }
    | { kind: 'integrity'; ctx: OutcomeContext; what: string }
  > {
    const prisma = this.deps.prisma;
    const row = await prisma.apiRemediationAction.findUnique({
      where: { id: claim.id },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        apiConnectionId: true,
        mailboxId: true,
        copyId: true,
        copyReceivedAt: true,
        messageId: true,
        action: true,
        generation: true,
        trigger: true,
        status: true,
        decision: true,
        reversesActionId: true,
        quarantineEntryId: true,
        releaseLogId: true,
        attempts: true,
        locateAttempts: true,
        lastErrorCode: true,
        verdictAt: true,
        rowVersion: true,
        clawbackId: true,
      },
    });
    if (!row || row.rowVersion !== claim.rowVersion || row.status !== 'in_progress') return 'lost';
    const action: ActionRow = { ...row, action: row.action };
    const [copy, mailbox, connection, conn] = await Promise.all([
      prisma.apiMessageCopy.findUnique({
        where: { id_receivedAt: { id: row.copyId, receivedAt: row.copyReceivedAt } },
        select: {
          id: true,
          receivedAt: true,
          publicId: true,
          organizationId: true,
          apiConnectionId: true,
          mailboxId: true,
          messageId: true,
          status: true,
          verdict: true,
          remediationState: true,
          remediationGeneration: true,
          lastActionId: true,
          providerMessageId: true,
        },
      }),
      prisma.apiMailbox.findUnique({
        where: { id: row.mailboxId },
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          apiConnectionId: true,
          providerUserId: true,
          primaryAddress: true,
          quarantineContainerId: true,
          tagContainerId: true,
        },
      }),
      loadConnectionContext(prisma, row.apiConnectionId),
      prisma.$queryRaw<Array<{ organization_id: bigint | number; remediation_paused: unknown }>>`
        SELECT organization_id, remediation_paused FROM api_mode_connections
        WHERE id = ${row.apiConnectionId}`,
    ]);
    const provider = connection?.provider ?? 'microsoft_365';
    const ctx: OutcomeContext = {
      action,
      provider,
      copy: {
        id: row.copyId,
        receivedAt: row.copyReceivedAt,
        publicId: copy?.publicId ?? '',
        messageId: row.messageId,
        mailboxId: row.mailboxId,
        verdict: copy?.verdict ?? null,
      },
      mailboxPublicId: mailbox?.publicId ?? '',
      connectionPublicId: connection?.publicId ?? '',
    };
    const org = row.organizationId;
    const mismatch = !copy
      ? 'copy'
      : copy.organizationId !== org ||
          copy.mailboxId !== row.mailboxId ||
          copy.messageId !== row.messageId
        ? 'copy'
        : !mailbox ||
            mailbox.organizationId !== org ||
            mailbox.apiConnectionId !== row.apiConnectionId
          ? 'mailbox'
          : !connection ||
              connection.organizationId !== org ||
              !conn[0] ||
              BigInt(conn[0].organization_id) !== org
            ? 'connection'
            : null;
    if (mismatch !== null || !copy || !mailbox || !connection) {
      return { kind: 'integrity', ctx, what: mismatch ?? 'row' };
    }
    const message = await prisma.emailMessage.findUnique({
      where: { id_receivedAt: { id: row.messageId, receivedAt: row.copyReceivedAt } },
      select: { organizationId: true, internetMessageId: true },
    });
    if (message && message.organizationId !== org) {
      return { kind: 'integrity', ctx, what: 'message' };
    }
    return {
      kind: 'ok',
      value: {
        action,
        ctx,
        connection,
        paused: bool(conn[0]!.remediation_paused),
        copy: {
          status: copy.status,
          remediationState: copy.remediationState,
          remediationGeneration: copy.remediationGeneration,
          lastActionId: copy.lastActionId,
          providerMessageId: copy.providerMessageId,
        },
        mailbox: {
          providerUserId: mailbox.providerUserId,
          primaryAddress: mailbox.primaryAddress,
          quarantineContainerId: mailbox.quarantineContainerId,
          tagContainerId: mailbox.tagContainerId,
        },
        internetMessageId: message?.internetMessageId ?? null,
      },
    };
  }

  /** R5.2 cancellations and the R10.3 release pre-checks; null when the action proceeds. */
  private async precheck(l: Loaded, held: HeldClaim, now: Date): Promise<ActionReport | null> {
    const a = l.action;
    const copy = l.copy;
    if (a.action === 'hard_delete' && !this.deps.config.hardDeleteEnabled) {
      // The platform setting was turned off after the decision: never irreversible by default.
      return this.report(
        await this.outcomes.cancel(l.ctx, held, 'hard_delete_disabled', now),
        'cancelled',
      );
    }
    if (isRemediationAction(a.action)) {
      // Every trigger: a remediation of an older generation (the copy was restored since, e.g. a
      // stale admin request retried) never moves the message again. Policy rows also yield to
      // any later action on the copy.
      const automatic = a.trigger === 'policy' || a.trigger === 'clawback';
      const movedOn =
        copy.remediationGeneration !== a.generation ||
        (automatic &&
          ((copy.lastActionId !== null && copy.lastActionId !== a.id) ||
            copy.remediationState === 'restored'));
      if (movedOn) {
        return this.report(await this.outcomes.cancel(l.ctx, held, null, now), 'cancelled');
      }
    }
    if (isReversal(a.action) && copy.remediationGeneration !== a.generation) {
      // This generation was already reversed (another restore succeeded first).
      return this.report(await this.outcomes.cancel(l.ctx, held, null, now), 'cancelled');
    }
    if (a.action !== 'restore_inbox' || a.quarantineEntryId === null) return null;
    // A release-triggered restore: the entry must still be `releasing` (R10.3).
    const prisma = this.deps.prisma;
    const check = await prisma.$transaction(async (tx) => {
      const entry = await lockEntry(tx, a.quarantineEntryId!, a.organizationId);
      if (!entry || entry.status !== 'releasing' || entry.location !== 'mailbox') {
        return { kind: 'stale' as const };
      }
      const log =
        a.releaseLogId === null ? null : await loadReleaseLog(tx, a.releaseLogId, a.organizationId);
      if (!log || log.mode !== 'approved') return { kind: 'proceed' as const };
      const settings = await resolveOrganizationQuarantineSettings(
        tx,
        a.organizationId,
        this.deps.config.bounds,
      );
      const recheck = await recheckApprovedRestore(tx, {
        entry,
        log,
        copyStatus: copy.status as never,
        settings,
      });
      if (!recheck || recheck.decision.outcome === 'release') return { kind: 'proceed' as const };
      return { kind: 'block' as const, entry, log, recheck, settings };
    });
    if (check.kind === 'proceed') return null;
    if (check.kind === 'stale') {
      return this.report(
        await this.outcomes.cancel(l.ctx, held, 'entry_not_releasing', now, { staleLog: true }),
        'cancelled',
      );
    }
    const code =
      check.recheck.decision.outcome === 'approval_required' ? 'approval_required' : 'refused';
    return this.report(
      await this.outcomes.cancel(l.ctx, held, code, now, {
        block: {
          entry: check.entry,
          log: check.log,
          recheck: check.recheck,
          settings: check.settings,
        },
      }),
      'cancelled',
    );
  }

  /** The provider ids to try first: the reversed action's ids, then the copy's stored id. */
  private async knownIds(l: Loaded): Promise<string[]> {
    const ids: string[] = [];
    if (l.action.reversesActionId !== null) {
      const reversed = await this.deps.prisma.apiRemediationAction.findUnique({
        where: { id: l.action.reversesActionId },
        select: { organizationId: true, providerRefs: true },
      });
      if (reversed && reversed.organizationId === l.action.organizationId) {
        const after = (reversed.providerRefs as { after?: unknown } | null)?.after;
        if (Array.isArray(after)) {
          for (const id of after) if (typeof id === 'string' && id.length <= 256) ids.push(id);
        }
      }
    }
    if (l.copy.providerMessageId) ids.push(l.copy.providerMessageId);
    return ids;
  }

  private async run(l: Loaded, claim: ClaimedAction): Promise<ExecResult> {
    const clients = this.deps.runtime.clientsFor(l.connection);
    const signal = AbortSignal.timeout(EXECUTION_TIMEOUT_MS);
    const leaseMs = this.deps.config.leaseSeconds * 1000;
    let leaseUntil = claim.leaseUntil.getTime();
    const keepAlive = async () => {
      const now = this.deps.now().getTime();
      if (leaseUntil - now > leaseMs / 2) return;
      leaseUntil = now + leaseMs;
      await renewLease(this.deps.prisma, claim, new Date(leaseUntil));
    };
    const containers: CachedContainers = {
      quarantineId: l.mailbox.quarantineContainerId,
      tagId: l.mailbox.tagContainerId,
    };
    const input = {
      action: l.action.action,
      knownIds: await this.knownIds(l),
      internetMessageId: l.internetMessageId,
      containers,
      names: this.deps.config,
      signal,
      keepAlive,
    };
    if (l.ctx.provider === 'microsoft_365') {
      if (!clients.graph) throw new Error('graph client unavailable');
      return executeGraph(clients.graph, this.folders, l.action.mailboxId.toString(), {
        ...input,
        user: l.mailbox.providerUserId ?? l.mailbox.primaryAddress,
      });
    }
    if (!clients.gmail) throw new Error('gmail client unavailable');
    return executeGmail(clients.gmail, { ...input, user: l.mailbox.primaryAddress });
  }

  /** Container ids ensured or found during the run, cached on the mailbox (R3 last line). */
  private async cacheContainers(l: Loaded, c: CachedContainers, now: Date): Promise<void> {
    await this.deps.prisma.$executeRaw`
      UPDATE api_mailboxes
      SET quarantine_container_id = ${c.quarantineId}, tag_container_id = ${c.tagId},
          containers_checked_at = ${now}
      WHERE id = ${l.action.mailboxId} AND organization_id = ${l.action.organizationId}`;
  }

  /** R5.3: no message found — locate back-off, then `message_not_found`. */
  private async onNotFound(
    l: Loaded,
    held: HeldClaim,
    locatable: boolean,
    now: Date,
  ): Promise<ActionReport> {
    const misses = l.action.locateAttempts + 1;
    if (!locatable || misses >= this.deps.config.locateAttempts) {
      return this.report(
        await this.outcomes.fail(
          l.ctx,
          held,
          { code: 'message_not_found', counted: true, errorCode: 'not_found', httpStatus: 404 },
          now,
        ),
        'failed',
      );
    }
    return this.report(
      await this.outcomes.retry(
        l.ctx,
        held,
        {
          nextAttemptAt: new Date(now.getTime() + locateBackoffMs(misses)),
          attempts: 0,
          locateAttempts: 1,
          errorCode: 'not_found',
          httpStatus: 404,
          outcome: 'retry',
        },
        now,
      ),
      'retry',
    );
  }

  /** R5.6: provider errors (classified), everything else retried with back-off. */
  private async onError(l: Loaded, held: HeldClaim, error: unknown): Promise<ActionReport> {
    const now = this.deps.now();
    const a = l.action;
    if (!isMailboxApiError(error)) {
      // A local failure (database, client construction): counted, retried with back-off.
      return this.retryOrFail(l, held, errorCode(error, 'internal_error'), null, now);
    }
    const c = classifyRemediationError(error);
    const status = error.status ?? null;
    switch (c.class) {
      case 'throttled': {
        const gate = await this.deps.throttle
          .remainingMs(l.connection.publicId, familyOf(l.ctx.provider))
          .catch(() => 0);
        const waitMs = Math.max(c.retryAfterMs ?? 0, gate, 1000);
        if (PROVIDER_THROTTLE_CODES.has(error.code)) {
          await this.deps.counters.add(a.apiConnectionId, { remediation_throttled: 1 });
        }
        return this.report(
          await this.outcomes.retry(
            l.ctx,
            held,
            {
              nextAttemptAt: new Date(now.getTime() + waitMs),
              attempts: 0,
              locateAttempts: 0,
              errorCode: error.code,
              httpStatus: status,
              outcome: 'throttled',
            },
            now,
          ),
          'throttled',
        );
      }
      case 'retryable':
        return this.retryOrFail(l, held, error.code, status, now);
      case 'not_found':
        return this.onNotFound(l, held, l.internetMessageId !== null, now);
      default:
        return this.report(
          await this.outcomes.fail(
            l.ctx,
            held,
            {
              code: c.failureCode ?? 'provider_rejected',
              counted: true,
              errorCode: error.code,
              httpStatus: status,
            },
            now,
          ),
          'failed',
        );
    }
  }

  private async retryOrFail(
    l: Loaded,
    held: HeldClaim,
    code: string,
    status: number | null,
    now: Date,
  ): Promise<ActionReport> {
    const attemptsBefore = l.action.attempts;
    if (attemptsBefore + 1 >= this.deps.config.maxAttempts) {
      return this.report(
        await this.outcomes.fail(
          l.ctx,
          held,
          { code: 'provider_unavailable', counted: true, errorCode: code, httpStatus: status },
          now,
        ),
        'failed',
      );
    }
    return this.report(
      await this.outcomes.retry(
        l.ctx,
        held,
        {
          nextAttemptAt: new Date(
            now.getTime() + retryBackoffMs(attemptsBefore, this.deps.config.backoffMaxSeconds),
          ),
          attempts: 1,
          locateAttempts: 0,
          errorCode: code,
          httpStatus: status,
          outcome: 'retry',
        },
        now,
      ),
      'retry',
    );
  }
}
