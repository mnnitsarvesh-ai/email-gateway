import { uuidv7 } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { InvalidDigestScheduleError, nextDigestWindows } from '@email-gateway/quarantine';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';
import { writeQuarantineNotification } from './outbox';
import type { QuarantineSettingsRepository } from './settings.repository';

/** Most digest runs one organization can have per day (Q20 `maxPerDay`). */
export const DIGEST_MAX_PER_DAY = 24;
const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;
const OPEN_STATES = ['held', 'pending_approval'] as const;

export interface DigestSchedulerOptions {
  /** Transaction-defaulted writer client (`withTransactionDefaults`). */
  prisma: PrismaClient;
  settings: Pick<QuarantineSettingsRepository, 'resolve'>;
  sink: QuarantineInconsistencySink;
  logger: Logger;
  /** QUARANTINE_DIGEST_MAX_USERS_PER_RUN: digests written per sweep (continued next sweep). */
  maxUsersPerSweep: number;
  /** Organizations examined per sweep. */
  batchSize: number;
  organizationIds?: readonly bigint[];
}

export interface DigestReport {
  runs: number;
  digests: number;
  alerts: number;
}

/**
 * The digest and admin-alert scheduler (step 5.3 Q20, sweeper step 5), run by the sweeper
 * leader:
 *
 * - **User digests**: for organizations with open entries, `digest_enabled` and
 *   `endUser.enabled`, the due schedule instants (`nextDigestWindows`, ≤ 24 a day, coalesced to
 *   ≥ 1 hour) each get one `quarantine_digest_runs` row (unique per organization, kind and
 *   instant); every active, verified, not opted-out user with `held`/`pending_approval` entries
 *   addressed to their e-mail and created in the run's window gets one `quarantine_digests` row
 *   (unique per run and user) and one `user_digest` notification event, in the same
 *   transaction. At most `maxUsersPerSweep` digests per sweep; an unfinished run is continued.
 * - **Admin alerts**: at most one `admin_alert` per organization per `alerts.minIntervalMinutes`
 *   when new hard-block entries (`alerts.hardBlocks`) or pending approvals older than one hour
 *   exist (a `quarantine_digest_runs` row of kind `admin_alert` is the rate bound).
 *
 * Fair across organizations: each sweep examines `batchSize` organizations with open entries
 * from a keyset cursor (`organization_id > cursor`, wrapping around to the lowest id), so every
 * organization is reached within ⌈organizations / batchSize⌉ sweeps however many tenants exist.
 * Admin alerts run for every examined organization (they do not use the digest budget). When the
 * digest budget runs out inside an organization, the next sweep starts at that organization
 * (its unfinished run continues) instead of at the lowest id. The cursor lives in the sweeper
 * leader's memory: a new leader starts at the lowest id, which only re-orders one rotation.
 *
 * Idempotent: the unique keys make a repeated pass write nothing new.
 */
export class DigestScheduler {
  private readonly logger: Logger;
  /** Exclusive lower bound of the next sweep's organizations (null: from the lowest id). */
  private cursor: bigint | null = null;

  constructor(private readonly options: DigestSchedulerOptions) {
    this.logger = options.logger.child({ component: 'quarantine-digests' });
  }

  private get orgFilter() {
    const ids = this.options.organizationIds;
    return ids ? { organizationId: { in: [...ids] } } : {};
  }

  /** The cursor of the next sweep (tests and diagnostics). */
  get nextCursor(): bigint | null {
    return this.cursor;
  }

  async run(now: Date): Promise<DigestReport> {
    const report: DigestReport = { runs: 0, digests: 0, alerts: 0 };
    const orgs = await this.page();
    let budget = this.options.maxUsersPerSweep;
    /** The first organization whose digests the budget cut short (next sweep starts there). */
    let resumeAt: bigint | null = null;
    let previous: bigint | null = this.cursor;
    let next: bigint | null = null;
    for (const organizationId of orgs) {
      const filter = this.options.organizationIds;
      if (filter !== undefined && !filter.includes(organizationId)) {
        quarantineWrongRead(this.options.sink, 'digests', 'organization filter');
      }
      try {
        const digests = resumeAt === null && budget > 0;
        const done = await this.organization(organizationId, now, digests ? budget : 0, report);
        budget -= done;
        if (digests && budget <= 0 && resumeAt === null) {
          resumeAt = organizationId;
          next = previous;
        }
      } catch (error) {
        if (!(error instanceof InvalidDigestScheduleError)) throw error;
        this.logger.warn(
          { organizationId: organizationId.toString(), field: error.message },
          'organization digest schedule or time zone is invalid; no digest scheduled',
        );
      }
      previous = organizationId;
    }
    // Every organization of the page was examined: continue after the last one; the budget ran
    // out inside one: start at it next time (`next` is the bound just below it).
    this.cursor = resumeAt !== null ? next : (orgs.at(-1) ?? null);
    return report;
  }

  /** `batchSize` organizations with open entries after the cursor, wrapping to the lowest id. */
  private async page(): Promise<bigint[]> {
    const groups = (after: bigint | null, upTo: bigint | null, take: number) =>
      this.options.prisma.quarantineMessage.groupBy({
        by: ['organizationId'],
        where: {
          ...this.orgFilter,
          status: { in: [...OPEN_STATES] },
          ...(after !== null || upTo !== null
            ? {
                AND: [
                  ...(after !== null ? [{ organizationId: { gt: after } }] : []),
                  ...(upTo !== null ? [{ organizationId: { lte: upTo } }] : []),
                ],
              }
            : {}),
        },
        orderBy: { organizationId: 'asc' },
        take,
      });
    const batch = this.options.batchSize;
    const ids = (await groups(this.cursor, null, batch)).map((g) => g.organizationId);
    if (ids.length < batch && this.cursor !== null) {
      // Wrap around: the lowest ids up to (and including) the cursor.
      const wrapped = await groups(null, this.cursor, batch - ids.length);
      ids.push(...wrapped.map((g) => g.organizationId));
    }
    return ids;
  }

  private async organization(
    organizationId: bigint,
    now: Date,
    budget: number,
    report: DigestReport,
  ): Promise<number> {
    const prisma = this.options.prisma;
    const settings = await prisma.$transaction((tx) =>
      this.options.settings.resolve(tx, organizationId),
    );
    await this.adminAlert(organizationId, settings.alerts, now, report);
    // Budget 0: only the admin alert this sweep (the digests wait for the cursor).
    if (budget <= 0) return 0;
    if (!settings.digestSchedule.enabled || !settings.endUser.enabled) return 0;

    // Due instants (one run row each, unique; an existing run is never duplicated).
    const last = await prisma.quarantineDigestRun.findFirst({
      where: { organizationId, kind: 'user_digest' },
      orderBy: { scheduledFor: 'desc' },
      select: { organizationId: true, scheduledFor: true },
    });
    if (last !== null && last.organizationId !== organizationId) {
      quarantineWrongRead(this.options.sink, 'digests', 'run echo');
    }
    const windows = nextDigestWindows(
      settings.digestSchedule.schedule,
      settings.digestSchedule.timeZone,
      last?.scheduledFor ?? null,
      now,
      DIGEST_MAX_PER_DAY,
    );
    if (windows.length > 0) {
      const created = await prisma.quarantineDigestRun.createMany({
        data: windows.map((w) => ({
          organizationId,
          kind: 'user_digest' as const,
          scheduledFor: w.scheduledFor,
          windowFrom: w.windowFrom,
        })),
        skipDuplicates: true,
      });
      report.runs += created.count;
    }

    // Continue every unfinished run (oldest first) within the budget.
    let written = 0;
    const open = await prisma.quarantineDigestRun.findMany({
      where: { organizationId, kind: 'user_digest', completedAt: null },
      orderBy: { scheduledFor: 'asc' },
      select: {
        id: true,
        organizationId: true,
        scheduledFor: true,
        windowFrom: true,
        usersTotal: true,
        usersDone: true,
      },
    });
    for (const run of open) {
      if (run.organizationId !== organizationId) {
        quarantineWrongRead(this.options.sink, 'digests', 'open run echo');
      }
      if (written >= budget) break;
      written += await this.digestRun(run, settings.digest.allowOptOut, budget - written, now);
    }
    report.digests += written;
    return written;
  }

  /** One run: the eligible users of its window without a digest yet, ≤ `budget`. */
  private async digestRun(
    run: { id: bigint; organizationId: bigint; scheduledFor: Date; windowFrom: Date },
    allowOptOut: boolean,
    budget: number,
    now: Date,
  ): Promise<number> {
    return this.options.prisma.$transaction(async (tx) => {
      const organizationId = run.organizationId;
      const addresses = await tx.quarantineMessage.groupBy({
        by: ['recipientAddress'],
        where: {
          organizationId,
          status: { in: [...OPEN_STATES] },
          quarantinedAt: { gt: run.windowFrom, lte: run.scheduledFor },
        },
      });
      const users =
        addresses.length === 0
          ? []
          : await tx.user.findMany({
              where: {
                organizationId,
                status: 'active',
                deletedAt: null,
                emailVerifiedAt: { not: null },
                email: { in: addresses.map((a) => a.recipientAddress) },
              },
              select: { id: true, publicId: true, organizationId: true, email: true, status: true },
              orderBy: { id: 'asc' },
            });
      for (const u of users) {
        if (u.organizationId !== organizationId || u.status !== 'active') {
          quarantineWrongRead(this.options.sink, 'users', 'digest user echo');
        }
      }
      const optedOut = new Set<bigint>();
      if (allowOptOut && users.length > 0) {
        const prefs = await tx.quarantineUserPreference.findMany({
          where: { organizationId, userId: { in: users.map((u) => u.id) }, digestOptOut: true },
          select: { organizationId: true, userId: true },
        });
        for (const p of prefs) {
          if (p.organizationId !== organizationId) {
            quarantineWrongRead(this.options.sink, 'digests', 'preference echo');
          }
          optedOut.add(p.userId);
        }
      }
      const eligible = users.filter((u) => !optedOut.has(u.id));
      const existing = await tx.quarantineDigest.findMany({
        where: { runId: run.id },
        select: { runId: true, userId: true },
      });
      if (existing.some((d) => d.runId !== run.id)) {
        quarantineWrongRead(this.options.sink, 'digests', 'digest echo');
      }
      const done = new Set(existing.map((d) => d.userId));
      const todo = eligible.filter((u) => !done.has(u.id)).slice(0, budget);
      let written = 0;
      for (const user of todo) {
        const address = user.email.toLowerCase();
        const entryCount = await tx.quarantineMessage.count({
          where: {
            organizationId,
            recipientAddress: address,
            status: { in: [...OPEN_STATES] },
            quarantinedAt: { gt: run.windowFrom, lte: run.scheduledFor },
          },
        });
        const eventId = uuidv7(now.getTime());
        const publicId = uuidv7(now.getTime());
        await tx.quarantineDigest.create({
          data: { publicId, runId: run.id, organizationId, userId: user.id, entryCount, eventId },
          select: { id: true },
        });
        await writeQuarantineNotification(tx, {
          organizationId,
          correlationId: `quarantine-digest:${run.id.toString()}`,
          at: now,
          eventId,
          payload: {
            kind: 'user_digest',
            refs: { userId: user.publicId, digestId: publicId },
            window: { from: run.windowFrom.toISOString(), to: run.scheduledFor.toISOString() },
            requestedAt: now.toISOString(),
          },
        });
        written += 1;
      }
      const total = eligible.length;
      const usersDone = done.size + written;
      await tx.quarantineDigestRun.updateMany({
        where: { id: run.id, organizationId },
        data: {
          usersTotal: Math.max(total, usersDone),
          usersDone,
          ...(usersDone >= total ? { completedAt: now } : {}),
        },
      });
      return written;
    });
  }

  /** Q20 admin alert, rate-bounded per organization by `alerts.minIntervalMinutes`. */
  private async adminAlert(
    organizationId: bigint,
    alerts: { hardBlocks: boolean; approvalRequests: boolean; minIntervalMinutes: number },
    now: Date,
    report: DigestReport,
  ): Promise<void> {
    const prisma = this.options.prisma;
    const interval = alerts.minIntervalMinutes * MINUTE_MS;
    const last = await prisma.quarantineDigestRun.findFirst({
      where: { organizationId, kind: 'admin_alert' },
      orderBy: { scheduledFor: 'desc' },
      select: { organizationId: true, scheduledFor: true },
    });
    if (last !== null && last.organizationId !== organizationId) {
      quarantineWrongRead(this.options.sink, 'digests', 'alert run echo');
    }
    if (last !== null && now.getTime() - last.scheduledFor.getTime() < interval) return;
    const from = last?.scheduledFor ?? new Date(now.getTime() - interval);
    const hardBlocks = alerts.hardBlocks
      ? await prisma.quarantineMessage.count({
          where: {
            organizationId,
            hasHardBlock: true,
            status: { in: [...OPEN_STATES] },
            quarantinedAt: { gt: from, lte: now },
          },
        })
      : 0;
    const oldApprovals = await prisma.quarantineApprovalRequest.count({
      where: {
        organizationId,
        status: 'pending',
        createdAt: { lte: new Date(now.getTime() - HOUR_MS) },
      },
    });
    if (hardBlocks === 0 && oldApprovals === 0) return;
    const scheduledFor = new Date(Math.floor(now.getTime() / MINUTE_MS) * MINUTE_MS);
    await prisma.$transaction(async (tx) => {
      const created = await tx.quarantineDigestRun.createMany({
        data: [{ organizationId, kind: 'admin_alert', scheduledFor, windowFrom: from }],
        skipDuplicates: true,
      });
      if (created.count === 0) return;
      await writeQuarantineNotification(tx, {
        organizationId,
        correlationId: `quarantine-alert:${organizationId.toString()}`,
        at: now,
        payload: {
          kind: 'admin_alert',
          refs: {},
          ...(from.getTime() < scheduledFor.getTime()
            ? { window: { from: from.toISOString(), to: scheduledFor.toISOString() } }
            : {}),
          requestedAt: now.toISOString(),
        },
      });
      await tx.quarantineDigestRun.updateMany({
        where: { organizationId, kind: 'admin_alert', scheduledFor },
        data: { usersTotal: 1, usersDone: 1, completedAt: now },
      });
      report.alerts += 1;
    });
  }
}
