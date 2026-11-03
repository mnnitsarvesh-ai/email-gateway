import { resolve } from 'node:path';
import type { AdvisoryLocks } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { LogFollower } from './log-follower';
import { parsePostfixLogLine, type PostfixLogEvent } from './postfix-log-parser';
import type { StatusSignalApplier } from './status-signal-applier';

export interface TailerOptions {
  prisma: PrismaClient;
  locks: AdvisoryLocks;
  applier: StatusSignalApplier;
  metrics: DeliveryMetrics;
  logger: Logger;
  /** DELIVERY_STATUS_LOG_PATH (relative paths resolve against the process cwd). */
  path: string;
  /** DELIVERY_STATUS_LOG_SOURCE_ID. */
  sourceId: string;
  /** DELIVERY_STATUS_LOG_POLL_MS. */
  pollMs: number;
  /** Bytes read per batch. */
  batchBytes?: number;
  /** How long the old file is drained after the path moved (rotation). */
  rotationGraceMs?: number;
  now?: () => Date;
}

/** The `stream_cursors` name of a log source (R9). */
export const logCursorName = (sourceId: string): string => `postfix-log:${sourceId}`;
/** The GET_LOCK name of a log source (single reader per source). */
export const logLockName = (sourceId: string): string => `dw:postfix-log:${sourceId}`;

const BATCH_BYTES = 256 * 1024;
const MAX_BATCHES_PER_POLL = 64;
const MISSING_LOG_EVERY_MS = 60_000;
/**
 * At the end of the file, the log is complete up to `now - IDLE_HORIZON_GRACE_MS` (postlogd
 * writes a line as it happens; the grace covers write latency and clock skew between the
 * postfix-outbound host and the worker).
 */
export const IDLE_HORIZON_GRACE_MS = 30_000;
/** How often an idle tailer commits its advanced horizon. */
const IDLE_COMMIT_INTERVAL_MS = 15_000;

/**
 * Reads postfix-outbound's delivery log incrementally (step 2.3 R9) and applies its lines as
 * delivery status signals. Position: `stream_cursors` `postfix-log:<source id>` (file identity,
 * byte offset, and the time the log is known complete up to: the newest line read, or
 * `now - IDLE_HORIZON_GRACE_MS` while caught up at the end of the file), committed **after** the batch's signals are
 * committed (at-least-once; every signal is idempotent, so a re-read never produces a second
 * transition). One reader per source across replicas (`GET_LOCK('dw:postfix-log:<source id>')`
 * on the dedicated lock connection). Rotation by rename is followed by device + inode, draining
 * the old file first. A missing file is logged and retried; it never crashes the worker.
 */
export class PostfixLogTailer {
  readonly cursorName: string;
  readonly lockName: string;
  private readonly follower: LogFollower;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private lastEventAt: Date | null = null;
  private lastIdleCommit = 0;
  private lastMissingLog = 0;
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;
  private stopped = false;

  constructor(private readonly options: TailerOptions) {
    this.cursorName = logCursorName(options.sourceId);
    this.lockName = logLockName(options.sourceId);
    this.follower = new LogFollower(resolve(options.path), {
      rotationGraceMs: options.rotationGraceMs ?? 2000,
    });
    this.logger = options.logger.child({
      component: 'postfix-log-tailer',
      sourceId: options.sourceId,
    });
    this.now = options.now ?? (() => new Date());
  }

  start(): void {
    this.stopped = false;
    this.logger.info({ path: this.follower.path }, 'delivery log tailer started');
    this.schedule(0);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running;
    await this.follower.close();
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One poll (public for tests): returns the number of lines read. */
  async pollOnce(): Promise<number> {
    if (!(await this.options.locks.ensure(this.lockName))) {
      if (this.follower.isOpen) await this.follower.close();
      return 0;
    }
    if (!this.follower.isOpen && !(await this.openFromCursor())) return 0;
    let total = 0;
    let idle = false;
    try {
      for (let batch = 0; batch < MAX_BATCHES_PER_POLL && !this.stopped; batch += 1) {
        const chunk = await this.follower.read(this.options.batchBytes ?? BATCH_BYTES);
        if (!chunk) break;
        if (chunk.lines.length === 0 && !chunk.more && !chunk.rotated && this.follower.caughtUp) {
          idle = true;
          await this.advanceIdleHorizon(chunk.fileId, chunk.offset);
          break;
        }
        if (chunk.rotated) this.logger.info('delivery log rotated; switched to the new file');
        const events: PostfixLogEvent[] = [];
        let newest: Date | null = null;
        for (const line of chunk.lines) {
          const parsed = parsePostfixLogLine(line, this.now());
          if (!parsed) continue;
          if (newest === null || parsed.timestamp > newest) newest = parsed.timestamp;
          if (parsed.kind !== 'other') events.push(parsed);
        }
        await this.options.applier.apply(events);
        if (newest !== null && (this.lastEventAt === null || newest > this.lastEventAt)) {
          this.lastEventAt = newest;
        }
        if (chunk.lines.length > 0 || chunk.rotated) {
          await this.commit(chunk.fileId, chunk.offset);
        }
        total += chunk.lines.length;
        if (!chunk.more) break;
      }
      if (total === 0) await this.options.applier.retryPending();
    } catch (err) {
      // Re-read from the committed cursor on the next poll (signals are idempotent).
      await this.follower.close();
      throw err;
    }
    if (idle) {
      this.options.metrics.statusLogLag.set(0);
    } else if (this.lastEventAt !== null) {
      this.options.metrics.statusLogLag.set(
        Math.max(0, (this.now().getTime() - this.lastEventAt.getTime()) / 1000),
      );
    }
    return total;
  }

  /**
   * Caught up at the end of the file: the cursor's `last_event_at` (the reconciler's log
   * horizon, R12) moves to `now - IDLE_HORIZON_GRACE_MS`, so a quiet postfix-outbound host still
   * lets the reconciler decide an expired lease (review fix of step 2.3). Committed at most every
   * IDLE_COMMIT_INTERVAL_MS; never moves the horizon backwards.
   */
  private async advanceIdleHorizon(fileId: string, offset: number): Promise<void> {
    const now = this.now().getTime();
    const horizon = new Date(now - IDLE_HORIZON_GRACE_MS);
    if (this.lastEventAt !== null && horizon <= this.lastEventAt) return;
    if (now - this.lastIdleCommit < IDLE_COMMIT_INTERVAL_MS) return;
    this.lastEventAt = horizon;
    this.lastIdleCommit = now;
    await this.commit(fileId, offset);
  }

  private async openFromCursor(): Promise<boolean> {
    const cursor = await this.options.prisma.streamCursor.findUnique({
      where: { name: this.cursorName },
      select: { fileId: true, fileOffset: true, lastEventAt: true },
    });
    const position =
      cursor?.fileId && cursor.fileOffset !== null
        ? { fileId: cursor.fileId, offset: Number(cursor.fileOffset) }
        : null;
    this.lastEventAt = cursor?.lastEventAt ?? this.lastEventAt;
    const opened = await this.follower.open(position);
    if (!opened.opened) {
      const now = Date.now();
      if (now - this.lastMissingLog >= MISSING_LOG_EVERY_MS) {
        this.lastMissingLog = now;
        this.logger.warn({ path: this.follower.path }, 'delivery log not found (yet); retrying');
      }
      return false;
    }
    if (position && !opened.resumed) {
      this.logger.warn(
        'delivery log was rotated while the reader was down; continuing with the current file (the unread tail is covered by bounce notices and the reconciler)',
      );
    }
    return true;
  }

  private async commit(fileId: string, offset: number): Promise<void> {
    const data = { fileId, fileOffset: BigInt(offset), lastEventAt: this.lastEventAt };
    await this.options.prisma.streamCursor.upsert({
      where: { name: this.cursorName },
      create: { name: this.cursorName, ...data },
      update: data,
    });
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.running = this.pollOnce()
        .then(() => undefined)
        .catch((err: unknown) => this.logger.warn({ err }, 'delivery log poll failed; retrying'))
        .finally(() => {
          this.running = undefined;
          this.schedule(this.options.pollMs);
        });
    }, delayMs);
    this.timer.unref();
  }
}
