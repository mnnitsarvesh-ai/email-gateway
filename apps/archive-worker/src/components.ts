import type { S3Client } from '@aws-sdk/client-s3';
import {
  type ArchiveRootKeyProvider,
  LocalRootKeyProvider,
  parseExportSigningPrivateKey,
} from '@email-gateway/archive';
import { type OpenSearchService, withTransactionDefaults } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { ArchiveRequestConsumer } from './capture/consumer';
import { type CaptureFaults, CaptureExecutor } from './capture/executor';
import { INTAKE_HEALTH_LOCK, IntakeHealthJob } from './capture/intake-health';
import { OrgContextCache } from './capture/org-context';
import { CaptureScheduler } from './capture/scheduler';
import {
  JOURNAL_SWEEP_CURSOR,
  JOURNAL_SWEEP_LOCK,
  JournalSweep,
  POLICY_RECONCILE_CURSOR,
  POLICY_RECONCILE_LOCK,
  PolicyReconciler,
} from './capture/sweeps';
import { daySeconds, hasRole, type WorkerConfig } from './config';
import { CaseSearchRunner } from './ediscovery/searches';
import { ExportBuilder } from './ediscovery/exports';
import { IndexManager } from './index/index-manager';
import { INDEX_SYNC_LOCK, IndexSync } from './index/index-sync';
import { INDEX_RECONCILE_LOCK, IndexReconciler } from './index/reconcile';
import { ROOT_REWRAP_LOCK, RootRewrapJob } from './keys/root-rewrap';
import { TenantKeyService } from './keys/tenant-keys';
import { DisposalPipeline } from './lifecycle/disposal';
import { ExpiryJob, LIFECYCLE_LOCK } from './lifecycle/expiry';
import { IntakeDataPruner } from './lifecycle/prune';
import {
  DISPOSAL_VERIFY_CURSOR,
  DisposalVerifier,
  LockPass,
  OrphanReconciler,
} from './lifecycle/maintenance';
import type { ArchiveMetrics } from './metrics/archive-metrics';
import { errorFields } from './shared/errors';
import { LeaderJob, type LeaderLock, Periodic } from './shared/loops';
import { ArchiveStorage, ObjectLockState } from './storage/archive-storage';
import { RecordObjects } from './storage/record-objects';

/** Idle poll of the capture scheduler (a full claim runs again at once). */
export const SCHEDULER_POLL_MS = 1_000;
export const INTENT_MAINTENANCE_INTERVAL_MS = 60_000;
export const EDISCOVERY_POLL_MS = 5_000;
export const EXPORT_EXPIRY_INTERVAL_MS = 60_000;
export const DISPOSAL_POLL_MAX_MS = 10_000;
export const DISPOSAL_VERIFY_SAMPLE = 5;

export interface ComponentDeps {
  /** The MySQL writer (transaction defaults are applied here). */
  prisma: PrismaClient;
  s3: S3Client;
  /** Required by the index and ediscovery roles; used by lifecycle when configured. */
  search: OpenSearchService | null;
  locks: LeaderLock;
  metrics: ArchiveMetrics;
  logger: Logger;
  /** Integration suites: restrict every job to these organizations. */
  organizationIds?: readonly bigint[];
  /** Integration suites: appended to every leader lock and global cursor name. */
  nameSuffix?: string;
  faults?: CaptureFaults;
  rootKeys?: ArchiveRootKeyProvider;
  now?: () => Date;
  random?: () => number;
}

export interface CaptureComponents {
  consumer: ArchiveRequestConsumer;
  journal: JournalSweep;
  policy: PolicyReconciler;
  scheduler: CaptureScheduler;
  executor: CaptureExecutor;
  /** Step 8.6 D9: the journal intake health job. */
  intakeHealth: IntakeHealthJob;
  loops: {
    journal: LeaderJob;
    policy: LeaderJob;
    scheduler: Periodic;
    maintain: Periodic;
    intakeHealth: LeaderJob;
  };
}

export interface IndexComponents {
  manager: IndexManager;
  sync: IndexSync;
  reconciler: IndexReconciler;
  loops: { sync: LeaderJob; reconcile: LeaderJob };
}

export interface LifecycleComponents {
  expiry: ExpiryJob;
  disposal: DisposalPipeline;
  lockPass: LockPass;
  orphans: OrphanReconciler;
  verifier: DisposalVerifier;
  rewrap: RootRewrapJob;
  /** Step 8.6: pruning of `archive_dedupe_keys` and `journal_intake_counters`. */
  pruner: IntakeDataPruner;
  loops: { lifecycle: LeaderJob; disposal: Periodic; rewrap: LeaderJob };
}

export interface EdiscoveryComponents {
  searches: CaseSearchRunner;
  exports: ExportBuilder;
  loops: { searches: Periodic; exports: Periodic[]; expiry: Periodic };
}

/** Every component of the roles this process runs (A1), plus start/stop of their loops. */
export class ArchiveComponents {
  readonly storage: ArchiveStorage;
  readonly lockState: ObjectLockState;
  readonly keys: TenantKeyService;
  readonly objects: RecordObjects;
  readonly orgs: OrgContextCache;
  readonly rootKeys: ArchiveRootKeyProvider;
  readonly capture: CaptureComponents | null;
  readonly index: IndexComponents | null;
  readonly lifecycle: LifecycleComponents | null;
  readonly ediscovery: EdiscoveryComponents | null;
  private started = false;

  constructor(
    readonly config: Readonly<WorkerConfig>,
    private readonly deps: ComponentDeps,
  ) {
    const prisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: config.ARCHIVE_DB_TX_TIMEOUT_MS,
    });
    const logger = deps.logger;
    const metrics = deps.metrics;
    const only = deps.organizationIds;
    const suffix = deps.nameSuffix ?? '';
    const lock = (name: string): string => `${name}${suffix}`.slice(0, 64);
    // Leader-written gauges go to 0 on a replica that is not (or no longer) the leader, so
    // `max()` over replicas is always the current leader's value (never a stale one).
    const resets: Record<string, () => void> = {
      journal_sweep: () => metrics.sweepLag.set({ sweep: 'journal' }, 0),
      policy_reconcile: () => metrics.sweepLag.set({ sweep: 'policy' }, 0),
      index_sync: () => {
        metrics.indexQueueDepth.set(0);
        metrics.indexOldest.set(0);
      },
      lifecycle: () => {
        metrics.disposalsPending.set(0);
        metrics.disposalOldestPending.set(0);
      },
      root_rewrap: () => metrics.rootRewrapPending.set(0),
      intake_health: () => metrics.intakeSources.reset(),
    };
    const leader = (job: string) => ({
      locks: deps.locks,
      logger,
      onLeadership: (on: boolean) => {
        metrics.leader.set({ job }, on ? 1 : 0);
        if (!on) resets[job]?.();
      },
    });
    this.rootKeys = deps.rootKeys ?? LocalRootKeyProvider.fromConfig(config);
    this.storage = new ArchiveStorage(
      deps.s3,
      { mail: config.S3_BUCKET_MAIL, archive: config.S3_BUCKET_ARCHIVE },
      { timeoutMs: config.ARCHIVE_S3_TIMEOUT_MS, partSizeBytes: config.ARCHIVE_S3_PART_SIZE_BYTES },
    );
    this.lockState = new ObjectLockState(config.ARCHIVE_OBJECT_LOCK);
    this.keys = new TenantKeyService(prisma, this.rootKeys, {
      cacheTtlMs: config.ARCHIVE_KEY_CACHE_TTL_MS,
    });
    this.objects = new RecordObjects(this.storage, this.keys);
    this.orgs = new OrgContextCache(prisma, {
      ttlMs: config.ARCHIVE_SETTINGS_CACHE_TTL_MS,
      logger,
      onUnresolved: (n) => metrics.scopeUnresolved.inc(n),
      onTruncated: () => metrics.scopeTruncated.inc(),
    });
    const days = daySeconds(config);

    if (hasRole(config, 'capture')) {
      const executor = new CaptureExecutor(prisma, {
        storage: this.storage,
        lockState: this.lockState,
        keys: this.keys,
        metrics,
        logger: logger.child({ component: 'archive-capture' }),
        chunkBytes: config.ARCHIVE_CHUNK_BYTES,
        previewPartMaxBytes: config.ARCHIVE_PREVIEW_PART_MAX_BYTES,
        daySeconds: days,
        dedupe: {
          windowHours: config.ARCHIVE_DEDUPE_WINDOW_HOURS,
          maxContentVariants: config.ARCHIVE_MAX_CONTENT_VARIANTS,
          maxMergedCopies: config.ARCHIVE_MAX_MERGED_COPIES,
        },
        ...(deps.faults ? { faults: deps.faults } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const scheduler = new CaptureScheduler(prisma, {
        orgs: this.orgs,
        executor,
        storage: this.storage,
        keys: this.keys,
        metrics,
        logger: logger.child({ component: 'archive-scheduler' }),
        concurrency: config.ARCHIVE_CAPTURE_CONCURRENCY,
        leaseSeconds: config.ARCHIVE_CAPTURE_LEASE_SECONDS,
        retryBaseMs: config.ARCHIVE_CAPTURE_RETRY_BASE_MS,
        retryMaxMs: config.ARCHIVE_CAPTURE_RETRY_MAX_MS,
        maxAgeDays: config.ARCHIVE_INTENT_MAX_AGE_DAYS,
        outcomeWindowDays: config.ARCHIVE_OUTCOME_WINDOW_DAYS,
        chunkBytes: config.ARCHIVE_CHUNK_BYTES,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.random ? { random: deps.random } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const sweepOptions = {
        metrics,
        logger,
        batchSize: config.ARCHIVE_SWEEP_BATCH_SIZE,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      };
      const journal = new JournalSweep(prisma, this.orgs, {
        ...sweepOptions,
        safetyLagSeconds: config.ARCHIVE_SWEEP_SAFETY_LAG_SECONDS,
        start: config.ARCHIVE_JOURNAL_SWEEP_START,
        cursorName: `${JOURNAL_SWEEP_CURSOR}${suffix}`,
      });
      const policy = new PolicyReconciler(prisma, this.orgs, {
        ...sweepOptions,
        safetyLagSeconds: config.ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS,
        start: config.ARCHIVE_POLICY_RECONCILE_START,
        cursorName: `${POLICY_RECONCILE_CURSOR}${suffix}`,
      });
      const consumer = new ArchiveRequestConsumer(prisma, this.orgs, {
        metrics,
        logger: logger.child({ component: 'archive-consumer' }),
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const intakeHealth = new IntakeHealthJob(prisma, {
        metrics,
        logger: logger.child({ component: 'archive-intake-health' }),
        alertMinIntervalHours: config.JOURNAL_INTAKE_ALERT_MIN_INTERVAL_HOURS,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      this.capture = {
        consumer,
        journal,
        policy,
        scheduler,
        executor,
        intakeHealth,
        loops: {
          intakeHealth: new LeaderJob(
            'archive-intake-health',
            lock(INTAKE_HEALTH_LOCK),
            config.JOURNAL_INTAKE_HEALTH_INTERVAL_MS,
            async () => void (await intakeHealth.runOnce()),
            leader('intake_health'),
          ),
          journal: new LeaderJob(
            'archive-journal-sweep',
            lock(JOURNAL_SWEEP_LOCK),
            config.ARCHIVE_SWEEP_INTERVAL_MS,
            async () => (await journal.runOnce()).more,
            leader('journal_sweep'),
          ),
          policy: new LeaderJob(
            'archive-policy-reconcile',
            lock(POLICY_RECONCILE_LOCK),
            config.ARCHIVE_SWEEP_INTERVAL_MS,
            async () => (await policy.runOnce()).more,
            leader('policy_reconcile'),
          ),
          scheduler: new Periodic(
            'archive-capture-scheduler',
            SCHEDULER_POLL_MS,
            async () => {
              await this.ensureProbed();
              return scheduler.runOnce();
            },
            logger,
          ),
          maintain: new Periodic(
            'archive-intent-maintenance',
            INTENT_MAINTENANCE_INTERVAL_MS,
            async () => void (await scheduler.maintain()),
            logger,
          ),
        },
      };
    } else {
      this.capture = null;
    }

    const prefix = config.ARCHIVE_SEARCH_INDEX_PREFIX;
    if (hasRole(config, 'index')) {
      if (deps.search === null) throw new Error('the index role needs ARCHIVE_SEARCH_URL');
      const manager = new IndexManager(deps.search, prisma, {
        prefix,
        shards: config.ARCHIVE_INDEX_SHARDS,
        replicas: config.ARCHIVE_INDEX_REPLICAS,
      });
      const sync = new IndexSync(prisma, {
        search: deps.search,
        manager,
        objects: this.objects,
        metrics,
        logger: logger.child({ component: 'archive-index' }),
        batchSize: config.ARCHIVE_INDEX_BATCH_SIZE,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.random ? { random: deps.random } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const reconciler = new IndexReconciler(prisma, {
        search: deps.search,
        manager,
        metrics,
        logger: logger.child({ component: 'archive-reconcile' }),
        recentDays: config.ARCHIVE_RECONCILE_RECENT_DAYS,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      this.index = {
        manager,
        sync,
        reconciler,
        loops: {
          sync: new LeaderJob(
            'archive-index-sync',
            lock(INDEX_SYNC_LOCK),
            config.ARCHIVE_INDEX_INTERVAL_MS,
            async () => (await sync.runOnce()).more,
            leader('index_sync'),
          ),
          reconcile: new LeaderJob(
            'archive-index-reconcile',
            lock(INDEX_RECONCILE_LOCK),
            config.ARCHIVE_RECONCILE_INTERVAL_MS,
            async () => void (await reconciler.runOnce()),
            leader('index_reconcile'),
          ),
        },
      };
    } else {
      this.index = null;
    }

    if (hasRole(config, 'lifecycle')) {
      const lifecycleLogger = logger.child({ component: 'archive-lifecycle' });
      const expiry = new ExpiryJob(prisma, {
        storage: this.storage,
        metrics,
        logger: lifecycleLogger,
        batchSize: config.ARCHIVE_LIFECYCLE_BATCH_SIZE,
        holdExtensionDays: config.ARCHIVE_HOLD_EXTENSION_DAYS,
        reviewExtensionDays: config.ARCHIVE_REVIEW_EXTENSION_DAYS,
        daySeconds: days,
        replicaTargets: config.ARCHIVE_REPLICA_TARGETS,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const disposal = new DisposalPipeline(prisma, {
        storage: this.storage,
        search: deps.search,
        indexPrefix: prefix,
        replicaTargets: config.ARCHIVE_REPLICA_TARGETS,
        governanceBypassOrphans: config.ARCHIVE_GOVERNANCE_BYPASS_ORPHANS,
        maxAttempts: config.ARCHIVE_DISPOSAL_MAX_ATTEMPTS,
        metrics,
        logger: lifecycleLogger,
        batchSize: config.ARCHIVE_LIFECYCLE_BATCH_SIZE,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.random ? { random: deps.random } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const lockPass = new LockPass(prisma, {
        storage: this.storage,
        lockState: this.lockState,
        metrics,
        logger: lifecycleLogger,
        batchSize: config.ARCHIVE_LIFECYCLE_BATCH_SIZE,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const orphans = new OrphanReconciler(prisma, {
        storage: this.storage,
        metrics,
        logger: lifecycleLogger,
        governanceBypass: config.ARCHIVE_GOVERNANCE_BYPASS_ORPHANS,
        windowDays: config.ARCHIVE_INTENT_MAX_AGE_DAYS + config.ARCHIVE_OUTCOME_WINDOW_DAYS + 2,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const verifier = new DisposalVerifier(prisma, {
        storage: this.storage,
        search: deps.search,
        indexPrefix: prefix,
        replicaTargets: config.ARCHIVE_REPLICA_TARGETS,
        metrics,
        logger: lifecycleLogger,
        sampleSize: DISPOSAL_VERIFY_SAMPLE,
        cursorName: `${DISPOSAL_VERIFY_CURSOR}${suffix}`,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const rewrap = new RootRewrapJob(prisma, {
        provider: this.rootKeys,
        metrics,
        logger: lifecycleLogger,
        batchSize: config.ARCHIVE_LIFECYCLE_BATCH_SIZE,
        ...(only ? { organizationIds: only } : {}),
      });
      const pruner = new IntakeDataPruner(prisma, {
        metrics,
        logger: lifecycleLogger,
        dedupeWindowHours: config.ARCHIVE_DEDUPE_WINDOW_HOURS,
        batchSize: config.ARCHIVE_LIFECYCLE_BATCH_SIZE,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      const step = async (name: string, fn: () => Promise<unknown>): Promise<void> => {
        try {
          await fn();
        } catch (error) {
          lifecycleLogger.warn({ step: name, ...errorFields(error) }, 'lifecycle step failed');
        }
      };
      this.lifecycle = {
        expiry,
        disposal,
        lockPass,
        orphans,
        verifier,
        rewrap,
        pruner,
        loops: {
          lifecycle: new LeaderJob(
            'archive-lifecycle',
            lock(LIFECYCLE_LOCK),
            config.ARCHIVE_LIFECYCLE_INTERVAL_MS,
            async () => {
              await this.ensureProbed();
              await step('expiry', () => expiry.runOnce());
              await step('lock_pass', () => lockPass.runOnce());
              await step('orphans', () => orphans.runOnce());
              await step('verify', () => verifier.runOnce());
              await step('prune', () => pruner.runOnce());
              await step('gauges', () => disposal.gauges());
            },
            leader('lifecycle'),
          ),
          disposal: new Periodic(
            'archive-disposals',
            Math.min(config.ARCHIVE_LIFECYCLE_INTERVAL_MS, DISPOSAL_POLL_MAX_MS),
            () => disposal.runOnce(),
            logger,
          ),
          rewrap: new LeaderJob(
            'archive-root-rewrap',
            lock(ROOT_REWRAP_LOCK),
            config.ARCHIVE_LIFECYCLE_INTERVAL_MS,
            async () => void (await rewrap.runOnce()),
            leader('root_rewrap'),
          ),
        },
      };
    } else {
      this.lifecycle = null;
    }

    if (hasRole(config, 'ediscovery')) {
      if (deps.search === null) throw new Error('the ediscovery role needs ARCHIVE_SEARCH_URL');
      const ediscoveryLogger = logger.child({ component: 'archive-ediscovery' });
      const searches = new CaseSearchRunner(prisma, {
        search: deps.search,
        metrics,
        logger: ediscoveryLogger,
        indexPrefix: prefix,
        maxHits: config.ARCHIVE_CASE_SEARCH_MAX_HITS,
        deadlineMs: config.ARCHIVE_CASE_SEARCH_DEADLINE_MS,
        timeoutMs: config.ARCHIVE_SEARCH_TIMEOUT_MS,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      // Not `exports`: compiled to CommonJS, a local `exports` shadows the module's own and the
      // `EDISCOVERY_POLL_MS` / `EXPORT_EXPIRY_INTERVAL_MS` references below became `undefined`
      // (NaN sleeps: the ediscovery loops spun about 500 claims a second each; WP6 fix).
      const exportBuilder = new ExportBuilder(prisma, {
        storage: this.storage,
        objects: this.objects,
        keys: this.keys,
        metrics,
        logger: ediscoveryLogger,
        signingKey: parseExportSigningPrivateKey(config.ARCHIVE_EXPORT_SIGNING_KEY),
        signingKeyId: config.ARCHIVE_EXPORT_SIGNING_KEY_ID,
        maxItems: config.ARCHIVE_EXPORT_MAX_ITEMS,
        maxBytes: config.ARCHIVE_EXPORT_MAX_BYTES,
        ttlHours: config.ARCHIVE_EXPORT_TTL_HOURS,
        chunkBytes: config.ARCHIVE_CHUNK_BYTES,
        ...(only ? { organizationIds: only } : {}),
        ...(deps.now ? { now: deps.now } : {}),
      });
      this.ediscovery = {
        searches,
        exports: exportBuilder,
        loops: {
          searches: new Periodic(
            'archive-case-searches',
            EDISCOVERY_POLL_MS,
            () => searches.runOnce(),
            logger,
          ),
          exports: Array.from(
            { length: config.ARCHIVE_EXPORT_CONCURRENCY },
            (_, i) =>
              new Periodic(
                `archive-exports-${i}`,
                EDISCOVERY_POLL_MS,
                () => exportBuilder.runOnce(),
                logger,
              ),
          ),
          expiry: new Periodic(
            'archive-export-expiry',
            EXPORT_EXPIRY_INTERVAL_MS,
            async () => (await exportBuilder.expire()) === 100,
            logger,
          ),
        },
      };
    } else {
      this.ediscovery = null;
    }
  }

  /** The Object Lock probe of the archive bucket (A10), until it succeeded once. */
  async ensureProbed(): Promise<void> {
    if (this.lockState.probed) return;
    try {
      const available = await this.storage.probeObjectLock();
      this.lockState.set(available);
      this.deps.metrics.objectLock.inc({ op: 'probe', result: available ? 'ok' : 'unavailable' });
      this.deps.logger.info({ objectLock: available }, 'archive bucket Object Lock probed');
    } catch (error) {
      this.deps.metrics.objectLock.inc({ op: 'probe', result: 'failed' });
      this.deps.logger.warn({ ...errorFields(error) }, 'Object Lock probe failed; retried');
    }
  }

  private allLoops(): Array<{ start(): void; stop(): Promise<void> }> {
    return [
      ...(this.capture ? Object.values(this.capture.loops) : []),
      ...(this.index ? Object.values(this.index.loops) : []),
      ...(this.lifecycle ? Object.values(this.lifecycle.loops) : []),
      ...(this.ediscovery
        ? [
            this.ediscovery.loops.searches,
            ...this.ediscovery.loops.exports,
            this.ediscovery.loops.expiry,
          ]
        : []),
    ];
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    await this.ensureProbed();
    for (const loop of this.allLoops()) loop.start();
  }

  async stop(): Promise<void> {
    if (!this.started) return;
    this.started = false;
    await Promise.all(this.allLoops().map((l) => l.stop()));
  }
}
