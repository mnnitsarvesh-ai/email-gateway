import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AdvisoryLocks,
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  ConfirmPublisher,
  type MessagingMetrics,
  PrismaConsumerProgress,
  PrismaService,
  S3Service,
  withTransactionDefaults,
} from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { URL_REWRITE_CONFIG } from '../core.module';
import { S3PolicyCopyWriter } from '../delivery/policy-copy';
import { CopyFactsReader, type PolicyUrlRewriteConfig } from '../delivery/policy-url-rewrite';
import { DirectoryRepository } from '../evaluation/directory.repository';
import { FactsRepository } from '../evaluation/facts.repository';
import { SnapshotRepository } from '../evaluation/snapshot.repository';
import { PolicyMetrics, type PolicyRead } from '../metrics/policy-metrics';
import { QuarantineMetrics, type QuarantineRead } from '../metrics/quarantine-metrics';
import { DigestScheduler } from './digest-scheduler';
import { DisposalFactsReader, S3QuarantineObjects } from './disposal';
import { ReleaseExecutor } from './release-executor';
import { ReleaseFactsReader } from './release-facts';
import { createQuarantineReleaseFeed, QuarantineReleaseConsumer } from './release.consumer';
import { QuarantineSettingsRepository } from './settings.repository';
import { QuarantineStoreWriter } from './store-writer';
import { QuarantineSweeper } from './sweeper';

/** The sweeper's advisory locks (a dedicated connection; tests override it). */
export const SWEEPER_LOCKS = Symbol('QUARANTINE_SWEEPER_LOCKS');

/** Starts the executor and the sweeper after bootstrap; stops them before the clients close. */
@Injectable()
export class QuarantineRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(QuarantineReleaseConsumer) private readonly consumer: QuarantineReleaseConsumer,
    @Inject(QuarantineSweeper) private readonly sweeper: QuarantineSweeper,
    @Inject(SWEEPER_LOCKS) private readonly locks: AdvisoryLocks,
  ) {}

  onApplicationBootstrap(): void {
    this.consumer.start();
    this.sweeper.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.consumer.stop();
    await this.sweeper.stop();
    await this.locks.close().catch(() => undefined);
  }
}

/**
 * The quarantine role (step 5.3 Q13.2, Q19, Q20, Q28): the release executor on
 * `email.quarantine` (ledger `policy-engine.quarantine`) and the leader-elected sweeper (expiry,
 * approval expiry, object purge, adoption, digests and admin alerts, row retention). Needs the
 * global `AmqpModule`, `S3Module`, `MetricsModule` and `PolicyEngineCoreModule`.
 */
@Module({})
export class QuarantineModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    const bounds = {
      maxHoldDays: config.QUARANTINE_MAX_HOLD_DAYS,
      maxReviewDays: config.QUARANTINE_MAX_REVIEW_DAYS,
    };
    return {
      module: QuarantineModule,
      providers: [
        {
          provide: S3QuarantineObjects,
          useFactory: (s3: S3Service) => new S3QuarantineObjects(s3.client, s3.mailBucket),
          inject: [S3Service],
        },
        {
          provide: ReleaseExecutor,
          useFactory: (
            policy: PolicyMetrics,
            q: QuarantineMetrics,
            facts: FactsRepository,
            snapshots: SnapshotRepository,
            directory: DirectoryRepository,
            settings: QuarantineSettingsRepository,
            store: QuarantineStoreWriter,
            copies: S3PolicyCopyWriter,
            copyFacts: CopyFactsReader,
            objects: S3QuarantineObjects,
            urlRewrite: PolicyUrlRewriteConfig,
          ) => {
            const sink = (read: QuarantineRead) => q.inconsistentReads.inc({ read });
            return new ReleaseExecutor({
              facts,
              snapshots,
              directory,
              releaseFacts: new ReleaseFactsReader(sink),
              settings,
              store,
              copies,
              copyFacts,
              objectExists: (key, signal) => objects.exists(key, signal),
              urlRewrite,
              bannerMaxPartBytes: config.POLICY_BANNER_MAX_PART_BYTES,
              bounds,
              staleness: {
                maxVerdictAgeHours: config.QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS,
                signatureMaxLagHours: config.QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS,
              },
              copyTimeoutMs: Math.floor(config.QUARANTINE_DB_TX_TIMEOUT_MS / 2),
              policySink: (read: PolicyRead) => policy.inconsistentReads.inc({ read }),
              sink,
              lifecycleMetrics: policy.lifecycle,
              logger,
            });
          },
          inject: [
            PolicyMetrics,
            QuarantineMetrics,
            FactsRepository,
            SnapshotRepository,
            DirectoryRepository,
            QuarantineSettingsRepository,
            QuarantineStoreWriter,
            S3PolicyCopyWriter,
            CopyFactsReader,
            S3QuarantineObjects,
            URL_REWRITE_CONFIG,
          ],
        },
        {
          provide: QuarantineReleaseConsumer,
          useFactory: (
            prisma: PrismaService,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            messaging: MessagingMetrics | null,
            executor: ReleaseExecutor,
            q: QuarantineMetrics,
            policy: PolicyMetrics,
          ) =>
            new QuarantineReleaseConsumer(
              createQuarantineReleaseFeed({
                connection,
                publisher,
                prefetch: config.QUARANTINE_RELEASE_PREFETCH,
                logger,
                ...(messaging ? { metrics: messaging } : {}),
                progress: new PrismaConsumerProgress(prisma),
              }),
              executor,
              prisma,
              q,
              config.QUARANTINE_DB_TX_TIMEOUT_MS,
              undefined,
              policy,
            ),
          inject: [
            PrismaService,
            AmqpConnection,
            ConfirmPublisher,
            AMQP_MESSAGING_METRICS,
            ReleaseExecutor,
            QuarantineMetrics,
            PolicyMetrics,
          ],
        },
        // GET_LOCK on its own connection (connection_limit=1), like the 4.5 evidence sweeper.
        { provide: SWEEPER_LOCKS, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: QuarantineSweeper,
          useFactory: (
            prisma: PrismaService,
            locks: AdvisoryLocks,
            objects: S3QuarantineObjects,
            store: QuarantineStoreWriter,
            settings: QuarantineSettingsRepository,
            q: QuarantineMetrics,
            policy: PolicyMetrics,
          ) => {
            const sink = (read: QuarantineRead) => q.inconsistentReads.inc({ read });
            return new QuarantineSweeper({
              prisma,
              locks,
              objects,
              store,
              settings,
              disposal: new DisposalFactsReader(sink),
              digests: new DigestScheduler({
                prisma: withTransactionDefaults(prisma, {
                  timeoutMs: config.QUARANTINE_DB_TX_TIMEOUT_MS,
                }),
                settings,
                sink,
                logger,
                maxUsersPerSweep: config.QUARANTINE_DIGEST_MAX_USERS_PER_RUN,
                batchSize: config.QUARANTINE_SWEEP_BATCH_SIZE,
              }),
              metrics: q,
              lifecycleMetrics: policy.lifecycle,
              sink,
              logger,
              intervalMs: config.QUARANTINE_SWEEP_INTERVAL_MS,
              txTimeoutMs: config.QUARANTINE_DB_TX_TIMEOUT_MS,
              batchSize: config.QUARANTINE_SWEEP_BATCH_SIZE,
              retentionDays: config.QUARANTINE_ENTRY_RETENTION_DAYS,
              bounds,
            });
          },
          inject: [
            PrismaService,
            SWEEPER_LOCKS,
            S3QuarantineObjects,
            QuarantineStoreWriter,
            QuarantineSettingsRepository,
            QuarantineMetrics,
            PolicyMetrics,
          ],
        },
        QuarantineRuntime,
      ],
      exports: [QuarantineReleaseConsumer, QuarantineSweeper],
    };
  }
}
