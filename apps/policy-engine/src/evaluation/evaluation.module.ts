import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  ConfirmPublisher,
  type MessagingMetrics,
  PrismaConsumerProgress,
  PrismaService,
} from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { URL_REWRITE_CONFIG } from '../core.module';
import { S3PolicyCopyWriter } from '../delivery/policy-copy';
import { CopyFactsReader, type PolicyUrlRewriteConfig } from '../delivery/policy-url-rewrite';
import { PolicyMetrics } from '../metrics/policy-metrics';
import { QuarantineMetrics } from '../metrics/quarantine-metrics';
import { QuarantineSettingsRepository } from '../quarantine/settings.repository';
import { QuarantineStoreWriter } from '../quarantine/store-writer';
import { DirectoryRepository } from './directory.repository';
import { PolicyEvaluationService } from './evaluation.service';
import { FactsRepository } from './facts.repository';
import { createPolicyEvaluateFeed, PolicyEvaluateConsumer } from './policy-evaluate.consumer';
import { SnapshotRepository } from './snapshot.repository';

/** Starts the consumer after bootstrap and stops it before the clients close. */
@Injectable()
export class EvaluationRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(@Inject(PolicyEvaluateConsumer) private readonly consumer: PolicyEvaluateConsumer) {}

  onApplicationBootstrap(): void {
    this.consumer.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.consumer.stop();
  }
}

/**
 * The evaluation pipeline (role `evaluate`, step 5.2 P13; step 5.3 Q2–Q6, Q22, Q23):
 * `email.policy.evaluate` → `PolicyEvaluationService` (facts, snapshot, directory, per-recipient
 * evaluation, policy copy with banner and URL rewrite, decision row, lifecycle, recipients,
 * quarantine entries, outbox) with the P24 and Q29 metrics. Needs the global `AmqpModule`,
 * `S3Module`, `MetricsModule` and `PolicyEngineCoreModule`.
 */
@Module({})
export class EvaluationModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: EvaluationModule,
      providers: [
        {
          provide: PolicyEvaluationService,
          useFactory: (
            metrics: PolicyMetrics,
            facts: FactsRepository,
            snapshots: SnapshotRepository,
            directory: DirectoryRepository,
            copies: S3PolicyCopyWriter,
            store: QuarantineStoreWriter,
            settings: QuarantineSettingsRepository,
            copyFacts: CopyFactsReader,
            urlRewrite: PolicyUrlRewriteConfig,
          ) =>
            new PolicyEvaluationService({
              facts,
              snapshots,
              directory,
              copies,
              quarantine: {
                store,
                settings,
                copyFacts,
                urlRewrite,
                bannerMaxPartBytes: config.POLICY_BANNER_MAX_PART_BYTES,
                bounds: {
                  maxHoldDays: config.QUARANTINE_MAX_HOLD_DAYS,
                  maxReviewDays: config.QUARANTINE_MAX_REVIEW_DAYS,
                },
              },
              metrics,
              logger,
              copyTimeoutMs: Math.floor(config.POLICY_DB_TX_TIMEOUT_MS / 2),
            }),
          inject: [
            PolicyMetrics,
            FactsRepository,
            SnapshotRepository,
            DirectoryRepository,
            S3PolicyCopyWriter,
            QuarantineStoreWriter,
            QuarantineSettingsRepository,
            CopyFactsReader,
            URL_REWRITE_CONFIG,
          ],
        },
        {
          provide: PolicyEvaluateConsumer,
          useFactory: (
            prisma: PrismaService,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            messaging: MessagingMetrics | null,
            service: PolicyEvaluationService,
            metrics: PolicyMetrics,
            quarantine: QuarantineMetrics,
          ) =>
            new PolicyEvaluateConsumer(
              createPolicyEvaluateFeed({
                connection,
                publisher,
                prefetch: config.POLICY_EVALUATE_PREFETCH,
                logger,
                ...(messaging ? { metrics: messaging } : {}),
                progress: new PrismaConsumerProgress(prisma),
              }),
              service,
              prisma,
              metrics,
              config.POLICY_DB_TX_TIMEOUT_MS,
              undefined,
              quarantine,
            ),
          inject: [
            PrismaService,
            AmqpConnection,
            ConfirmPublisher,
            AMQP_MESSAGING_METRICS,
            PolicyEvaluationService,
            PolicyMetrics,
            QuarantineMetrics,
          ],
        },
        EvaluationRuntime,
      ],
      exports: [PolicyEvaluateConsumer],
    };
  }
}
