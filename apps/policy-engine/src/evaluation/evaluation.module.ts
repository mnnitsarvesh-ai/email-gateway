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
  MetricsService,
  PrismaConsumerProgress,
  PrismaService,
  S3Service,
} from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { S3PolicyCopyWriter } from '../delivery/policy-copy';
import { PolicyMetrics, type PolicyRead } from '../metrics/policy-metrics';
import { DirectoryRepository } from './directory.repository';
import { PolicyEvaluationService } from './evaluation.service';
import { FactsRepository } from './facts.repository';
import { createPolicyEvaluateFeed, PolicyEvaluateConsumer } from './policy-evaluate.consumer';
import { SnapshotCache } from './snapshot-cache';
import { type LoadedSnapshot, SnapshotRepository } from './snapshot.repository';

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
 * The evaluation pipeline of step 5.2 (P13): `email.policy.evaluate` → `PolicyEvaluationService`
 * (facts, snapshot, directory, evaluation, policy copy, decision row, lifecycle, outbox) with the
 * P24 metrics. Needs the global `AmqpModule`, `S3Module` and `MetricsModule`.
 */
@Module({})
export class EvaluationModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: EvaluationModule,
      providers: [
        {
          provide: PolicyMetrics,
          useFactory: (metrics: MetricsService) => new PolicyMetrics(metrics),
          inject: [MetricsService],
        },
        {
          provide: PolicyEvaluationService,
          useFactory: (metrics: PolicyMetrics, s3: S3Service) => {
            const inconsistent = (read: PolicyRead) => metrics.inconsistentReads.inc({ read });
            return new PolicyEvaluationService({
              facts: new FactsRepository(inconsistent),
              snapshots: new SnapshotRepository(
                new SnapshotCache<LoadedSnapshot>(config.POLICY_SNAPSHOT_CACHE_MAX_ENTRIES),
                config.POLICY_PLATFORM_DEFAULT,
                inconsistent,
                ({ policyPublicId }) =>
                  logger.warn(
                    { policyPublicId },
                    'active policy points to a version that is not published; it contributes no rule',
                  ),
              ),
              directory: new DirectoryRepository(inconsistent),
              copies: new S3PolicyCopyWriter(s3.client, s3.mailBucket, {
                maxMessageBytes: config.POLICY_COPY_MAX_MESSAGE_BYTES,
                maxHeaderBytes: config.POLICY_COPY_MAX_HEADER_BYTES,
              }),
              metrics,
              logger,
              copyTimeoutMs: Math.floor(config.POLICY_DB_TX_TIMEOUT_MS / 2),
            });
          },
          inject: [PolicyMetrics, S3Service],
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
            ),
          inject: [
            PrismaService,
            AmqpConnection,
            ConfirmPublisher,
            AMQP_MESSAGING_METRICS,
            PolicyEvaluationService,
            PolicyMetrics,
          ],
        },
        EvaluationRuntime,
      ],
      exports: [PolicyMetrics, PolicyEvaluateConsumer],
    };
  }
}
