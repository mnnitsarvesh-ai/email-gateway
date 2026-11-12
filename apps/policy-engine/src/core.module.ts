import { type DynamicModule, Global, Module } from '@nestjs/common';
import { MetricsService, S3Service } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { parseTokenKey } from '@email-gateway/url-security';
import type { WorkerConfig } from './config';
import { S3PolicyCopyWriter } from './delivery/policy-copy';
import { CopyFactsReader, type PolicyUrlRewriteConfig } from './delivery/policy-url-rewrite';
import { DirectoryRepository } from './evaluation/directory.repository';
import { FactsRepository } from './evaluation/facts.repository';
import { SnapshotCache } from './evaluation/snapshot-cache';
import { type LoadedSnapshot, SnapshotRepository } from './evaluation/snapshot.repository';
import { PolicyMetrics, type PolicyRead } from './metrics/policy-metrics';
import { QuarantineMetrics, type QuarantineRead } from './metrics/quarantine-metrics';
import { QuarantineSettingsRepository } from './quarantine/settings.repository';
import { QuarantineStoreWriter } from './quarantine/store-writer';

/** The policy URL rewrite configuration (Q23) from the engine's keys. */
export function urlRewriteConfig(config: Readonly<WorkerConfig>): PolicyUrlRewriteConfig {
  return {
    enabled: config.POLICY_URL_REWRITE_ENABLED,
    key:
      config.URL_TOKEN_KEY_CURRENT === undefined
        ? null
        : parseTokenKey(config.URL_TOKEN_KEY_CURRENT, config.URL_TOKEN_KEY_CURRENT_ID),
    clickBaseUrl: config.URL_CLICK_BASE_URL,
    defaultExpiryDays: config.URL_TOKEN_DEFAULT_EXPIRY_DAYS,
    maxExpiryDays: config.URL_TOKEN_MAX_EXPIRY_DAYS,
    dkimSignedPolicy: config.URL_REWRITE_DKIM_SIGNED,
    limits: {
      maxMessageBytes: config.URL_REWRITE_MAX_MESSAGE_BYTES,
      maxPartBytes: config.URL_REWRITE_MAX_PART_BYTES,
    },
  };
}

/** Injection token of the policy URL rewrite configuration. */
export const URL_REWRITE_CONFIG = Symbol('URL_REWRITE_CONFIG');

/**
 * What both roles share (step 5.3 Q28): the metrics, the writer readers (facts, snapshot cache,
 * directory, quarantine settings, copy facts), the quarantine store writer and the policy copy
 * writer (header edits, WARN banners, policy URL rewriting). Global: the role modules inject it.
 */
@Global()
@Module({})
export class PolicyEngineCoreModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: PolicyEngineCoreModule,
      providers: [
        {
          provide: PolicyMetrics,
          useFactory: (metrics: MetricsService) => new PolicyMetrics(metrics),
          inject: [MetricsService],
        },
        {
          provide: QuarantineMetrics,
          useFactory: (metrics: MetricsService) => new QuarantineMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: URL_REWRITE_CONFIG, useValue: urlRewriteConfig(config) },
        {
          provide: FactsRepository,
          useFactory: (m: PolicyMetrics) =>
            new FactsRepository((read: PolicyRead) => m.inconsistentReads.inc({ read })),
          inject: [PolicyMetrics],
        },
        {
          provide: SnapshotRepository,
          useFactory: (m: PolicyMetrics) =>
            new SnapshotRepository(
              new SnapshotCache<LoadedSnapshot>(config.POLICY_SNAPSHOT_CACHE_MAX_ENTRIES),
              config.POLICY_PLATFORM_DEFAULT,
              (read: PolicyRead) => m.inconsistentReads.inc({ read }),
              ({ policyPublicId }) =>
                logger.warn(
                  { policyPublicId },
                  'active policy points to a version that is not published; it contributes no rule',
                ),
            ),
          inject: [PolicyMetrics],
        },
        {
          provide: DirectoryRepository,
          useFactory: (m: PolicyMetrics) =>
            new DirectoryRepository((read: PolicyRead) => m.inconsistentReads.inc({ read })),
          inject: [PolicyMetrics],
        },
        {
          provide: CopyFactsReader,
          useFactory: (m: PolicyMetrics, rewrite: PolicyUrlRewriteConfig) =>
            new CopyFactsReader(rewrite, (read: PolicyRead) => m.inconsistentReads.inc({ read })),
          inject: [PolicyMetrics, URL_REWRITE_CONFIG],
        },
        {
          provide: QuarantineSettingsRepository,
          useFactory: (q: QuarantineMetrics) =>
            new QuarantineSettingsRepository(
              {
                maxHoldDays: config.QUARANTINE_MAX_HOLD_DAYS,
                maxReviewDays: config.QUARANTINE_MAX_REVIEW_DAYS,
              },
              (read: QuarantineRead) => q.inconsistentReads.inc({ read }),
              () => q.settingsInvalid.inc(),
            ),
          inject: [QuarantineMetrics],
        },
        {
          provide: QuarantineStoreWriter,
          useFactory: (q: QuarantineMetrics) =>
            new QuarantineStoreWriter((read: QuarantineRead) => q.inconsistentReads.inc({ read })),
          inject: [QuarantineMetrics],
        },
        {
          provide: S3PolicyCopyWriter,
          useFactory: (s3: S3Service) =>
            new S3PolicyCopyWriter(s3.client, s3.mailBucket, {
              maxMessageBytes: config.POLICY_COPY_MAX_MESSAGE_BYTES,
              maxHeaderBytes: config.POLICY_COPY_MAX_HEADER_BYTES,
            }),
          inject: [S3Service],
        },
      ],
      exports: [
        PolicyMetrics,
        QuarantineMetrics,
        URL_REWRITE_CONFIG,
        FactsRepository,
        SnapshotRepository,
        DirectoryRepository,
        CopyFactsReader,
        QuarantineSettingsRepository,
        QuarantineStoreWriter,
        S3PolicyCopyWriter,
      ],
    };
  }
}
