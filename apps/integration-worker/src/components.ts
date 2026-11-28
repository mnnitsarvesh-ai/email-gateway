import { readFileSync } from 'node:fs';
import { rootCertificates } from 'node:tls';
import { withTransactionDefaults } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { CheckRunner } from './checks/checks';
import { DnsProbeResolver, type ProbeResolver } from './checks/dns';
import { probeSmtp, type SmtpProbeOptions, type SmtpProbeResult } from './checks/smtp-probe';
import { hasRole, isLocalEnv, probeHelo, type WorkerConfig } from './config';
import { type HealthFaults, HealthRunner } from './health/health-runner';
import { MAINTENANCE_LOCK, Maintenance } from './maintenance/maintenance';
import type { IntegrationMetrics } from './metrics/integration-metrics';
import { ProviderRuntime, type ProviderRuntimeOptions } from './providers/provider-runtime';
import { LeaderJob, type LeaderLock, Periodic } from './shared/loops';
import { orgFilter } from './shared/db';
import { DomainCheckTask } from './tasks/domain-checks';
import { GrantVerifier } from './tasks/grant-verifier';
import { ProviderOwnershipTask } from './tasks/provider-ownership';
import { TenantBinder } from './tasks/tenant-binding';
import { ValidationRunner } from './tasks/validation-runner';

/** Interval of the maintenance leader job. */
export const MAINTENANCE_INTERVAL_MS = 5 * 60_000;

export interface ComponentDeps {
  /** The MySQL writer (claims, updates, audit, outbox). */
  writer: PrismaClient;
  /** The reader (delivery statistics); the writer when no replica is configured. */
  reader: () => PrismaClient;
  locks: LeaderLock;
  metrics: IntegrationMetrics;
  logger: Logger;
  /** Integration suites: restrict every job to these organizations. */
  organizationIds?: readonly bigint[];
  /** Integration suites: appended to the leader lock name. */
  nameSuffix?: string;
  provider?: ProviderRuntimeOptions;
  resolver?: ProbeResolver;
  probeSmtp?: (options: SmtpProbeOptions) => Promise<SmtpProbeResult>;
  healthFaults?: HealthFaults;
  now?: () => Date;
}

/** Every component of the roles this process runs (D11), plus start/stop of their loops. */
export class IntegrationComponents {
  readonly runtime: ProviderRuntime;
  readonly checks: CheckRunner;
  readonly binder: TenantBinder;
  readonly verifier: GrantVerifier;
  readonly domainChecks: DomainCheckTask;
  readonly ownership: ProviderOwnershipTask;
  readonly validations: ValidationRunner;
  readonly health: HealthRunner;
  readonly maintenance: Maintenance;
  private readonly loops: Array<{ start(): void; stop(): Promise<void> }> = [];
  private readonly abort = new AbortController();
  private started = false;

  constructor(
    readonly config: Readonly<WorkerConfig>,
    private readonly deps: ComponentDeps,
  ) {
    const writer = withTransactionDefaults(deps.writer, {
      timeoutMs: config.INTEGRATION_TX_TIMEOUT_MS,
    });
    const now = deps.now ?? (() => new Date());
    const logger = deps.logger;
    const metrics = deps.metrics;
    const only = deps.organizationIds;
    this.runtime = new ProviderRuntime(config, writer, metrics, logger, {
      ...deps.provider,
      ...(deps.now ? { now: deps.now } : {}),
    });
    if (config.PROVIDER_M365_ALLOW_PLATFORM_SECRET && config.APP_ENV === 'production') {
      logger.warn(
        { key: 'PROVIDER_M365_ALLOW_PLATFORM_SECRET' },
        'the platform Microsoft app authenticates with a client secret in production (D2: use the certificate)',
      );
    }
    const extraCa = config.INTEGRATION_PROBE_CA_PATH
      ? [...rootCertificates, readFileSync(config.INTEGRATION_PROBE_CA_PATH, 'utf8')]
      : undefined;
    this.checks = new CheckRunner({
      writer,
      reader: deps.reader,
      runtime: this.runtime,
      resolver:
        deps.resolver ??
        new DnsProbeResolver({
          servers: config.INTEGRATION_PROBE_DNS_SERVERS,
          timeoutMs: Math.min(10_000, config.INTEGRATION_SMTP_PROBE_TIMEOUT_MS),
        }),
      probeSmtp: deps.probeSmtp ?? probeSmtp,
      metrics,
      now,
      settings: {
        gatewayMxHosts: config.GATEWAY_MX_HOSTS,
        spfInclude: config.GATEWAY_SPF_INCLUDE ?? null,
        egressMaxAgeDays: config.PROVIDER_EGRESS_MAX_AGE_DAYS,
        relayIdleWarnHours: config.INTEGRATION_RELAY_IDLE_WARN_HOURS,
        probeHelo: probeHelo(config),
        probeTimeoutMs: config.INTEGRATION_SMTP_PROBE_TIMEOUT_MS,
        probeCa: extraCa,
        // Local/ci stand-in sinks live on private Compose networks; production probes public
        // provider hosts only (unless the operator allowed non-public destinations, R3).
        allowNonPublicProbeAddresses:
          isLocalEnv(config) || config.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS,
        destinationHosts: {
          allowNonPublic: config.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS,
          deniedSuffixes: config.ROUTING_DENIED_DESTINATION_SUFFIXES,
          gatewayHosts: new Set([
            ...config.GATEWAY_MX_HOSTS,
            config.POSTFIX_MYHOSTNAME,
            config.POSTFIX_OUTBOUND_MYHOSTNAME,
          ]),
          ...(config.POSTFIX_BOUNCE_DOMAIN ? { bounceDomain: config.POSTFIX_BOUNCE_DOMAIN } : {}),
        },
      },
    });
    const scoped = only ? { organizationIds: only } : {};
    this.binder = new TenantBinder(writer, {
      runtime: this.runtime,
      logger: logger.child({ component: 'tenant-binding' }),
      now,
    });
    this.verifier = new GrantVerifier(writer, {
      runtime: this.runtime,
      checks: this.checks,
      binder: this.binder,
      metrics,
      logger: logger.child({ component: 'grant-verifier' }),
      now,
      ...scoped,
    });
    this.domainChecks = new DomainCheckTask(writer, {
      checks: this.checks,
      binder: this.binder,
      logger: logger.child({ component: 'domain-checks' }),
      now,
      ...scoped,
    });
    this.ownership = new ProviderOwnershipTask(writer, {
      runtime: this.runtime,
      metrics,
      logger: logger.child({ component: 'provider-ownership' }),
      now,
      batch: config.PROVIDER_OWNERSHIP_CHECK_BATCH,
      ...scoped,
    });
    this.validations = new ValidationRunner(writer, {
      checks: this.checks,
      metrics,
      logger: logger.child({ component: 'validations' }),
      now,
      probeTtlSeconds: config.PROVIDER_PROBE_TTL_SECONDS,
      ...scoped,
    });
    this.health = new HealthRunner(writer, {
      checks: this.checks,
      binder: this.binder,
      metrics,
      logger: logger.child({ component: 'health' }),
      now,
      intervalSeconds: config.INTEGRATION_HEALTH_INTERVAL_SECONDS,
      graceMinutes: config.INTEGRATION_HEALTH_ERROR_GRACE_MINUTES,
      ...scoped,
      ...(deps.healthFaults ? { faults: deps.healthFaults } : {}),
    });
    this.maintenance = new Maintenance(writer, {
      grants: this.runtime.grants,
      validations: this.validations,
      metrics,
      logger: logger.child({ component: 'maintenance' }),
      now,
      hasPreviousKey: config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS !== undefined,
      ...scoped,
    });

    const concurrency = config.INTEGRATION_TASK_CONCURRENCY;
    if (hasRole(config, 'tasks')) {
      this.loops.push(
        new Periodic(
          'integration-tasks',
          config.INTEGRATION_TASK_POLL_MS,
          async () => {
            const signal = this.abort.signal;
            await this.updateTaskLag();
            const [grants, domains, runs, probes, ownership] = await Promise.all([
              this.verifier.runOnce(concurrency, signal),
              this.domainChecks.runOnce(concurrency, signal),
              this.validations.runOnce(concurrency, signal),
              this.validations.completeProbes(50),
              this.ownership.runOnce(signal).then((r) => r.length),
            ]);
            return grants + domains + runs + probes + ownership > 0;
          },
          logger,
        ),
      );
    }
    if (hasRole(config, 'health')) {
      this.loops.push(
        new Periodic(
          'integration-health',
          config.INTEGRATION_HEALTH_TICK_SECONDS * 1000,
          async () => (await this.health.runOnce(concurrency * 2, this.abort.signal)) > 0,
          logger,
        ),
      );
    }
    if (hasRole(config, 'maintenance')) {
      this.loops.push(
        new LeaderJob(
          'integration-maintenance',
          `${MAINTENANCE_LOCK}${deps.nameSuffix ?? ''}`.slice(0, 64),
          MAINTENANCE_INTERVAL_MS,
          async () => void (await this.maintenance.runOnce()),
          {
            locks: deps.locks,
            logger,
            onLeadership: (on) => {
              metrics.leader.set({ job: 'maintenance' }, on ? 1 : 0);
              if (!on) this.maintenance.resetGauges();
            },
          },
        ),
      );
    }
  }

  /**
   * `integration_worker_task_lag_seconds`: the oldest pending grant verification, queued run or
   * unchecked provider ownership verification (step API-4 B3.3).
   */
  async updateTaskLag(): Promise<number> {
    const now = (this.deps.now ?? (() => new Date()))();
    const only = this.deps.organizationIds;
    const [row] = await this.deps.writer.$queryRaw<Array<{ oldest: Date | null }>>`
      SELECT MIN(t) AS oldest FROM (
        SELECT MIN(verify_requested_at) AS t FROM provider_connection_grants
         WHERE status = 'verifying' ${orgFilter('organization_id', only)}
        UNION ALL
        SELECT MIN(created_at) AS t FROM provider_validation_runs
         WHERE status = 'queued' ${orgFilter('organization_id', only)}
        UNION ALL
        SELECT MIN(created_at) AS t FROM domain_verifications
         WHERE method = 'provider_tenant' AND status = 'pending' AND provider_checked_at IS NULL
           ${orgFilter('organization_id', only)}
      ) pending`;
    const lag = row?.oldest
      ? Math.max(0, (now.getTime() - new Date(row.oldest).getTime()) / 1000)
      : 0;
    this.deps.metrics.taskLag.set(lag);
    return lag;
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    for (const loop of this.loops) loop.start();
  }

  async stop(): Promise<void> {
    if (!this.started) return;
    this.started = false;
    this.abort.abort();
    await Promise.all(this.loops.map((l) => l.stop()));
  }
}
