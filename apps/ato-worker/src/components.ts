import {
  atoIncidentHandler,
  AtoStore,
  AtoWindows,
  type IdentityProviderAdapter,
  type ProviderRegistry,
} from '@email-gateway/ato-detection';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { IncidentCategoryRegistry, IncidentStore } from '@email-gateway/security-incidents';
import type { RestrictedResolver } from '@email-gateway/url-security';
import type { Redis } from 'ioredis';
import { hasRole, type WorkerConfig } from './config';
import { AccountChangeHandler } from './detect/account-change.handler';
import { AtoEventsConsumer, AtoMailConsumer } from './detect/consumers';
import type { DetectDeps } from './detect/context';
import { LoginHandler } from './detect/login.handler';
import { MailHandler } from './detect/mail.handler';
import { DetectionPipeline, WorkerCapabilities } from './detect/pipeline';
import { SmtpHandler } from './detect/smtp.handler';
import { Enricher } from './enrichment/enricher';
import { AtoGeoIp } from './enrichment/geoip';
import { MeteredRedis, type IoRedisLike } from './enrichment/redis';
import { createAtoReputation, type AtoReputation } from './enrichment/reputation';
import { AtoMaintenance } from './maintenance/jobs';
import type { AtoMetrics } from './metrics/ato-metrics';
import { ProviderContextCache } from './provider/provider-context';
import { createProviderRegistry } from './provider/registry';
import { ProviderRunner } from './provider/runner';
import { OrgContextCache } from './reads/org-context';
import { RespondConsumer } from './respond/respond.consumer';
import { AtoDb } from './shared/db';
import { LeaderJob, Periodic, type LeaderLock } from './shared/loops';

export interface ComponentDeps {
  prisma: PrismaClient;
  /** The ioredis client of `REDIS_URL` (Nest `RedisService.client`). */
  redis: Redis;
  locks: LeaderLock;
  metrics: AtoMetrics | null;
  logger: Logger;
  now?: () => Date;
  /** Restricts every consumer and job to these organizations (integration suites). */
  organizationIds?: readonly bigint[];
  /** Test seams: a scripted fake adapter instance, a DNS resolver for the DNSBL zones. */
  fakeAdapter?: IdentityProviderAdapter;
  resolver?: RestrictedResolver;
  /** Per-run lock name prefix (integration suites run beside a paused live worker). */
  lockPrefix?: string;
  /** TEST SEAM: a synthetic organization acting as the platform organization (D5, D21). */
  platformOrganizationId?: bigint;
}

/** Leader lock names of the maintenance jobs (`GET_LOCK('eg:ato:<job>')`, D3). */
export const MAINTENANCE_JOBS = [
  'mail-catchup',
  'decay',
  'baselines',
  'expiry',
  'confirm',
  'digests',
  'retention',
  'retirement',
  'status',
] as const;
export type MaintenanceJob = (typeof MAINTENANCE_JOBS)[number];

/**
 * Every component of the ato-worker (D3), built once per process and started per role: `detect`
 * (the `ato.events` and `ato.mail` handlers), `respond` (the `ato.responses` handler),
 * `maintenance` (leader-elected jobs) and `provider` (the ingestion runner). GeoIP reloads and the
 * capability refresh run on every replica.
 */
export class AtoComponents {
  readonly db: AtoDb;
  readonly orgs: OrgContextCache;
  readonly store: AtoStore;
  readonly incidents: IncidentStore;
  readonly windows: AtoWindows;
  readonly redis: MeteredRedis;
  readonly enricher: Enricher;
  readonly capabilities: WorkerCapabilities;
  readonly providers: ProviderContextCache;
  readonly pipeline: DetectionPipeline;
  readonly detectDeps: DetectDeps;
  readonly login: LoginHandler;
  readonly accountChange: AccountChangeHandler;
  readonly smtp: SmtpHandler;
  readonly mail: MailHandler;
  readonly eventsConsumer: AtoEventsConsumer;
  readonly mailConsumer: AtoMailConsumer;
  readonly respond: RespondConsumer;
  readonly maintenance: AtoMaintenance;
  readonly runner: ProviderRunner;
  readonly jobs: Map<MaintenanceJob, LeaderJob>;
  private readonly periodics: Periodic[] = [];
  private readonly roleJobs: LeaderJob[] = [];
  private providerLoop: Periodic | null = null;

  private constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly deps: ComponentDeps,
    readonly geo: AtoGeoIp,
    readonly reputation: AtoReputation,
    readonly registry: ProviderRegistry,
  ) {
    const now = deps.now ?? (() => new Date());
    const { prisma, metrics, logger } = deps;
    this.db = new AtoDb(prisma, config.ATO_TX_TIMEOUT_MS);
    const ttlMs = config.ATO_SETTINGS_CACHE_SECONDS * 1000;
    this.orgs = new OrgContextCache(prisma, ttlMs, now, 10_000, deps.platformOrganizationId);
    // The ATO store and the incident store need each other (the handler's false-positive hook).
    // eslint-disable-next-line prefer-const
    let store: AtoStore;
    this.incidents = new IncidentStore({
      registry: new IncidentCategoryRegistry([atoIncidentHandler({ store: () => store })]),
      now,
    });
    store = new AtoStore({
      now,
      incidents: this.incidents,
      config: {
        approvalTtlHours: config.ATO_APPROVAL_TTL_HOURS,
        automatedResponsesEnabled: config.ATO_AUTOMATED_RESPONSES_ENABLED,
        maxAutomatedPerOrgPerHour: config.ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR,
        maxActiveRestrictionsPerOrg: config.ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG,
      },
    });
    this.store = store;
    // ioredis' overloads are wider than the subset the windows use.
    this.redis = new MeteredRedis(deps.redis as unknown as IoRedisLike, metrics);
    this.windows = new AtoWindows(this.redis, { hmacKey: config.ATO_HMAC_KEY });
    this.enricher = new Enricher(geo, reputation, this.windows, this.redis, prisma, {
      allowDocumentationRanges: config.ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES,
      now,
    });
    this.capabilities = new WorkerCapabilities(geo, reputation);
    this.providers = new ProviderContextCache(prisma, registry, ttlMs, now);
    this.pipeline = new DetectionPipeline({
      store,
      windows: this.windows,
      enricher: this.enricher,
      capabilities: this.capabilities,
      providers: this.providers,
      metrics,
      logger,
      now,
    });
    this.detectDeps = {
      db: this.db,
      prisma,
      orgs: this.orgs,
      store,
      windows: this.windows,
      enricher: this.enricher,
      pipeline: this.pipeline,
      metrics,
      logger,
      now,
      hmacKey: config.ATO_HMAC_KEY,
      campaign: {
        windowMinutes: config.ATO_IP_CAMPAIGN_WINDOW_MINUTES,
        minAccounts: config.ATO_IP_CAMPAIGN_MIN_ACCOUNTS,
        flagHours: config.ATO_IP_CAMPAIGN_FLAG_HOURS,
      },
      allowDocumentationRanges: config.ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES,
      ...(deps.organizationIds !== undefined && { organizationIds: deps.organizationIds }),
    };
    this.login = new LoginHandler(this.detectDeps, this.pipeline);
    this.accountChange = new AccountChangeHandler(this.detectDeps, this.pipeline);
    this.smtp = new SmtpHandler(this.detectDeps, this.pipeline);
    this.mail = new MailHandler(this.detectDeps, this.pipeline);
    this.eventsConsumer = new AtoEventsConsumer(
      { login: this.login, accountChange: this.accountChange, smtp: this.smtp },
      metrics,
      logger,
      deps.organizationIds,
    );
    this.mailConsumer = new AtoMailConsumer(this.mail, metrics, logger, deps.organizationIds);
    this.respond = new RespondConsumer({
      db: this.db,
      prisma,
      store,
      registry,
      metrics,
      logger,
      ...(deps.organizationIds !== undefined && { organizationIds: deps.organizationIds }),
    });
    this.maintenance = new AtoMaintenance({
      db: this.db,
      prisma,
      store,
      orgs: this.orgs,
      mail: this.mail,
      registry,
      geo,
      reputation,
      capabilities: this.capabilities,
      metrics,
      logger,
      now,
      config: {
        mailCatchupLagSeconds: config.ATO_MAIL_CATCHUP_LAG_SECONDS,
        mailCatchupBatch: config.ATO_MAIL_CATCHUP_BATCH,
        mailCatchupMaxAgeHours: config.ATO_MAIL_CATCHUP_MAX_AGE_HOURS,
        decayIntervalSeconds: config.ATO_DECAY_SWEEP_INTERVAL_SECONDS,
        baselineRebuildHourUtc: config.ATO_BASELINE_REBUILD_HOUR_UTC,
        baselineBatch: config.ATO_BASELINE_BATCH,
        retentionIncidentDays: config.ATO_RETENTION_INCIDENT_DAYS,
        digestEnabled: config.ATO_DIGEST_ENABLED,
      },
      ...(deps.organizationIds !== undefined && { organizationIds: deps.organizationIds }),
    });
    this.runner = new ProviderRunner({
      ...this.detectDeps,
      pipelineRef: this.pipeline,
      registry,
      store,
      metrics,
      logger,
      config: {
        pollIntervalSeconds: config.ATO_PROVIDER_POLL_INTERVAL_SECONDS,
        maxPagesPerPoll: config.ATO_PROVIDER_MAX_PAGES_PER_POLL,
        maxConsecutiveFailures: config.ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES,
      },
    });

    const maintenanceMs = config.ATO_MAINTENANCE_INTERVAL_SECONDS * 1000;
    const intervals: Record<MaintenanceJob, number> = {
      'mail-catchup': config.ATO_MAIL_CATCHUP_INTERVAL_SECONDS * 1000,
      decay: config.ATO_DECAY_SWEEP_INTERVAL_SECONDS * 1000,
      baselines: maintenanceMs,
      expiry: maintenanceMs,
      confirm: maintenanceMs,
      digests: maintenanceMs,
      retention: maintenanceMs,
      retirement: Math.max(maintenanceMs, 3_600_000),
      status: maintenanceMs,
    };
    const tasks: Record<MaintenanceJob, () => Promise<boolean>> = {
      'mail-catchup': () => this.maintenance.mailCatchup(),
      decay: () => this.maintenance.decaySweep(),
      baselines: () => this.maintenance.baselineRebuild(),
      expiry: () => this.maintenance.expiry(),
      confirm: () => this.maintenance.providerConfirmations(),
      digests: () => this.maintenance.digests(),
      retention: () => this.maintenance.retention(),
      retirement: () => this.maintenance.retirement(),
      status: () => this.maintenance.status(),
    };
    const prefix = deps.lockPrefix ?? 'eg:ato:';
    this.jobs = new Map(
      MAINTENANCE_JOBS.map((job) => [
        job,
        new LeaderJob(
          job,
          `${prefix}${job}`,
          intervals[job],
          async () => {
            try {
              const more = await tasks[job]();
              metrics?.maintenanceRuns.inc({ job, result: 'ok' });
              return more;
            } catch (error) {
              metrics?.maintenanceRuns.inc({ job, result: 'error' });
              throw error;
            }
          },
          {
            locks: deps.locks,
            logger,
            onLeadership: (leader) => metrics?.leader.set({ job }, leader ? 1 : 0),
          },
        ),
      ]),
    );
  }

  static async create(config: Readonly<WorkerConfig>, deps: ComponentDeps): Promise<AtoComponents> {
    const geo = await AtoGeoIp.open(config, deps.metrics, deps.now);
    const reputation = createAtoReputation(config, {
      prisma: deps.prisma,
      redis: deps.redis,
      metrics: deps.metrics,
      ...(deps.now ? { now: deps.now } : {}),
      ...(deps.resolver ? { resolver: deps.resolver } : {}),
    });
    const registry = createProviderRegistry(config, deps.fakeAdapter);
    return new AtoComponents(config, deps, geo, reputation, registry);
  }

  /** Starts the periodic work of this process's roles (consumers are started by the module). */
  async start(): Promise<void> {
    const { config, deps } = this;
    const capabilityRefresh = async () => {
      this.capabilities.breachIndicators = await this.maintenance.breachIndicatorCount(
        (deps.now ?? (() => new Date()))(),
      );
    };
    await capabilityRefresh().catch(() => undefined);
    this.periodics.push(
      new Periodic(
        'geoip-reload',
        config.ATO_GEOIP_RELOAD_SECONDS * 1000,
        async () => {
          await this.geo.reload();
        },
        deps.logger,
      ),
      new Periodic('capability-refresh', 300_000, capabilityRefresh, deps.logger),
    );
    if (hasRole(config, 'maintenance')) {
      for (const job of this.jobs.values()) this.roleJobs.push(job);
    }
    if (hasRole(config, 'provider')) {
      this.providerLoop = new Periodic(
        'provider-runner',
        Math.max(10_000, Math.min(60_000, config.ATO_PROVIDER_POLL_INTERVAL_SECONDS * 1000)),
        () => this.runner.runOnce(),
        deps.logger,
      );
      this.periodics.push(this.providerLoop);
    }
    for (const p of this.periodics) p.start();
    for (const j of this.roleJobs) j.start();
  }

  async stop(): Promise<void> {
    await Promise.all([
      ...this.periodics.map((p) => p.stop()),
      ...this.roleJobs.map((j) => j.stop()),
    ]);
  }
}
