import {
  ConflictException,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { type AuditActor, AuditService, SYSTEM_ACTOR } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { KeyValueStore } from '../../../kv/key-value-store';
import type { ClientContext } from '../../auth/services/session.service';
import {
  type CheckOutcomeSummary,
  ownershipIntent,
  planReportApplication,
  reportApplies,
  type StoredDomainState,
} from '../domain/apply-report';
import { PUBLISHED_KEY_STATUSES } from '../domain/dkim-rotation';
import {
  defaultJitter,
  type Jitter,
  type ScheduleConfig,
  scheduleConfigFrom,
} from '../domain/schedule';
import { nextStatus } from '../domain/state-machine';
import { toStatusView } from '../domain.mapper';
import {
  DAY_MS,
  DomainAuditAction,
  domainKvKeys,
  FIRST_CHECK_DELAY_SECONDS,
  VERIFY_LIMIT_PER_WINDOW,
  VERIFY_WINDOW_SECONDS,
} from '../domains.constants';
import {
  domainNotFound,
  TooManyVerificationsException,
  VERIFICATION_IN_PROGRESS,
} from '../domains.errors';
import type { DomainStatusView } from '../dto/domains.schemas';
import { DomainDnsChecker } from '../engine/domain-dns-checker';
import { type GatewayDnsConfig, gatewayDnsConfigFrom } from '../engine/gateway-dns-config';
import type { DomainCheckReport } from '../engine/types';
import { generateVerificationToken, verificationRecord } from '../engine/verification';
import { DkimKeysRepository } from '../repositories/dkim-keys.repository';
import { DnsRecordsRepository } from '../repositories/dns-records.repository';
import { DomainOwnershipRepository } from '../repositories/domain-ownership.repository';
import {
  type DomainRow,
  DomainsRepository,
  isUniqueViolation,
  isWriteConflict,
} from '../repositories/domains.repository';
import { MxObservationsRepository } from '../repositories/mx-observations.repository';
import { VerificationsRepository } from '../repositories/verifications.repository';
import { acquireCheckLock, releaseCheckLock } from './check-lock';
import { DomainConfigurationService } from './domain-configuration.service';
import { DomainEventsService } from './domain-events.service';

type Client = Prisma.TransactionClient;

export type DomainVerificationConfig = Pick<
  ApiConfig,
  | 'GATEWAY_MX_HOSTS'
  | 'GATEWAY_SPF_INCLUDE'
  | 'GATEWAY_DMARC_RUA'
  | 'GATEWAY_DMARC_RUF'
  | 'DOMAIN_VERIFICATION_LABEL'
  | 'DOMAIN_VERIFICATION_TTL_DAYS'
  | 'DOMAIN_RETRY_BASE_SECONDS'
  | 'DOMAIN_RETRY_MAX_SECONDS'
  | 'DOMAIN_RECHECK_INCOMPLETE_SECONDS'
  | 'DOMAIN_RECHECK_INTERVAL_SECONDS'
  | 'DKIM_ROTATION_OVERLAP_DAYS'
>;

/** Who triggered a check and how. */
export interface CheckOptions {
  /** User-triggered checks skip DNS cache reads. */
  bypassCache: boolean;
  actor: AuditActor;
  sourceIp: string | null;
  /** Time of the check (tests and the scheduler pass their tick time). */
  now?: Date;
}

export type CheckResult = CheckOutcomeSummary | 'skipped';

/** Jitter source of the schedule; replaceable in tests (`{ provide: DOMAIN_SCHEDULE_JITTER }`). */
export const DOMAIN_SCHEDULE_JITTER = Symbol('DOMAIN_SCHEDULE_JITTER');

/**
 * Domain verification and DNS checks (D4, D10): manual verification (`POST /verify`), the check
 * the scheduler runs, and the persistence of a check report in one writer transaction with the
 * domain row locked — record results, the ownership race ("first to verify wins"), expiry, DKIM
 * key activation, audit rows and outbox events for transitions only.
 */
@Injectable()
export class DomainVerificationService {
  private readonly logger = new Logger(DomainVerificationService.name);
  private readonly gateway: GatewayDnsConfig;
  private readonly schedule: ScheduleConfig;

  constructor(
    @Inject(API_CONFIG) private readonly config: DomainVerificationConfig,
    @Inject(DOMAIN_SCHEDULE_JITTER) private readonly jitter: Jitter,
    private readonly kv: KeyValueStore,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly domains: DomainsRepository,
    private readonly verifications: VerificationsRepository,
    private readonly records: DnsRecordsRepository,
    private readonly keys: DkimKeysRepository,
    private readonly mx: MxObservationsRepository,
    private readonly ownership: DomainOwnershipRepository,
    private readonly events: DomainEventsService,
    private readonly configuration: DomainConfigurationService,
    private readonly checker: DomainDnsChecker,
  ) {
    this.gateway = gatewayDnsConfigFrom(config);
    this.schedule = scheduleConfigFrom(config);
  }

  /**
   * `POST /domains/{id}/verify` (§4): per-domain limit (6 per minute → `429` with
   * `Retry-After`), per-domain check lock (held → `409`), KV unavailable → `503`. A `failed`
   * domain is restarted first (D3). Runs a fresh check (cache bypassed) and returns the status
   * view; an indeterminate result is a `200` with the retry scheduled, never an error.
   */
  async verifyNow(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<DomainStatusView> {
    const domain = await this.domains.findByPublicId(scope, publicId);
    if (!domain) throw domainNotFound();

    const counterKey = domainKvKeys.verifyCounter(domain.id);
    let lock;
    try {
      const count = await this.kv.incrWithTtl(counterKey, VERIFY_WINDOW_SECONDS);
      if (count > VERIFY_LIMIT_PER_WINDOW) {
        const ttl = await this.kv.ttl(counterKey);
        throw new TooManyVerificationsException(ttl > 0 ? ttl : VERIFY_WINDOW_SECONDS);
      }
      lock = await acquireCheckLock(this.kv, domain.id);
    } catch (err) {
      if (err instanceof TooManyVerificationsException) throw err;
      this.logger.error({ message: 'Domain verification store unavailable', err });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (!lock) throw new ConflictException(VERIFICATION_IN_PROGRESS);

    try {
      const actor = this.audit.actorFrom(principal);
      if (domain.status === 'failed') {
        await this.restart(scope, domain.id, actor, client.ip, new Date());
      }
      await this.runCheck(scope, domain.id, {
        bypassCache: true,
        actor,
        sourceIp: client.ip,
      });
    } finally {
      await releaseCheckLock(this.kv, lock);
    }
    return this.statusView(scope, publicId);
  }

  /** `GET /domains/{id}/status`: the stored state, no DNS lookups. */
  async statusView(scope: TenantScope, publicId: string): Promise<DomainStatusView> {
    const domain = await this.domains.findByPublicId(scope, publicId);
    if (!domain) throw domainNotFound();
    const [records, dkimKeys, mx] = await Promise.all([
      this.records.listForDomain(scope, domain.id),
      this.keys.listForDomain(scope, domain.id),
      this.mx.list(scope, domain.id),
    ]);
    return toStatusView({ domain, records, dkimKeys, mx, gateway: this.gateway });
  }

  /**
   * One check of a domain: configuration pass (D12), DNS check, persistence. The caller holds
   * the per-domain check lock. `skipped` when the domain is gone or not in a checked status.
   */
  async runCheck(
    scope: TenantScope,
    domainId: bigint,
    options: CheckOptions,
  ): Promise<CheckResult> {
    await this.configuration.ensure(scope, domainId, options.now);
    const domain = await this.domains.findById(scope, domainId);
    if (!domain) return 'skipped';
    if (!reportApplies(domain.status)) {
      return this.transactions.run((tx) => this.skip(tx, scope, domain.id));
    }
    const [verification, keys] = await Promise.all([
      this.verifications.findCurrent(scope, domain.id),
      this.keys.listForDomain(scope, domain.id),
    ]);
    const ownershipRecord = verification
      ? verificationRecord(domain.name, verification.token, this.gateway.verificationLabel)
      : null;
    const report = await this.checker.check(
      {
        domain: domain.name,
        verification: ownershipRecord
          ? { host: ownershipRecord.host, expectedValue: ownershipRecord.value }
          : null,
        dkimKeys: keys
          .filter((k) => PUBLISHED_KEY_STATUSES.has(k.status))
          .map((k) => ({
            selector: k.selector,
            algorithm: k.algorithm,
            publicKeyDns: k.publicKey,
          })),
        gateway: this.gateway,
      },
      { bypassCache: options.bypassCache },
    );
    return this.applyReport(scope, domainId, report, options);
  }

  /**
   * Persists a check report (D10) in one writer transaction with the domain row locked. A
   * concurrent winner of the same name surfaces as a unique violation on `verified_name` (or a
   * deadlock between the two claim transactions): the whole transaction is retried once and
   * then lands in the "owned elsewhere" branch (D4).
   */
  async applyReport(
    scope: TenantScope,
    domainId: bigint,
    report: DomainCheckReport,
    options: Omit<CheckOptions, 'bypassCache'>,
  ): Promise<CheckResult> {
    const now = options.now ?? new Date();
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.transactions.run((tx) =>
          this.applyInTransaction(tx, scope, domainId, report, { ...options, now }),
        );
      } catch (err) {
        if (attempt === 0 && (isUniqueViolation(err) || isWriteConflict(err))) continue;
        throw err;
      }
    }
  }

  private async applyInTransaction(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    report: DomainCheckReport,
    options: Omit<CheckOptions, 'bypassCache'> & { now: Date },
  ): Promise<CheckResult> {
    const { now } = options;
    const domain = await this.domains.lockById(tx, scope, domainId);
    if (!domain) return 'skipped';
    if (!reportApplies(domain.status)) return this.skip(tx, scope, domain.id, domain);

    const [verification, records, dkimKeys] = await Promise.all([
      this.verifications.findCurrent(scope, domain.id, tx),
      this.records.listForDomain(scope, domain.id, tx),
      this.keys.listForDomain(scope, domain.id, tx),
    ]);
    const state: StoredDomainState = { domain, verification, records, dkimKeys };

    let ownership: 'won' | 'lost' | undefined;
    if (ownershipIntent(state, report, now) === 'claim') {
      const owner = await this.ownership.findVerifiedOwner(tx, domain.name);
      ownership = owner && owner.id !== domain.id ? 'lost' : 'won';
    }
    const plan = planReportApplication(state, report, {
      now,
      ownership,
      schedule: this.schedule,
      overlapDays: this.config.DKIM_ROTATION_OVERLAP_DAYS,
      jitter: this.jitter,
    });

    for (const update of plan.records) {
      await this.records.writeResult(tx, scope, update.id, update.data);
    }
    if (plan.verification) {
      await this.verifications.update(tx, scope, plan.verification.id, plan.verification.data);
    }
    if (plan.mxObservations) {
      const gatewayHosts = new Set(this.gateway.mxHosts.map((h) => h.host));
      await this.mx.replace(
        tx,
        scope,
        domain.id,
        plan.mxObservations.map((answer) => ({
          priority: answer.priority,
          host: answer.exchange === '' ? '.' : answer.exchange,
          pointsToGateway: gatewayHosts.has(answer.exchange),
        })),
        now,
      );
    }
    for (const change of plan.keyChanges) {
      if (change.to === 'rotating') {
        await this.keys.startRotating(tx, scope, change.keyId, change.retireAfter!);
      } else {
        await this.keys.activate(tx, scope, change.keyId, now);
      }
    }
    // A concurrent winner makes this update fail on the verified_name unique key (D4).
    await this.domains.update(tx, scope, domain.id, plan.domain);

    const ref = { id: domain.id, publicId: domain.publicId, name: domain.name };
    if (plan.transition) {
      await this.events.transition(tx, {
        organizationId: scope.organizationId,
        domain: ref,
        from: plan.transition.from,
        to: plan.transition.to,
        reason: plan.transition.reason,
        action: plan.transition.auditAction,
        actor: options.actor,
        sourceIp: options.sourceIp,
        at: now,
      });
      if (plan.transition.to === 'verified') {
        await this.supersedeOtherClaims(tx, domain, now);
      }
    }
    for (const activation of plan.keyActivations) {
      await this.events.record(tx, {
        organizationId: scope.organizationId,
        domain: ref,
        action: DomainAuditAction.DkimKeyActivated,
        actor: options.actor,
        sourceIp: options.sourceIp,
        metadata: { ...activation },
      });
    }
    if (plan.ownershipRecordMissing) {
      await this.events.record(tx, {
        organizationId: scope.organizationId,
        domain: ref,
        action: DomainAuditAction.OwnershipRecordMissing,
        actor: options.actor,
        sourceIp: options.sourceIp,
        metadata: { recordPurpose: 'verification', outcome: plan.ownershipRecordMissing.outcome },
      });
    }
    return plan.outcome;
  }

  /** D4: every other organization's pending claim on the name fails (system actor). */
  private async supersedeOtherClaims(tx: Client, winner: DomainRow, now: Date): Promise<void> {
    const superseded = await this.ownership.supersedePendingClaims(tx, winner.name, winner.id, now);
    for (const claim of superseded) {
      await this.events.transition(tx, {
        organizationId: claim.organizationId,
        domain: { id: claim.domainId, publicId: claim.domainPublicId, name: winner.name },
        from: 'pending_verification',
        to: 'failed',
        reason: 'claimed_by_another_organization',
        action: DomainAuditAction.ClaimSuperseded,
        actor: SYSTEM_ACTOR,
        at: now,
      });
    }
  }

  /** A domain that is not checked any more: make sure the scheduler stops picking it up. */
  private async skip(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    locked?: DomainRow,
  ): Promise<CheckResult> {
    const domain = locked ?? (await this.domains.lockById(tx, scope, domainId));
    if (domain && domain.nextCheckAt !== null && !reportApplies(domain.status)) {
      await this.domains.update(tx, scope, domain.id, { nextCheckAt: null });
    }
    return 'skipped';
  }

  /**
   * `failed → pending_verification` (D3): a new verification row with the same token (a record
   * that is already published keeps working) and a new expiry; audit and event.
   */
  private async restart(
    scope: TenantScope,
    domainId: bigint,
    actor: AuditActor,
    sourceIp: string | null,
    now: Date,
  ): Promise<void> {
    await this.transactions.run(async (tx) => {
      const domain = await this.domains.lockById(tx, scope, domainId);
      if (!domain || domain.status !== 'failed') return;
      const to = nextStatus(domain.status, 'verification_restarted');
      const previous = await this.verifications.findCurrent(scope, domain.id, tx);
      const nextCheckAt = new Date(now.getTime() + FIRST_CHECK_DELAY_SECONDS * 1000);
      await this.verifications.create(tx, scope, {
        domainId: domain.id,
        token: previous?.token ?? generateVerificationToken(),
        status: 'pending',
        expiresAt: new Date(now.getTime() + this.config.DOMAIN_VERIFICATION_TTL_DAYS * DAY_MS),
        nextCheckAt,
      });
      await this.domains.update(tx, scope, domain.id, {
        status: to,
        statusReason: null,
        statusChangedAt: now,
        checkFailures: 0,
        nextCheckAt,
      });
      await this.events.transition(tx, {
        organizationId: scope.organizationId,
        domain: { id: domain.id, publicId: domain.publicId, name: domain.name },
        from: domain.status,
        to,
        reason: null,
        action: DomainAuditAction.VerificationRestarted,
        actor,
        sourceIp,
        at: now,
      });
    });
  }
}

/** Provider of the production jitter (±10 %, D11). */
export const domainScheduleJitterProvider = {
  provide: DOMAIN_SCHEDULE_JITTER,
  useValue: defaultJitter,
};
