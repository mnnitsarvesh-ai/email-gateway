import { Inject, Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService, SYSTEM_ACTOR } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { KeyValueStore } from '../../../kv/key-value-store';
import type { ClientContext } from '../../auth/services/session.service';
import { planRotation } from '../domain/dkim-rotation';
import { toDkimKeyView, toDnsRecordView } from '../domain.mapper';
import {
  DomainAuditAction,
  domainKvKeys,
  RETIREMENT_BATCH_SIZE,
  ROTATE_LIMIT_PER_WINDOW,
  ROTATE_WINDOW_SECONDS,
} from '../domains.constants';
import { domainNotFound, TooManyRotationsException } from '../domains.errors';
import type { RotateDkimInput, RotateDkimResponse } from '../dto/domains.schemas';
import { generateDkimKeyPair } from '../engine/dkim';
import { DkimKeysRepository } from '../repositories/dkim-keys.repository';
import { DnsRecordsRepository } from '../repositories/dns-records.repository';
import { DomainJobsRepository } from '../repositories/domain-jobs.repository';
import { DomainsRepository } from '../repositories/domains.repository';
import { VerificationsRepository } from '../repositories/verifications.repository';
import { DomainConfigurationService } from './domain-configuration.service';
import { DomainEventsService } from './domain-events.service';

export type DkimRotationConfig = Pick<ApiConfig, 'DKIM_ROTATION_OVERLAP_DAYS'>;

/**
 * DKIM key rotation and retirement (D9, ADR-0018). Rotation creates a new pending key whose
 * record the customer publishes; the check activates it once the record is valid and moves the
 * previous key to `rotating` for the overlap; the scheduler retires rotating keys afterwards.
 */
@Injectable()
export class DkimRotationService {
  private readonly logger = new Logger(DkimRotationService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: DkimRotationConfig,
    private readonly kv: KeyValueStore,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly domains: DomainsRepository,
    private readonly verifications: VerificationsRepository,
    private readonly records: DnsRecordsRepository,
    private readonly keys: DkimKeysRepository,
    private readonly jobs: DomainJobsRepository,
    private readonly configuration: DomainConfigurationService,
    private readonly events: DomainEventsService,
  ) {}

  /**
   * `POST /domains/{id}/dkim/rotate` (D9). Cheap checks first (domain in scope, rotation
   * rules, per-domain limit: 10 per 24 h → `429` with `Retry-After`, KV unavailable → `503`),
   * so unknown ids, foreign domains and refused rotations never pay for key generation. The key
   * is then generated outside the transaction, and the rules are re-evaluated under the domain
   * row lock: a pending key next to an active one → `409`; a family whose only key is pending
   * (never published) has it revoked and replaced; otherwise a new pending key joins the active
   * one. Returns the record to publish.
   */
  async rotate(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    input: RotateDkimInput,
    client: ClientContext,
  ): Promise<RotateDkimResponse> {
    const found = await this.domains.findByPublicId(scope, publicId);
    if (!found) throw domainNotFound();
    planRotation(found.status, await this.keys.listForDomain(scope, found.id), input.algorithm);
    await this.countRotation(found.id);

    // Key generation takes a while: never inside the transaction (D9).
    const pair = await generateDkimKeyPair(input.algorithm);
    const now = new Date();
    const { domain, selector, previousId } = await this.transactions.run(async (tx) => {
      const locked = await this.domains.lockByPublicId(tx, scope, publicId);
      if (!locked) throw domainNotFound();
      const keys = await this.keys.listForDomain(scope, locked.id, tx);
      const plan = planRotation(locked.status, keys, input.algorithm);
      if (plan.kind === 'replace_pending') {
        await this.keys.revoke(tx, scope, [plan.previous.id]);
      }
      const created = await this.configuration.insertKey(tx, scope, locked, pair, keys, now);
      const current = await this.keys.listForDomain(scope, locked.id, tx);
      const verification = await this.verifications.findCurrent(scope, locked.id, tx);
      await this.configuration.syncRecords(tx, scope, locked, verification?.token ?? null, current);
      await this.events.record(tx, {
        organizationId: scope.organizationId,
        domain: locked,
        action: DomainAuditAction.DkimRotationStarted,
        actor: this.audit.actorFrom(principal),
        sourceIp: client.ip,
        metadata: {
          algorithm: input.algorithm,
          selector: created.selector,
          previousSelector: plan.previous?.selector ?? null,
          replacedPending: plan.kind === 'replace_pending',
        },
      });
      return { domain: locked, selector: created.selector, previousId: plan.previous?.id ?? null };
    });

    const [keys, records] = await Promise.all([
      this.keys.listForDomain(scope, domain.id),
      this.records.listForDomain(scope, domain.id),
    ]);
    const key = keys.find((k) => k.selector === selector)!;
    const previous = previousId === null ? null : (keys.find((k) => k.id === previousId) ?? null);
    const record = records.find((r) => r.recordKey === `dkim:${selector}`)!;
    return {
      domainId: domain.publicId,
      key: toDkimKeyView(key, domain.name),
      previous: previous ? toDkimKeyView(previous, domain.name) : null,
      dnsRecord: toDnsRecordView(record, domain.name),
      overlapDays: this.config.DKIM_ROTATION_OVERLAP_DAYS,
    };
  }

  /** Per-domain rotation counter (§4, D9): over the limit `429`, store unavailable `503`. */
  private async countRotation(domainId: bigint): Promise<void> {
    const key = domainKvKeys.rotateCounter(domainId);
    try {
      const count = await this.kv.incrWithTtl(key, ROTATE_WINDOW_SECONDS);
      if (count <= ROTATE_LIMIT_PER_WINDOW) return;
      const ttl = await this.kv.ttl(key);
      throw new TooManyRotationsException(ttl > 0 ? ttl : ROTATE_WINDOW_SECONDS);
    } catch (err) {
      if (err instanceof TooManyRotationsException) throw err;
      this.logger.error({ message: 'DKIM rotation store unavailable', err });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
  }

  /**
   * Retires rotating keys whose overlap ended (D9, scheduler step 4): status `retired`,
   * `retired_at`, ciphertext cleared, record row deleted, audit `domain.dkim_key_retired`.
   * One transaction per key with the domain row locked; per-key errors are logged and skipped.
   */
  async retireDue(now: Date = new Date()): Promise<number> {
    const due = await this.jobs.findKeysDueForRetirement(now, RETIREMENT_BATCH_SIZE);
    let retired = 0;
    for (const item of due) {
      try {
        const done = await this.transactions.run(async (tx) => {
          const scope = systemScope(item.organizationId);
          const domain = await this.domains.lockById(tx, scope, item.domainId);
          if (!domain) return false;
          const key = (await this.keys.listForDomain(scope, domain.id, tx)).find(
            (k) => k.id === item.keyId,
          );
          if (!key || !(await this.keys.retire(tx, scope, key.id, now))) return false;
          await this.records.deleteByKeys(tx, scope, domain.id, [`dkim:${key.selector}`]);
          await this.events.record(tx, {
            organizationId: scope.organizationId,
            domain,
            action: DomainAuditAction.DkimKeyRetired,
            actor: SYSTEM_ACTOR,
            metadata: { selector: key.selector, algorithm: key.algorithm },
          });
          return true;
        });
        if (done) retired++;
      } catch (err) {
        this.logger.error({
          message: 'DKIM key retirement failed',
          domainId: item.domainId.toString(),
          err,
        });
      }
    }
    return retired;
  }
}
