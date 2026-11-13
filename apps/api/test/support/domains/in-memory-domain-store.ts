/**
 * In-memory stand-ins for the domains module's repositories (unit tests of the services). They
 * follow the repositories' contracts — tenant filtering by scope, conditional updates, the
 * `verified_name` / `live_name` unique keys (raising Prisma's `P2002`) — without transactions:
 * the fake `TransactionRunner` runs the callback directly and nothing is rolled back.
 */
import { randomUUID } from 'node:crypto';
import { ConflictException } from '@nestjs/common';
import {
  type DkimAlgorithm,
  type DnsRecordPurpose,
  type DomainStatus,
  type OrganizationStatus,
  Prisma,
} from '@email-gateway/database';
import type { AuditEntry, AuditService } from '../../../src/audit/audit.service';
import { AuditService as RealAuditService } from '../../../src/audit/audit.service';
import type { TenantScope } from '../../../src/auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../src/database/transaction-runner';
import type { OrganizationLimitsService } from '../../../src/tenancy/organization-limits.service';
import type {
  DkimKeyRow,
  DkimKeysRepository,
} from '../../../src/modules/domains/repositories/dkim-keys.repository';
import type {
  DnsRecordDefinition,
  DnsRecordResultWrite,
  DnsRecordRow,
  DnsRecordsRepository,
} from '../../../src/modules/domains/repositories/dns-records.repository';
import type {
  DomainJobsRepository,
  DueDomain,
  RetirableKey,
} from '../../../src/modules/domains/repositories/domain-jobs.repository';
import type { DomainOutboxRepository } from '../../../src/modules/domains/repositories/domain-outbox.repository';
import type {
  DomainOwnershipRepository,
  SupersededClaim,
} from '../../../src/modules/domains/repositories/domain-ownership.repository';
import type {
  DomainListFilter,
  DomainRow,
  DomainsRepository,
  DomainWrite,
  ListWindow,
} from '../../../src/modules/domains/repositories/domains.repository';
import type {
  MxObservation,
  MxObservationRow,
  MxObservationsRepository,
} from '../../../src/modules/domains/repositories/mx-observations.repository';
import type {
  VerificationRow,
  VerificationsRepository,
  VerificationWrite,
} from '../../../src/modules/domains/repositories/verifications.repository';
import {
  type DomainDnsRecordsChangedV1,
  domainDnsRecordsChangedV1,
  type DomainStatusChangedV1,
} from '@email-gateway/event-contracts';

const OWNED: ReadonlySet<DomainStatus> = new Set(['verified', 'active', 'suspended']);

type StoredVerification = VerificationRow & { organizationId: bigint; evidence: unknown };
type StoredRecord = DnsRecordRow & { organizationId: bigint };
type StoredKey = DkimKeyRow & { organizationId: bigint; privateKeyCiphertext: string | null };
type StoredMx = MxObservationRow & { organizationId: bigint; domainId: bigint };

export interface OutboxRow {
  organizationId: bigint;
  correlationId: string;
  payload: DomainStatusChangedV1;
}

/** A `domain.dns.records_changed.v1` outbox row (step 6.2 §4.1), kept apart from `outbox`. */
export interface RecordsChangedRow {
  organizationId: bigint;
  correlationId: string;
  payload: DomainDnsRecordsChangedV1;
}

const clone = <T>(value: T): T => structuredClone(value);

function uniqueViolation(target: string): Prisma.PrismaClientKnownRequestError {
  return new Prisma.PrismaClientKnownRequestError(`Unique constraint failed: ${target}`, {
    code: 'P2002',
    clientVersion: 'test',
  });
}

export class InMemoryDomainStore {
  domains: DomainRow[] = [];
  verifications: StoredVerification[] = [];
  records: StoredRecord[] = [];
  keys: StoredKey[] = [];
  mx: StoredMx[] = [];
  outbox: OutboxRow[] = [];
  recordsChanged: RecordsChangedRow[] = [];
  audits: AuditEntry[] = [];
  organizationStatus = new Map<bigint, OrganizationStatus>();
  /** `max_domains` per organization (absent = unlimited). */
  maxDomains = new Map<bigint, number>();
  /** Called before every domain update (inject concurrent writers or failures). */
  beforeDomainUpdate: ((id: bigint, data: DomainWrite) => void) | undefined;
  transactionCount = 0;
  private seq = 100n;

  nextId(): bigint {
    this.seq += 1n;
    return this.seq;
  }

  /** Adds a domain row directly (fixtures). */
  addDomain(organizationId: bigint, name: string, patch: Partial<DomainRow> = {}): DomainRow {
    const now = new Date();
    const row: DomainRow = {
      id: this.nextId(),
      publicId: randomUUID(),
      organizationId,
      name,
      status: 'pending_verification',
      statusReason: null,
      statusChangedAt: now,
      inboundEnabled: true,
      outboundEnabled: false,
      verifiedAt: null,
      activatedAt: null,
      deletedAt: null,
      nextCheckAt: null,
      lastCheckedAt: null,
      checkFailures: 0,
      createdAt: now,
      updatedAt: now,
      ...patch,
    };
    this.domains.push(row);
    return row;
  }

  domain(id: bigint): DomainRow {
    const row = this.domains.find((d) => d.id === id);
    if (!row) throw new Error(`no domain ${id}`);
    return row;
  }

  recordsOf(domainId: bigint): StoredRecord[] {
    return this.records.filter((r) => r.domainId === domainId);
  }

  keysOf(domainId: bigint): StoredKey[] {
    return this.keys.filter((k) => k.domainId === domainId);
  }

  verificationsOf(domainId: bigint): StoredVerification[] {
    return this.verifications.filter((v) => v.domainId === domainId);
  }

  private checkUniques(candidate: DomainRow): void {
    for (const other of this.domains) {
      if (other.id === candidate.id) continue;
      if (OWNED.has(candidate.status) && OWNED.has(other.status) && other.name === candidate.name) {
        throw uniqueViolation('domains_verified_name_key');
      }
      if (
        candidate.status !== 'deleted' &&
        other.status !== 'deleted' &&
        other.organizationId === candidate.organizationId &&
        other.name === candidate.name
      ) {
        throw uniqueViolation('domains_organization_id_live_name_key');
      }
    }
  }

  // ---- Fakes ---------------------------------------------------------------------------

  transactionRunner(): TransactionRunner {
    return {
      run: async <T>(fn: (tx: Prisma.TransactionClient) => Promise<T>) => {
        this.transactionCount++;
        return fn({} as Prisma.TransactionClient);
      },
    } as unknown as TransactionRunner;
  }

  auditService(): AuditService {
    const real = new RealAuditService({} as never);
    return {
      actorFrom: real.actorFrom.bind(real),
      record: (entry: AuditEntry) => {
        this.audits.push(clone(entry));
        return Promise.resolve();
      },
    } as unknown as AuditService;
  }

  limitsService(): OrganizationLimitsService {
    return {
      lockOrganization: () => Promise.resolve(),
      assertWithinLimit: (_tx: unknown, organizationId: bigint, key: string, count: number) => {
        const limit = this.maxDomains.get(organizationId);
        if (key === 'max_domains' && limit !== undefined && count >= limit) {
          return Promise.reject(new ConflictException(`Organization limit reached: ${key}`));
        }
        return Promise.resolve();
      },
    } as unknown as OrganizationLimitsService;
  }

  domainsRepository(): DomainsRepository {
    const visible = (scope: TenantScope, row: DomainRow) =>
      row.organizationId === scope.organizationId;
    return {
      findByPublicId: (scope: TenantScope, publicId: string) =>
        Promise.resolve(
          clone(
            this.domains.find(
              (d) => visible(scope, d) && d.publicId === publicId && d.status !== 'deleted',
            ) ?? null,
          ),
        ),
      findById: (scope: TenantScope, id: bigint) =>
        Promise.resolve(clone(this.domains.find((d) => visible(scope, d) && d.id === id) ?? null)),
      lockByPublicId: (_tx: unknown, scope: TenantScope, publicId: string) =>
        Promise.resolve(
          clone(
            this.domains.find(
              (d) => visible(scope, d) && d.publicId === publicId && d.status !== 'deleted',
            ) ?? null,
          ),
        ),
      lockById: (_tx: unknown, scope: TenantScope, id: bigint) =>
        Promise.resolve(clone(this.domains.find((d) => visible(scope, d) && d.id === id) ?? null)),
      list: (scope: TenantScope, filter: DomainListFilter, page: ListWindow) =>
        Promise.resolve(
          clone(
            this.domains
              .filter(
                (d) =>
                  visible(scope, d) &&
                  (filter.status ? d.status === filter.status : d.status !== 'deleted') &&
                  (filter.q === undefined || d.name.startsWith(filter.q)) &&
                  (page.beforeId === undefined || d.id < page.beforeId),
              )
              .sort((a, b) => (a.id > b.id ? -1 : 1))
              .slice(0, page.take),
          ),
        ),
      countLive: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          this.domains.filter((d) => visible(scope, d) && d.status !== 'deleted').length,
        ),
      existsLive: (_tx: unknown, scope: TenantScope, name: string) =>
        Promise.resolve(
          this.domains.some((d) => visible(scope, d) && d.name === name && d.status !== 'deleted'),
        ),
      create: (
        _tx: unknown,
        scope: TenantScope,
        data: { name: string; inboundEnabled: boolean; nextCheckAt: Date; now: Date },
      ) => {
        const row = this.addDomain(scope.organizationId, data.name, {
          inboundEnabled: data.inboundEnabled,
          nextCheckAt: data.nextCheckAt,
          statusChangedAt: data.now,
        });
        try {
          this.checkUniques(row);
        } catch (err) {
          this.domains.pop();
          throw err;
        }
        return Promise.resolve(clone(row));
      },
      update: (_tx: unknown, scope: TenantScope, id: bigint, data: DomainWrite) => {
        this.beforeDomainUpdate?.(id, data);
        const row = this.domains.find((d) => visible(scope, d) && d.id === id);
        if (!row) return Promise.resolve(false);
        const next = { ...row, ...data, updatedAt: new Date() };
        this.checkUniques(next);
        Object.assign(row, next);
        return Promise.resolve(true);
      },
    } as unknown as DomainsRepository;
  }

  verificationsRepository(): VerificationsRepository {
    return {
      findCurrent: (scope: TenantScope, domainId: bigint) =>
        Promise.resolve(
          clone(
            this.verifications
              .filter((v) => v.organizationId === scope.organizationId && v.domainId === domainId)
              .sort((a, b) => (a.id > b.id ? -1 : 1))[0] ?? null,
          ),
        ),
      create: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          domainId: bigint;
          token: string;
          status: VerificationRow['status'];
          expiresAt: Date;
          verifiedAt?: Date | null;
          nextCheckAt?: Date | null;
        },
      ) => {
        const row: StoredVerification = {
          id: this.nextId(),
          organizationId: scope.organizationId,
          domainId: data.domainId,
          method: 'dns_txt',
          token: data.token,
          status: data.status,
          attempts: 0,
          nextCheckAt: data.nextCheckAt ?? null,
          lastCheckedAt: null,
          lastError: null,
          lastOutcome: null,
          verifiedAt: data.verifiedAt ?? null,
          expiresAt: data.expiresAt,
          createdAt: new Date(),
          evidence: null,
        };
        this.verifications.push(row);
        return Promise.resolve(clone(row));
      },
      update: (_tx: unknown, scope: TenantScope, id: bigint, data: VerificationWrite) => {
        const row = this.verifications.find(
          (v) => v.organizationId === scope.organizationId && v.id === id,
        );
        if (row) Object.assign(row, data);
        return Promise.resolve();
      },
      expirePending: (_tx: unknown, scope: TenantScope, domainId: bigint) => {
        let count = 0;
        for (const v of this.verifications) {
          if (
            v.organizationId === scope.organizationId &&
            v.domainId === domainId &&
            v.status === 'pending'
          ) {
            v.status = 'expired';
            v.nextCheckAt = null;
            count++;
          }
        }
        return Promise.resolve(count);
      },
    } as unknown as VerificationsRepository;
  }

  dnsRecordsRepository(): DnsRecordsRepository {
    return {
      listForDomain: (scope: TenantScope, domainId: bigint) =>
        Promise.resolve(
          clone(
            this.records
              .filter((r) => r.organizationId === scope.organizationId && r.domainId === domainId)
              .sort((a, b) => (a.id < b.id ? -1 : 1)),
          ),
        ),
      upsert: (_tx: unknown, scope: TenantScope, domainId: bigint, record: DnsRecordDefinition) => {
        const existing = this.records.find(
          (r) =>
            r.organizationId === scope.organizationId &&
            r.domainId === domainId &&
            r.recordKey === record.recordKey,
        );
        if (existing) {
          Object.assign(existing, record);
        } else {
          this.records.push({
            id: this.nextId(),
            organizationId: scope.organizationId,
            domainId,
            ...record,
            observedValue: null,
            status: 'pending',
            statusChangedAt: null,
            lastOutcome: null,
            lastError: null,
            evidence: null,
            lastCheckedAt: null,
            createdAt: new Date(),
          });
        }
        return Promise.resolve();
      },
      writeResult: (_tx: unknown, scope: TenantScope, id: bigint, data: DnsRecordResultWrite) => {
        const row = this.records.find(
          (r) => r.organizationId === scope.organizationId && r.id === id,
        );
        if (row) Object.assign(row, clone(data));
        return Promise.resolve();
      },
      deleteByKeys: (_tx: unknown, scope: TenantScope, domainId: bigint, keys: string[]) => {
        const before = this.records.length;
        this.records = this.records.filter(
          (r) =>
            !(
              r.organizationId === scope.organizationId &&
              r.domainId === domainId &&
              keys.includes(r.recordKey)
            ),
        );
        return Promise.resolve(before - this.records.length);
      },
    } as unknown as DnsRecordsRepository;
  }

  dkimKeysRepository(): DkimKeysRepository {
    const strip = ({ organizationId: _o, privateKeyCiphertext: _c, ...row }: StoredKey) =>
      clone(row);
    const find = (scope: TenantScope, id: bigint) =>
      this.keys.find((k) => k.organizationId === scope.organizationId && k.id === id);
    return {
      listForDomain: (scope: TenantScope, domainId: bigint) =>
        Promise.resolve(
          this.keys
            .filter((k) => k.organizationId === scope.organizationId && k.domainId === domainId)
            .sort((a, b) => (a.id < b.id ? -1 : 1))
            .map(strip),
        ),
      create: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          domainId: bigint;
          selector: string;
          algorithm: DkimAlgorithm;
          publicKey: string;
          privateKeyCiphertext: string;
        },
      ) => {
        if (this.keys.some((k) => k.domainId === data.domainId && k.selector === data.selector)) {
          throw uniqueViolation('domain_dkim_keys_domain_id_selector_key');
        }
        const row: StoredKey = {
          id: this.nextId(),
          organizationId: scope.organizationId,
          ...data,
          status: 'pending',
          activatedAt: null,
          retireAfter: null,
          retiredAt: null,
          createdAt: new Date(),
        };
        this.keys.push(row);
        return Promise.resolve(strip(row));
      },
      activate: (_tx: unknown, scope: TenantScope, id: bigint, now: Date) => {
        const key = find(scope, id);
        if (key?.status === 'pending') Object.assign(key, { status: 'active', activatedAt: now });
        return Promise.resolve();
      },
      startRotating: (_tx: unknown, scope: TenantScope, id: bigint, retireAfter: Date) => {
        const key = find(scope, id);
        if (key?.status === 'active') Object.assign(key, { status: 'rotating', retireAfter });
        return Promise.resolve();
      },
      revoke: (_tx: unknown, scope: TenantScope, ids: bigint[]) => {
        let count = 0;
        for (const id of ids) {
          const key = find(scope, id);
          if (key && key.status !== 'retired' && key.status !== 'revoked') {
            Object.assign(key, { status: 'revoked', privateKeyCiphertext: null });
            count++;
          }
        }
        return Promise.resolve(count);
      },
      retire: (_tx: unknown, scope: TenantScope, id: bigint, now: Date) => {
        const key = find(scope, id);
        if (key?.status !== 'rotating' || !key.retireAfter || key.retireAfter > now) {
          return Promise.resolve(false);
        }
        Object.assign(key, { status: 'retired', retiredAt: now, privateKeyCiphertext: null });
        return Promise.resolve(true);
      },
    } as unknown as DkimKeysRepository;
  }

  mxObservationsRepository(): MxObservationsRepository {
    return {
      list: (scope: TenantScope, domainId: bigint) =>
        Promise.resolve(
          this.mx
            .filter((m) => m.organizationId === scope.organizationId && m.domainId === domainId)
            .map(({ organizationId: _o, domainId: _d, ...row }) => clone(row)),
        ),
      replace: (
        _tx: unknown,
        scope: TenantScope,
        domainId: bigint,
        observed: MxObservation[],
        now: Date,
      ) => {
        this.mx = this.mx.filter(
          (m) => !(m.organizationId === scope.organizationId && m.domainId === domainId),
        );
        for (const o of observed) {
          this.mx.push({ organizationId: scope.organizationId, domainId, ...o, lastSeenAt: now });
        }
        return Promise.resolve();
      },
    } as unknown as MxObservationsRepository;
  }

  ownershipRepository(): DomainOwnershipRepository {
    return {
      findVerifiedOwner: (_tx: unknown, name: string) => {
        const owner = this.domains.find((d) => d.name === name && OWNED.has(d.status));
        return Promise.resolve(
          owner ? { id: owner.id, organizationId: owner.organizationId } : null,
        );
      },
      supersedePendingClaims: (_tx: unknown, name: string, winner: bigint, now: Date) => {
        const claims: SupersededClaim[] = [];
        for (const d of this.domains) {
          if (d.name !== name || d.id === winner || d.status !== 'pending_verification') continue;
          Object.assign(d, {
            status: 'failed',
            statusReason: 'claimed_by_another_organization',
            statusChangedAt: now,
            nextCheckAt: null,
          });
          for (const v of this.verificationsOf(d.id)) {
            if (v.status === 'pending') Object.assign(v, { status: 'failed', nextCheckAt: null });
          }
          claims.push({
            domainId: d.id,
            domainPublicId: d.publicId,
            organizationId: d.organizationId,
          });
        }
        return Promise.resolve(claims);
      },
    };
  }

  jobsRepository(): DomainJobsRepository {
    return {
      findDue: (now: Date, limit: number): Promise<DueDomain[]> =>
        Promise.resolve(
          this.domains
            .filter((d) => d.nextCheckAt !== null && d.nextCheckAt <= now)
            .sort((a, b) => a.nextCheckAt!.getTime() - b.nextCheckAt!.getTime())
            .slice(0, limit)
            .map((d) => ({
              id: d.id,
              organizationId: d.organizationId,
              nextCheckAt: new Date(d.nextCheckAt!),
              organizationStatus: this.organizationStatus.get(d.organizationId) ?? 'active',
            })),
        ),
      claim: (id: bigint, expected: Date, until: Date) => {
        const d = this.domains.find((x) => x.id === id);
        if (!d || d.nextCheckAt?.getTime() !== expected.getTime()) return Promise.resolve(false);
        d.nextCheckAt = until;
        return Promise.resolve(true);
      },
      findKeysDueForRetirement: (now: Date, limit: number): Promise<RetirableKey[]> =>
        Promise.resolve(
          this.keys
            .filter(
              (k) => k.status === 'rotating' && k.retireAfter !== null && k.retireAfter <= now,
            )
            .slice(0, limit)
            .map((k) => ({ keyId: k.id, domainId: k.domainId, organizationId: k.organizationId })),
        ),
    } as unknown as DomainJobsRepository;
  }

  outboxRepository(): DomainOutboxRepository {
    return {
      insertStatusChanged: (
        _tx: unknown,
        event: { organizationId: bigint; correlationId: string; payload: DomainStatusChangedV1 },
      ) => {
        this.outbox.push(clone(event));
        return Promise.resolve(randomUUID());
      },
      insertRecordsChanged: (
        _tx: unknown,
        event: {
          organizationId: bigint;
          correlationId: string;
          payload: DomainDnsRecordsChangedV1;
        },
      ) => {
        // The production repository parses the contract; so does the double.
        this.recordsChanged.push(
          clone({ ...event, payload: domainDnsRecordsChangedV1.parse(event.payload) }),
        );
        return Promise.resolve(randomUUID());
      },
      // Step 2.3: the domain onboarding flows never change destinations.
      insertRoutingChanged: () =>
        Promise.reject(new Error('unexpected domain.routing.changed.v1 in a domain test')),
    };
  }

  /** Adds a record row directly (fixtures). */
  addRecord(
    domain: DomainRow,
    recordKey: string,
    purpose: DnsRecordPurpose,
    patch: Partial<StoredRecord> = {},
  ): StoredRecord {
    const row: StoredRecord = {
      id: this.nextId(),
      organizationId: domain.organizationId,
      domainId: domain.id,
      recordKey,
      purpose,
      recordType: purpose === 'mx' ? 'MX' : 'TXT',
      host: domain.name,
      dkimKeyId: null,
      expectedValue: 'expected',
      observedValue: null,
      status: 'pending',
      statusChangedAt: null,
      lastOutcome: null,
      lastError: null,
      evidence: null,
      lastCheckedAt: null,
      createdAt: new Date(),
      ...patch,
    };
    this.records.push(row);
    return row;
  }

  /** Adds a DKIM key directly (fixtures). */
  addKey(domain: DomainRow, selector: string, patch: Partial<StoredKey> = {}): StoredKey {
    const row: StoredKey = {
      id: this.nextId(),
      organizationId: domain.organizationId,
      domainId: domain.id,
      selector,
      algorithm: 'rsa_2048',
      publicKey: 'AAAA',
      privateKeyCiphertext: 'ciphertext',
      status: 'pending',
      activatedAt: null,
      retireAfter: null,
      retiredAt: null,
      createdAt: new Date(),
      ...patch,
    };
    this.keys.push(row);
    return row;
  }
}
