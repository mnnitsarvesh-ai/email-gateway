/**
 * In-memory doubles of the step 8.1 api repositories and infrastructure for the stubbed e2e suites
 * (archive, eDiscovery, route inventory and security): a tiny tenant-scoped "database" of archive
 * settings, retention policies, key versions, the message registry, archive records (seeded with
 * the real crypto of `archive-seed.ts`), capture intents, disposals, the index queue, download
 * grants, legal holds, cases, custodians, searches, hits and exports; the archive bucket as a map
 * of encrypted objects; the tenant search alias as a list of documents per organization; a
 * switchable `archiving` feature and retention plan limit; and a fake re-authentication
 * (`correct-horse` is the right password). Organization scoping mirrors the real repositories.
 * Test-only: never used by production code.
 */
/* eslint-disable @typescript-eslint/no-this-alias -- the doubles close over the world's state */
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { uuidv7 } from '@email-gateway/common';
import { AuditService } from '../../src/audit/audit.service';
import type { UserPrincipal } from '../../src/auth-contracts/principal';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { ReauthenticationService } from '../../src/modules/auth/services/reauthentication.service';
import {
  ArchiveConfigRepository,
  type KeyRow,
  type PolicyRow,
  type SettingsRow,
  type SettingsWrite,
} from '../../src/modules/archive/repositories/archive-config.repository';
import {
  ArchiveGrantsRepository,
  type ExportDownloadRow,
  type GrantRow,
  type NewGrant,
} from '../../src/modules/archive/repositories/archive-grants.repository';
import {
  ArchiveRecordsRepository,
  type CaptureIssueRow,
  type DisposalRow,
  type HoldRefRow,
  type MessageKeyRow,
  type RecordRow,
} from '../../src/modules/archive/repositories/archive-records.repository';
import {
  ArchiveObjectError,
  ArchiveObjectStore,
} from '../../src/modules/archive/services/archive-object-store';
import {
  ArchiveSearchClient,
  type ArchiveSearchSource,
} from '../../src/modules/archive/services/archive-search.client';
import {
  type CaseRow,
  type CustodianRow,
  EdiscoveryRepository,
  type ExportRow,
  type HitRow,
  type HoldRow,
  type SearchRow,
} from '../../src/modules/ediscovery/repositories/ediscovery.repository';
import { OrganizationFeaturesService } from '../../src/tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../src/tenancy/organization-limits.service';
import {
  type SeededRecord,
  type SeedRecordInput,
  seedRecord,
  searchSourceOf,
  type SeedTenantKey,
  seedTenantKey,
} from './archive-seed';
import { RecordingAuditService } from './messages-fixtures';

/** The password the fake re-authentication accepts (never a real credential). */
export const TEST_REAUTH_PASSWORD = 'correct-horse';

const copy = <T>(value: T): T => structuredClone(value);
const lower = (s: string) => s.toLowerCase();

type Stored<T> = T & { organizationId: bigint };

interface StoredHold {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  caseId: bigint | null;
  name: string;
  reason: string;
  criteria: unknown;
  criteriaVersion: string | null;
  status: 'active' | 'released';
  releasedAt: Date | null;
  releaseReason: string | null;
  releasedBy: string | null;
  createdBy: string | null;
  rowVersion: number;
  createdAt: Date;
}

interface StoredCase {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
  description: string | null;
  matterReference: string | null;
  status: 'open' | 'closed';
  rowVersion: number;
  createdAt: Date;
  updatedAt: Date;
  closedAt: Date | null;
  createdBy: string | null;
}

interface StoredSearch {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  caseId: bigint;
  criteria: unknown;
  criteriaSha256: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  hitCount: number;
  truncated: boolean;
  indexComplete: boolean | null;
  incompleteReason: string | null;
  errorCode: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  requestedBy: string | null;
}

interface StoredHit extends HitRow {
  organizationId: bigint;
  searchId: bigint;
}

interface StoredExport {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  caseId: bigint;
  searchId: bigint;
  status: 'queued' | 'building' | 'completed' | 'failed' | 'expired';
  reviewTags: string[];
  acknowledgeMalicious: boolean;
  itemCount: number;
  maliciousCount: number;
  packageBytes: bigint | null;
  packageSha256: string | null;
  manifestSha256: string | null;
  signingKeyId: string | null;
  objectKey: string | null;
  objectVersionId: string | null;
  keyVersion: number | null;
  wrappedDek: string | null;
  expiresAt: Date | null;
  errorCode: string | null;
  createdAt: Date;
  completedAt: Date | null;
  requestedBy: string | null;
}

export class ArchiveWorld {
  settings = new Map<bigint, SettingsRow>();
  policies: PolicyRow[] = [];
  keys: Array<KeyRow & { wrappedKey: string | null }> = [];
  registry: MessageKeyRow[] = [];
  records: RecordRow[] = [];
  intents: Array<Stored<CaptureIssueRow>> = [];
  disposals: Array<Stored<DisposalRow>> = [];
  indexQueue: Array<{
    organizationId: bigint;
    createdAt: Date;
    op: string;
    messagePublicId: string;
  }> = [];
  grants: Array<Stored<GrantRow>> = [];
  holds: StoredHold[] = [];
  cases: StoredCase[] = [];
  custodians: Array<{
    organizationId: bigint;
    caseId: bigint;
    publicId: string;
    address: string;
    userPublicId: string | null;
  }> = [];
  searches: StoredSearch[] = [];
  hits: StoredHit[] = [];
  exports: StoredExport[] = [];
  objects = new Map<string, Buffer>();
  docs: Array<{ organizationId: bigint; source: ArchiveSearchSource }> = [];
  domains: Array<{ organizationId: bigint; publicId: string; name: string; verified: boolean }> =
    [];
  departments: Array<{ organizationId: bigint; publicId: string }> = [];
  users: Array<{ organizationId: bigint; id: bigint; publicId: string; email: string }> = [];
  lockLoggingCursors: string[] = [];
  archivingDisabled = new Set<bigint>();
  retentionLimit = new Map<bigint, bigint | null>();
  lockAvailable = true;
  searchConfigured = true;
  searchDown = false;
  /** Search bodies sent to the "OpenSearch" double (tenant alias and query assertions). */
  searchCalls: Array<{ organizationId: bigint; body: Record<string, unknown> }> = [];
  tenantKeys = new Map<string, SeedTenantKey>();
  private nextId = 5000n;
  rootKey: { ARCHIVE_ROOT_KEY: string; ARCHIVE_ROOT_KEY_ID?: string | undefined } | null = null;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  reset(): void {
    this.settings.clear();
    this.policies = [];
    this.keys = [];
    this.registry = [];
    this.records = [];
    this.intents = [];
    this.disposals = [];
    this.indexQueue = [];
    this.grants = [];
    this.holds = [];
    this.cases = [];
    this.custodians = [];
    this.searches = [];
    this.hits = [];
    this.exports = [];
    this.objects.clear();
    this.docs = [];
    this.domains = [];
    this.departments = [];
    this.users = [];
    this.lockLoggingCursors = [];
    this.archivingDisabled.clear();
    this.retentionLimit.clear();
    this.lockAvailable = true;
    this.searchConfigured = true;
    this.searchDown = false;
    this.searchCalls = [];
    this.tenantKeys.clear();
  }

  // ---- fixtures ---------------------------------------------------------------------------------

  async tenantKey(organizationId: bigint, version = 1): Promise<SeedTenantKey> {
    const id = `${organizationId}:${version}`;
    const existing = this.tenantKeys.get(id);
    if (existing) return existing;
    if (this.rootKey === null) throw new Error('ArchiveWorld.rootKey not set');
    const key = await seedTenantKey(this.rootKey, organizationId, version);
    this.tenantKeys.set(id, key);
    this.keys.push({
      id: this.id(),
      publicId: uuidv7(),
      organizationId,
      version,
      status: 'active',
      rootKeyId: key.rootKeyId,
      algorithm: key.algorithm,
      rotationReason: null,
      createdAt: new Date(),
      activatedAt: new Date(),
      retiredAt: null,
      destroyedAt: null,
      createdByPublicId: null,
      wrappedKey: key.wrappedKey,
    });
    return key;
  }

  /** A captured record of `organizationId` (registry row, record, objects, search document). */
  async addRecord(
    organizationId: bigint,
    input: Omit<SeedRecordInput, 'organizationId' | 'messageId'> = {},
  ): Promise<SeededRecord & { record: RecordRow }> {
    const key = await this.tenantKey(organizationId);
    const messageId = this.id();
    const seeded = seedRecord(key, { ...input, organizationId, messageId });
    this.registry.push({
      id: messageId,
      publicId: seeded.row.messagePublicId,
      receivedAt: seeded.row.receivedAt,
      organizationId,
    });
    const record = {
      id: this.id(),
      outcomeRefreshedAt: null,
      ...seeded.row,
    } as unknown as RecordRow;
    this.records.push(record);
    for (const [k, v] of seeded.objects) this.objects.set(k, v);
    this.docs.push({ organizationId, source: searchSourceOf(seeded.row) });
    return { ...seeded, record };
  }

  addPolicy(organizationId: bigint, patch: Partial<PolicyRow> = {}): PolicyRow {
    const now = new Date();
    const row: PolicyRow = {
      id: this.id(),
      publicId: uuidv7(),
      organizationId,
      name: `policy-${this.nextId}`,
      retentionDays: 365,
      onExpiry: 'delete',
      priority: 100,
      criteria: {},
      rowVersion: 1,
      deletedAt: null,
      createdAt: now,
      updatedAt: now,
      ...patch,
    };
    this.policies.push(row);
    return row;
  }

  addCase(organizationId: bigint, patch: Partial<StoredCase> = {}): StoredCase {
    const now = new Date();
    const row: StoredCase = {
      id: this.id(),
      publicId: uuidv7(),
      organizationId,
      name: `case-${this.nextId}`,
      description: null,
      matterReference: null,
      status: 'open',
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      createdBy: null,
      ...patch,
    };
    this.cases.push(row);
    return row;
  }

  addHold(organizationId: bigint, patch: Partial<StoredHold> = {}): StoredHold {
    const row: StoredHold = {
      id: this.id(),
      publicId: uuidv7(),
      organizationId,
      caseId: null,
      name: `hold-${this.nextId}`,
      reason: 'test',
      criteria: {},
      criteriaVersion: 'archive-hold/1',
      status: 'active',
      releasedAt: null,
      releaseReason: null,
      releasedBy: null,
      createdBy: null,
      rowVersion: 1,
      createdAt: new Date(),
      ...patch,
    };
    this.holds.push(row);
    return row;
  }

  addSearch(
    organizationId: bigint,
    caseId: bigint,
    patch: Partial<StoredSearch> = {},
  ): StoredSearch {
    const row: StoredSearch = {
      id: this.id(),
      publicId: uuidv7(),
      organizationId,
      caseId,
      criteria: { from: '2026-01-01', to: '2026-12-31' },
      criteriaSha256: 'c'.repeat(64),
      status: 'completed',
      hitCount: 0,
      truncated: false,
      indexComplete: true,
      incompleteReason: null,
      errorCode: null,
      startedAt: new Date(),
      completedAt: new Date(),
      createdAt: new Date(),
      requestedBy: null,
      ...patch,
    };
    this.searches.push(row);
    return row;
  }

  addHit(organizationId: bigint, searchId: bigint, record: RecordRow): StoredHit {
    const row: StoredHit = {
      id: this.id(),
      organizationId,
      searchId,
      messageId: record.messageId,
      messageReceivedAt: record.receivedAt,
      messagePublicId: record.messagePublicId,
      reviewTag: 'untagged',
      reviewedAt: null,
      reviewedByPublicId: null,
    };
    this.hits.push(row);
    return row;
  }

  addExport(
    organizationId: bigint,
    caseId: bigint,
    searchId: bigint,
    patch: Partial<StoredExport> = {},
  ): StoredExport {
    const row: StoredExport = {
      id: this.id(),
      publicId: uuidv7(),
      organizationId,
      caseId,
      searchId,
      status: 'queued',
      reviewTags: ['untagged', 'relevant', 'privileged'],
      acknowledgeMalicious: false,
      itemCount: 0,
      maliciousCount: 0,
      packageBytes: null,
      packageSha256: null,
      manifestSha256: null,
      signingKeyId: null,
      objectKey: null,
      objectVersionId: null,
      keyVersion: null,
      wrappedDek: null,
      expiresAt: null,
      errorCode: null,
      createdAt: new Date(),
      completedAt: null,
      requestedBy: null,
      ...patch,
    };
    this.exports.push(row);
    return row;
  }

  setSettings(organizationId: bigint, patch: Partial<SettingsRow> = {}): SettingsRow {
    const row: SettingsRow = {
      id: this.id(),
      organizationId,
      enabled: false,
      objectLockMode: 'none',
      defaultRetentionPolicyId: null,
      defaultRetentionPolicyPublicId: null,
      settings: null,
      generation: 1n,
      rowVersion: 1,
      journalEnabledAt: null,
      updatedAt: new Date(),
      ...patch,
    };
    this.settings.set(organizationId, row);
    return row;
  }

  // ---- doubles ------------------------------------------------------------------------------------

  private policyById(id: bigint) {
    return this.policies.find((p) => p.id === id) ?? null;
  }

  private settingsView(org: bigint): SettingsRow | null {
    const s = this.settings.get(org);
    if (!s) return null;
    const p =
      s.defaultRetentionPolicyId === null ? null : this.policyById(s.defaultRetentionPolicyId);
    return copy({ ...s, defaultRetentionPolicyPublicId: p?.publicId ?? null });
  }

  configDouble(): Partial<Record<keyof ArchiveConfigRepository, unknown>> {
    const w = this;
    const own = (scope: TenantScope) => scope.organizationId;
    return {
      settings: (scope: TenantScope) => Promise.resolve(w.settingsView(own(scope))),
      settingsOnWriter: (scope: TenantScope) => Promise.resolve(w.settingsView(own(scope))),
      lockSettings: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(w.settingsView(own(scope))),
      writeSettings: (
        _tx: unknown,
        scope: TenantScope,
        current: SettingsRow | null,
        data: SettingsWrite,
      ) => {
        const org = own(scope);
        const stored = w.settings.get(org);
        if (current === null) {
          w.setSettings(org, {
            enabled: data.enabled,
            objectLockMode: data.objectLockMode,
            defaultRetentionPolicyId: data.defaultRetentionPolicyId,
            settings: data.settings,
            journalEnabledAt: data.journalEnabledAt,
            generation: 1n,
            rowVersion: 1,
          });
          return Promise.resolve(true);
        }
        if (!stored || stored.rowVersion !== current.rowVersion) return Promise.resolve(false);
        Object.assign(stored, {
          enabled: data.enabled,
          objectLockMode: data.objectLockMode,
          defaultRetentionPolicyId: data.defaultRetentionPolicyId,
          settings: data.settings,
          journalEnabledAt: data.journalEnabledAt,
          generation: stored.generation + 1n,
          rowVersion: stored.rowVersion + 1,
          updatedAt: new Date(),
        });
        return Promise.resolve(true);
      },
      requestLockPass: (_tx: unknown, scope: TenantScope) => {
        w.lockLoggingCursors.push(`archive:lock:${own(scope)}`);
        return Promise.resolve();
      },
      resolveScope: (
        _tx: unknown,
        scope: TenantScope,
        s: { domainIds: string[]; departmentIds: string[]; userIds: string[]; addresses: string[] },
      ) => {
        const org = own(scope);
        const has = (list: Array<{ organizationId: bigint; publicId: string }>, id: string) =>
          list.some((x) => x.organizationId === org && lower(x.publicId) === lower(id));
        return Promise.resolve({
          scope: {
            addresses: s.addresses,
            userEmails: w.users
              .filter((u) => u.organizationId === org && s.userIds.includes(u.publicId))
              .map((u) => u.email),
            departmentAddresses: [],
            domains: w.domains
              .filter(
                (d) => d.organizationId === org && d.verified && s.domainIds.includes(d.publicId),
              )
              .map((d) => d.name),
          },
          unresolved: {
            domainIds: s.domainIds.filter((id) => !has(w.domains, id)),
            departmentIds: s.departmentIds.filter((id) => !has(w.departments, id)),
            userIds: s.userIds.filter((id) => !has(w.users, id)),
          },
        });
      },
      existingCriteriaIds: (
        _tx: unknown,
        scope: TenantScope,
        ids: { domainIds: readonly string[]; departmentIds: readonly string[] },
      ) => {
        const org = own(scope);
        return Promise.resolve({
          domainIds: new Set(
            w.domains
              .filter((d) => d.organizationId === org && ids.domainIds.includes(lower(d.publicId)))
              .map((d) => lower(d.publicId)),
          ),
          departmentIds: new Set(
            w.departments
              .filter(
                (d) => d.organizationId === org && ids.departmentIds.includes(lower(d.publicId)),
              )
              .map((d) => lower(d.publicId)),
          ),
        });
      },
      listPolicies: (
        scope: TenantScope,
        page: { take: number; after?: { priority: number; id: bigint } },
      ) => {
        const rows = w.policies
          .filter((p) => p.organizationId === own(scope) && p.deletedAt === null)
          .sort((a, b) => a.priority - b.priority || (a.id < b.id ? -1 : 1))
          .filter(
            (p) =>
              !page.after ||
              p.priority > page.after.priority ||
              (p.priority === page.after.priority && p.id > page.after.id),
          );
        return Promise.resolve(copy(rows.slice(0, page.take)));
      },
      findPolicy: (scope: TenantScope, publicId: string) =>
        Promise.resolve(
          copy(
            w.policies.find(
              (p) =>
                p.organizationId === own(scope) && p.publicId === publicId && p.deletedAt === null,
            ) ?? null,
          ),
        ),
      lockPolicy: (_tx: unknown, scope: TenantScope, publicId: string) =>
        Promise.resolve(
          copy(
            w.policies.find(
              (p) =>
                p.organizationId === own(scope) && p.publicId === publicId && p.deletedAt === null,
            ) ?? null,
          ),
        ),
      policyById: (_tx: unknown, scope: TenantScope, id: bigint) =>
        Promise.resolve(
          copy(w.policies.find((p) => p.organizationId === own(scope) && p.id === id) ?? null),
        ),
      countLivePolicies: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          w.policies.filter((p) => p.organizationId === own(scope) && p.deletedAt === null).length,
        ),
      policyNameTaken: (_tx: unknown, scope: TenantScope, name: string, exceptId?: bigint) =>
        Promise.resolve(
          w.policies.some(
            (p) => p.organizationId === own(scope) && p.name === name && p.id !== exceptId,
          ),
        ),
      createPolicy: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          publicId: string;
          name: string;
          retentionDays: number;
          onExpiry: 'delete' | 'review';
          priority: number;
          criteria: unknown;
        },
      ) =>
        Promise.resolve(
          copy(
            w.addPolicy(own(scope), {
              publicId: data.publicId,
              name: data.name,
              retentionDays: data.retentionDays,
              onExpiry: data.onExpiry,
              priority: data.priority,
              criteria: data.criteria as never,
            }),
          ),
        ),
      updatePolicy: (
        _tx: unknown,
        scope: TenantScope,
        current: PolicyRow,
        data: Record<string, unknown>,
      ) => {
        const row = w.policies.find((p) => p.organizationId === own(scope) && p.id === current.id);
        if (!row || row.rowVersion !== current.rowVersion) return Promise.resolve(false);
        const { updatedByUserId: _u, ...changes } = data;
        Object.assign(row, changes, { rowVersion: row.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(true);
      },
      listKeys: (scope: TenantScope, page: { take: number; beforeVersion?: number }) =>
        Promise.resolve(
          w.keys
            .filter(
              (k) =>
                k.organizationId === own(scope) &&
                (page.beforeVersion === undefined || k.version < page.beforeVersion),
            )
            .sort((a, b) => b.version - a.version)
            .slice(0, page.take)
            .map(({ wrappedKey: _w, ...k }) => copy(k)),
        ),
      keysOnWriter: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          w.keys
            .filter((k) => k.organizationId === own(scope))
            .sort((a, b) => b.version - a.version)
            .map(({ wrappedKey: _w, ...k }) => copy(k)),
        ),
      retireKeys: (_tx: unknown, scope: TenantScope, now: Date) => {
        let n = 0;
        for (const k of w.keys) {
          if (k.organizationId === own(scope) && k.status === 'active') {
            k.status = 'retired';
            k.retiredAt = now;
            n += 1;
          }
        }
        return Promise.resolve(n);
      },
      insertKey: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          publicId: string;
          version: number;
          wrappedKey: string;
          rootKeyId: string;
          algorithm: string;
          rotationReason: string;
          now: Date;
        },
      ) => {
        const row = {
          id: w.id(),
          publicId: data.publicId,
          organizationId: own(scope),
          version: data.version,
          status: 'active' as const,
          rootKeyId: data.rootKeyId,
          algorithm: data.algorithm,
          rotationReason: data.rotationReason,
          createdAt: data.now,
          activatedAt: data.now,
          retiredAt: null,
          destroyedAt: null,
          createdByPublicId: null,
          wrappedKey: data.wrappedKey,
        };
        w.keys.push(row);
        const { wrappedKey: _w, ...view } = row;
        return Promise.resolve(copy(view));
      },
      wrappedKey: (scope: TenantScope, version: number) => {
        const k = w.keys.find((x) => x.organizationId === own(scope) && x.version === version);
        return Promise.resolve(
          k ? { version: k.version, status: k.status, wrappedKey: k.wrappedKey } : null,
        );
      },
    };
  }

  recordsDouble(): Partial<Record<keyof ArchiveRecordsRepository, unknown>> {
    const w = this;
    const own = (scope: TenantScope) => scope.organizationId;
    const holdRef = (h: StoredHold): HoldRefRow => ({
      id: h.id,
      publicId: h.publicId,
      name: h.name,
      criteria: h.criteria,
      criteriaVersion: h.criteriaVersion,
      casePublicId:
        h.caseId === null ? null : (w.cases.find((c) => c.id === h.caseId)?.publicId ?? null),
    });
    return {
      messageKey: (scope: TenantScope, publicId: string) =>
        Promise.resolve(
          copy(
            w.registry.find((r) => r.organizationId === own(scope) && r.publicId === publicId) ??
              null,
          ),
        ),
      record: (scope: TenantScope, key: MessageKeyRow) =>
        Promise.resolve(
          copy(
            w.records.find(
              (r) =>
                r.organizationId === own(scope) &&
                r.messageId === key.id &&
                r.receivedAt.getTime() === key.receivedAt.getTime(),
            ) ?? null,
          ),
        ),
      lockOrganizationForHolds: () => Promise.resolve(),
      lockRecord: (_tx: unknown, scope: TenantScope, key: MessageKeyRow) =>
        Promise.resolve(
          copy(
            w.records.find((r) => r.organizationId === own(scope) && r.messageId === key.id) ??
              null,
          ),
        ),
      recordsByKeys: (scope: TenantScope, keys: Array<{ messageId: bigint; receivedAt: Date }>) =>
        Promise.resolve(
          copy(
            w.records.filter(
              (r) =>
                r.organizationId === own(scope) && keys.some((k) => k.messageId === r.messageId),
            ),
          ),
        ),
      policyFacts: (scope: TenantScope, policyId: bigint) => {
        const p = w.policies.find((x) => x.organizationId === own(scope) && x.id === policyId);
        return Promise.resolve(
          p
            ? {
                publicId: p.publicId,
                name: p.name,
                retentionDays: p.retentionDays,
                onExpiry: p.onExpiry,
                live: p.deletedAt === null,
              }
            : null,
        );
      },
      activeHolds: (scope: TenantScope) =>
        Promise.resolve(
          w.holds
            .filter((h) => h.organizationId === own(scope) && h.status === 'active')
            .map(holdRef),
        ),
      writeDisposalDecision: (
        _tx: unknown,
        scope: TenantScope,
        d: { record: RecordRow; reason: DisposalRow['reason']; now: Date },
      ) => {
        const r = w.records.find((x) => x.organizationId === own(scope) && x.id === d.record.id);
        if (!r) throw new Error('record vanished');
        Object.assign(r, { status: 'disposing', wrappedDek: null, deletedAt: d.now });
        w.disposals.push({
          id: w.id(),
          organizationId: own(scope),
          requestedAt: d.now,
          messagePublicId: r.messagePublicId,
          messageReceivedAt: r.receivedAt,
          reason: d.reason,
          state: 'shredded',
          sha256: r.sha256,
          sizeBytes: r.sizeBytes,
          attempts: 0,
          completedAt: null,
        });
        w.indexQueue.push({
          organizationId: own(scope),
          createdAt: d.now,
          op: 'delete',
          messagePublicId: r.messagePublicId,
        });
        return Promise.resolve();
      },
      captureIssues: (
        scope: TenantScope,
        page: {
          take: number;
          statuses: string[];
          agedBefore: Date;
          before?: { at: Date; id: bigint };
        },
      ) => {
        const rows = w.intents
          .filter((i) => i.organizationId === own(scope))
          .filter(
            (i) =>
              (i.status !== 'pending' &&
                page.statuses.includes(i.status) &&
                (i.status !== 'skipped' || i.skipReason === 'max_age')) ||
              (i.status === 'pending' &&
                page.statuses.includes('pending') &&
                i.createdAt <= page.agedBefore),
          )
          .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime() || (a.id < b.id ? 1 : -1))
          .filter(
            (i) =>
              !page.before ||
              i.receivedAt < page.before.at ||
              (i.receivedAt.getTime() === page.before.at.getTime() && i.id < page.before.id),
          );
        return Promise.resolve(
          copy(rows.slice(0, page.take).map(({ organizationId: _o, ...r }) => r)),
        );
      },
      lockIntent: (_tx: unknown, scope: TenantScope, key: MessageKeyRow) => {
        const i = w.intents.find((x) => x.organizationId === own(scope) && x.messageId === key.id);
        return Promise.resolve(i ? { id: i.id, status: i.status } : null);
      },
      retryIntent: (
        _tx: unknown,
        scope: TenantScope,
        _key: MessageKeyRow,
        intentId: bigint,
        now: Date,
      ) => {
        const i = w.intents.find(
          (x) => x.organizationId === own(scope) && x.id === intentId && x.status === 'failed',
        );
        if (!i) return Promise.resolve(false);
        Object.assign(i, { status: 'pending', nextCheckAt: now });
        return Promise.resolve(true);
      },
      disposals: (
        scope: TenantScope,
        page: {
          take: number;
          from: Date;
          to: Date;
          reasons?: string[];
          states?: string[];
          before?: { at: Date; id: bigint };
        },
      ) => {
        const rows = w.disposals
          .filter(
            (d) =>
              d.organizationId === own(scope) &&
              d.requestedAt >= page.from &&
              d.requestedAt < page.to,
          )
          .filter(
            (d) =>
              (!page.reasons || page.reasons.includes(d.reason)) &&
              (!page.states || page.states.includes(d.state)),
          )
          .sort(
            (a, b) => b.requestedAt.getTime() - a.requestedAt.getTime() || (a.id < b.id ? 1 : -1),
          )
          .filter(
            (d) =>
              !page.before ||
              d.requestedAt < page.before.at ||
              (d.requestedAt.getTime() === page.before.at.getTime() && d.id < page.before.id),
          );
        return Promise.resolve(
          copy(rows.slice(0, page.take).map(({ organizationId: _o, ...r }) => r)),
        );
      },
      oldestIndexOpAt: (scope: TenantScope) => {
        const ops = w.indexQueue
          .filter((q) => q.organizationId === own(scope))
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
        return Promise.resolve(ops[0]?.createdAt ?? null);
      },
      statusCounts: (scope: TenantScope) => {
        const org = own(scope);
        const intents: Record<string, number> = {};
        for (const i of w.intents.filter((x) => x.organizationId === org))
          intents[i.status] = (intents[i.status] ?? 0) + 1;
        const recs = w.records.filter((r) => r.organizationId === org);
        const keys = w.keys.filter((k) => k.organizationId === org);
        const queue = w.indexQueue.filter((q) => q.organizationId === org);
        return Promise.resolve({
          intents,
          oldestPendingAt: null,
          records: {
            active: recs.filter((r) => r.status === 'active').length,
            expiryReview: recs.filter((r) => r.status === 'expiry_review').length,
            disposing: recs.filter((r) => r.status === 'disposing').length,
          },
          indexQueued: queue.length,
          oldestQueuedAt: queue[0]?.createdAt ?? null,
          disposalsInProgress: w.disposals.filter(
            (d) => d.organizationId === org && d.state !== 'completed' && d.state !== 'failed',
          ).length,
          disposalsFailed: w.disposals.filter(
            (d) => d.organizationId === org && d.state === 'failed',
          ).length,
          keys: {
            activeVersion: keys.find((k) => k.status === 'active')?.version ?? null,
            versions: keys.length,
          },
        });
      },
    };
  }

  grantsDouble(): Partial<Record<keyof ArchiveGrantsRepository, unknown>> {
    const w = this;
    return {
      insert: (_tx: unknown, scope: TenantScope, g: NewGrant) => {
        w.grants.push({ ...g, organizationId: scope.organizationId, consumedAt: null });
        return Promise.resolve();
      },
      consume: (_tx: unknown, scope: TenantScope, jti: string, userId: bigint, now: Date) => {
        const g = w.grants.find((x) => x.organizationId === scope.organizationId && x.jti === jti);
        if (g && g.userId === userId && g.consumedAt === null && g.expiresAt > now) {
          g.consumedAt = now;
          return Promise.resolve('ok');
        }
        if (g && g.userId === userId && g.consumedAt !== null) return Promise.resolve('used');
        return Promise.resolve('invalid');
      },
      byJti: (_tx: unknown, scope: TenantScope, jti: string) => {
        const g = w.grants.find((x) => x.organizationId === scope.organizationId && x.jti === jti);
        if (!g) return Promise.resolve(null);
        const { organizationId: _o, ...rest } = g;
        return Promise.resolve(copy(rest));
      },
      exportForDownload: (
        _tx: unknown,
        scope: TenantScope,
        publicId: string,
      ): Promise<ExportDownloadRow | null> => {
        const e = w.exports.find(
          (x) => x.organizationId === scope.organizationId && x.publicId === publicId,
        );
        if (!e) return Promise.resolve(null);
        const c = w.cases.find((x) => x.id === e.caseId)!;
        return Promise.resolve({
          id: e.id,
          publicId: e.publicId,
          casePublicId: c.publicId,
          status: e.status,
          objectKey: e.objectKey,
          objectVersionId: e.objectVersionId,
          keyVersion: e.keyVersion,
          wrappedDek: e.wrappedDek,
          packageSha256: e.packageSha256,
          packageBytes: e.packageBytes,
          expiresAt: e.expiresAt,
        });
      },
    };
  }

  objectsDouble(): Partial<Record<keyof ArchiveObjectStore, unknown>> {
    const w = this;
    const get = (organizationId: bigint, area: string, key: string) => {
      if (!key.startsWith(`org/${organizationId}/${area}/`))
        throw new ArchiveObjectError('foreign_key');
      const bytes = w.objects.get(key);
      if (!bytes) throw new ArchiveObjectError('not_found');
      return bytes;
    };
    return {
      open: (organizationId: bigint, area: string, key: string) => {
        const bytes = get(organizationId, area, key);
        return Promise.resolve({ body: Readable.from([bytes]), sizeBytes: bytes.length });
      },
      read: (organizationId: bigint, key: string) =>
        Promise.resolve(get(organizationId, 'archive', key)),
      objectLockAvailable: () => Promise.resolve(w.lockAvailable),
    };
  }

  searchDouble(): Partial<Record<keyof ArchiveSearchClient, unknown>> {
    const w = this;
    return {
      get configured() {
        return w.searchConfigured;
      },
      aliasOf: (organizationId: bigint) => `eg-archive-t${organizationId}`,
      search: async (organizationId: bigint, body: Record<string, unknown>) => {
        const { archiveSearchUnavailable } =
          await import('../../src/modules/archive/archive.errors');
        if (!w.searchConfigured || w.searchDown) throw archiveSearchUnavailable();
        w.searchCalls.push({ organizationId, body: copy(body) });
        const order = (body.sort as Array<{ received_at: { order: string } }>)[0]!.received_at
          .order;
        const after = body.search_after as [number, string] | undefined;
        const size = body.size as number;
        const docs = w.docs
          .filter((d) => d.organizationId === organizationId)
          .map((d) => ({
            ms: new Date(d.source.received_at!).getTime(),
            id: d.source.message_id!,
            d,
          }))
          .sort((a, b) =>
            order === 'desc'
              ? b.ms - a.ms || (b.id < a.id ? -1 : 1)
              : a.ms - b.ms || (a.id < b.id ? -1 : 1),
          )
          .filter(
            (x) =>
              !after ||
              (order === 'desc'
                ? x.ms < after[0] || (x.ms === after[0] && x.id < after[1])
                : x.ms > after[0] || (x.ms === after[0] && x.id > after[1])),
          );
        return {
          timedOut: false,
          hits: docs.slice(0, size).map((x) => ({
            _index: 'eg-archive-v1-2026',
            _id: x.id,
            _source: copy(x.d.source),
            sort: [x.ms, x.id],
          })),
        };
      },
      available: () => Promise.resolve(w.searchConfigured && !w.searchDown),
    };
  }

  ediscoveryDouble(): Partial<Record<keyof EdiscoveryRepository, unknown>> {
    const w = this;
    const own = (scope: TenantScope) => scope.organizationId;
    const userRef = (publicId: string | null) => (publicId === null ? null : { publicId });
    const holdRow = (h: StoredHold): HoldRow =>
      copy({
        id: h.id,
        publicId: h.publicId,
        organizationId: h.organizationId,
        caseId: h.caseId,
        name: h.name,
        reason: h.reason,
        criteria: h.criteria,
        criteriaVersion: h.criteriaVersion,
        status: h.status,
        releasedAt: h.releasedAt,
        releaseReason: h.releaseReason,
        rowVersion: h.rowVersion,
        createdAt: h.createdAt,
        case:
          h.caseId === null ? null : { publicId: w.cases.find((c) => c.id === h.caseId)!.publicId },
        createdBy: userRef(h.createdBy),
        releasedBy: userRef(h.releasedBy),
      }) as unknown as HoldRow;
    const caseRow = (c: StoredCase): CaseRow => copy({ ...c, createdByUser: userRef(c.createdBy) });
    const searchRow = (s: StoredSearch): SearchRow =>
      copy({ ...s, requestedByUser: userRef(s.requestedBy) }) as unknown as SearchRow;
    const exportRow = (e: StoredExport): ExportRow =>
      copy({
        ...e,
        search: { publicId: w.searches.find((s) => s.id === e.searchId)!.publicId },
        requestedByUser: userRef(e.requestedBy),
      });
    const page = <T extends { id: bigint }>(rows: T[], take: number, beforeId?: bigint) =>
      rows
        .sort((a, b) => (a.id < b.id ? 1 : -1))
        .filter((r) => beforeId === undefined || r.id < beforeId)
        .slice(0, take);
    return {
      listHolds: (
        scope: TenantScope,
        p: { take: number; beforeId?: bigint; statuses?: string[]; caseId?: bigint | null },
      ) =>
        Promise.resolve(
          page(
            w.holds.filter(
              (h) =>
                h.organizationId === own(scope) &&
                (!p.statuses || p.statuses.includes(h.status)) &&
                (p.caseId == null || h.caseId === p.caseId),
            ),
            p.take,
            p.beforeId,
          ).map(holdRow),
        ),
      findHold: (scope: TenantScope, publicId: string) => {
        const h = w.holds.find((x) => x.organizationId === own(scope) && x.publicId === publicId);
        return Promise.resolve(h ? holdRow(h) : null);
      },
      lockHold: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const h = w.holds.find((x) => x.organizationId === own(scope) && x.publicId === publicId);
        return Promise.resolve(h ? holdRow(h) : null);
      },
      countActiveHolds: (_tx: unknown, scope: TenantScope, caseId?: bigint) =>
        Promise.resolve(
          w.holds.filter(
            (h) =>
              h.organizationId === own(scope) &&
              h.status === 'active' &&
              (caseId === undefined || h.caseId === caseId),
          ).length,
        ),
      createHold: (
        _tx: unknown,
        scope: TenantScope,
        d: { publicId: string; caseId: bigint; name: string; reason: string; criteria: unknown },
      ) =>
        Promise.resolve(
          holdRow(
            w.addHold(own(scope), {
              publicId: d.publicId,
              caseId: d.caseId,
              name: d.name,
              reason: d.reason,
              criteria: d.criteria,
            }),
          ),
        ),
      releaseHold: (
        _tx: unknown,
        scope: TenantScope,
        hold: HoldRow,
        d: { reason: string; now: Date },
      ) => {
        const h = w.holds.find((x) => x.organizationId === own(scope) && x.id === hold.id);
        if (!h || h.status !== 'active' || h.rowVersion !== hold.rowVersion)
          return Promise.resolve(false);
        Object.assign(h, {
          status: 'released',
          releasedAt: d.now,
          releaseReason: d.reason,
          rowVersion: h.rowVersion + 1,
        });
        return Promise.resolve(true);
      },
      listCases: (
        scope: TenantScope,
        p: { take: number; beforeId?: bigint; statuses?: string[] },
      ) =>
        Promise.resolve(
          page(
            w.cases.filter(
              (c) =>
                c.organizationId === own(scope) && (!p.statuses || p.statuses.includes(c.status)),
            ),
            p.take,
            p.beforeId,
          ).map(caseRow),
        ),
      findCase: (scope: TenantScope, publicId: string) => {
        const c = w.cases.find((x) => x.organizationId === own(scope) && x.publicId === publicId);
        return Promise.resolve(c ? caseRow(c) : null);
      },
      lockCase: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const c = w.cases.find((x) => x.organizationId === own(scope) && x.publicId === publicId);
        return Promise.resolve(c ? caseRow(c) : null);
      },
      countOpenCases: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          w.cases.filter((c) => c.organizationId === own(scope) && c.status === 'open').length,
        ),
      caseNameTaken: (_tx: unknown, scope: TenantScope, name: string, exceptId?: bigint) =>
        Promise.resolve(
          w.cases.some(
            (c) => c.organizationId === own(scope) && c.name === name && c.id !== exceptId,
          ),
        ),
      createCase: (
        _tx: unknown,
        scope: TenantScope,
        d: {
          publicId: string;
          name: string;
          description: string | null;
          matterReference: string | null;
        },
      ) => Promise.resolve(caseRow(w.addCase(own(scope), d))),
      updateCase: (
        _tx: unknown,
        scope: TenantScope,
        current: CaseRow,
        changes: Record<string, unknown>,
      ) => {
        const c = w.cases.find((x) => x.organizationId === own(scope) && x.id === current.id);
        if (!c || c.rowVersion !== current.rowVersion) return Promise.resolve(false);
        const { updatedByUserId: _u, closedByUserId: _c, ...rest } = changes;
        Object.assign(c, rest, { rowVersion: c.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(true);
      },
      custodians: (scope: TenantScope, caseId: bigint): Promise<CustodianRow[]> =>
        Promise.resolve(
          w.custodians
            .filter((x) => x.organizationId === own(scope) && x.caseId === caseId)
            .sort((a, b) => a.address.localeCompare(b.address))
            .map((x) => ({
              publicId: x.publicId,
              address: x.address,
              userPublicId: x.userPublicId,
            })),
        ),
      replaceCustodians: (
        _tx: unknown,
        scope: TenantScope,
        caseId: bigint,
        list: Array<{ publicId: string; address: string; userId: bigint | null }>,
      ) => {
        w.custodians = w.custodians.filter(
          (x) => !(x.organizationId === own(scope) && x.caseId === caseId),
        );
        for (const c of list) {
          w.custodians.push({
            organizationId: own(scope),
            caseId,
            publicId: c.publicId,
            address: c.address,
            userPublicId:
              c.userId === null ? null : (w.users.find((u) => u.id === c.userId)?.publicId ?? null),
          });
        }
        return Promise.resolve();
      },
      usersByEmail: (_tx: unknown, scope: TenantScope, emails: string[]) =>
        Promise.resolve(
          new Map(
            w.users
              .filter((u) => u.organizationId === own(scope) && emails.includes(u.email))
              .map((u) => [u.email, u.id]),
          ),
        ),
      caseCounts: (scope: TenantScope, caseId: bigint) =>
        Promise.resolve({
          custodians: w.custodians.filter(
            (x) => x.organizationId === own(scope) && x.caseId === caseId,
          ).length,
          activeHolds: w.holds.filter(
            (h) => h.organizationId === own(scope) && h.caseId === caseId && h.status === 'active',
          ).length,
          searches: w.searches.filter((s) => s.organizationId === own(scope) && s.caseId === caseId)
            .length,
          exports: w.exports.filter((e) => e.organizationId === own(scope) && e.caseId === caseId)
            .length,
        }),
      listSearches: (
        scope: TenantScope,
        caseId: bigint,
        p: { take: number; beforeId?: bigint; statuses?: string[] },
      ) =>
        Promise.resolve(
          page(
            w.searches.filter(
              (s) =>
                s.organizationId === own(scope) &&
                s.caseId === caseId &&
                (!p.statuses || p.statuses.includes(s.status)),
            ),
            p.take,
            p.beforeId,
          ).map(searchRow),
        ),
      findSearch: (scope: TenantScope, caseId: bigint, publicId: string) => {
        const s = w.searches.find(
          (x) => x.organizationId === own(scope) && x.caseId === caseId && x.publicId === publicId,
        );
        return Promise.resolve(s ? searchRow(s) : null);
      },
      countActiveSearches: (_tx: unknown, scope: TenantScope, caseId: bigint) =>
        Promise.resolve(
          w.searches.filter(
            (s) =>
              s.organizationId === own(scope) &&
              s.caseId === caseId &&
              (s.status === 'queued' || s.status === 'running'),
          ).length,
        ),
      createSearch: (
        _tx: unknown,
        scope: TenantScope,
        d: { publicId: string; caseId: bigint; criteria: unknown; criteriaSha256: string },
      ) =>
        Promise.resolve(
          searchRow(
            w.addSearch(own(scope), d.caseId, {
              publicId: d.publicId,
              criteria: d.criteria,
              criteriaSha256: d.criteriaSha256,
              status: 'queued',
              indexComplete: null,
              startedAt: null,
              completedAt: null,
            }),
          ),
        ),
      listHits: (
        scope: TenantScope,
        searchId: bigint,
        p: { take: number; beforeId?: bigint; tags?: string[] },
      ) =>
        Promise.resolve(
          page(
            w.hits.filter(
              (h) =>
                h.organizationId === own(scope) &&
                h.searchId === searchId &&
                (!p.tags || p.tags.includes(h.reviewTag)),
            ),
            p.take,
            p.beforeId,
          ).map(({ organizationId: _o, searchId: _s, ...h }) => copy(h)),
        ),
      reviewHits: (
        _tx: unknown,
        scope: TenantScope,
        searchId: bigint,
        ids: string[],
        d: { tag: HitRow['reviewTag']; now: Date },
      ) => {
        let n = 0;
        for (const h of w.hits) {
          if (
            h.organizationId === own(scope) &&
            h.searchId === searchId &&
            ids.includes(h.messagePublicId)
          ) {
            h.reviewTag = d.tag;
            h.reviewedAt = d.now;
            n += 1;
          }
        }
        return Promise.resolve(n);
      },
      selectionStats: (_tx: unknown, scope: TenantScope, searchId: bigint, tags: string[]) => {
        const selected = w.hits.filter(
          (h) =>
            h.organizationId === own(scope) &&
            h.searchId === searchId &&
            tags.includes(h.reviewTag),
        );
        const recs = selected
          .map((h) => w.records.find((r) => r.messageId === h.messageId && r.deletedAt === null))
          .filter((r): r is RecordRow => r !== undefined);
        return Promise.resolve({
          items: recs.length,
          bytes: recs.reduce((n, r) => n + r.sizeBytes, 0),
          malicious: recs.filter((r) => r.malicious).length,
        });
      },
      listExports: (
        scope: TenantScope,
        caseId: bigint,
        p: { take: number; beforeId?: bigint; statuses?: string[] },
      ) =>
        Promise.resolve(
          page(
            w.exports.filter(
              (e) =>
                e.organizationId === own(scope) &&
                e.caseId === caseId &&
                (!p.statuses || p.statuses.includes(e.status)),
            ),
            p.take,
            p.beforeId,
          ).map(exportRow),
        ),
      findExport: (scope: TenantScope, caseId: bigint, publicId: string) => {
        const e = w.exports.find(
          (x) => x.organizationId === own(scope) && x.caseId === caseId && x.publicId === publicId,
        );
        return Promise.resolve(e ? exportRow(e) : null);
      },
      createExport: (
        _tx: unknown,
        scope: TenantScope,
        d: {
          publicId: string;
          caseId: bigint;
          searchId: bigint;
          reviewTags: string[];
          acknowledgeMalicious: boolean;
          itemCount: number;
          maliciousCount: number;
        },
      ) => Promise.resolve(exportRow(w.addExport(own(scope), d.caseId, d.searchId, d))),
    };
  }
}

/** Overrides every step 8.1 repository and infrastructure provider with the world's doubles. */
export function overrideArchive(
  builder: TestingModuleBuilder,
  world: ArchiveWorld,
  audit: RecordingAuditService,
): TestingModuleBuilder {
  return builder
    .overrideProvider(ArchiveConfigRepository)
    .useValue(world.configDouble())
    .overrideProvider(ArchiveRecordsRepository)
    .useValue(world.recordsDouble())
    .overrideProvider(ArchiveGrantsRepository)
    .useValue(world.grantsDouble())
    .overrideProvider(ArchiveObjectStore)
    .useValue(world.objectsDouble())
    .overrideProvider(ArchiveSearchClient)
    .useValue(world.searchDouble())
    .overrideProvider(EdiscoveryRepository)
    .useValue(world.ediscoveryDouble())
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(ReauthenticationService)
    .useValue({
      verify: (_p: UserPrincipal, input: { password: string }) =>
        Promise.resolve(
          input.password === TEST_REAUTH_PASSWORD
            ? { ok: true }
            : { ok: false, reason: 'password' },
        ),
    })
    .overrideProvider(OrganizationFeaturesService)
    .useValue({
      isEnabled: (organizationId: bigint, key: string) =>
        Promise.resolve(key === 'archiving' && !world.archivingDisabled.has(organizationId)),
    })
    .overrideProvider(OrganizationLimitsService)
    .useValue({
      lockOrganization: () => Promise.resolve(),
      getLimit: (_tx: unknown, organizationId: bigint) =>
        Promise.resolve(world.retentionLimit.get(organizationId) ?? null),
    });
}

/** A random message public id (unknown to every world). */
export const unknownId = (): string => randomUUID();

export { RecordingAuditService };
