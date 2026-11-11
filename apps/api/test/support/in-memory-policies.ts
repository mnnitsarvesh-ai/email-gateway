import type { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type {
  DepartmentRow,
  DepartmentsRepository,
  MemberRow,
} from '../../src/modules/directory/repositories/departments.repository';
import { InconsistentPolicyReadError } from '../../src/modules/policies/policies.errors';
import type {
  ActiveVersionRef,
  NewPolicy,
  PoliciesManagementRepository,
  PolicyPageWindow,
  PolicyRow,
  SettingsRow,
  VersionContent,
  VersionCounts,
  VersionPageWindow,
  VersionRow,
} from '../../src/modules/policies/repositories/policies-management.repository';
import type {
  DirectoryRows,
  PolicyFactsRepository,
  SnapshotRows,
} from '../../src/modules/policies/repositories/policy-facts.repository';

interface SettingsRecord {
  id: bigint;
  organizationId: bigint;
  generation: bigint;
  settings: unknown;
  settingsSha256: string;
  rowVersion: number;
  updatedByUserId: bigint | null;
  updatedAt: Date;
}

interface PolicyRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
  description: string | null;
  direction: PolicyRow['direction'];
  priority: number;
  status: PolicyRow['status'];
  activeVersionId: bigint | null;
  rowVersion: number;
  createdByUserId: bigint | null;
  updatedByUserId: bigint | null;
  deletedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface VersionRecord {
  id: bigint;
  organizationId: bigint;
  policyId: bigint;
  version: number;
  status: VersionRow['status'];
  definition: unknown;
  definitionSha256: string;
  dslVersion: string | null;
  references: unknown;
  hasOverrideRules: boolean;
  ruleCount: number;
  rowVersion: number;
  changeNote: string | null;
  createdByUserId: bigint | null;
  updatedByUserId: bigint | null;
  publishedByUserId: bigint | null;
  publishedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface DepartmentRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
  description: string | null;
  rowVersion: number;
  createdByUserId: bigint | null;
  updatedByUserId: bigint | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MemberRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  departmentId: bigint;
  address: string | null;
  userId: bigint | null;
  createdByUserId: bigint | null;
  createdAt: Date;
}

export interface UserRecord {
  publicId: string;
  organizationId: bigint;
  email: string;
  status: 'active' | 'invited' | 'disabled';
  deleted: boolean;
}

interface State {
  settings: SettingsRecord[];
  policies: PolicyRecord[];
  versions: VersionRecord[];
  departments: DepartmentRecord[];
  members: MemberRecord[];
  nextId: bigint;
}

const uuidOf = (n: bigint): string => `0190f0f0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;

/**
 * An in-memory stand-in for `PoliciesManagementRepository`, `DepartmentsRepository`, the
 * snapshot/directory reads of `PolicyFactsRepository` and the writer `TransactionRunner`, with the
 * semantics the services rely on: tenant filtering by the scope's organization, the lazily
 * created settings row, `status = 'draft'` + `row_version` compare-and-set, the policy
 * `row_version` CAS, generation increments, and a transaction that rolls every change back when
 * its callback throws. `calls` records every repository method called.
 */
export class InMemoryPolicies {
  private state: State = {
    settings: [],
    policies: [],
    versions: [],
    departments: [],
    members: [],
    nextId: 100n,
  };
  readonly calls: string[] = [];
  readonly txOptions: unknown[] = [];
  /** userId → user (the `createdBy`/`updatedBy` relations, users of the directory). */
  readonly users = new Map<bigint, UserRecord>();
  /** Active domains: `<organizationId>:<name>`. */
  readonly activeDomains = new Set<string>();
  private clock = Date.parse('2026-11-11T09:00:00.000Z');
  /** Next writer read of `read` throws an echo mismatch once (the 4.2 §6 defect), when set. */
  injectWrongRead: string | null = null;

  get policies(): readonly PolicyRecord[] {
    return this.state.policies;
  }
  get versions(): readonly VersionRecord[] {
    return this.state.versions;
  }
  get settingsRows(): readonly SettingsRecord[] {
    return this.state.settings;
  }
  get departmentRows(): readonly DepartmentRecord[] {
    return this.state.departments;
  }
  get memberRows(): readonly MemberRecord[] {
    return this.state.members;
  }
  generationOf(organizationId: bigint): bigint {
    return this.state.settings.find((s) => s.organizationId === organizationId)?.generation ?? 0n;
  }

  readonly transactions = {
    run: async <T>(fn: (tx: Prisma.TransactionClient) => Promise<T>, options?: unknown) => {
      this.txOptions.push(options);
      const before = structuredClone(this.state);
      try {
        return await fn({} as Prisma.TransactionClient);
      } catch (error) {
        this.state = before;
        throw error;
      }
    },
  };

  private now(): Date {
    this.clock += 1000;
    return new Date(this.clock);
  }
  private id(): bigint {
    this.state.nextId += 1n;
    return this.state.nextId;
  }
  private by(userId: bigint | null) {
    return userId === null ? null : { publicId: this.users.get(userId)?.publicId ?? '' };
  }
  private wrong(read: string): void {
    if (this.injectWrongRead === read) {
      this.injectWrongRead = null;
      throw new InconsistentPolicyReadError(read);
    }
  }
  private log(name: string): void {
    this.calls.push(name);
  }

  private policyRow(p: PolicyRecord): PolicyRow {
    return {
      id: p.id,
      publicId: p.publicId,
      organizationId: p.organizationId,
      name: p.name,
      description: p.description,
      direction: p.direction,
      priority: p.priority,
      status: p.status,
      activeVersionId: p.activeVersionId,
      rowVersion: p.rowVersion,
      deletedAt: p.deletedAt,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
      createdBy: this.by(p.createdByUserId),
      updatedBy: this.by(p.updatedByUserId),
    };
  }

  private versionRow(v: VersionRecord): VersionRow {
    return {
      id: v.id,
      organizationId: v.organizationId,
      policyId: v.policyId,
      version: v.version,
      status: v.status,
      definition: structuredClone(v.definition) as Prisma.JsonValue,
      definitionSha256: v.definitionSha256,
      dslVersion: v.dslVersion,
      references: structuredClone(v.references) as Prisma.JsonValue,
      hasOverrideRules: v.hasOverrideRules,
      ruleCount: v.ruleCount,
      rowVersion: v.rowVersion,
      changeNote: v.changeNote,
      publishedAt: v.publishedAt,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
      createdBy: this.by(v.createdByUserId),
      updatedBy: this.by(v.updatedByUserId),
      publishedBy: this.by(v.publishedByUserId),
    };
  }

  private settingsRow(s: SettingsRecord): SettingsRow {
    return {
      id: s.id,
      organizationId: s.organizationId,
      generation: s.generation,
      settings: structuredClone(s.settings) as Prisma.JsonValue,
      settingsSha256: s.settingsSha256,
      rowVersion: s.rowVersion,
      updatedAt: s.updatedAt,
      updatedBy: this.by(s.updatedByUserId),
    };
  }

  private counts(org: bigint, policyId: bigint): VersionCounts {
    const vs = this.state.versions.filter(
      (v) => v.organizationId === org && v.policyId === policyId,
    );
    return {
      drafts: vs.filter((v) => v.status === 'draft').length,
      published: vs.filter((v) => v.status === 'published').length,
      superseded: vs.filter((v) => v.status === 'superseded' || v.status === 'rolled_back').length,
    };
  }

  // ------------------------------------------------------------------- policies repository

  readonly repository: PoliciesManagementRepository = {
    findPolicy: (scope: TenantScope, publicId: string) => {
      this.log('findPolicy');
      const p = this.state.policies.find(
        (x) => x.organizationId === scope.organizationId && x.publicId === publicId && !x.deletedAt,
      );
      return Promise.resolve(p ? this.policyRow(p) : null);
    },
    listPolicies: (scope: TenantScope, page: PolicyPageWindow) => {
      this.log('listPolicies');
      const rows = this.state.policies
        .filter(
          (p) =>
            p.organizationId === scope.organizationId &&
            p.deletedAt === null &&
            (page.status === undefined ? p.status !== 'archived' : p.status === page.status) &&
            (page.direction === undefined || p.direction === page.direction) &&
            (page.beforeId === undefined || p.id < page.beforeId),
        )
        .sort((a, b) => (a.id > b.id ? -1 : 1))
        .slice(0, page.take);
      return Promise.resolve(rows.map((p) => this.policyRow(p)));
    },
    versionNumbers: (scope: TenantScope, policies: readonly PolicyRow[]) => {
      const out = new Map<bigint, { active: number | null; latest: number | null }>();
      for (const p of policies) {
        const vs = this.state.versions.filter(
          (v) => v.organizationId === scope.organizationId && v.policyId === p.id,
        );
        out.set(p.id, {
          active: vs.find((v) => v.id === p.activeVersionId)?.version ?? null,
          latest: vs.length === 0 ? null : Math.max(...vs.map((v) => v.version)),
        });
      }
      return Promise.resolve(out);
    },
    findVersion: (scope: TenantScope, policyId: bigint, versionNo: number) => {
      const v = this.state.versions.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.policyId === policyId &&
          x.version === versionNo,
      );
      return Promise.resolve(v ? this.versionRow(v) : null);
    },
    versionById: (scope: TenantScope, id: bigint) => {
      const v = this.state.versions.find(
        (x) => x.organizationId === scope.organizationId && x.id === id,
      );
      return Promise.resolve(v ? this.versionRow(v) : null);
    },
    listVersions: (scope: TenantScope, policyId: bigint, page: VersionPageWindow) => {
      const rows = this.state.versions
        .filter(
          (v) =>
            v.organizationId === scope.organizationId &&
            v.policyId === policyId &&
            (page.beforeId === undefined || v.id < page.beforeId) &&
            (page.status === undefined ||
              v.status === page.status ||
              (page.status === 'superseded' && v.status === 'rolled_back')),
        )
        .sort((a, b) => (a.id > b.id ? -1 : 1))
        .slice(0, page.take);
      return Promise.resolve(rows.map((v) => this.versionRow(v)));
    },
    countVersions: (scope: TenantScope, policyId: bigint) =>
      Promise.resolve(this.counts(scope.organizationId, policyId)),
    findSettings: (scope: TenantScope) => {
      const s = this.state.settings.find((x) => x.organizationId === scope.organizationId);
      return Promise.resolve(s ? this.settingsRow(s) : null);
    },
    lockSettings: (_tx: unknown, scope: TenantScope, emptySha256: string) => {
      this.log('lockSettings');
      this.wrong('policy_settings_lock');
      let s = this.state.settings.find((x) => x.organizationId === scope.organizationId);
      if (!s) {
        s = {
          id: this.id(),
          organizationId: scope.organizationId,
          generation: 0n,
          settings: {},
          settingsSha256: emptySha256,
          rowVersion: 1,
          updatedByUserId: null,
          updatedAt: this.now(),
        };
        this.state.settings.push(s);
      }
      return Promise.resolve(this.settingsRow(s));
    },
    bumpGeneration: (_tx: unknown, scope: TenantScope, settingsId: bigint) => {
      this.log('bumpGeneration');
      const s = this.state.settings.find(
        (x) => x.organizationId === scope.organizationId && x.id === settingsId,
      )!;
      s.generation += 1n;
      return Promise.resolve(s.generation);
    },
    generationTx: (_tx: unknown, scope: TenantScope) =>
      Promise.resolve(this.generationOf(scope.organizationId)),
    updateSettings: (
      _tx: unknown,
      scope: TenantScope,
      settingsId: bigint,
      expectedRowVersion: number,
      change: { settings: Prisma.InputJsonValue; settingsSha256: string },
      userId: bigint | null,
    ) => {
      this.log('updateSettings');
      const s = this.state.settings.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.id === settingsId &&
          x.rowVersion === expectedRowVersion,
      );
      if (!s) return Promise.resolve(false);
      Object.assign(s, {
        settings: structuredClone(change.settings),
        settingsSha256: change.settingsSha256,
        updatedByUserId: userId,
        rowVersion: s.rowVersion + 1,
        generation: s.generation + 1n,
        updatedAt: this.now(),
      });
      return Promise.resolve(true);
    },
    settingsAfterWrite: (_tx: unknown, scope: TenantScope, settingsId: bigint) =>
      Promise.resolve(
        this.settingsRow(
          this.state.settings.find(
            (x) => x.organizationId === scope.organizationId && x.id === settingsId,
          )!,
        ),
      ),
    policyForUpdate: (_tx: unknown, scope: TenantScope, publicId: string) => {
      this.log('policyForUpdate');
      this.wrong('email_policy');
      const p = this.state.policies.find(
        (x) => x.organizationId === scope.organizationId && x.publicId === publicId,
      );
      return Promise.resolve(
        p && p.deletedAt === null && p.status !== 'archived' ? this.policyRow(p) : null,
      );
    },
    policyAfterWrite: (_tx: unknown, scope: TenantScope, id: bigint) =>
      Promise.resolve(
        this.policyRow(
          this.state.policies.find(
            (x) => x.organizationId === scope.organizationId && x.id === id,
          )!,
        ),
      ),
    countPoliciesTx: (_tx: unknown, scope: TenantScope) =>
      Promise.resolve(
        this.state.policies.filter(
          (p) =>
            p.organizationId === scope.organizationId &&
            p.deletedAt === null &&
            p.status !== 'archived',
        ).length,
      ),
    nameTakenTx: (_tx: unknown, scope: TenantScope, name: string, exceptId: bigint | null) =>
      Promise.resolve(
        this.state.policies.some(
          (p) => p.organizationId === scope.organizationId && p.name === name && p.id !== exceptId,
        ),
      ),
    versionForUpdate: (_tx: unknown, scope: TenantScope, policyId: bigint, versionNo: number) => {
      this.log('versionForUpdate');
      const v = this.state.versions.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.policyId === policyId &&
          x.version === versionNo,
      );
      return Promise.resolve(v ? this.versionRow(v) : null);
    },
    versionByIdTx: (_tx: unknown, scope: TenantScope, id: bigint) =>
      this.repository.versionById(scope, id),
    versionAfterWrite: async (_tx: unknown, scope: TenantScope, id: bigint) =>
      (await this.repository.versionById(scope, id))!,
    countVersionsTx: (_tx: unknown, scope: TenantScope, policyId: bigint) =>
      Promise.resolve(this.counts(scope.organizationId, policyId)),
    maxVersionNo: (_tx: unknown, scope: TenantScope, policyId: bigint) => {
      const vs = this.state.versions.filter(
        (v) => v.organizationId === scope.organizationId && v.policyId === policyId,
      );
      return Promise.resolve(vs.length === 0 ? 0 : Math.max(...vs.map((v) => v.version)));
    },
    newestDraftTx: (_tx: unknown, scope: TenantScope, policyId: bigint) => {
      const v = this.state.versions
        .filter(
          (x) =>
            x.organizationId === scope.organizationId &&
            x.policyId === policyId &&
            x.status === 'draft',
        )
        .sort((a, b) => b.version - a.version)[0];
      return Promise.resolve(v ? this.versionRow(v) : null);
    },
    activeVersionsTx: (_tx: unknown, scope: TenantScope) => {
      const out: ActiveVersionRef[] = [];
      for (const p of this.state.policies) {
        if (p.organizationId !== scope.organizationId || p.status !== 'active' || p.deletedAt) {
          continue;
        }
        const v = this.state.versions.find(
          (x) => x.id === p.activeVersionId && x.status === 'published',
        );
        if (!v) continue;
        out.push({
          policyId: p.id,
          policyPublicId: p.publicId,
          versionId: v.id,
          versionNo: v.version,
          ruleCount: v.ruleCount,
          definition: structuredClone(v.definition),
          definitionSha256: v.definitionSha256,
          references: structuredClone(v.references),
        });
      }
      return Promise.resolve(out);
    },
    existingDirectoryIdsTx: (
      _tx: unknown,
      scope: TenantScope,
      refs: { departmentIds: readonly string[]; userIds: readonly string[] },
    ) =>
      Promise.resolve({
        departmentIds: new Set(
          this.state.departments
            .filter(
              (d) =>
                d.organizationId === scope.organizationId &&
                refs.departmentIds.includes(d.publicId),
            )
            .map((d) => d.publicId),
        ),
        userIds: new Set(
          [...this.users.values()]
            .filter(
              (u) =>
                u.organizationId === scope.organizationId &&
                !u.deleted &&
                refs.userIds.includes(u.publicId),
            )
            .map((u) => u.publicId),
        ),
      }),
    createPolicy: (_tx: unknown, scope: TenantScope, data: NewPolicy, userId: bigint | null) => {
      this.log('createPolicy');
      const at = this.now();
      const p: PolicyRecord = {
        ...data,
        id: this.id(),
        organizationId: scope.organizationId,
        status: 'draft',
        activeVersionId: null,
        rowVersion: 1,
        createdByUserId: userId,
        updatedByUserId: userId,
        deletedAt: null,
        createdAt: at,
        updatedAt: at,
      };
      this.state.policies.push(p);
      return Promise.resolve(this.policyRow(p));
    },
    updatePolicy: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      expectedRowVersion: number,
      data: Prisma.EmailPolicyUncheckedUpdateManyInput,
      userId: bigint | null,
    ) => {
      this.log('updatePolicy');
      const p = this.state.policies.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.id === id &&
          x.rowVersion === expectedRowVersion &&
          x.deletedAt === null &&
          x.status !== 'archived',
      );
      if (!p) return Promise.resolve(false);
      Object.assign(p, data, {
        updatedByUserId: userId,
        rowVersion: p.rowVersion + 1,
        updatedAt: this.now(),
      });
      return Promise.resolve(true);
    },
    createVersion: (
      _tx: unknown,
      scope: TenantScope,
      data: VersionContent & { policyId: bigint; version: number; changeNote: string | null },
      userId: bigint | null,
    ) => {
      this.log('createVersion');
      if (
        this.state.versions.some((v) => v.policyId === data.policyId && v.version === data.version)
      ) {
        throw new Error('unique (policy_id, version)');
      }
      const at = this.now();
      const v: VersionRecord = {
        ...data,
        definition: structuredClone(data.definition),
        references: structuredClone(data.references),
        id: this.id(),
        organizationId: scope.organizationId,
        status: 'draft',
        rowVersion: 1,
        createdByUserId: userId,
        updatedByUserId: userId,
        publishedByUserId: null,
        publishedAt: null,
        createdAt: at,
        updatedAt: at,
      };
      this.state.versions.push(v);
      return Promise.resolve(this.versionRow(v));
    },
    updateDraft: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      expectedRowVersion: number,
      change: VersionContent & { changeNote: string | null },
      userId: bigint | null,
    ) => {
      this.log('updateDraft');
      const v = this.state.versions.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.id === id &&
          x.status === 'draft' &&
          x.rowVersion === expectedRowVersion,
      );
      if (!v) return Promise.resolve(false);
      Object.assign(v, structuredClone(change), {
        updatedByUserId: userId,
        rowVersion: v.rowVersion + 1,
        updatedAt: this.now(),
      });
      return Promise.resolve(true);
    },
    deleteDraft: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      expectedRowVersion: number | undefined,
    ) => {
      this.log('deleteDraft');
      const index = this.state.versions.findIndex(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.id === id &&
          x.status === 'draft' &&
          (expectedRowVersion === undefined || x.rowVersion === expectedRowVersion),
      );
      if (index === -1) return Promise.resolve(false);
      this.state.versions.splice(index, 1);
      return Promise.resolve(true);
    },
    publishDraft: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      expectedRowVersion: number,
      content: VersionContent,
      at: Date,
      userId: bigint | null,
    ) => {
      this.log('publishDraft');
      const v = this.state.versions.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.id === id &&
          x.status === 'draft' &&
          x.rowVersion === expectedRowVersion,
      );
      if (!v) return Promise.resolve(false);
      Object.assign(v, structuredClone(content), {
        status: 'published',
        publishedAt: at,
        publishedByUserId: userId,
        updatedByUserId: userId,
        rowVersion: v.rowVersion + 1,
        updatedAt: this.now(),
      });
      return Promise.resolve(true);
    },
  } as unknown as PoliciesManagementRepository;

  // ---------------------------------------------------------- facts (snapshot, directory)

  readonly facts: Pick<PolicyFactsRepository, 'snapshot' | 'policyVersion' | 'directory'> = {
    snapshot: (scope: TenantScope): Promise<SnapshotRows> => {
      this.log('snapshot');
      const s = this.state.settings.find((x) => x.organizationId === scope.organizationId);
      const policies: SnapshotRows['policies'] = [];
      for (const p of this.state.policies) {
        if (p.organizationId !== scope.organizationId || p.status !== 'active' || p.deletedAt) {
          continue;
        }
        const v = this.state.versions.find(
          (x) => x.id === p.activeVersionId && x.status === 'published',
        );
        if (v) {
          policies.push({
            policyId: p.id,
            publicId: p.publicId,
            versionNo: v.version,
            definition: structuredClone(v.definition) as Prisma.JsonValue,
            definitionSha256: v.definitionSha256,
          });
        }
      }
      return Promise.resolve({
        generation: s?.generation ?? 0n,
        settings: s?.settings ?? null,
        policies,
      });
    },
    policyVersion: (scope: TenantScope, policyPublicId: string, versionNo: number) => {
      const p = this.state.policies.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.publicId === policyPublicId &&
          x.deletedAt === null,
      );
      const v = p
        ? this.state.versions.find((x) => x.policyId === p.id && x.version === versionNo)
        : undefined;
      return Promise.resolve(
        p && v
          ? {
              policyId: p.id,
              publicId: p.publicId,
              status: v.status,
              definition: structuredClone(v.definition) as Prisma.JsonValue,
              definitionSha256: v.definitionSha256,
            }
          : null,
      );
    },
    directory: (
      scope: TenantScope,
      addresses: readonly string[],
      refs: { departmentIds: readonly string[]; userIds: readonly string[] },
    ): Promise<DirectoryRows> => {
      const out: DirectoryRows = { departmentPairs: [], userPairs: [] };
      const emailOf = (id: bigint | null) => {
        const u = id === null ? undefined : this.users.get(id);
        return u && u.status === 'active' && !u.deleted ? u.email : undefined;
      };
      for (const [, u] of this.users) {
        if (
          u.organizationId === scope.organizationId &&
          u.status === 'active' &&
          !u.deleted &&
          refs.userIds.includes(u.publicId) &&
          addresses.includes(u.email)
        ) {
          out.userPairs.push([u.email, u.publicId]);
        }
      }
      for (const m of this.state.members) {
        const d = this.state.departments.find((x) => x.id === m.departmentId);
        if (!d || d.organizationId !== scope.organizationId) continue;
        if (!refs.departmentIds.includes(d.publicId)) continue;
        const address = m.address ?? emailOf(m.userId);
        if (address !== undefined && addresses.includes(address)) {
          out.departmentPairs.push([address, d.publicId]);
        }
      }
      return Promise.resolve(out);
    },
  };

  // --------------------------------------------------------------- departments repository

  private departmentRow(d: DepartmentRecord): DepartmentRow {
    return {
      id: d.id,
      publicId: d.publicId,
      organizationId: d.organizationId,
      name: d.name,
      description: d.description,
      rowVersion: d.rowVersion,
      createdAt: d.createdAt,
      updatedAt: d.updatedAt,
      createdBy: this.by(d.createdByUserId),
      updatedBy: this.by(d.updatedByUserId),
      _count: { members: this.state.members.filter((m) => m.departmentId === d.id).length },
    };
  }

  private memberRow(m: MemberRecord): MemberRow {
    return {
      id: m.id,
      publicId: m.publicId,
      organizationId: m.organizationId,
      departmentId: m.departmentId,
      address: m.address,
      createdAt: m.createdAt,
      user: this.by(m.userId),
      createdBy: this.by(m.createdByUserId),
    };
  }

  private dept(scope: TenantScope, publicId: string) {
    return this.state.departments.find(
      (d) => d.organizationId === scope.organizationId && d.publicId === publicId,
    );
  }

  readonly departments: DepartmentsRepository = {
    list: (scope: TenantScope, page: { take: number; beforeId?: bigint }) =>
      Promise.resolve(
        this.state.departments
          .filter(
            (d) =>
              d.organizationId === scope.organizationId &&
              (page.beforeId === undefined || d.id < page.beforeId),
          )
          .sort((a, b) => (a.id > b.id ? -1 : 1))
          .slice(0, page.take)
          .map((d) => this.departmentRow(d)),
      ),
    find: (scope: TenantScope, publicId: string) => {
      const d = this.dept(scope, publicId);
      return Promise.resolve(d ? this.departmentRow(d) : null);
    },
    listMembers: (
      scope: TenantScope,
      departmentId: bigint,
      page: { take: number; beforeId?: bigint },
    ) =>
      Promise.resolve(
        this.state.members
          .filter(
            (m) =>
              m.organizationId === scope.organizationId &&
              m.departmentId === departmentId &&
              (page.beforeId === undefined || m.id < page.beforeId),
          )
          .sort((a, b) => (a.id > b.id ? -1 : 1))
          .slice(0, page.take)
          .map((m) => this.memberRow(m)),
      ),
    forUpdate: (_tx: unknown, scope: TenantScope, publicId: string) => {
      const d = this.dept(scope, publicId);
      return Promise.resolve(d ? this.departmentRow(d) : null);
    },
    afterWrite: (_tx: unknown, scope: TenantScope, id: bigint) =>
      Promise.resolve(
        this.departmentRow(
          this.state.departments.find(
            (d) => d.organizationId === scope.organizationId && d.id === id,
          )!,
        ),
      ),
    countTx: (_tx: unknown, scope: TenantScope) =>
      Promise.resolve(
        this.state.departments.filter((d) => d.organizationId === scope.organizationId).length,
      ),
    nameTakenTx: (_tx: unknown, scope: TenantScope, name: string, exceptId: bigint | null) =>
      Promise.resolve(
        this.state.departments.some(
          (d) => d.organizationId === scope.organizationId && d.name === name && d.id !== exceptId,
        ),
      ),
    countMembersTx: (_tx: unknown, scope: TenantScope, departmentId: bigint) =>
      Promise.resolve(
        this.state.members.filter(
          (m) => m.organizationId === scope.organizationId && m.departmentId === departmentId,
        ).length,
      ),
    memberForUpdate: (_tx: unknown, scope: TenantScope, departmentId: bigint, publicId: string) => {
      const m = this.state.members.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.departmentId === departmentId &&
          x.publicId === publicId,
      );
      return Promise.resolve(m ? this.memberRow(m) : null);
    },
    memberExistsTx: (
      _tx: unknown,
      scope: TenantScope,
      departmentId: bigint,
      key: { address: string } | { userId: bigint },
    ) =>
      Promise.resolve(
        this.state.members.some(
          (m) =>
            m.organizationId === scope.organizationId &&
            m.departmentId === departmentId &&
            ('address' in key ? m.address === key.address : m.userId === key.userId),
        ),
      ),
    activeDomainTx: (_tx: unknown, scope: TenantScope, domain: string) =>
      Promise.resolve(this.activeDomains.has(`${scope.organizationId.toString()}:${domain}`)),
    userTx: (_tx: unknown, scope: TenantScope, publicId: string) => {
      for (const [id, u] of this.users) {
        if (u.organizationId === scope.organizationId && u.publicId === publicId && !u.deleted) {
          return Promise.resolve(id);
        }
      }
      return Promise.resolve(null);
    },
    create: (
      _tx: unknown,
      scope: TenantScope,
      data: { publicId: string; name: string; description: string | null },
      userId: bigint | null,
    ) => {
      const at = this.now();
      const d: DepartmentRecord = {
        ...data,
        id: this.id(),
        organizationId: scope.organizationId,
        rowVersion: 1,
        createdByUserId: userId,
        updatedByUserId: userId,
        createdAt: at,
        updatedAt: at,
      };
      this.state.departments.push(d);
      return Promise.resolve(this.departmentRow(d));
    },
    update: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      expectedRowVersion: number,
      data: { name?: string; description?: string | null },
      userId: bigint | null,
    ) => {
      const d = this.state.departments.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          x.id === id &&
          x.rowVersion === expectedRowVersion,
      );
      if (!d) return Promise.resolve(false);
      Object.assign(d, data, {
        updatedByUserId: userId,
        rowVersion: d.rowVersion + 1,
        updatedAt: this.now(),
      });
      return Promise.resolve(true);
    },
    delete: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      expectedRowVersion: number | undefined,
    ) => {
      const before = this.state.members.length;
      this.state.members = this.state.members.filter(
        (m) => !(m.organizationId === scope.organizationId && m.departmentId === id),
      );
      const members = before - this.state.members.length;
      const index = this.state.departments.findIndex(
        (d) =>
          d.organizationId === scope.organizationId &&
          d.id === id &&
          (expectedRowVersion === undefined || d.rowVersion === expectedRowVersion),
      );
      if (index !== -1) this.state.departments.splice(index, 1);
      return Promise.resolve({ deleted: index !== -1, members });
    },
    createMember: (
      _tx: unknown,
      scope: TenantScope,
      data: { publicId: string; departmentId: bigint; address?: string; userId?: bigint },
      createdBy: bigint | null,
    ) => {
      const m: MemberRecord = {
        id: this.id(),
        publicId: data.publicId,
        organizationId: scope.organizationId,
        departmentId: data.departmentId,
        address: data.address ?? null,
        userId: data.userId ?? null,
        createdByUserId: createdBy,
        createdAt: this.now(),
      };
      if ((m.address === null) === (m.userId === null)) throw new Error('exactly one');
      this.state.members.push(m);
      return Promise.resolve(this.memberRow(m));
    },
    deleteMember: (_tx: unknown, scope: TenantScope, id: bigint) => {
      const index = this.state.members.findIndex(
        (m) => m.organizationId === scope.organizationId && m.id === id,
      );
      if (index !== -1) this.state.members.splice(index, 1);
      return Promise.resolve(index !== -1);
    },
  } as unknown as DepartmentsRepository;

  /** A user of the directory (also the actor public id for `createdBy`). */
  addUser(id: bigint, user: Partial<UserRecord> & { organizationId: bigint }): UserRecord {
    const record: UserRecord = {
      publicId: uuidOf(id),
      email: `user${id.toString()}@acme.example`,
      status: 'active',
      deleted: false,
      ...user,
    };
    this.users.set(id, record);
    return record;
  }
}
