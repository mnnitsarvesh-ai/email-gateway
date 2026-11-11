import type { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type {
  DraftChange,
  NewVersion,
  ProfileRow,
  RiskProfilesRepository,
  VersionCounts,
  VersionPage,
  VersionRow,
} from '../../src/modules/risk-scoring/repositories/risk-profiles.repository';
import { InconsistentRiskReadError } from '../../src/modules/risk-scoring/risk-scoring.errors';

interface ProfileRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  activeVersionId: bigint | null;
  version: number;
  updatedByUserId: bigint | null;
  updatedAt: Date;
}

interface VersionRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  profileId: bigint;
  versionNo: number;
  status: 'draft' | 'published';
  baseProfile: string;
  overrides: unknown;
  overridesSha256: string;
  profileSha256: string | null;
  changeNote: string | null;
  rowVersion: number;
  createdByUserId: bigint | null;
  updatedByUserId: bigint | null;
  publishedByUserId: bigint | null;
  publishedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface State {
  profiles: ProfileRecord[];
  versions: VersionRecord[];
  nextId: bigint;
}

const clone = (state: State): State => structuredClone(state);

/**
 * An in-memory stand-in for `RiskProfilesRepository` and the writer `TransactionRunner` with the
 * real semantics the service relies on: tenant filtering by the scope's organization,
 * `status = 'draft'` + `row_version` compare-and-set, the profile `version` CAS, and a
 * transaction that rolls every change back when its callback throws. `calls` records every
 * repository method called (to prove a code path wrote nothing).
 */
export class InMemoryRiskProfiles {
  private state: State = { profiles: [], versions: [], nextId: 100n };
  readonly calls: string[] = [];
  readonly txOptions: unknown[] = [];
  /** userId → public id (the `createdBy`/`updatedBy`/`publishedBy` relations). */
  readonly users = new Map<bigint, string>();
  private clock = Date.parse('2026-11-11T09:00:00.000Z');

  /** Next writer read of `read` returns a wrong row once (the 4.2 §6 defect), when set. */
  injectWrongRead: string | null = null;

  get versions(): readonly VersionRecord[] {
    return this.state.versions;
  }

  get profiles(): readonly ProfileRecord[] {
    return this.state.profiles;
  }

  readonly transactions = {
    run: async <T>(fn: (tx: Prisma.TransactionClient) => Promise<T>, options?: unknown) => {
      this.txOptions.push(options);
      const before = clone(this.state);
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
    return userId === null ? null : { publicId: this.users.get(userId) ?? '' };
  }

  private profileRow(p: ProfileRecord): ProfileRow {
    return {
      id: p.id,
      publicId: p.publicId,
      organizationId: p.organizationId,
      activeVersionId: p.activeVersionId,
      version: p.version,
      updatedAt: p.updatedAt,
      updatedBy: this.by(p.updatedByUserId),
    };
  }

  private versionRow(v: VersionRecord): VersionRow {
    return {
      id: v.id,
      publicId: v.publicId,
      organizationId: v.organizationId,
      profileId: v.profileId,
      versionNo: v.versionNo,
      status: v.status,
      baseProfile: v.baseProfile,
      overrides: structuredClone(v.overrides) as Prisma.JsonValue,
      overridesSha256: v.overridesSha256,
      profileSha256: v.profileSha256,
      changeNote: v.changeNote,
      rowVersion: v.rowVersion,
      publishedAt: v.publishedAt,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
      createdBy: this.by(v.createdByUserId),
      updatedBy: this.by(v.updatedByUserId),
      publishedBy: this.by(v.publishedByUserId),
    };
  }

  private counts(scope: TenantScope): VersionCounts {
    const mine = this.state.versions.filter((v) => v.organizationId === scope.organizationId);
    return {
      drafts: mine.filter((v) => v.status === 'draft').length,
      published: mine.filter((v) => v.status === 'published').length,
    };
  }

  private profileOf(scope: TenantScope): ProfileRecord | undefined {
    return this.state.profiles.find((p) => p.organizationId === scope.organizationId);
  }

  private versionOf(scope: TenantScope, match: (v: VersionRecord) => boolean) {
    return this.state.versions.find((v) => v.organizationId === scope.organizationId && match(v));
  }

  /** A wrong-read stand-in: the row of another key when `read` is armed. */
  private maybeWrong<T extends { organizationId: bigint }>(read: string, row: T | null): T | null {
    if (this.injectWrongRead !== read || row === null) return row;
    this.injectWrongRead = null;
    return { ...row, organizationId: row.organizationId + 1000n };
  }

  /** The repository surface the services use. */
  readonly repository: RiskProfilesRepository = (() => {
    const track =
      <A extends unknown[], R>(name: string, fn: (...args: A) => R) =>
      (...args: A): R => {
        this.calls.push(name);
        return fn(...args);
      };
    const echo = <T extends { organizationId: bigint }>(
      scope: TenantScope,
      read: string,
      row: T | null,
    ): Promise<T | null> => {
      const result = this.maybeWrong(read, row);
      if (result !== null && result.organizationId !== scope.organizationId) {
        return Promise.reject(new InconsistentRiskReadError(read));
      }
      return Promise.resolve(result);
    };
    const repo = {
      findProfile: track('findProfile', (scope: TenantScope) => {
        const p = this.profileOf(scope);
        return Promise.resolve(p ? this.profileRow(p) : null);
      }),
      findVersion: track('findVersion', (scope: TenantScope, publicId: string) => {
        const v = this.versionOf(scope, (x) => x.publicId === publicId);
        return Promise.resolve(v ? this.versionRow(v) : null);
      }),
      versionById: track('versionById', (scope: TenantScope, id: bigint) => {
        const v = this.versionOf(scope, (x) => x.id === id);
        return Promise.resolve(v ? this.versionRow(v) : null);
      }),
      listVersions: track('listVersions', (scope: TenantScope, page: VersionPage) => {
        const rows = this.state.versions
          .filter(
            (v) =>
              v.organizationId === scope.organizationId &&
              (page.beforeId === undefined || v.id < page.beforeId) &&
              (page.status === undefined || v.status === page.status),
          )
          .sort((a, b) => (a.id < b.id ? 1 : -1))
          .slice(0, page.take)
          .map((v) => this.versionRow(v));
        return Promise.resolve(rows);
      }),
      countVersions: track('countVersions', (scope: TenantScope) =>
        Promise.resolve(this.counts(scope)),
      ),
      lockOrganization: track('lockOrganization', () => Promise.resolve()),
      profileForUpdate: track('profileForUpdate', (_tx: unknown, scope: TenantScope) => {
        const p = this.profileOf(scope);
        return echo(scope, 'risk_profile', p ? this.profileRow(p) : null);
      }),
      createProfile: track(
        'createProfile',
        (_tx: unknown, scope: TenantScope, publicId: string, userId: bigint | null) => {
          if (this.profileOf(scope)) throw new Error('unique organization_id');
          const record: ProfileRecord = {
            id: this.id(),
            publicId,
            organizationId: scope.organizationId,
            activeVersionId: null,
            version: 1,
            updatedByUserId: userId,
            updatedAt: this.now(),
          };
          this.state.profiles.push(record);
          return Promise.resolve(this.profileRow(record));
        },
      ),
      versionForUpdate: track(
        'versionForUpdate',
        (_tx: unknown, scope: TenantScope, publicId: string) => {
          const v = this.versionOf(scope, (x) => x.publicId === publicId);
          return echo(scope, 'risk_profile_version', v ? this.versionRow(v) : null);
        },
      ),
      versionByIdTx: track('versionByIdTx', (_tx: unknown, scope: TenantScope, id: bigint) => {
        const v = this.versionOf(scope, (x) => x.id === id);
        return echo(scope, 'risk_profile_version_id', v ? this.versionRow(v) : null);
      }),
      versionAfterWrite: track(
        'versionAfterWrite',
        (_tx: unknown, scope: TenantScope, id: bigint) => {
          const v = this.versionOf(scope, (x) => x.id === id);
          if (!v) throw new Error('version vanished');
          return Promise.resolve(this.versionRow(v));
        },
      ),
      profileAfterWrite: track(
        'profileAfterWrite',
        (_tx: unknown, scope: TenantScope, id: bigint) => {
          const p = this.profileOf(scope);
          if (!p || p.id !== id) throw new Error('profile vanished');
          return Promise.resolve(this.profileRow(p));
        },
      ),
      countVersionsTx: track('countVersionsTx', (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(this.counts(scope)),
      ),
      maxVersionNo: track('maxVersionNo', (_tx: unknown, scope: TenantScope, profileId: bigint) =>
        Promise.resolve(
          this.state.versions
            .filter((v) => v.organizationId === scope.organizationId && v.profileId === profileId)
            .reduce((max, v) => Math.max(max, v.versionNo), 0),
        ),
      ),
      createVersion: track(
        'createVersion',
        (_tx: unknown, scope: TenantScope, data: NewVersion, userId: bigint | null) => {
          if (
            this.state.versions.some(
              (v) => v.profileId === data.profileId && v.versionNo === data.versionNo,
            )
          ) {
            throw new Error('unique (profile_id, version_no)');
          }
          const at = this.now();
          const record: VersionRecord = {
            id: this.id(),
            publicId: data.publicId,
            organizationId: scope.organizationId,
            profileId: data.profileId,
            versionNo: data.versionNo,
            status: 'draft',
            baseProfile: data.baseProfile,
            overrides: structuredClone(data.overrides),
            overridesSha256: data.overridesSha256,
            profileSha256: null,
            changeNote: data.changeNote,
            rowVersion: 1,
            createdByUserId: userId,
            updatedByUserId: userId,
            publishedByUserId: null,
            publishedAt: null,
            createdAt: at,
            updatedAt: at,
          };
          this.state.versions.push(record);
          return Promise.resolve(this.versionRow(record));
        },
      ),
      updateDraft: track(
        'updateDraft',
        (
          _tx: unknown,
          scope: TenantScope,
          id: bigint,
          expectedRowVersion: number,
          change: DraftChange,
          userId: bigint | null,
        ) => {
          const v = this.versionOf(
            scope,
            (x) => x.id === id && x.status === 'draft' && x.rowVersion === expectedRowVersion,
          );
          if (!v) return Promise.resolve(false);
          Object.assign(v, {
            overrides: structuredClone(change.overrides),
            overridesSha256: change.overridesSha256,
            changeNote: change.changeNote,
            updatedByUserId: userId,
            rowVersion: v.rowVersion + 1,
            updatedAt: this.now(),
          });
          return Promise.resolve(true);
        },
      ),
      deleteDraft: track(
        'deleteDraft',
        (_tx: unknown, scope: TenantScope, id: bigint, expectedRowVersion: number | undefined) => {
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
      ),
      publishDraft: track(
        'publishDraft',
        (
          _tx: unknown,
          scope: TenantScope,
          id: bigint,
          expectedRowVersion: number,
          published: { profileSha256: string; at: Date },
          userId: bigint | null,
        ) => {
          const v = this.versionOf(
            scope,
            (x) => x.id === id && x.status === 'draft' && x.rowVersion === expectedRowVersion,
          );
          if (!v) return Promise.resolve(false);
          Object.assign(v, {
            status: 'published',
            profileSha256: published.profileSha256,
            publishedAt: published.at,
            publishedByUserId: userId,
            updatedByUserId: userId,
            rowVersion: v.rowVersion + 1,
            updatedAt: this.now(),
          });
          return Promise.resolve(true);
        },
      ),
      movePointer: track(
        'movePointer',
        (
          _tx: unknown,
          scope: TenantScope,
          profileId: bigint,
          expectedVersion: number,
          activeVersionId: bigint | null,
          userId: bigint | null,
        ) => {
          const p = this.profileOf(scope);
          if (!p || p.id !== profileId || p.version !== expectedVersion) {
            return Promise.resolve(false);
          }
          Object.assign(p, {
            activeVersionId,
            updatedByUserId: userId,
            version: p.version + 1,
            updatedAt: this.now(),
          });
          return Promise.resolve(true);
        },
      ),
    };
    return repo as unknown as RiskProfilesRepository;
  })();

  /** Test hook: patch a stored version (e.g. to simulate a retired base profile). */
  forceVersion(publicId: string, patch: Partial<VersionRecord>): void {
    const v = this.state.versions.find((x) => x.publicId === publicId);
    if (!v) throw new Error('unknown version');
    Object.assign(v, patch);
  }
}
