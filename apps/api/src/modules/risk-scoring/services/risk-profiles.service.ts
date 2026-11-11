import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import {
  changedPaths,
  checkOverrides,
  platformProfileView,
  profileView,
  resolveVersion,
  versionDetail,
  versionSummary,
} from '../domain/risk-profile';
import type {
  RiskPlatformProfileView,
  RiskPointerChange,
  RiskProfileView,
  RiskPublishResult,
  RiskVersionCreate,
  RiskVersionDetail,
  RiskVersionListQuery,
  RiskVersionPage,
  RiskVersionPublish,
  RiskVersionUpdate,
} from '../dto/risk-scoring.schemas';
import {
  type ProfileRow,
  RiskProfilesRepository,
  type VersionRow,
} from '../repositories/risk-profiles.repository';
import {
  InconsistentRiskReadError,
  riskProfileInvalid,
  riskProfileLimitReached,
  riskProfileVersionConflict,
  riskProfileVersionImmutable,
  riskProfileVersionNotFound,
  riskProfileVersionNotPublished,
} from '../risk-scoring.errors';
import {
  RISK_AUDIT,
  RISK_RESOURCE,
  RiskAuditor,
  RiskMetrics,
  type RiskProfileOperation,
  RiskWriter,
  userIdOf,
} from './risk-writer';

type Settings = { RISK_PLATFORM_PROFILE: string; RISK_PROFILE_MAX_VERSIONS: number };
type Tx = Prisma.TransactionClient;

/**
 * The organization's risk scoring profile and its versions (step 5.1 R10, R15; ADR-0041 decision
 * 7). Reads use the replica. Writes run on the writer (120 s budget, one retry on an echo-check
 * mismatch) under the organization row lock: the profile row is created lazily, versions are
 * numbered 1, 2, … per profile and capped at RISK_PROFILE_MAX_VERSIONS; drafts change only
 * `WHERE status = 'draft'` with a `row_version` compare-and-set, so published versions are
 * immutable; activation, rollback and reset move the pointer with the profile `version`
 * compare-and-set. Every change writes its audit row in the same transaction (ids, numbers,
 * hashes and changed override paths only). The organization always comes from the
 * authenticated scope. A change applies to rounds opened afterwards only (the round snapshots
 * the pointer, R13).
 */
@Injectable()
export class RiskProfilesService {
  private readonly logger = new Logger(RiskProfilesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly repository: RiskProfilesRepository,
    private readonly writer: RiskWriter,
    private readonly auditor: RiskAuditor,
    private readonly metrics: RiskMetrics,
  ) {}

  private get platformId(): string {
    return this.settings.RISK_PLATFORM_PROFILE;
  }

  platform(): RiskPlatformProfileView {
    return platformProfileView(this.platformId);
  }

  async profile(scope: TenantScope): Promise<RiskProfileView> {
    const profile = await this.repository.findProfile(scope);
    const [active, counts] = await Promise.all([
      profile?.activeVersionId != null
        ? this.repository.versionById(scope, profile.activeVersionId)
        : Promise.resolve(null),
      this.repository.countVersions(scope),
    ]);
    return profileView(
      this.platformId,
      this.settings.RISK_PROFILE_MAX_VERSIONS,
      profile,
      active,
      counts,
    );
  }

  async listVersions(scope: TenantScope, query: RiskVersionListQuery): Promise<RiskVersionPage> {
    const [profile, rows] = await Promise.all([
      this.repository.findProfile(scope),
      this.repository.listVersions(scope, {
        ...pageWindow(query),
        ...(query.status !== undefined && { status: query.status }),
      }),
    ]);
    const activeId = profile?.activeVersionId ?? null;
    return toPage(rows, query.limit, (row) => versionSummary(row, activeId));
  }

  async getVersion(scope: TenantScope, versionId: string): Promise<RiskVersionDetail> {
    const [profile, row] = await Promise.all([
      this.repository.findProfile(scope),
      this.repository.findVersion(scope, versionId),
    ]);
    if (!row) throw riskProfileVersionNotFound();
    return versionDetail(row, profile?.activeVersionId ?? null, this.platformId);
  }

  async createDraft(
    principal: Principal,
    scope: TenantScope,
    body: RiskVersionCreate,
    client: ClientContext,
  ): Promise<RiskVersionDetail> {
    // Without a source version the document is checked before any database access.
    if (body.basedOnVersionId === undefined) {
      const early = checkOverrides(body.overrides ?? {}, this.platformId);
      if (!early.ok) throw riskProfileInvalid(early.violations);
    }
    const view = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      let profile = await this.repository.profileForUpdate(tx, scope);
      let baseProfile = this.platformId;
      let doc: unknown = body.overrides;
      let basedOn: VersionRow | null = null;
      if (body.basedOnVersionId !== undefined) {
        basedOn = await this.repository.versionForUpdate(tx, scope, body.basedOnVersionId);
        if (!basedOn) throw riskProfileVersionNotFound();
        baseProfile = basedOn.baseProfile;
        doc ??= basedOn.overrides;
      }
      const check = checkOverrides(doc ?? {}, baseProfile);
      if (!check.ok) throw riskProfileInvalid(check.violations);
      const counts = await this.repository.countVersionsTx(tx, scope);
      const limit = this.settings.RISK_PROFILE_MAX_VERSIONS;
      if (counts.drafts + counts.published >= limit) throw riskProfileLimitReached(limit);
      profile ??= await this.repository.createProfile(tx, scope, uuidv7(), userIdOf(principal));
      const versionNo = (await this.repository.maxVersionNo(tx, scope, profile.id)) + 1;
      const row = await this.repository.createVersion(
        tx,
        scope,
        {
          publicId: uuidv7(),
          profileId: profile.id,
          versionNo,
          baseProfile,
          overrides: check.overrides,
          overridesSha256: check.sha256,
          changeNote: body.changeNote ?? null,
        },
        userIdOf(principal),
      );
      await this.record(tx, principal, scope, client, RISK_AUDIT.draftCreated, row.publicId, {
        versionId: row.publicId,
        versionNo: row.versionNo,
        baseProfile,
        overridesSha256: row.overridesSha256,
        basedOnVersionId: basedOn?.publicId ?? null,
        basedOnVersionNo: basedOn?.versionNo ?? null,
        changedPaths: changedPaths({}, check.overrides),
      });
      return versionDetail(row, profile.activeVersionId, this.platformId);
    });
    this.changed('draft_created', scope, view.id, view.versionNo);
    return view;
  }

  async updateDraft(
    principal: Principal,
    scope: TenantScope,
    versionId: string,
    body: RiskVersionUpdate,
    client: ClientContext,
  ): Promise<RiskVersionDetail> {
    const view = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.draftForChange(tx, scope, versionId, body.expectedRowVersion);
      const check = checkOverrides(body.overrides, current.baseProfile);
      if (!check.ok) throw riskProfileInvalid(check.violations);
      const changed = await this.repository.updateDraft(
        tx,
        scope,
        current.id,
        body.expectedRowVersion,
        {
          overrides: check.overrides,
          overridesSha256: check.sha256,
          changeNote: body.changeNote === undefined ? current.changeNote : body.changeNote,
        },
        userIdOf(principal),
      );
      if (!changed) throw riskProfileVersionConflict('rowVersion', current.rowVersion);
      const row = await this.repository.versionAfterWrite(tx, scope, current.id);
      await this.record(tx, principal, scope, client, RISK_AUDIT.draftUpdated, row.publicId, {
        versionId: row.publicId,
        versionNo: row.versionNo,
        rowVersion: row.rowVersion,
        overridesSha256Before: current.overridesSha256,
        overridesSha256: row.overridesSha256,
        changedPaths: changedPaths(current.overrides, check.overrides),
      });
      const profile = await this.repository.profileForUpdate(tx, scope);
      return versionDetail(row, profile?.activeVersionId ?? null, this.platformId);
    });
    this.changed('draft_updated', scope, view.id, view.versionNo);
    return view;
  }

  async deleteDraft(
    principal: Principal,
    scope: TenantScope,
    versionId: string,
    expectedRowVersion: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    const deleted = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.draftForChange(tx, scope, versionId, expectedRowVersion);
      const gone = await this.repository.deleteDraft(tx, scope, current.id, expectedRowVersion);
      if (!gone) throw riskProfileVersionConflict('rowVersion', current.rowVersion);
      await this.record(tx, principal, scope, client, RISK_AUDIT.draftDeleted, current.publicId, {
        versionId: current.publicId,
        versionNo: current.versionNo,
        rowVersion: current.rowVersion,
        overridesSha256: current.overridesSha256,
        changedPaths: changedPaths(current.overrides, {}),
      });
      return current;
    });
    this.changed('draft_deleted', scope, deleted.publicId, deleted.versionNo);
  }

  async publish(
    principal: Principal,
    scope: TenantScope,
    versionId: string,
    body: RiskVersionPublish,
    client: ClientContext,
  ): Promise<RiskPublishResult> {
    const outcome = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const profile = await this.repository.profileForUpdate(tx, scope);
      const current = await this.draftForChange(tx, scope, versionId, body.expectedRowVersion);
      // A version implies its profile row (FK); a missing one is a wrong read (§6).
      if (!profile || profile.id !== current.profileId) {
        throw new InconsistentRiskReadError('risk_profile');
      }
      const resolved = resolveVersion(this.platformId, current);
      if (resolved.source !== 'tenant') throw riskProfileInvalid(resolved.violations);
      const published = await this.repository.publishDraft(
        tx,
        scope,
        current.id,
        body.expectedRowVersion,
        { profileSha256: resolved.sha256, at: new Date() },
        userIdOf(principal),
      );
      if (!published) throw riskProfileVersionConflict('rowVersion', current.rowVersion);
      await this.record(tx, principal, scope, client, RISK_AUDIT.published, current.publicId, {
        versionId: current.publicId,
        versionNo: current.versionNo,
        baseProfile: current.baseProfile,
        overridesSha256: current.overridesSha256,
        profileSha256: resolved.sha256,
        profileId: resolved.id,
        activate: body.activate,
      });
      let activated = false;
      if (body.activate && profile.activeVersionId !== current.id) {
        await this.movePointer(tx, principal, scope, client, profile, current);
        activated = true;
      }
      const row = await this.repository.versionAfterWrite(tx, scope, current.id);
      const view = await this.profileViewTx(tx, scope);
      return {
        activated,
        result: {
          version: versionDetail(
            row,
            activated ? current.id : profile.activeVersionId,
            this.platformId,
          ),
          profile: view,
        },
      };
    });
    const { version } = outcome.result;
    this.changed('published', scope, version.id, version.versionNo);
    if (outcome.activated) this.changed('activated', scope, version.id, version.versionNo);
    return outcome.result;
  }

  async activate(
    principal: Principal,
    scope: TenantScope,
    versionId: string,
    body: RiskPointerChange,
    client: ClientContext,
  ): Promise<RiskProfileView> {
    const outcome = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const profile = await this.repository.profileForUpdate(tx, scope);
      const version = await this.repository.versionForUpdate(tx, scope, versionId);
      if (!version) throw riskProfileVersionNotFound();
      if (!profile || profile.id !== version.profileId) {
        throw new InconsistentRiskReadError('risk_profile');
      }
      if (version.status !== 'published') throw riskProfileVersionNotPublished();
      this.checkProfileVersion(profile, body.expectedProfileVersion);
      let activated = false;
      if (profile.activeVersionId !== version.id) {
        await this.movePointer(tx, principal, scope, client, profile, version);
        activated = true;
      }
      return { activated, version, view: await this.profileViewTx(tx, scope) };
    });
    if (outcome.activated) {
      this.changed('activated', scope, outcome.version.publicId, outcome.version.versionNo);
    }
    return outcome.view;
  }

  async reset(
    principal: Principal,
    scope: TenantScope,
    body: RiskPointerChange,
    client: ClientContext,
  ): Promise<RiskProfileView> {
    const outcome = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const profile = await this.repository.profileForUpdate(tx, scope);
      this.checkProfileVersion(profile, body.expectedProfileVersion);
      if (!profile || profile.activeVersionId === null) {
        return { reset: false, view: await this.profileViewTx(tx, scope) };
      }
      const previous = await this.repository.versionByIdTx(tx, scope, profile.activeVersionId);
      const moved = await this.repository.movePointer(
        tx,
        scope,
        profile.id,
        profile.version,
        null,
        userIdOf(principal),
      );
      if (!moved) throw riskProfileVersionConflict('profileVersion', profile.version);
      await this.record(tx, principal, scope, client, RISK_AUDIT.reset, profile.publicId, {
        profileId: profile.publicId,
        previousVersionId: previous?.publicId ?? null,
        previousVersionNo: previous?.versionNo ?? null,
        profileVersion: profile.version + 1,
      });
      return { reset: true, view: await this.profileViewTx(tx, scope) };
    });
    if (outcome.reset) this.changed('reset', scope, outcome.view.id ?? 'none', null);
    return outcome.view;
  }

  // ------------------------------------------------------------------------------- helpers

  /** The draft to change: 404 unknown, 409 published, 409 at another `row_version`. */
  private async draftForChange(
    tx: Tx,
    scope: TenantScope,
    versionId: string,
    expectedRowVersion: number | undefined,
  ): Promise<VersionRow> {
    const current = await this.repository.versionForUpdate(tx, scope, versionId);
    if (!current) throw riskProfileVersionNotFound();
    if (current.status !== 'draft') throw riskProfileVersionImmutable();
    if (expectedRowVersion !== undefined && current.rowVersion !== expectedRowVersion) {
      throw riskProfileVersionConflict('rowVersion', current.rowVersion);
    }
    return current;
  }

  private checkProfileVersion(profile: ProfileRow | null, expected: number | undefined): void {
    const current = profile?.version ?? 0;
    if (expected !== undefined && expected !== current) {
      throw riskProfileVersionConflict('profileVersion', current);
    }
  }

  /** Pointer → `version` (CAS on the profile `version`), audited with the previous version. */
  private async movePointer(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    profile: ProfileRow,
    version: VersionRow,
  ): Promise<void> {
    const previous =
      profile.activeVersionId === null
        ? null
        : await this.repository.versionByIdTx(tx, scope, profile.activeVersionId);
    const moved = await this.repository.movePointer(
      tx,
      scope,
      profile.id,
      profile.version,
      version.id,
      userIdOf(principal),
    );
    if (!moved) throw riskProfileVersionConflict('profileVersion', profile.version);
    await this.record(tx, principal, scope, client, RISK_AUDIT.activated, version.publicId, {
      versionId: version.publicId,
      versionNo: version.versionNo,
      profileSha256: version.profileSha256 ?? resolveVersion(this.platformId, version).sha256,
      previousVersionId: previous?.publicId ?? null,
      previousVersionNo: previous?.versionNo ?? null,
      profileVersion: profile.version + 1,
    });
  }

  private async profileViewTx(tx: Tx, scope: TenantScope): Promise<RiskProfileView> {
    const profile = await this.repository.profileForUpdate(tx, scope);
    const active =
      profile?.activeVersionId != null
        ? await this.repository.versionByIdTx(tx, scope, profile.activeVersionId)
        : null;
    const counts = await this.repository.countVersionsTx(tx, scope);
    return profileView(
      this.platformId,
      this.settings.RISK_PROFILE_MAX_VERSIONS,
      profile,
      active,
      counts,
    );
  }

  private record(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: (typeof RISK_AUDIT)[keyof typeof RISK_AUDIT],
    resourceId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, {
      principal,
      scope,
      client,
      action,
      resourceType: action === RISK_AUDIT.reset ? RISK_RESOURCE.profile : RISK_RESOURCE.version,
      resourceId,
      metadata,
    });
  }

  /** Counts the committed change and logs ids and numbers only (never overrides). */
  private changed(
    operation: RiskProfileOperation,
    scope: TenantScope,
    id: string,
    versionNo: number | null,
  ): void {
    this.metrics.profileChanges.inc({ operation });
    this.logger.log({
      message: `risk profile ${operation.replace('_', ' ')}`,
      organizationId: scope.organizationId.toString(),
      id,
      ...(versionNo !== null && { versionNo }),
    });
  }
}
