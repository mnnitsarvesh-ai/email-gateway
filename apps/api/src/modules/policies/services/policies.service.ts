import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { resolvePolicySettings } from '@email-gateway/policy-dsl';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import {
  catalogView,
  changedSettingsPaths,
  checkDefinition,
  checkSettings,
  EMPTY_SETTINGS_SHA256,
  overrideRuleIds,
  type PolicyBounds,
  policyDetail,
  policySummary,
  referencesOf,
  settingsView,
  unknownReferenceViolations,
  versionDetail,
  versionSummary,
} from '../domain/policy-definition';
import type {
  PolicyCatalog,
  PolicyChangeResult,
  PolicyCreate,
  PolicyCreated,
  PolicyDetail,
  PolicyListQuery,
  PolicyPage,
  PolicyRowChange,
  PolicySettingsUpdate,
  PolicySettingsView,
  PolicyUpdate,
  PolicyVersionCreate,
  PolicyVersionDetail,
  PolicyVersionListQuery,
  PolicyVersionPage,
  PolicyVersionPublish,
  PolicyVersionUpdate,
} from '../dto/policies.schemas';
import {
  policyConflict,
  policyDefinitionInvalid,
  policyLimitReached,
  policyNameTaken,
  policyNoActiveVersion,
  policyNotFound,
  policyRuleLimitReached,
  policySettingsInvalid,
  policyVersionImmutable,
  policyVersionLimitReached,
  policyVersionNotFound,
  policyVersionNotPublished,
} from '../policies.errors';
import {
  type PolicyRow,
  PoliciesManagementRepository,
  type SettingsRow,
  type VersionRow,
} from '../repositories/policies-management.repository';
import {
  POLICY_AUDIT,
  POLICY_RESOURCE,
  PolicyAuditor,
  type PolicyAuditAction,
  PolicyMetrics,
  type PolicyOperation,
  type PolicyResource,
  PolicyWriter,
  userIdOf,
} from './policy-writer';

type Tx = Prisma.TransactionClient;
type Settings = PolicyBounds;

interface Actor {
  principal: Principal;
  scope: TenantScope;
  client: ClientContext;
}

const isUniqueViolation = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';

/**
 * Tenant policies, their versions and the policy settings (step 5.2 P11, P12, P17, P22;
 * ADR-0043 decision 7). Reads use the replica. Every write runs on the writer (120 s budget, one
 * retry on an echo-check mismatch) under the organization's `policy_settings` row lock (created
 * lazily): version numbers are MAX + 1, drafts change only `WHERE status = 'draft'` with a
 * `row_version` compare-and-set (published versions are immutable), publishing re-validates and
 * stores the hashes, references, rule count and override flag, and every change evaluation sees
 * (activation, rollback, enable, disable, delete of an active policy, settings) increments the
 * generation exactly once; a change that changes nothing writes nothing. Every change writes
 * its audit row in the same transaction (ids, numbers, hashes, counts, override rule ids and
 * changed paths only). The organization always comes from the authenticated scope.
 */
@Injectable()
export class PoliciesService {
  private readonly logger = new Logger(PoliciesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly repository: PoliciesManagementRepository,
    private readonly writer: PolicyWriter,
    private readonly auditor: PolicyAuditor,
    private readonly metrics: PolicyMetrics,
  ) {}

  catalog(): PolicyCatalog {
    return catalogView(this.settings);
  }

  // ----------------------------------------------------------------------------- reads

  async list(scope: TenantScope, query: PolicyListQuery): Promise<PolicyPage> {
    const [settings, rows] = await Promise.all([
      this.repository.findSettings(scope),
      this.repository.listPolicies(scope, {
        ...pageWindow(query),
        ...(query.status !== undefined && { status: query.status }),
        ...(query.direction !== undefined && { direction: query.direction }),
      }),
    ]);
    const numbers = await this.repository.versionNumbers(scope, rows.slice(0, query.limit));
    const page = toPage(rows, query.limit, (row) =>
      policySummary(row, numbers.get(row.id) ?? { active: null, latest: null }),
    );
    return { ...page, generation: (settings?.generation ?? 0n).toString() };
  }

  async get(scope: TenantScope, policyId: string): Promise<PolicyDetail> {
    const policy = await this.repository.findPolicy(scope, policyId);
    if (!policy || policy.status === 'archived') throw policyNotFound();
    const [active, counts, numbers] = await Promise.all([
      policy.activeVersionId === null
        ? Promise.resolve(null)
        : this.repository.versionById(scope, policy.activeVersionId),
      this.repository.countVersions(scope, policy.id),
      this.repository.versionNumbers(scope, [policy]),
    ]);
    return policyDetail(
      policy,
      active,
      numbers.get(policy.id)?.latest ?? null,
      counts,
      this.settings.POLICY_MAX_VERSIONS_PER_POLICY,
    );
  }

  async listVersions(
    scope: TenantScope,
    policyId: string,
    query: PolicyVersionListQuery,
  ): Promise<PolicyVersionPage> {
    const policy = await this.repository.findPolicy(scope, policyId);
    if (!policy || policy.status === 'archived') throw policyNotFound();
    const rows = await this.repository.listVersions(scope, policy.id, {
      ...pageWindow(query),
      ...(query.status !== undefined && { status: query.status }),
    });
    return toPage(rows, query.limit, (row) =>
      versionSummary(policy.publicId, row, policy.activeVersionId),
    );
  }

  async getVersion(
    scope: TenantScope,
    policyId: string,
    versionNo: number,
  ): Promise<PolicyVersionDetail> {
    const policy = await this.repository.findPolicy(scope, policyId);
    if (!policy || policy.status === 'archived') throw policyNotFound();
    const row = await this.repository.findVersion(scope, policy.id, versionNo);
    if (!row) throw policyVersionNotFound();
    return versionDetail(policy.publicId, row, policy.activeVersionId);
  }

  async getSettings(scope: TenantScope): Promise<PolicySettingsView> {
    return settingsView(await this.repository.findSettings(scope));
  }

  // ---------------------------------------------------------------------------- policies

  async create(
    principal: Principal,
    scope: TenantScope,
    body: PolicyCreate,
    client: ClientContext,
  ): Promise<PolicyCreated> {
    const check = checkDefinition(body.definition);
    if (!check.ok) throw policyDefinitionInvalid(check.violations);
    const actor = { principal, scope, client };
    const created = await this.writer
      .run(async (tx) => {
        await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
        const limit = this.settings.POLICY_MAX_POLICIES;
        if ((await this.repository.countPoliciesTx(tx, scope)) >= limit) {
          throw policyLimitReached(limit);
        }
        if (await this.repository.nameTakenTx(tx, scope, body.name, null)) throw policyNameTaken();
        const policy = await this.repository.createPolicy(
          tx,
          scope,
          {
            publicId: uuidv7(),
            name: body.name,
            description: body.description ?? null,
            direction: check.definition.direction,
            priority: check.definition.priority,
          },
          userIdOf(principal),
        );
        const version = await this.repository.createVersion(
          tx,
          scope,
          {
            ...check.content,
            policyId: policy.id,
            version: 1,
            changeNote: body.changeNote ?? null,
          },
          userIdOf(principal),
        );
        await this.record(
          tx,
          actor,
          POLICY_AUDIT.created,
          POLICY_RESOURCE.policy,
          policy.publicId,
          {
            policyId: policy.publicId,
            rowVersion: policy.rowVersion,
            versionNo: version.version,
            definitionSha256: version.definitionSha256,
            ruleCount: version.ruleCount,
            hasOverrideRules: version.hasOverrideRules,
          },
        );
        return {
          policy: await this.detailTx(tx, scope, policy),
          version: versionDetail(policy.publicId, version, null),
        };
      })
      .catch((error: unknown) => {
        throw isUniqueViolation(error) ? policyNameTaken() : error;
      });
    this.changed('created', scope, created.policy.id, 1);
    return created;
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    body: PolicyUpdate,
    client: ClientContext,
  ): Promise<PolicyDetail> {
    const actor = { principal, scope, client };
    const view = await this.writer
      .run(async (tx) => {
        await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
        const policy = await this.policyForChange(tx, scope, policyId, body.expectedRowVersion);
        const changed: string[] = [];
        if (body.name !== undefined && body.name !== policy.name) changed.push('name');
        if (body.description !== undefined && body.description !== policy.description) {
          changed.push('description');
        }
        if (changed.length === 0) return { view: await this.detailTx(tx, scope, policy), changed };
        if (
          changed.includes('name') &&
          (await this.repository.nameTakenTx(tx, scope, body.name!, policy.id))
        ) {
          throw policyNameTaken();
        }
        const ok = await this.repository.updatePolicy(
          tx,
          scope,
          policy.id,
          policy.rowVersion,
          {
            ...(changed.includes('name') && { name: body.name! }),
            ...(changed.includes('description') && { description: body.description ?? null }),
          },
          userIdOf(principal),
        );
        if (!ok) throw policyConflict(policy.rowVersion);
        const after = await this.repository.policyAfterWrite(tx, scope, policy.id);
        await this.record(
          tx,
          actor,
          POLICY_AUDIT.updated,
          POLICY_RESOURCE.policy,
          policy.publicId,
          {
            policyId: policy.publicId,
            rowVersion: after.rowVersion,
            changedPaths: changed,
          },
        );
        return { view: await this.detailTx(tx, scope, after), changed };
      })
      .catch((error: unknown) => {
        throw isUniqueViolation(error) ? policyNameTaken() : error;
      });
    if (view.changed.length > 0) this.changed('updated', scope, policyId, null);
    return view.view;
  }

  async enable(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    body: PolicyRowChange,
    client: ClientContext,
  ): Promise<PolicyDetail> {
    const actor = { principal, scope, client };
    const outcome = await this.writer.run(async (tx) => {
      const settings = await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, body.expectedRowVersion);
      if (policy.activeVersionId === null) throw policyNoActiveVersion();
      if (policy.status === 'active') {
        return { changed: false, view: await this.detailTx(tx, scope, policy) };
      }
      const version = await this.repository.versionAfterWrite(tx, scope, policy.activeVersionId);
      if (version.policyId !== policy.id || version.status !== 'published') {
        throw policyNoActiveVersion();
      }
      await this.checkActivatable(tx, scope, policy, version);
      const ok = await this.repository.updatePolicy(
        tx,
        scope,
        policy.id,
        policy.rowVersion,
        { status: 'active' },
        userIdOf(principal),
      );
      if (!ok) throw policyConflict(policy.rowVersion);
      const generation = await this.repository.bumpGeneration(tx, scope, settings.id);
      const after = await this.repository.policyAfterWrite(tx, scope, policy.id);
      await this.record(tx, actor, POLICY_AUDIT.enabled, POLICY_RESOURCE.policy, policy.publicId, {
        policyId: policy.publicId,
        rowVersion: after.rowVersion,
        versionNo: version.version,
        generation,
      });
      return { changed: true, view: await this.detailTx(tx, scope, after) };
    });
    if (outcome.changed) this.changed('enabled', scope, policyId, null);
    return outcome.view;
  }

  async disable(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    body: PolicyRowChange,
    client: ClientContext,
  ): Promise<PolicyDetail> {
    const actor = { principal, scope, client };
    const outcome = await this.writer.run(async (tx) => {
      const settings = await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, body.expectedRowVersion);
      // Only an active policy is evaluated; disabling anything else changes nothing.
      if (policy.status !== 'active') {
        return { changed: false, view: await this.detailTx(tx, scope, policy) };
      }
      const ok = await this.repository.updatePolicy(
        tx,
        scope,
        policy.id,
        policy.rowVersion,
        { status: 'disabled' },
        userIdOf(principal),
      );
      if (!ok) throw policyConflict(policy.rowVersion);
      const generation = await this.repository.bumpGeneration(tx, scope, settings.id);
      const after = await this.repository.policyAfterWrite(tx, scope, policy.id);
      await this.record(tx, actor, POLICY_AUDIT.disabled, POLICY_RESOURCE.policy, policy.publicId, {
        policyId: policy.publicId,
        rowVersion: after.rowVersion,
        generation,
      });
      return { changed: true, view: await this.detailTx(tx, scope, after) };
    });
    if (outcome.changed) this.changed('disabled', scope, policyId, null);
    return outcome.view;
  }

  async remove(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    expectedRowVersion: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    const actor = { principal, scope, client };
    await this.writer.run(async (tx) => {
      const settings = await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, expectedRowVersion);
      const wasActive = policy.status === 'active';
      const ok = await this.repository.updatePolicy(
        tx,
        scope,
        policy.id,
        policy.rowVersion,
        { status: 'archived', deletedAt: new Date() },
        userIdOf(principal),
      );
      if (!ok) throw policyConflict(policy.rowVersion);
      const generation = wasActive
        ? await this.repository.bumpGeneration(tx, scope, settings.id)
        : settings.generation;
      await this.record(tx, actor, POLICY_AUDIT.deleted, POLICY_RESOURCE.policy, policy.publicId, {
        policyId: policy.publicId,
        rowVersion: policy.rowVersion + 1,
        wasActive,
        generation,
      });
    });
    this.changed('deleted', scope, policyId, null);
  }

  // ---------------------------------------------------------------------------- versions

  async createDraft(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    body: PolicyVersionCreate,
    client: ClientContext,
  ): Promise<PolicyVersionDetail> {
    // Without a source version the document is checked before any database access.
    if (body.definition !== undefined) {
      const early = checkDefinition(body.definition);
      if (!early.ok) throw policyDefinitionInvalid(early.violations);
    }
    const actor = { principal, scope, client };
    const view = await this.writer.run(async (tx) => {
      await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, undefined);
      let basedOn: VersionRow | null = null;
      if (body.basedOnVersionNo !== undefined) {
        basedOn = await this.repository.versionForUpdate(
          tx,
          scope,
          policy.id,
          body.basedOnVersionNo,
        );
        if (!basedOn) throw policyVersionNotFound();
      }
      const check = checkDefinition(body.definition ?? basedOn!.definition);
      if (!check.ok) throw policyDefinitionInvalid(check.violations);
      const counts = await this.repository.countVersionsTx(tx, scope, policy.id);
      const limit = this.settings.POLICY_MAX_VERSIONS_PER_POLICY;
      if (counts.drafts + counts.published + counts.superseded >= limit) {
        throw policyVersionLimitReached(limit);
      }
      const versionNo = (await this.repository.maxVersionNo(tx, scope, policy.id)) + 1;
      const row = await this.repository.createVersion(
        tx,
        scope,
        {
          ...check.content,
          policyId: policy.id,
          version: versionNo,
          changeNote: body.changeNote ?? null,
        },
        userIdOf(principal),
      );
      await this.syncNeverActivated(tx, scope, policy, userIdOf(principal));
      await this.record(
        tx,
        actor,
        POLICY_AUDIT.draftCreated,
        POLICY_RESOURCE.version,
        policy.publicId,
        {
          policyId: policy.publicId,
          versionNo: row.version,
          rowVersion: row.rowVersion,
          definitionSha256: row.definitionSha256,
          ruleCount: row.ruleCount,
          hasOverrideRules: row.hasOverrideRules,
          basedOnVersionNo: basedOn?.version ?? null,
        },
      );
      return versionDetail(policy.publicId, row, policy.activeVersionId);
    });
    this.changed('draft_created', scope, policyId, view.versionNo);
    return view;
  }

  async updateDraft(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    versionNo: number,
    body: PolicyVersionUpdate,
    client: ClientContext,
  ): Promise<PolicyVersionDetail> {
    const actor = { principal, scope, client };
    const view = await this.writer.run(async (tx) => {
      await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, undefined);
      const current = await this.draftForChange(
        tx,
        scope,
        policy,
        versionNo,
        body.expectedRowVersion,
      );
      const check = checkDefinition(body.definition);
      if (!check.ok) throw policyDefinitionInvalid(check.violations);
      const ok = await this.repository.updateDraft(
        tx,
        scope,
        current.id,
        body.expectedRowVersion,
        {
          ...check.content,
          changeNote: body.changeNote === undefined ? current.changeNote : body.changeNote,
        },
        userIdOf(principal),
      );
      if (!ok) throw policyConflict(current.rowVersion);
      const row = await this.repository.versionAfterWrite(tx, scope, current.id);
      await this.syncNeverActivated(tx, scope, policy, userIdOf(principal));
      await this.record(
        tx,
        actor,
        POLICY_AUDIT.draftUpdated,
        POLICY_RESOURCE.version,
        policy.publicId,
        {
          policyId: policy.publicId,
          versionNo: row.version,
          rowVersion: row.rowVersion,
          definitionSha256Before: current.definitionSha256,
          definitionSha256: row.definitionSha256,
          ruleCount: row.ruleCount,
          hasOverrideRules: row.hasOverrideRules,
        },
      );
      return versionDetail(policy.publicId, row, policy.activeVersionId);
    });
    this.changed('draft_updated', scope, policyId, view.versionNo);
    return view;
  }

  async deleteDraft(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    versionNo: number,
    expectedRowVersion: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    const actor = { principal, scope, client };
    await this.writer.run(async (tx) => {
      await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, undefined);
      const current = await this.draftForChange(tx, scope, policy, versionNo, expectedRowVersion);
      const gone = await this.repository.deleteDraft(tx, scope, current.id, expectedRowVersion);
      if (!gone) throw policyConflict(current.rowVersion);
      await this.syncNeverActivated(tx, scope, policy, userIdOf(principal));
      await this.record(
        tx,
        actor,
        POLICY_AUDIT.draftDeleted,
        POLICY_RESOURCE.version,
        policy.publicId,
        {
          policyId: policy.publicId,
          versionNo: current.version,
          rowVersion: current.rowVersion,
          definitionSha256: current.definitionSha256,
        },
      );
    });
    this.changed('draft_deleted', scope, policyId, versionNo);
  }

  async publish(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    versionNo: number,
    body: PolicyVersionPublish,
    client: ClientContext,
  ): Promise<PolicyChangeResult> {
    const actor = { principal, scope, client };
    const outcome = await this.writer.run(async (tx) => {
      const settings = await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, undefined);
      const current = await this.draftForChange(
        tx,
        scope,
        policy,
        versionNo,
        body.expectedRowVersion,
      );
      const check = checkDefinition(current.definition);
      if (!check.ok) throw policyDefinitionInvalid(check.violations);
      await this.checkReferences(tx, scope, check.content.definition);
      const ok = await this.repository.publishDraft(
        tx,
        scope,
        current.id,
        body.expectedRowVersion,
        check.content,
        new Date(),
        userIdOf(principal),
      );
      if (!ok) throw policyConflict(current.rowVersion);
      const published = await this.repository.versionAfterWrite(tx, scope, current.id);
      await this.record(
        tx,
        actor,
        POLICY_AUDIT.published,
        POLICY_RESOURCE.version,
        policy.publicId,
        {
          policyId: policy.publicId,
          versionNo: published.version,
          rowVersion: published.rowVersion,
          definitionSha256: published.definitionSha256,
          ruleCount: published.ruleCount,
          hasOverrideRules: published.hasOverrideRules,
          activate: body.activate,
        },
      );
      if (published.hasOverrideRules) {
        await this.record(
          tx,
          actor,
          POLICY_AUDIT.overrideRulesPublished,
          POLICY_RESOURCE.version,
          policy.publicId,
          {
            policyId: policy.publicId,
            versionNo: published.version,
            overrideRuleIds: overrideRuleIds(published.definition),
          },
        );
      }
      let activated = false;
      let generation = settings.generation;
      if (body.activate) {
        const moved = await this.activateTx(tx, actor, settings, policy, published);
        activated = moved !== null;
        generation = moved ?? generation;
      }
      const after = await this.repository.policyAfterWrite(tx, scope, policy.id);
      return {
        activated,
        result: {
          version: versionDetail(policy.publicId, published, after.activeVersionId),
          policy: await this.detailTx(tx, scope, after),
          generation: generation.toString(),
        },
      };
    });
    this.changed('published', scope, policyId, versionNo);
    if (outcome.activated) this.changed('activated', scope, policyId, versionNo);
    return outcome.result;
  }

  async activate(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    versionNo: number,
    body: PolicyRowChange,
    client: ClientContext,
  ): Promise<PolicyChangeResult> {
    const actor = { principal, scope, client };
    const outcome = await this.writer.run(async (tx) => {
      const settings = await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const policy = await this.policyForChange(tx, scope, policyId, body.expectedRowVersion);
      const version = await this.repository.versionForUpdate(tx, scope, policy.id, versionNo);
      if (!version) throw policyVersionNotFound();
      if (version.status !== 'published' || version.dslVersion === null) {
        throw policyVersionNotPublished();
      }
      const moved = await this.activateTx(tx, actor, settings, policy, version);
      const after = await this.repository.policyAfterWrite(tx, scope, policy.id);
      return {
        activated: moved !== null,
        result: {
          version: versionDetail(policy.publicId, version, after.activeVersionId),
          policy: await this.detailTx(tx, scope, after),
          generation: (moved ?? settings.generation).toString(),
        },
      };
    });
    if (outcome.activated) this.changed('activated', scope, policyId, versionNo);
    return outcome.result;
  }

  // ---------------------------------------------------------------------------- settings

  async putSettings(
    principal: Principal,
    scope: TenantScope,
    body: PolicySettingsUpdate,
    client: ClientContext,
  ): Promise<PolicySettingsView> {
    const check = checkSettings(body.settings);
    if (!check.ok) throw policySettingsInvalid(check.violations);
    const actor = { principal, scope, client };
    const outcome = await this.writer.run(async (tx) => {
      const current = await this.repository.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      // A row that was never changed (absent before, or created lazily) is at row version 0/1.
      const pristine = current.rowVersion === 1 && current.settingsSha256 === EMPTY_SETTINGS_SHA256;
      const matches =
        body.expectedRowVersion === current.rowVersion ||
        (pristine && body.expectedRowVersion === 0);
      if (!matches) throw policyConflict(current.rowVersion);
      if (check.sha256 === current.settingsSha256) {
        return { changed: false, view: settingsView(current) };
      }
      const ok = await this.repository.updateSettings(
        tx,
        scope,
        current.id,
        current.rowVersion,
        { settings: check.settings, settingsSha256: check.sha256 },
        userIdOf(principal),
      );
      if (!ok) throw policyConflict(current.rowVersion);
      const after = await this.repository.settingsAfterWrite(tx, scope, current.id);
      const resourceId = after.id.toString();
      await this.record(
        tx,
        actor,
        POLICY_AUDIT.settingsUpdated,
        POLICY_RESOURCE.settings,
        resourceId,
        {
          rowVersion: after.rowVersion,
          generation: after.generation,
          settingsSha256Before: current.settingsSha256,
          settingsSha256: after.settingsSha256,
          changedPaths: changedSettingsPaths(current.settings, after.settings),
        },
      );
      const wasOn = resolvePolicySettings(current.settings).settings.allowRecommendationOverrides;
      const isOn = resolvePolicySettings(after.settings).settings.allowRecommendationOverrides;
      if (!wasOn && isOn) {
        await this.record(
          tx,
          actor,
          POLICY_AUDIT.settingsOverridesEnabled,
          POLICY_RESOURCE.settings,
          resourceId,
          { rowVersion: after.rowVersion, generation: after.generation },
        );
      }
      return { changed: true, view: settingsView(after) };
    });
    if (outcome.changed) this.changed('settings_updated', scope, 'settings', null);
    return outcome.view;
  }

  // ----------------------------------------------------------------------------- helpers

  /** A non-archived policy of the organization, optionally at `expectedRowVersion`. */
  private async policyForChange(
    tx: Tx,
    scope: TenantScope,
    policyId: string,
    expectedRowVersion: number | undefined,
  ): Promise<PolicyRow> {
    const policy = await this.repository.policyForUpdate(tx, scope, policyId);
    if (!policy) throw policyNotFound();
    if (expectedRowVersion !== undefined && policy.rowVersion !== expectedRowVersion) {
      throw policyConflict(policy.rowVersion);
    }
    return policy;
  }

  /** The draft to change: 404 unknown, 409 not a draft, 409 at another `row_version`. */
  private async draftForChange(
    tx: Tx,
    scope: TenantScope,
    policy: PolicyRow,
    versionNo: number,
    expectedRowVersion: number | undefined,
  ): Promise<VersionRow> {
    const current = await this.repository.versionForUpdate(tx, scope, policy.id, versionNo);
    if (!current) throw policyVersionNotFound();
    if (current.status !== 'draft') throw policyVersionImmutable();
    if (expectedRowVersion !== undefined && current.rowVersion !== expectedRowVersion) {
      throw policyConflict(current.rowVersion);
    }
    return current;
  }

  /** Every department and user the definition references exists in the organization (P5). */
  private async checkReferences(tx: Tx, scope: TenantScope, definition: unknown): Promise<void> {
    const validation = checkDefinition(definition);
    if (!validation.ok) throw policyDefinitionInvalid(validation.violations);
    const wanted = referencesOf(validation.content.references);
    if (wanted.departmentIds.length === 0 && wanted.userIds.length === 0) return;
    const existing = await this.repository.existingDirectoryIdsTx(tx, scope, wanted);
    const violations = unknownReferenceViolations(definition, existing);
    if (violations.length > 0) throw policyDefinitionInvalid(violations);
  }

  /**
   * Re-validates a version for activation: the DSL still accepts it, its references exist, and
   * the organization's active rules stay within POLICY_MAX_ACTIVE_RULES.
   */
  private async checkActivatable(
    tx: Tx,
    scope: TenantScope,
    policy: PolicyRow,
    version: VersionRow,
  ): Promise<{ direction: PolicyRow['direction']; priority: number }> {
    const check = checkDefinition(version.definition);
    if (!check.ok) throw policyDefinitionInvalid(check.violations);
    await this.checkReferences(tx, scope, version.definition);
    const active = await this.repository.activeVersionsTx(tx, scope);
    const others = active
      .filter((a) => a.policyId !== policy.id)
      .reduce((sum, a) => sum + a.ruleCount, 0);
    const requested = others + check.content.ruleCount;
    const limit = this.settings.POLICY_MAX_ACTIVE_RULES;
    if (requested > limit) throw policyRuleLimitReached(limit, requested);
    return { direction: check.definition.direction, priority: check.definition.priority };
  }

  /**
   * Activation (P17): pointer → `version`, status `active`, direction and priority from the
   * definition, `generation++`, audited with the previous and new version. Returns the new
   * generation, or null when the version is already the active one of an active policy (no-op).
   */
  private async activateTx(
    tx: Tx,
    actor: Actor,
    settings: SettingsRow,
    policy: PolicyRow,
    version: VersionRow,
  ): Promise<bigint | null> {
    if (policy.activeVersionId === version.id && policy.status === 'active') return null;
    const { direction, priority } = await this.checkActivatable(tx, actor.scope, policy, version);
    const previous =
      policy.activeVersionId === null
        ? null
        : await this.repository.versionByIdTx(tx, actor.scope, policy.activeVersionId);
    const ok = await this.repository.updatePolicy(
      tx,
      actor.scope,
      policy.id,
      policy.rowVersion,
      { activeVersionId: version.id, status: 'active', direction, priority },
      userIdOf(actor.principal),
    );
    if (!ok) throw policyConflict(policy.rowVersion);
    const generation = await this.repository.bumpGeneration(tx, actor.scope, settings.id);
    await this.record(tx, actor, POLICY_AUDIT.activated, POLICY_RESOURCE.version, policy.publicId, {
      policyId: policy.publicId,
      versionNo: version.version,
      definitionSha256: version.definitionSha256,
      previousVersionNo: previous?.version ?? null,
      previousStatus: policy.status,
      rowVersion: policy.rowVersion + 1,
      generation,
    });
    return generation;
  }

  /**
   * Before the first activation the listed direction and priority follow the newest draft
   * (P17); afterwards they follow the active version only.
   */
  private async syncNeverActivated(
    tx: Tx,
    scope: TenantScope,
    policy: PolicyRow,
    userId: bigint | null,
  ): Promise<void> {
    if (policy.activeVersionId !== null) return;
    const newest = await this.repository.newestDraftTx(tx, scope, policy.id);
    if (!newest) return;
    const def = newest.definition as { direction?: PolicyRow['direction']; priority?: number };
    if (typeof def?.priority !== 'number' || typeof def.direction !== 'string') return;
    if (def.direction === policy.direction && def.priority === policy.priority) return;
    const ok = await this.repository.updatePolicy(
      tx,
      scope,
      policy.id,
      policy.rowVersion,
      { direction: def.direction, priority: def.priority },
      userId,
    );
    if (!ok) throw policyConflict(policy.rowVersion);
  }

  private async detailTx(tx: Tx, scope: TenantScope, policy: PolicyRow): Promise<PolicyDetail> {
    const active =
      policy.activeVersionId === null
        ? null
        : await this.repository.versionByIdTx(tx, scope, policy.activeVersionId);
    const counts = await this.repository.countVersionsTx(tx, scope, policy.id);
    const latest = await this.repository.maxVersionNo(tx, scope, policy.id);
    return policyDetail(
      policy,
      active,
      latest === 0 ? null : latest,
      counts,
      this.settings.POLICY_MAX_VERSIONS_PER_POLICY,
    );
  }

  private record(
    tx: Tx,
    actor: Actor,
    action: PolicyAuditAction,
    resourceType: PolicyResource,
    resourceId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, { ...actor, action, resourceType, resourceId, metadata });
  }

  /** Counts the committed change and logs ids and numbers only (never definitions). */
  private changed(
    operation: PolicyOperation,
    scope: TenantScope,
    id: string,
    versionNo: number | null,
  ): void {
    this.metrics.changes.inc({ operation });
    this.logger.log({
      message: `policy ${operation.replace('_', ' ')}`,
      organizationId: scope.organizationId.toString(),
      id,
      ...(versionNo !== null && { versionNo }),
    });
  }
}
