import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { DlpRuleConditions } from '@email-gateway/security-contracts';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import {
  dlpDirectionsInvalid,
  dlpExists,
  dlpInUse,
  dlpLimitReached,
  dlpNotFound,
  dlpReferenceInvalid,
  dlpVersionConflict,
} from '../dlp.errors';
import { directionsWithin, parseRuleConditions, referencedIds } from '../domain/dlp-inputs';
import type {
  DlpListQuery,
  DlpPolicyCreate,
  DlpPolicyDetail,
  DlpPolicyPage,
  DlpPolicyUpdate,
  DlpRuleCreate,
  DlpRuleUpdate,
  DlpRuleView,
} from '../dto/dlp.schemas';
import {
  DlpConfigRepository,
  type PolicyData,
  type PolicyRow,
  type RuleData,
  type RuleRow,
} from '../repositories/dlp-config.repository';
import {
  conditionsOf,
  directionsOf,
  DlpAuditor,
  policyImage,
  policyView,
  ruleImage,
  ruleView,
} from './dlp-views';
import { DLP_AUDIT, DLP_RESOURCE, DlpWriter, userIdOf } from './dlp-writer';

type Limits = { DLP_POLICIES_MAX_PER_TENANT: number; DLP_RULES_MAX_PER_POLICY: number };

/**
 * DLP policies and their ordered rules (step 4.5 D11, D21). Writes run on the writer under the
 * organization row lock (caps, unique names, references), compare and set `version`, and write
 * their audit row with the before-image in the same transaction; lists and reads use the
 * replica. Rule conditions are normalized and validated with `dlpRuleConditionsSchema`; their
 * directions must be within the policy's and the custom pattern / dictionary ids they select
 * must be the organization's (`400 dlp_reference_invalid`). The organization always comes from
 * the authenticated scope.
 */
@Injectable()
export class DlpPoliciesService {
  private readonly logger = new Logger(DlpPoliciesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: Limits,
    private readonly repository: DlpConfigRepository,
    private readonly writer: DlpWriter,
    private readonly auditor: DlpAuditor,
  ) {}

  async list(scope: TenantScope, query: DlpListQuery): Promise<DlpPolicyPage> {
    const rows = await this.repository.listPolicies(scope, {
      ...pageWindow(query),
      ...(query.enabled !== undefined && { enabled: query.enabled }),
    });
    return toPage(rows, query.limit, policyView);
  }

  async get(scope: TenantScope, id: string): Promise<DlpPolicyDetail> {
    const row = await this.repository.findPolicy(scope, id);
    if (!row) throw dlpNotFound('policy');
    const rules = await this.repository.rulesOf(scope, row.id);
    return { ...policyView(row), rules: rules.map(ruleView) };
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: DlpPolicyCreate,
    client: ClientContext,
  ): Promise<DlpPolicyDetail> {
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const existing = await this.repository.policyByName(tx, scope, body.name);
        if (existing) throw dlpExists('policy', existing.publicId);
        const count = await this.repository.countPolicies(tx, scope);
        if (count >= this.limits.DLP_POLICIES_MAX_PER_TENANT) {
          throw dlpLimitReached('policies', this.limits.DLP_POLICIES_MAX_PER_TENANT);
        }
        const row = await this.repository.createPolicy(
          tx,
          scope,
          uuidv7(),
          {
            name: body.name,
            description: body.description ?? null,
            enabled: body.enabled,
            mode: body.mode,
            priority: body.priority,
            directions: [...body.directions],
          },
          userIdOf(principal),
        );
        await this.record(
          tx,
          principal,
          scope,
          client,
          DLP_AUDIT.policyCreated,
          DLP_RESOURCE.policy,
          row.publicId,
          {
            after: policyImage(row),
          },
        );
        return { ...policyView(row), rules: [] };
      });
      this.logChange('policy created', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('policy', null);
      throw error;
    }
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: DlpPolicyUpdate,
    client: ClientContext,
  ): Promise<DlpPolicyDetail> {
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const current = await this.repository.findPolicyForUpdate(tx, scope, id);
        if (!current) throw dlpNotFound('policy');
        if (current.version !== body.version) throw dlpVersionConflict(current.version);
        if (body.name !== undefined && body.name !== current.name) {
          const other = await this.repository.policyByName(tx, scope, body.name);
          if (other && other.id !== current.id) throw dlpExists('policy', other.publicId);
        }
        const data: PolicyData = {
          name: body.name ?? current.name,
          description: body.description === undefined ? current.description : body.description,
          enabled: body.enabled ?? current.enabled,
          mode: body.mode ?? current.mode,
          priority: body.priority ?? current.priority,
          directions: body.directions ? [...body.directions] : directionsOf(current.directions),
        };
        const rules = await this.repository.rulesOfForUpdate(tx, scope, current.id);
        if (body.directions !== undefined) {
          const outside = rules.filter(
            (rule) => !directionsWithin(conditionsOf(rule.conditions), data.directions),
          );
          if (outside.length > 0) throw dlpDirectionsInvalid(outside.length);
        }
        const updated = await this.repository.updatePolicy(
          tx,
          scope,
          current.id,
          body.version,
          data,
          userIdOf(principal),
        );
        if (!updated) throw dlpVersionConflict(current.version);
        const row = await this.repository.policyById(tx, scope, current.id);
        await this.record(
          tx,
          principal,
          scope,
          client,
          DLP_AUDIT.policyUpdated,
          DLP_RESOURCE.policy,
          row.publicId,
          {
            before: policyImage(current),
            after: policyImage(row),
          },
        );
        return { ...policyView(row), rules: rules.map(ruleView) };
      });
      this.logChange('policy updated', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('policy', null);
      throw error;
    }
  }

  /** Deletes the policy and its rules in one transaction; exceptions must not target them. */
  async remove(
    principal: Principal,
    scope: TenantScope,
    id: string,
    version: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.repository.findPolicyForUpdate(tx, scope, id);
      if (!current) throw dlpNotFound('policy');
      if (version !== undefined && current.version !== version) {
        throw dlpVersionConflict(current.version);
      }
      const rules = await this.repository.rulesOfForUpdate(tx, scope, current.id);
      const references = await this.repository.countExceptionsTargeting(tx, scope, {
        policyId: current.id,
        ruleIds: rules.map((r) => r.id),
      });
      if (references > 0) throw dlpInUse('policy', references);
      await this.repository.deletePolicy(tx, scope, current.id);
      await this.record(
        tx,
        principal,
        scope,
        client,
        DLP_AUDIT.policyDeleted,
        DLP_RESOURCE.policy,
        current.publicId,
        {
          before: { ...policyImage(current), rules: rules.map(ruleImage) },
        },
      );
    });
    this.logChange('policy deleted', scope, id);
  }

  // ------------------------------------------------------------------------------------- rules

  async createRule(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    body: DlpRuleCreate,
    client: ClientContext,
  ): Promise<DlpRuleView> {
    const conditions = parseRuleConditions(body.conditions);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const policy = await this.repository.findPolicyForUpdate(tx, scope, policyId);
        if (!policy) throw dlpNotFound('policy');
        await this.checkRule(tx, scope, policy, conditions);
        const existing = await this.repository.ruleByName(tx, scope, policy.id, body.name);
        if (existing) throw dlpExists('rule', existing.publicId);
        const count = await this.repository.countRules(tx, scope, policy.id);
        if (count >= this.limits.DLP_RULES_MAX_PER_POLICY) {
          throw dlpLimitReached('rules', this.limits.DLP_RULES_MAX_PER_POLICY);
        }
        const row = await this.repository.createRule(
          tx,
          scope,
          uuidv7(),
          policy.id,
          {
            name: body.name,
            enabled: body.enabled,
            priority: body.priority,
            conditions,
            action: body.action,
          },
          userIdOf(principal),
        );
        await this.record(
          tx,
          principal,
          scope,
          client,
          DLP_AUDIT.ruleCreated,
          DLP_RESOURCE.rule,
          row.publicId,
          {
            after: ruleImage(row),
          },
        );
        return ruleView(row);
      });
      this.logChange('rule created', scope, view.id, view.policyId);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('rule', null);
      throw error;
    }
  }

  async updateRule(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    ruleId: string,
    body: DlpRuleUpdate,
    client: ClientContext,
  ): Promise<DlpRuleView> {
    const conditions =
      body.conditions === undefined ? undefined : parseRuleConditions(body.conditions);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const policy = await this.repository.findPolicyForUpdate(tx, scope, policyId);
        if (!policy) throw dlpNotFound('policy');
        const current = await this.repository.findRuleForUpdate(tx, scope, policy.id, ruleId);
        if (!current) throw dlpNotFound('rule');
        if (current.version !== body.version) throw dlpVersionConflict(current.version);
        if (conditions !== undefined) await this.checkRule(tx, scope, policy, conditions);
        if (body.name !== undefined && body.name !== current.name) {
          const other = await this.repository.ruleByName(tx, scope, policy.id, body.name);
          if (other && other.id !== current.id) throw dlpExists('rule', other.publicId);
        }
        const data: RuleData = {
          name: body.name ?? current.name,
          enabled: body.enabled ?? current.enabled,
          priority: body.priority ?? current.priority,
          conditions: conditions ?? conditionsOf(current.conditions),
          action: body.action ?? current.action,
        };
        const updated = await this.repository.updateRule(
          tx,
          scope,
          current.id,
          body.version,
          data,
          userIdOf(principal),
        );
        if (!updated) throw dlpVersionConflict(current.version);
        const row = await this.repository.ruleById(tx, scope, current.id);
        await this.record(
          tx,
          principal,
          scope,
          client,
          DLP_AUDIT.ruleUpdated,
          DLP_RESOURCE.rule,
          row.publicId,
          {
            before: ruleImage(current),
            after: ruleImage(row),
          },
        );
        return ruleView(row);
      });
      this.logChange('rule updated', scope, view.id, view.policyId);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('rule', null);
      throw error;
    }
  }

  async removeRule(
    principal: Principal,
    scope: TenantScope,
    policyId: string,
    ruleId: string,
    version: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const policy = await this.repository.findPolicyForUpdate(tx, scope, policyId);
      if (!policy) throw dlpNotFound('policy');
      const current: RuleRow | null = await this.repository.findRuleForUpdate(
        tx,
        scope,
        policy.id,
        ruleId,
      );
      if (!current) throw dlpNotFound('rule');
      if (version !== undefined && current.version !== version) {
        throw dlpVersionConflict(current.version);
      }
      const references = await this.repository.countExceptionsTargeting(tx, scope, {
        ruleIds: [current.id],
      });
      if (references > 0) throw dlpInUse('rule', references);
      await this.repository.deleteRule(tx, scope, current.id);
      await this.record(
        tx,
        principal,
        scope,
        client,
        DLP_AUDIT.ruleDeleted,
        DLP_RESOURCE.rule,
        current.publicId,
        {
          before: ruleImage(current),
        },
      );
    });
    this.logChange('rule deleted', scope, ruleId, policyId);
  }

  /** Directions within the policy's and every referenced pattern/dictionary the tenant's. */
  private async checkRule(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    policy: PolicyRow,
    conditions: DlpRuleConditions,
  ): Promise<void> {
    if (!directionsWithin(conditions, directionsOf(policy.directions))) {
      throw dlpDirectionsInvalid(1);
    }
    const refs = referencedIds(conditions);
    const patterns = await this.repository.existingPatternIds(tx, scope, refs.patterns);
    const badPattern = refs.patterns.findIndex((id) => !patterns.has(id));
    if (badPattern !== -1) {
      throw dlpReferenceInvalid('conditions.selectors.customPatternIds', badPattern);
    }
    const dictionaries = await this.repository.existingDictionaryIds(tx, scope, refs.dictionaries);
    const badDictionary = refs.dictionaries.findIndex((id) => !dictionaries.has(id));
    if (badDictionary !== -1) {
      throw dlpReferenceInvalid('conditions.selectors.dictionaryIds', badDictionary);
    }
  }

  private record(
    tx: Prisma.TransactionClient,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    resourceType: string,
    resourceId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, {
      principal,
      scope,
      client,
      action,
      resourceType,
      resourceId,
      metadata,
    });
  }

  /** Ids only: names and conditions are never logged. */
  private logChange(message: string, scope: TenantScope, id: string, policyId?: string): void {
    this.logger.log({
      message: `dlp ${message}`,
      organizationId: scope.organizationId.toString(),
      id,
      ...(policyId !== undefined && { policyId }),
    });
  }
}
