import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type {
  DlpAction,
  DlpAadhaarBasis,
  DlpDictionaryCategory,
  DlpDirection,
  DlpExceptionFilters,
  DlpExceptionScope,
  DlpMaskStyle,
  DlpPatternValidator,
  DlpPolicyMode,
  DlpRuleConditions,
  DlpTenantSeverity,
} from '@email-gateway/security-contracts';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentDlpReadError } from '../dlp.errors';

type Client = Prisma.TransactionClient;

const by = { select: { publicId: true } } as const;

const policySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  description: true,
  enabled: true,
  mode: true,
  priority: true,
  directions: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
  _count: { select: { rules: true } },
} satisfies Prisma.DlpPolicySelect;
export type PolicyRow = Prisma.DlpPolicyGetPayload<{ select: typeof policySelect }>;

const ruleSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  policyId: true,
  policy: by,
  name: true,
  enabled: true,
  priority: true,
  conditions: true,
  action: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
} satisfies Prisma.DlpPolicyRuleSelect;
export type RuleRow = Prisma.DlpPolicyRuleGetPayload<{ select: typeof ruleSelect }>;

const exceptionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  scope: true,
  value: true,
  policyId: true,
  ruleId: true,
  policy: by,
  rule: by,
  targetKey: true,
  filters: true,
  reason: true,
  expiresAt: true,
  enabled: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
} satisfies Prisma.DlpExceptionSelect;
export type ExceptionRow = Prisma.DlpExceptionGetPayload<{ select: typeof exceptionSelect }>;

const patternSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  pattern: true,
  caseInsensitive: true,
  validator: true,
  contextKeywords: true,
  requireContext: true,
  severity: true,
  baseConfidence: true,
  maskStyle: true,
  enabled: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
} satisfies Prisma.DlpCustomPatternSelect;
export type PatternRow = Prisma.DlpCustomPatternGetPayload<{ select: typeof patternSelect }>;

const dictionarySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  category: true,
  termCount: true,
  severity: true,
  baseConfidence: true,
  minMatches: true,
  enabled: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
} satisfies Prisma.DlpKeywordDictionarySelect;
export type DictionaryRow = Prisma.DlpKeywordDictionaryGetPayload<{
  select: typeof dictionarySelect;
}>;
const dictionaryDetailSelect = { ...dictionarySelect, terms: true } as const;
export type DictionaryDetailRow = Prisma.DlpKeywordDictionaryGetPayload<{
  select: typeof dictionaryDetailSelect;
}>;

const complianceSelect = {
  id: true,
  organizationId: true,
  aadhaarEnabled: true,
  aadhaarBasis: true,
  aadhaarReference: true,
  aadhaarAttested: true,
  aadhaarRecordedAt: true,
  aadhaarReviewDueAt: true,
  aadhaarRecordedBy: by,
  version: true,
  updatedAt: true,
} satisfies Prisma.DlpComplianceSettingsSelect;
export type ComplianceRow = Prisma.DlpComplianceSettingsGetPayload<{
  select: typeof complianceSelect;
}>;

export interface PolicyData {
  name: string;
  description: string | null;
  enabled: boolean;
  mode: DlpPolicyMode;
  priority: number;
  directions: DlpDirection[];
}

export interface RuleData {
  name: string;
  enabled: boolean;
  priority: number;
  conditions: DlpRuleConditions;
  action: DlpAction;
}

export interface ExceptionData {
  scope: DlpExceptionScope;
  value: string;
  policyId: bigint | null;
  ruleId: bigint | null;
  targetKey: string;
  filters: DlpExceptionFilters | null;
  reason: string;
  expiresAt: Date;
  enabled: boolean;
}

export interface PatternData {
  name: string;
  pattern: string;
  caseInsensitive: boolean;
  validator: DlpPatternValidator;
  contextKeywords: string[];
  requireContext: boolean;
  severity: DlpTenantSeverity;
  baseConfidence: number;
  maskStyle: DlpMaskStyle;
  enabled: boolean;
}

export interface DictionaryData {
  name: string;
  category: DlpDictionaryCategory;
  terms: string[];
  severity: DlpTenantSeverity;
  baseConfidence: number;
  minMatches: number;
  enabled: boolean;
}

export interface AadhaarData {
  aadhaarEnabled: boolean;
  aadhaarBasis: DlpAadhaarBasis | null;
  aadhaarReference: string | null;
  aadhaarAttested: boolean;
  aadhaarRecordedByUserId: bigint | null;
  aadhaarRecordedAt: Date | null;
  aadhaarReviewDueAt: Date | null;
}

export interface ListPage {
  take: number;
  beforeId?: bigint;
  enabled?: boolean;
}

/** Throws when a writer read returned a row of another organization or key (4.2 §6). */
function echo<T extends { organizationId: bigint }>(
  row: T | null,
  scope: TenantScope,
  read: string,
  matches: (row: T) => boolean,
): T | null {
  if (row !== null && (row.organizationId !== scope.organizationId || !matches(row))) {
    throw new InconsistentDlpReadError(read);
  }
  return row;
}

/**
 * Name lookups match under the column collation (case- and accent-insensitive), which JavaScript
 * cannot reproduce exactly: their echo check is the organization (and the policy for rules).
 */
const sameName = (): boolean => true;

function required<T>(row: T | null, read: string): T {
  if (row === null) throw new InconsistentDlpReadError(read);
  return row;
}

const page = (p: ListPage) => ({
  ...(p.beforeId !== undefined && { id: { lt: p.beforeId } }),
  ...(p.enabled !== undefined && { enabled: p.enabled }),
});

/**
 * Tenant-scoped access to the DLP configuration tables (step 4.5 D8, D9, D11, D12, D17, D21).
 * Lists and single reads use the replica (`PrismaReadService`, writer fallback above the lag
 * threshold); every read that decides a write runs on the writer transaction the service
 * passes, is locked (`FOR UPDATE`) where it is changed and echo-checked (organization and key);
 * every query matches the scope's organization, so another tenant's rows are never read or
 * written.
 */
@Injectable()
export class DlpConfigRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /**
   * Serializes the DLP writes of one organization (caps, unique names, references and in-use
   * checks are evaluated under this lock): the organization row, `FOR UPDATE`. Echo-checked.
   */
  async lockOrganization(tx: Client, scope: TenantScope): Promise<void> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR UPDATE`;
    if (rows.length !== 1 || BigInt(rows[0]!.id) !== scope.organizationId) {
      throw new InconsistentDlpReadError('organization_lock');
    }
  }

  // ---------------------------------------------------------------------------------- policies

  listPolicies(scope: TenantScope, p: ListPage): Promise<PolicyRow[]> {
    return this.db.dlpPolicy.findMany({
      where: tenantWhere(scope, page(p)),
      select: policySelect,
      orderBy: { id: 'desc' },
      take: p.take,
    });
  }

  findPolicy(scope: TenantScope, publicId: string): Promise<PolicyRow | null> {
    return this.db.dlpPolicy.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: policySelect,
    });
  }

  /** A policy's rules from the replica (by priority, then id). */
  rulesOf(scope: TenantScope, policyId: bigint): Promise<RuleRow[]> {
    return this.db.dlpPolicyRule.findMany({
      where: tenantWhere(scope, { policyId }),
      select: ruleSelect,
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
      take: 1000,
    });
  }

  async findPolicyForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<PolicyRow | null> {
    await tx.$queryRaw`SELECT id FROM dlp_policies
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.dlpPolicy.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: policySelect,
    });
    return echo(row, scope, 'policy', (r) => r.publicId === publicId);
  }

  async policyByName(tx: Client, scope: TenantScope, name: string): Promise<PolicyRow | null> {
    const row = await tx.dlpPolicy.findFirst({
      where: tenantWhere(scope, { name }),
      select: policySelect,
    });
    return echo(row, scope, 'policy_name', sameName);
  }

  countPolicies(tx: Client, scope: TenantScope): Promise<number> {
    return tx.dlpPolicy.count({ where: tenantWhere(scope) });
  }

  createPolicy(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: PolicyData,
    userId: bigint | null,
  ): Promise<PolicyRow> {
    return tx.dlpPolicy.create({
      data: {
        ...data,
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: policySelect,
    });
  }

  /** Compare-and-set on `version`; false when the version moved. */
  async updatePolicy(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: PolicyData,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.dlpPolicy.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: { ...data, updatedByUserId: userId, version: { increment: 1 } },
    });
    return count === 1;
  }

  async policyById(tx: Client, scope: TenantScope, id: bigint): Promise<PolicyRow> {
    const row = await tx.dlpPolicy.findFirst({
      where: tenantWhere(scope, { id }),
      select: policySelect,
    });
    return required(
      echo(row, scope, 'policy_id', (r) => r.id === id),
      'policy_id',
    );
  }

  /** A policy's rules on the writer (echo-checked: organization and policy). */
  async rulesOfForUpdate(tx: Client, scope: TenantScope, policyId: bigint): Promise<RuleRow[]> {
    await tx.$queryRaw`SELECT id FROM dlp_policy_rules
      WHERE organization_id = ${scope.organizationId} AND policy_id = ${policyId} FOR UPDATE`;
    const rows = await tx.dlpPolicyRule.findMany({
      where: tenantWhere(scope, { policyId }),
      select: ruleSelect,
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
    });
    for (const row of rows) echo(row, scope, 'policy_rules', (r) => r.policyId === policyId);
    return rows;
  }

  /** Deletes a policy and its rules (rules first: `policy_id` is RESTRICT). */
  async deletePolicy(tx: Client, scope: TenantScope, id: bigint): Promise<number> {
    const { count } = await tx.dlpPolicyRule.deleteMany({
      where: tenantWhere(scope, { policyId: id }),
    });
    await tx.dlpPolicy.deleteMany({ where: tenantWhere(scope, { id }) });
    return count;
  }

  /** Exceptions that target the policy or one of the given rules (FK RESTRICT). */
  countExceptionsTargeting(
    tx: Client,
    scope: TenantScope,
    target: { policyId?: bigint; ruleIds?: bigint[] },
  ): Promise<number> {
    const or: Prisma.DlpExceptionWhereInput[] = [];
    if (target.policyId !== undefined) or.push({ policyId: target.policyId });
    if (target.ruleIds !== undefined && target.ruleIds.length > 0) {
      or.push({ ruleId: { in: target.ruleIds } });
    }
    if (or.length === 0) return Promise.resolve(0);
    return tx.dlpException.count({ where: tenantWhere(scope, { OR: or }) });
  }

  // ------------------------------------------------------------------------------------- rules

  async findRuleForUpdate(
    tx: Client,
    scope: TenantScope,
    policyId: bigint,
    publicId: string,
  ): Promise<RuleRow | null> {
    await tx.$queryRaw`SELECT id FROM dlp_policy_rules
      WHERE organization_id = ${scope.organizationId} AND policy_id = ${policyId}
        AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.dlpPolicyRule.findFirst({
      where: tenantWhere(scope, { policyId, publicId }),
      select: ruleSelect,
    });
    return echo(row, scope, 'rule', (r) => r.publicId === publicId && r.policyId === policyId);
  }

  async ruleByName(
    tx: Client,
    scope: TenantScope,
    policyId: bigint,
    name: string,
  ): Promise<RuleRow | null> {
    const row = await tx.dlpPolicyRule.findFirst({
      where: tenantWhere(scope, { policyId, name }),
      select: ruleSelect,
    });
    return echo(row, scope, 'rule_name', (r) => r.policyId === policyId);
  }

  countRules(tx: Client, scope: TenantScope, policyId: bigint): Promise<number> {
    return tx.dlpPolicyRule.count({ where: tenantWhere(scope, { policyId }) });
  }

  createRule(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    policyId: bigint,
    data: RuleData,
    userId: bigint | null,
  ): Promise<RuleRow> {
    return tx.dlpPolicyRule.create({
      data: {
        ...data,
        conditions: data.conditions,
        publicId,
        policyId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: ruleSelect,
    });
  }

  async updateRule(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: RuleData,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.dlpPolicyRule.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: {
        ...data,
        conditions: data.conditions,
        updatedByUserId: userId,
        version: { increment: 1 },
      },
    });
    return count === 1;
  }

  async deleteRule(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.dlpPolicyRule.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async ruleById(tx: Client, scope: TenantScope, id: bigint): Promise<RuleRow> {
    const row = await tx.dlpPolicyRule.findFirst({
      where: tenantWhere(scope, { id }),
      select: ruleSelect,
    });
    return required(
      echo(row, scope, 'rule_id', (r) => r.id === id),
      'rule_id',
    );
  }

  /** Every rule of the organization (public id and conditions) for the in-use checks. */
  async allRuleConditions(
    tx: Client,
    scope: TenantScope,
  ): Promise<Array<{ publicId: string; conditions: Prisma.JsonValue }>> {
    const rows = await tx.dlpPolicyRule.findMany({
      where: tenantWhere(scope),
      select: { publicId: true, conditions: true, organizationId: true },
    });
    for (const row of rows) echo(row, scope, 'rule_conditions', () => true);
    return rows.map((r) => ({ publicId: r.publicId, conditions: r.conditions }));
  }

  /** The internal id of a policy or rule of the organization by public id (writer), or null. */
  async policyIdOf(tx: Client, scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await tx.dlpPolicy.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, organizationId: true },
    });
    return echo(row, scope, 'policy_ref', (r) => r.publicId === publicId)?.id ?? null;
  }

  async ruleIdOf(tx: Client, scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await tx.dlpPolicyRule.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, organizationId: true },
    });
    return echo(row, scope, 'rule_ref', (r) => r.publicId === publicId)?.id ?? null;
  }

  // -------------------------------------------------------------------------------- exceptions

  listExceptions(
    scope: TenantScope,
    p: ListPage & { scope?: DlpExceptionScope; active?: boolean; now: Date },
  ): Promise<ExceptionRow[]> {
    const active =
      p.active === undefined
        ? {}
        : p.active
          ? { enabled: true, expiresAt: { gt: p.now } }
          : { OR: [{ enabled: false }, { expiresAt: { lte: p.now } }] };
    return this.db.dlpException.findMany({
      where: tenantWhere(scope, {
        ...page(p),
        ...(p.scope !== undefined && { scope: p.scope }),
        ...active,
      }),
      select: exceptionSelect,
      orderBy: { id: 'desc' },
      take: p.take,
    });
  }

  async findExceptionForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<ExceptionRow | null> {
    await tx.$queryRaw`SELECT id FROM dlp_exceptions
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.dlpException.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: exceptionSelect,
    });
    return echo(row, scope, 'exception', (r) => r.publicId === publicId);
  }

  async exceptionByKey(
    tx: Client,
    scope: TenantScope,
    key: { scope: DlpExceptionScope; value: string; targetKey: string },
  ): Promise<ExceptionRow | null> {
    const row = await tx.dlpException.findFirst({
      where: tenantWhere(scope, key),
      select: exceptionSelect,
    });
    return echo(
      row,
      scope,
      'exception_key',
      (r) => r.scope === key.scope && r.value === key.value && r.targetKey === key.targetKey,
    );
  }

  countExceptions(tx: Client, scope: TenantScope): Promise<number> {
    return tx.dlpException.count({ where: tenantWhere(scope) });
  }

  createException(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: ExceptionData,
    userId: bigint | null,
  ): Promise<ExceptionRow> {
    return tx.dlpException.create({
      data: {
        ...data,
        filters: data.filters === null ? Prisma.DbNull : (data.filters as Prisma.InputJsonValue),
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: exceptionSelect,
    });
  }

  async updateException(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: Pick<ExceptionData, 'reason' | 'expiresAt' | 'enabled' | 'filters'>,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.dlpException.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: {
        ...data,
        filters: data.filters === null ? Prisma.DbNull : (data.filters as Prisma.InputJsonValue),
        updatedByUserId: userId,
        version: { increment: 1 },
      },
    });
    return count === 1;
  }

  async deleteException(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.dlpException.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async exceptionById(tx: Client, scope: TenantScope, id: bigint): Promise<ExceptionRow> {
    const row = await tx.dlpException.findFirst({
      where: tenantWhere(scope, { id }),
      select: exceptionSelect,
    });
    return required(
      echo(row, scope, 'exception_id', (r) => r.id === id),
      'exception_id',
    );
  }

  // ---------------------------------------------------------------------------------- patterns

  listPatterns(scope: TenantScope, p: ListPage): Promise<PatternRow[]> {
    return this.db.dlpCustomPattern.findMany({
      where: tenantWhere(scope, page(p)),
      select: patternSelect,
      orderBy: { id: 'desc' },
      take: p.take,
    });
  }

  findPattern(scope: TenantScope, publicId: string): Promise<PatternRow | null> {
    return this.db.dlpCustomPattern.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: patternSelect,
    });
  }

  async findPatternForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<PatternRow | null> {
    await tx.$queryRaw`SELECT id FROM dlp_custom_patterns
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.dlpCustomPattern.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: patternSelect,
    });
    return echo(row, scope, 'pattern', (r) => r.publicId === publicId);
  }

  async patternByName(tx: Client, scope: TenantScope, name: string): Promise<PatternRow | null> {
    const row = await tx.dlpCustomPattern.findFirst({
      where: tenantWhere(scope, { name }),
      select: patternSelect,
    });
    return echo(row, scope, 'pattern_name', sameName);
  }

  countPatterns(tx: Client, scope: TenantScope): Promise<number> {
    return tx.dlpCustomPattern.count({ where: tenantWhere(scope) });
  }

  createPattern(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: PatternData,
    userId: bigint | null,
  ): Promise<PatternRow> {
    return tx.dlpCustomPattern.create({
      data: {
        ...data,
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: patternSelect,
    });
  }

  async updatePattern(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: PatternData,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.dlpCustomPattern.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: { ...data, updatedByUserId: userId, version: { increment: 1 } },
    });
    return count === 1;
  }

  async deletePattern(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.dlpCustomPattern.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async patternById(tx: Client, scope: TenantScope, id: bigint): Promise<PatternRow> {
    const row = await tx.dlpCustomPattern.findFirst({
      where: tenantWhere(scope, { id }),
      select: patternSelect,
    });
    return required(
      echo(row, scope, 'pattern_id', (r) => r.id === id),
      'pattern_id',
    );
  }

  /** Which of the given public ids are custom patterns of the organization (writer). */
  async existingPatternIds(tx: Client, scope: TenantScope, ids: string[]): Promise<Set<string>> {
    if (ids.length === 0) return new Set();
    const rows = await tx.dlpCustomPattern.findMany({
      where: tenantWhere(scope, { publicId: { in: ids } }),
      select: { publicId: true, organizationId: true },
    });
    for (const row of rows) echo(row, scope, 'pattern_refs', (r) => ids.includes(r.publicId));
    return new Set(rows.map((r) => r.publicId));
  }

  // ------------------------------------------------------------------------------ dictionaries

  listDictionaries(scope: TenantScope, p: ListPage): Promise<DictionaryRow[]> {
    return this.db.dlpKeywordDictionary.findMany({
      where: tenantWhere(scope, page(p)),
      select: dictionarySelect,
      orderBy: { id: 'desc' },
      take: p.take,
    });
  }

  findDictionary(scope: TenantScope, publicId: string): Promise<DictionaryDetailRow | null> {
    return this.db.dlpKeywordDictionary.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: dictionaryDetailSelect,
    });
  }

  async findDictionaryForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<DictionaryDetailRow | null> {
    await tx.$queryRaw`SELECT id FROM dlp_keyword_dictionaries
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.dlpKeywordDictionary.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: dictionaryDetailSelect,
    });
    return echo(row, scope, 'dictionary', (r) => r.publicId === publicId);
  }

  async dictionaryByName(
    tx: Client,
    scope: TenantScope,
    name: string,
  ): Promise<DictionaryRow | null> {
    const row = await tx.dlpKeywordDictionary.findFirst({
      where: tenantWhere(scope, { name }),
      select: dictionarySelect,
    });
    return echo(row, scope, 'dictionary_name', sameName);
  }

  countDictionaries(tx: Client, scope: TenantScope): Promise<number> {
    return tx.dlpKeywordDictionary.count({ where: tenantWhere(scope) });
  }

  createDictionary(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: DictionaryData,
    userId: bigint | null,
  ): Promise<DictionaryDetailRow> {
    return tx.dlpKeywordDictionary.create({
      data: {
        ...data,
        termCount: data.terms.length,
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: dictionaryDetailSelect,
    });
  }

  async updateDictionary(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: DictionaryData,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.dlpKeywordDictionary.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: {
        ...data,
        termCount: data.terms.length,
        updatedByUserId: userId,
        version: { increment: 1 },
      },
    });
    return count === 1;
  }

  async deleteDictionary(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.dlpKeywordDictionary.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async dictionaryById(tx: Client, scope: TenantScope, id: bigint): Promise<DictionaryDetailRow> {
    const row = await tx.dlpKeywordDictionary.findFirst({
      where: tenantWhere(scope, { id }),
      select: dictionaryDetailSelect,
    });
    return required(
      echo(row, scope, 'dictionary_id', (r) => r.id === id),
      'dictionary_id',
    );
  }

  async existingDictionaryIds(tx: Client, scope: TenantScope, ids: string[]): Promise<Set<string>> {
    if (ids.length === 0) return new Set();
    const rows = await tx.dlpKeywordDictionary.findMany({
      where: tenantWhere(scope, { publicId: { in: ids } }),
      select: { publicId: true, organizationId: true },
    });
    for (const row of rows) echo(row, scope, 'dictionary_refs', (r) => ids.includes(r.publicId));
    return new Set(rows.map((r) => r.publicId));
  }

  // -------------------------------------------------------------------------------- compliance

  findCompliance(scope: TenantScope): Promise<ComplianceRow | null> {
    return this.db.dlpComplianceSettings.findFirst({
      where: tenantWhere(scope),
      select: complianceSelect,
    });
  }

  async findComplianceForUpdate(tx: Client, scope: TenantScope): Promise<ComplianceRow | null> {
    await tx.$queryRaw`SELECT id FROM dlp_compliance_settings
      WHERE organization_id = ${scope.organizationId} FOR UPDATE`;
    const row = await tx.dlpComplianceSettings.findFirst({
      where: tenantWhere(scope),
      select: complianceSelect,
    });
    return echo(row, scope, 'compliance', () => true);
  }

  createCompliance(tx: Client, scope: TenantScope, data: AadhaarData): Promise<ComplianceRow> {
    return tx.dlpComplianceSettings.create({
      data: { ...data, organizationId: scope.organizationId },
      select: complianceSelect,
    });
  }

  async updateCompliance(
    tx: Client,
    scope: TenantScope,
    expectedVersion: number,
    data: AadhaarData,
  ): Promise<boolean> {
    const { count } = await tx.dlpComplianceSettings.updateMany({
      where: tenantWhere(scope, { version: expectedVersion }),
      data: { ...data, version: { increment: 1 } },
    });
    return count === 1;
  }

  async complianceOf(tx: Client, scope: TenantScope): Promise<ComplianceRow> {
    const row = await tx.dlpComplianceSettings.findFirst({
      where: tenantWhere(scope),
      select: complianceSelect,
    });
    return required(
      echo(row, scope, 'compliance', () => true),
      'compliance',
    );
  }
}
