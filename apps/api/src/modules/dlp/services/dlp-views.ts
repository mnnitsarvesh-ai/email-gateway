import { Injectable } from '@nestjs/common';
import {
  DLP_DIRECTIONS,
  type DlpDirection,
  type DlpRuleConditions,
  dlpExceptionFiltersSchema,
  dlpRuleConditionsSchema,
} from '@email-gateway/security-contracts';
import type { Prisma } from '@email-gateway/database';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ClientContext } from '../../auth/services/session.service';
import { aadhaarActive, twoDecimals } from '../domain/dlp-inputs';
import type {
  DlpComplianceView,
  DlpDictionaryDetail,
  DlpDictionaryView,
  DlpExceptionView,
  DlpPatternView,
  DlpPolicyView,
  DlpRuleView,
} from '../dto/dlp.schemas';
import type {
  ComplianceRow,
  DictionaryDetailRow,
  DictionaryRow,
  ExceptionRow,
  PatternRow,
  PolicyRow,
  RuleRow,
} from '../repositories/dlp-config.repository';
import { iso } from './dlp-writer';

/**
 * Row → view mapping of the DLP configuration routes and the audit images (step 4.5 D21).
 * Stored JSON is parsed defensively. Audit images never hold dictionary terms (counts only), and
 * no key matches `/code/i` (AuditService.scrubMetadata would drop it).
 */

const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];

export const directionsOf = (value: unknown): DlpDirection[] =>
  strings(value).filter((d): d is DlpDirection =>
    (DLP_DIRECTIONS as readonly string[]).includes(d),
  );

export function conditionsOf(value: unknown): DlpRuleConditions {
  const parsed = dlpRuleConditionsSchema.safeParse(value);
  // Stored conditions were validated on write (the api is their only writer); shown as stored.
  return parsed.success ? parsed.data : (value as DlpRuleConditions);
}

const audit = (row: {
  version: number;
  createdBy: { publicId: string } | null;
  updatedBy: { publicId: string } | null;
  createdAt: Date;
  updatedAt: Date;
}) => ({
  version: row.version,
  createdByUserId: row.createdBy?.publicId ?? null,
  updatedByUserId: row.updatedBy?.publicId ?? null,
  createdAt: row.createdAt.toISOString(),
  updatedAt: row.updatedAt.toISOString(),
});

export const policyView = (row: PolicyRow): DlpPolicyView => ({
  id: row.publicId,
  name: row.name,
  description: row.description,
  enabled: row.enabled,
  mode: row.mode,
  priority: row.priority,
  directions: directionsOf(row.directions),
  ruleCount: row._count.rules,
  ...audit(row),
});

export const policyImage = (row: PolicyRow) => ({
  name: row.name,
  description: row.description,
  enabled: row.enabled,
  mode: row.mode,
  priority: row.priority,
  directions: directionsOf(row.directions),
  version: row.version,
});

export const ruleView = (row: RuleRow): DlpRuleView => ({
  id: row.publicId,
  policyId: row.policy.publicId,
  name: row.name,
  enabled: row.enabled,
  priority: row.priority,
  conditions: conditionsOf(row.conditions),
  action: row.action,
  ...audit(row),
});

export const ruleImage = (row: RuleRow) => ({
  policyId: row.policy.publicId,
  name: row.name,
  enabled: row.enabled,
  priority: row.priority,
  conditions: conditionsOf(row.conditions),
  action: row.action,
  version: row.version,
});

const filtersOf = (value: unknown) => {
  if (value === null || value === undefined) return null;
  const parsed = dlpExceptionFiltersSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
};

export const exceptionView = (row: ExceptionRow, now: Date): DlpExceptionView => ({
  id: row.publicId,
  scope: row.scope,
  value: row.value,
  policyId: row.policy?.publicId ?? null,
  ruleId: row.rule?.publicId ?? null,
  filters: filtersOf(row.filters),
  reason: row.reason,
  expiresAt: row.expiresAt.toISOString(),
  expired: row.expiresAt.getTime() <= now.getTime(),
  enabled: row.enabled,
  ...audit(row),
});

export const exceptionImage = (row: ExceptionRow) => ({
  scope: row.scope,
  value: row.value,
  policyId: row.policy?.publicId ?? null,
  ruleId: row.rule?.publicId ?? null,
  filters: filtersOf(row.filters),
  reason: row.reason,
  expiresAt: row.expiresAt.toISOString(),
  enabled: row.enabled,
  version: row.version,
});

export const patternView = (row: PatternRow): DlpPatternView => ({
  id: row.publicId,
  name: row.name,
  pattern: row.pattern,
  caseInsensitive: row.caseInsensitive,
  validator: row.validator,
  contextKeywords: strings(row.contextKeywords),
  requireContext: row.requireContext,
  severity: row.severity,
  baseConfidence: twoDecimals(row.baseConfidence),
  maskStyle: row.maskStyle,
  enabled: row.enabled,
  ...audit(row),
});

/** The pattern is tenant configuration and may be in the before-image (D21); never a sample. */
export const patternImage = (row: PatternRow) => ({
  name: row.name,
  pattern: row.pattern,
  caseInsensitive: row.caseInsensitive,
  validator: row.validator,
  contextKeywords: strings(row.contextKeywords),
  requireContext: row.requireContext,
  severity: row.severity,
  baseConfidence: twoDecimals(row.baseConfidence),
  maskStyle: row.maskStyle,
  enabled: row.enabled,
  version: row.version,
});

export const dictionaryView = (row: DictionaryRow): DlpDictionaryView => ({
  id: row.publicId,
  name: row.name,
  category: row.category,
  termCount: row.termCount,
  severity: row.severity,
  baseConfidence: twoDecimals(row.baseConfidence),
  minMatches: row.minMatches,
  enabled: row.enabled,
  ...audit(row),
});

export const dictionaryDetail = (row: DictionaryDetailRow): DlpDictionaryDetail => ({
  ...dictionaryView(row),
  terms: strings(row.terms),
});

/** Term **count** only: dictionary terms (possibly confidential names) never reach the audit. */
export const dictionaryImage = (row: DictionaryRow) => ({
  name: row.name,
  category: row.category,
  termCount: row.termCount,
  severity: row.severity,
  baseConfidence: twoDecimals(row.baseConfidence),
  minMatches: row.minMatches,
  enabled: row.enabled,
  version: row.version,
});

export function complianceView(row: ComplianceRow | null, now: Date): DlpComplianceView {
  return {
    aadhaar: {
      enabled: row?.aadhaarEnabled ?? false,
      active: aadhaarActive(row, now),
      basis: row?.aadhaarBasis ?? null,
      reference: row?.aadhaarReference ?? null,
      attested: row?.aadhaarAttested ?? false,
      recordedByUserId: row?.aadhaarRecordedBy?.publicId ?? null,
      recordedAt: iso(row?.aadhaarRecordedAt ?? null),
      reviewDueAt: iso(row?.aadhaarReviewDueAt ?? null),
    },
    version: row?.version ?? 0,
    updatedAt: iso(row?.updatedAt ?? null),
  };
}

export const complianceImage = (row: ComplianceRow | null) =>
  row === null
    ? null
    : {
        enabled: row.aadhaarEnabled,
        basis: row.aadhaarBasis,
        reference: row.aadhaarReference,
        attested: row.aadhaarAttested,
        recordedAt: iso(row.aadhaarRecordedAt),
        reviewDueAt: iso(row.aadhaarReviewDueAt),
        version: row.version,
      };

/** Writes the DLP audit rows in the caller's transaction (D21: before-images in the same tx). */
@Injectable()
export class DlpAuditor {
  constructor(private readonly audit: AuditService) {}

  record(
    tx: Prisma.TransactionClient,
    entry: {
      principal: Principal;
      scope: TenantScope;
      client: ClientContext;
      action: string;
      resourceType: string;
      resourceId: string | null;
      metadata: Record<string, unknown>;
    },
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: entry.scope.organizationId,
        actor: this.audit.actorFrom(entry.principal),
        action: entry.action,
        resourceType: entry.resourceType,
        resourceId: entry.resourceId,
        sourceIp: entry.client.ip,
        metadata: entry.metadata,
      },
      tx,
    );
  }
}
