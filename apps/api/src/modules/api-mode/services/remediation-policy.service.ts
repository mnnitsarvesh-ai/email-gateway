import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import {
  canonicalJson,
  canonicalPolicySha256,
  DEFAULT_REMEDIATION_POLICY,
  effectivePolicyMapping,
  hardDeleteRuleIds,
  type PolicyMapping,
  parseRemediationPolicy,
  REMEDIATION_PRESETS,
  type RemediationPolicyDocument,
  validateDetectOnly,
} from '@email-gateway/mailbox-api';
import { createHash } from 'node:crypto';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import {
  API_MODE_AUDIT,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
  type ApiModeConfig,
} from '../api-mode.constants';
import {
  detectOnlyInvalid,
  domainNotFound,
  hardDeleteDisabled,
  organizationNotFound,
  remediationPolicyConflict,
} from '../api-mode.errors';
import {
  type DetectOnlyView,
  type EffectivePolicyMappingView,
  type PutRemediationPolicyBody,
  PutRemediationPolicyBodySchema,
  type RemediationPolicyChangeView,
  type RemediationPolicyDocumentView,
  type RemediationPolicyView,
} from '../dto/api-mode-remediation.schemas';
import {
  ApiRemediationRepository,
  type PolicyRow,
  type PolicyWrite,
} from '../repositories/api-remediation.repository';
import { parseBody, parsePublicId } from './protection-mode.service';

type Tx = Prisma.TransactionClient;

const principalUserId = (p: Principal): bigint | null => (p.kind === 'user' ? p.userId : null);

/** A Prisma unique violation (a concurrent creation of the same scope's row). */
const isUniqueViolation = (error: unknown): boolean =>
  (error as { code?: unknown } | null)?.code === 'P2002';

/**
 * Validates the body's document with the strict `api-remediation-policy/1` schema (R2.1): `400
 * validation_failed` with the issues prefixed `document.`, then the platform rule of R-I2: a
 * `hard_delete` rule while `API_MODE_HARD_DELETE_ENABLED` is off → `422
 * api_mode_hard_delete_disabled` with the rule ids.
 */
export function validatePolicyDocument(
  raw: unknown,
  hardDeleteEnabled: boolean,
): RemediationPolicyDocument {
  const parsed = parseRemediationPolicy(raw);
  if (!parsed.ok) {
    throw new BadRequestException(
      parsed.issues
        .slice(0, 20)
        .map((i) => `document${i.path.map((p) => `.${String(p)}`).join('')}: ${i.message}`),
    );
  }
  const hardDelete = hardDeleteRuleIds(parsed.document);
  if (hardDelete.length > 0 && !hardDeleteEnabled) throw hardDeleteDisabled(hardDelete);
  return parsed.document;
}

/** The stored document as the view returns it (stored rows were validated on write). */
const documentOf = (value: Prisma.JsonValue): RemediationPolicyDocumentView =>
  value as unknown as RemediationPolicyDocumentView;

const clone = <T>(value: T): T => structuredClone(value);

/** B7: `simulatedSinceStart` stops counting here. */
export const DETECT_ONLY_SIMULATED_CAP = 10_000;

/** A4.2: the effective mapping of a stored document (missing keys → defaults). */
export function mappingOf(document: unknown): EffectivePolicyMappingView {
  const mapping =
    document !== null && typeof document === 'object' && !Array.isArray(document)
      ? ((document as { policyMapping?: PolicyMapping }).policyMapping ?? undefined)
      : undefined;
  return effectivePolicyMapping(mapping);
}

/** Audit metadata: hex SHA-256 of the canonical effective mapping (A12, §6 audit). */
export function mappingSha256(mapping: EffectivePolicyMappingView): string {
  return createHash('sha256').update(canonicalJson(mapping), 'utf8').digest('hex');
}

/** The period columns of a policy row as the view returns them (null = no period). */
export function detectOnlyViewOf(
  row: Pick<PolicyRow, 'detectOnlyUntil' | 'detectOnlyThen' | 'detectOnlyStartedAt'>,
  now: Date,
  simulatedSinceStart: number,
): DetectOnlyView {
  if (row.detectOnlyUntil === null || row.detectOnlyThen === null) return null;
  return {
    until: row.detectOnlyUntil.toISOString(),
    then: row.detectOnlyThen,
    startedAt: row.detectOnlyStartedAt?.toISOString() ?? null,
    ended: row.detectOnlyUntil.getTime() <= now.getTime(),
    simulatedSinceStart,
  };
}

/**
 * The remediation policy routes (step API-2 R2, R13 #1-#4; ADR-0101): the organization policy
 * (absent = the platform default P1) with the per-domain overrides, the presets and whether the
 * platform allows hard delete; PUT of the organization or a domain policy with CAS on
 * `row_version` (`expectedRowVersion: null` creates), DELETE of a domain override (back to
 * inheriting). Writes lock the organization row first (then the domain), so concurrent creations
 * of one scope serialize; each writes its `api_mode.remediation_policy_updated` audit row
 * (`{ scope, from: { mode, sha256 } | null, to: { mode, sha256 } | null, reason }`) in the same
 * transaction as the change and the stored Idempotency-Key response.
 */
@Injectable()
export class RemediationPolicyService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<ApiModeConfig, 'API_MODE_HARD_DELETE_ENABLED'>,
    private readonly repository: ApiRemediationRepository,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** `GET /api-mode/remediation-policy` (R13 #1). */
  async get(scope: TenantScope): Promise<RemediationPolicyView> {
    const rows = await this.repository.policies(scope);
    const org = rows.organization;
    const platform = DEFAULT_REMEDIATION_POLICY;
    const now = this.now();
    const detectOnly = (row: PolicyRow, domainId: bigint | null) =>
      this.detectOnlyOf(scope, row, domainId, now);
    return {
      organization:
        org === null
          ? {
              source: 'platform_default',
              id: null,
              mode: platform.mode,
              document: clone(platform.document) as RemediationPolicyDocumentView,
              sha256: canonicalPolicySha256(platform.document),
              rowVersion: null,
              updatedAt: null,
              effectivePolicyMapping: mappingOf(platform.document),
              detectOnly: null,
            }
          : {
              source: 'organization',
              id: org.publicId,
              mode: org.mode,
              document: documentOf(org.document),
              sha256: org.documentSha256,
              rowVersion: org.rowVersion,
              updatedAt: org.updatedAt.toISOString(),
              effectivePolicyMapping: mappingOf(org.document),
              detectOnly: await detectOnly(org, null),
            },
      domains: await Promise.all(
        rows.domains.map(async (d) => ({
          id: d.publicId,
          domainId: d.domain.publicId,
          domainName: d.domain.name,
          mode: d.mode,
          document: documentOf(d.document),
          sha256: d.documentSha256,
          rowVersion: d.rowVersion,
          updatedAt: d.updatedAt.toISOString(),
          effectivePolicyMapping: mappingOf(d.document),
          detectOnly: await detectOnly(d, d.domainId),
        })),
      ),
      presets: {
        p1: clone(REMEDIATION_PRESETS.p1) as RemediationPolicyView['presets']['p1'],
        detectOnlyStart: clone(
          REMEDIATION_PRESETS.detectOnlyStart,
        ) as RemediationPolicyView['presets']['p1'],
        strict: clone(REMEDIATION_PRESETS.strict) as RemediationPolicyView['presets']['p1'],
      },
      hardDeleteAvailable: this.config.API_MODE_HARD_DELETE_ENABLED,
    };
  }

  /** B7: the view of a row's period with the bounded simulated count since its start. */
  async detectOnlyOf(
    scope: TenantScope,
    row: PolicyRow,
    domainId: bigint | null,
    now: Date,
  ): Promise<DetectOnlyView> {
    if (row.detectOnlyUntil === null || row.detectOnlyThen === null) return null;
    const since = row.detectOnlyStartedAt;
    const simulated =
      since === null
        ? 0
        : await this.repository.simulatedSince(scope, domainId, since, DETECT_ONLY_SIMULATED_CAP);
    return detectOnlyViewOf(row, now, simulated);
  }

  /** `PUT /api-mode/remediation-policy` (R13 #2). */
  async putOrganization(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<RemediationPolicyChangeView>> {
    return this.put(principal, scope, { ...input, domainId: null }, sourceIp);
  }

  /** `PUT /api-mode/remediation-policy/domains/{domainId}` (R13 #3). */
  async putDomain(
    principal: Principal,
    scope: TenantScope,
    input: { domainId: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<RemediationPolicyChangeView>> {
    const domainId = parsePublicId(input.domainId, 'domainId');
    return this.put(principal, scope, { ...input, domainId }, sourceIp);
  }

  private async put(
    principal: Principal,
    scope: TenantScope,
    input: { domainId: string | null; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<RemediationPolicyChangeView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(PutRemediationPolicyBodySchema, input.body);
    const document = validatePolicyDocument(
      body.document,
      this.config.API_MODE_HARD_DELETE_ENABLED,
    );
    const period = validateDetectOnly(body.detectOnly, body.mode, this.now());
    if (!period.ok) throw detectOnlyInvalid(period.reason);
    const operation =
      input.domainId === null ? API_MODE_OPERATIONS.policyPut : API_MODE_OPERATIONS.domainPolicyPut;
    const resourceId = input.domainId ?? 'organization';
    return this.idempotency.execute<RemediationPolicyChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId,
        fingerprint: requestFingerprint({ operation, resourceId, body }),
      },
      async (tx) => {
        try {
          return {
            statusCode: 200,
            body: await this.applyPut(
              tx,
              principal,
              scope,
              input.domainId,
              body,
              document,
              sourceIp,
            ),
          };
        } catch (error) {
          // A concurrent creation of the same scope's row won the unique key: a CAS conflict.
          if (isUniqueViolation(error)) throw remediationPolicyConflict(null);
          throw error;
        }
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  private async applyPut(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    domainPublicId: string | null,
    body: PutRemediationPolicyBody,
    document: RemediationPolicyDocument,
    sourceIp: string | null,
  ): Promise<RemediationPolicyChangeView> {
    if (!(await this.repository.lockOrganization(tx, scope))) throw organizationNotFound();
    let domain: { id: bigint; publicId: string; name: string } | null = null;
    if (domainPublicId !== null) {
      domain = await this.repository.lockDomain(tx, scope, domainPublicId);
      if (domain === null) throw domainNotFound();
    }
    const current = await this.repository.lockPolicy(tx, scope, domain?.id ?? null);
    if ((current?.rowVersion ?? null) !== body.expectedRowVersion) {
      throw remediationPolicyConflict(current?.rowVersion ?? null);
    }
    const sha256 = canonicalPolicySha256(document);
    const now = this.now();
    // B7: `enforce` clears the period; a new period starts now (`notified_at` cleared); a
    // detect-only body without `detectOnly` keeps the stored period (API-2 bodies stay valid).
    const period = validateDetectOnly(body.detectOnly, body.mode, now);
    if (!period.ok) throw detectOnlyInvalid(period.reason);
    const keepDetectOnly = body.mode === 'detect_only' && body.detectOnly === undefined;
    const write: PolicyWrite = {
      mode: body.mode,
      document: document as unknown as Prisma.InputJsonValue,
      documentSha256: sha256,
      updatedByUserId: principalUserId(principal),
      detectOnly:
        period.period === null
          ? null
          : { until: period.period.until, then: period.period.then, startedAt: now },
      keepDetectOnly,
    };
    let after: PolicyRow | null;
    if (current === null) {
      after = await this.repository.createPolicy(tx, scope, domain?.id ?? null, write);
    } else {
      const ok = await this.repository.updatePolicy(
        tx,
        scope,
        current.id,
        current.rowVersion,
        write,
      );
      if (!ok) throw remediationPolicyConflict(current.rowVersion);
      after = await this.repository.policyById(tx, scope, current.id);
    }
    if (after === null) throw remediationPolicyConflict(null);
    const mapping = mappingOf(after.document);
    const detectOnly = detectOnlyViewOf(after, now, 0);
    await this.record(tx, principal, scope, sourceIp, {
      policyId: after.publicId,
      domain,
      from:
        current === null
          ? null
          : {
              mode: current.mode,
              sha256: current.documentSha256,
              policyMappingSha256: mappingSha256(mappingOf(current.document)),
            },
      to: { mode: after.mode, sha256, policyMappingSha256: mappingSha256(mapping) },
      detectOnly:
        detectOnly === null
          ? null
          : { until: detectOnly.until, then: detectOnly.then, startedAt: detectOnly.startedAt },
      reason: body.reason,
      rowVersion: after.rowVersion,
    });
    return {
      scope: domain === null ? 'organization' : 'domain',
      id: after.publicId,
      domainId: domain?.publicId ?? null,
      mode: after.mode,
      document: documentOf(after.document),
      sha256,
      rowVersion: after.rowVersion,
      updatedAt: after.updatedAt.toISOString(),
      effectivePolicyMapping: mapping,
      // A new period starts now (nothing simulated yet); a kept period counts since its start.
      detectOnly:
        detectOnly === null || write.detectOnly !== null
          ? detectOnly
          : await this.detectOnlyOf(scope, after, domain?.id ?? null, now),
      created: current === null,
    };
  }

  /**
   * `DELETE /api-mode/remediation-policy/domains/{domainId}` (R13 #4): the domain inherits the
   * organization policy again; `204` (also when it had no override: nothing changes, no audit).
   */
  async deleteDomain(
    principal: Principal,
    scope: TenantScope,
    input: { domainId: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<{ domainId: string; deleted: boolean }>> {
    const domainId = parsePublicId(input.domainId, 'domainId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const operation = API_MODE_OPERATIONS.domainPolicyDelete;
    return this.idempotency.execute<{ domainId: string; deleted: boolean }>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: domainId,
        fingerprint: requestFingerprint({ operation, resourceId: domainId, body: {} }),
      },
      async (tx) => {
        if (!(await this.repository.lockOrganization(tx, scope))) throw organizationNotFound();
        const domain = await this.repository.lockDomain(tx, scope, domainId);
        if (domain === null) throw domainNotFound();
        const current = await this.repository.lockPolicy(tx, scope, domain.id);
        if (current !== null) {
          await this.repository.deletePolicy(tx, scope, current.id);
          await this.record(tx, principal, scope, sourceIp, {
            policyId: current.publicId,
            domain,
            from: { mode: current.mode, sha256: current.documentSha256 },
            to: null,
            reason: null,
            rowVersion: current.rowVersion,
          });
        }
        return { statusCode: 204, body: { domainId: domain.publicId, deleted: current !== null } };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  private record(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    sourceIp: string | null,
    change: {
      policyId: string;
      domain: { publicId: string; name: string } | null;
      from: { mode: string; sha256: string; policyMappingSha256?: string } | null;
      to: { mode: string; sha256: string; policyMappingSha256?: string } | null;
      detectOnly?: { until: string; then: string; startedAt: string | null } | null;
      reason: string | null;
      rowVersion: number;
    },
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: API_MODE_AUDIT.remediationPolicyUpdated,
        resourceType: API_MODE_RESOURCES.remediationPolicy,
        resourceId: change.policyId,
        sourceIp,
        metadata: {
          scope: change.domain === null ? 'organization' : 'domain',
          domainId: change.domain?.publicId ?? null,
          domainName: change.domain?.name ?? null,
          from: change.from,
          to: change.to,
          ...(change.detectOnly !== undefined && { detectOnly: change.detectOnly }),
          rowVersion: change.rowVersion,
          ...(change.reason !== null && { reason: change.reason }),
        },
      },
      tx,
    );
  }
}
