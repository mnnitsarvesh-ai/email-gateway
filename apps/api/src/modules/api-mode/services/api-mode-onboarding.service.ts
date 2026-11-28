import { Inject, Injectable } from '@nestjs/common';
import {
  canonicalPolicySha256,
  DEFAULT_REMEDIATION_POLICY,
  REMEDIATION_PRESETS,
  type RemediationPolicyDocument,
} from '@email-gateway/mailbox-api';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { ApiModeStatusService } from '../../../tenancy/api-mode-status.service';
import { DomainOwnershipReader } from '../../domains/services/domain-ownership-reader';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import {
  API_MODE_AUDIT,
  API_MODE_CURSOR_RESOURCES,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
  type ApiModeConfig,
  FIRST_COPY_FAILURE_CAP,
  FIRST_COPY_FAILURE_WINDOW_MS,
} from '../api-mode.constants';
import {
  domainNotFound,
  scopeConflict,
  scopeDepartmentInvalid,
  scopeDomainNotApi,
  scopeMailboxInvalid,
} from '../api-mode.errors';
import { computeDomainOnboarding, type OnboardingInput } from '../domain/domain-onboarding';
import {
  type DomainCoverageFacts,
  domainCoverage,
  PROTECTION_MODE_CAPABILITIES,
} from '../domain/protection-coverage';
import {
  checkScopeChange,
  departmentIdsOf,
  type ScopeRefusal,
  storedDepartmentIds,
} from '../domain/scope-rules';
import {
  type DomainOnboardingResponse,
  type DomainScopeChangeView,
  type DomainScopeView,
  type ProtectionCoverageQuery,
  type ProtectionCoverageView,
  PutDomainScopeBodySchema,
} from '../dto/api-mode-onboarding.schemas';
import {
  ApiModeOnboardingRepository,
  type DomainSettingsRow,
  type OnboardingDomainRow,
} from '../repositories/api-mode-onboarding.repository';
import { ApiModeRepository, type ConnectionFacts } from '../repositories/api-mode.repository';
import { ApiClawbackRepository } from '../repositories/api-clawback.repository';
import {
  ApiRemediationRepository,
  type DomainPolicyRow,
  type PolicyRow,
} from '../repositories/api-remediation.repository';
import { effectiveSettings } from './org-settings.service';
import { parseBody, parsePublicId } from './protection-mode.service';

type Tx = Prisma.TransactionClient;

const isUniqueViolation = (error: unknown): boolean =>
  (error as { code?: unknown } | null)?.code === 'P2002';

const effectiveMode = (d: OnboardingDomainRow) => d.configuredMode ?? d.organizationMode;

/** The effective remediation policy row of a domain (R2.6) and its source. */
function effectivePolicy(
  rows: { organization: PolicyRow | null; domains: DomainPolicyRow[] },
  domainId: bigint,
): { source: 'platform_default' | 'organization' | 'domain'; row: PolicyRow | null } {
  const domain = rows.domains.find((d) => d.domainId === domainId);
  if (domain) return { source: 'domain', row: domain };
  if (rows.organization) return { source: 'organization', row: rows.organization };
  return { source: 'platform_default', row: null };
}

const PRESET_SHAS = new Map(
  (Object.entries(REMEDIATION_PRESETS) as Array<[keyof typeof REMEDIATION_PRESETS, unknown]>).map(
    ([key, preset]) => [
      `${(preset as { mode: string }).mode}:${canonicalPolicySha256(
        (preset as { document: RemediationPolicyDocument }).document,
      )}`,
      key,
    ],
  ),
);

/** The preset a stored policy equals (mode + canonical document), else null. */
function presetKeyOf(row: PolicyRow | null): 'p1' | 'detectOnlyStart' | 'strict' | null {
  if (row === null) {
    const d = DEFAULT_REMEDIATION_POLICY;
    return PRESET_SHAS.get(`${d.mode}:${canonicalPolicySha256(d.document)}`) ?? null;
  }
  return PRESET_SHAS.get(`${row.mode}:${row.documentSha256}`) ?? null;
}

/**
 * The API-mode onboarding reads and the scope write (step API-4 A10, B6, B8, ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md): protection by mode (a signed v1 page of the
 * organization's domains with the static capability matrix and each domain's coverage and gaps),
 * the server-computed onboarding state of one domain (`computeDomainOnboarding`) and the domain's
 * mailbox scope (read; CAS write that requests the mailbox-worker's re-evaluation, audited
 * `api_mode.scope_updated`). Counts and codes only; the tenant always comes from the principal.
 */
@Injectable()
export class ApiModeOnboardingService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<ApiModeConfig, 'API_MODE_FIRST_COPY_HINT_AFTER_MINUTES'>,
    private readonly repository: ApiModeOnboardingRepository,
    private readonly apiMode: ApiModeRepository,
    private readonly remediation: ApiRemediationRepository,
    private readonly clawbacks: ApiClawbackRepository,
    private readonly status: ApiModeStatusService,
    private readonly ownership: DomainOwnershipReader,
    private readonly codec: CursorCodec,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---- protection by mode (A10) --------------------------------------------------------------

  /** `GET /api-mode/protection-coverage` (v1 cursor over the domains, newest first). */
  async coverage(
    principal: Principal,
    scope: TenantScope,
    query: ProtectionCoverageQuery,
  ): Promise<ProtectionCoverageView> {
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.coverage,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const modes = query.filters.effectiveMode?.values;
    const [status, fetched] = await Promise.all([
      this.status.status(scope.organizationId),
      this.repository.domains(scope, {
        take: query.limit + 1,
        ...(decoded && { beforeId: decimalKey(decoded.keys[0]) }),
        ...(modes && { modes: [...modes] }),
      }),
    ]);
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    const page = fetched.slice(0, decision.rows);
    const ids = page.map((d) => d.id);
    const [connections, policies, settingsRow, stats, domainSettings] = await Promise.all([
      this.apiMode.connections(scope),
      this.remediation.policies(scope),
      this.clawbacks.orgSettings(scope),
      this.repository.mailboxStats(scope, ids),
      this.repository.settings(scope, ids),
    ]);
    const policyEvaluation = effectiveSettings(settingsRow).policyEvaluationEnabled;
    const byId = new Map(connections.map((c) => [c.id, c]));
    return {
      entitled: status.entitled,
      organizationMode: status.organizationMode,
      totals: { ...status.domainsByEffectiveMode },
      capabilities: PROTECTION_MODE_CAPABILITIES.map((c) => ({ ...c })),
      items: page.map((d) =>
        domainCoverage(
          this.coverageFacts(d, {
            connection:
              d.linkedConnectionId === null ? null : (byId.get(d.linkedConnectionId) ?? null),
            policy: effectivePolicy(policies, d.id),
            stats: stats.get(d.id) ?? ApiModeOnboardingRepository.emptyStats(),
            settings: domainSettings.get(d.id) ?? null,
            policyEvaluation,
          }),
        ),
      ),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  private coverageFacts(
    d: OnboardingDomainRow,
    parts: {
      connection: ConnectionFacts | null;
      policy: ReturnType<typeof effectivePolicy>;
      stats: ReturnType<typeof ApiModeOnboardingRepository.emptyStats>;
      settings: DomainSettingsRow | null;
      policyEvaluation: boolean;
    },
  ): DomainCoverageFacts {
    const c = parts.connection;
    const row = parts.policy.row;
    return {
      domainId: d.publicId,
      name: d.name,
      status: d.status,
      effectiveMode: effectiveMode(d),
      inherited: d.configuredMode === null,
      inboundEnabled: d.inboundEnabled,
      outboundEnabled: d.outboundEnabled,
      mxPointsToGateway: d.mxPointsToGateway,
      connection:
        c === null
          ? null
          : {
              id: c.publicId,
              provider: c.provider,
              health: c.api?.healthStatus ?? 'unknown',
              disabled: c.status === 'disabled',
              mailboxGrantStatus: c.grant?.status ?? null,
              journalSources: c.journalSources.map((s) => ({
                status: s.status,
                verified: s.verifiedAt !== null,
              })),
              feedsEnabled: c.api?.feedsEnabled ?? false,
            },
      scopeKind: parts.settings?.scopeKind ?? 'all',
      mailboxes: {
        total: parts.stats.total === 0 && c?.api?.mailboxesTotal == null ? null : parts.stats.total,
        inScope: parts.stats.inScope,
        covered: parts.stats.covered,
        gap: parts.stats.gap,
        feedsActive: parts.stats.feedsActive,
      },
      remediation: {
        source: parts.policy.source,
        mode: row?.mode ?? DEFAULT_REMEDIATION_POLICY.mode,
        detectOnlyUntil: row?.mode === 'detect_only' ? (row.detectOnlyUntil ?? null) : null,
      },
      policyEvaluation: parts.policyEvaluation,
      lastCopyAt: parts.stats.lastSeenAt,
    };
  }

  // ---- domain onboarding (B8) ----------------------------------------------------------------

  /** `GET /api-mode/domains/{domainId}/onboarding`. */
  async onboarding(scope: TenantScope, rawId: unknown): Promise<DomainOnboardingResponse> {
    const domain = await this.repository.domain(scope, parsePublicId(rawId, 'domainId'));
    if (domain === null) throw domainNotFound();
    const now = this.now();
    const [ownership, connections, policies, stats, settings] = await Promise.all([
      this.ownership.view(scope, domain),
      this.apiMode.connections(scope),
      this.remediation.policies(scope),
      this.repository.mailboxStats(scope, [domain.id]),
      this.repository.settings(scope, [domain.id]),
    ]);
    const connection =
      domain.linkedConnectionId === null
        ? null
        : (connections.find((c) => c.id === domain.linkedConnectionId) ?? null);
    const setting = settings.get(domain.id) ?? null;
    const stat = stats.get(domain.id) ?? ApiModeOnboardingRepository.emptyStats();
    const [mailFlow, sources, firstCopy, failed] = await Promise.all([
      connection === null
        ? Promise.resolve(new Map<bigint, string>())
        : this.repository.mailFlowGrants(scope, [connection.id]),
      connection === null
        ? Promise.resolve([])
        : this.repository.journalSources(scope, connection.id),
      setting?.firstCopyId != null && setting.firstCopyReceivedAt !== null
        ? this.repository
            .copy(scope, setting.firstCopyId, setting.firstCopyReceivedAt)
            .then((c) => c ?? this.repository.newestCopy(scope, domain.id, now))
        : this.repository.newestCopy(scope, domain.id, now),
      connection?.api == null
        ? Promise.resolve(0)
        : this.repository.failedCopies(
            scope,
            connection.api.id,
            new Date(now.getTime() - FIRST_COPY_FAILURE_WINDOW_MS),
            FIRST_COPY_FAILURE_CAP,
          ),
    ]);
    const policy = effectivePolicy(policies, domain.id);
    const row = policy.row;
    const input: OnboardingInput = {
      now,
      hintAfterMinutes: this.config.API_MODE_FIRST_COPY_HINT_AFTER_MINUTES,
      domain: {
        id: domain.publicId,
        status: domain.status as OnboardingInput['domain']['status'],
        effectiveMode: effectiveMode(domain),
        createdAt: domain.createdAt,
        activatedAt: domain.activatedAt,
      },
      ownership: {
        method: ownership.method,
        providerCheck: ownership.providerCheck,
        providerCheckAvailable: ownership.providerCheckAvailable,
      },
      connection:
        connection === null
          ? null
          : {
              id: connection.publicId,
              provider: connection.provider,
              bound: connection.activeTenantKey !== null,
              status: connection.status,
              mailFlowGrant: mailFlow.get(connection.id) ?? null,
              mailboxAccessGrant: connection.grant?.status ?? null,
              throttledUntil: connection.api?.throttledUntil ?? null,
            },
      journalSources: sources.map((s) => ({
        id: s.publicId,
        status: s.status,
        health: s.healthStatus,
        verified: s.verifiedAt !== null,
        lastAcceptedAt: s.lastAcceptedAt,
      })),
      feeds: {
        enabled: connection?.api?.feedsEnabled ?? false,
        mode: connection?.api?.feedMode ?? 'poll',
        activeMailboxes: stat.feedsActive,
        inScopeMailboxes: stat.inScope,
      },
      scope: {
        kind: setting?.scopeKind ?? 'all',
        inScope: stat.inScope,
        excluded: stat.excluded,
      },
      mailboxesKnown: stat.total,
      action: {
        source: policy.source,
        mode: row?.mode ?? DEFAULT_REMEDIATION_POLICY.mode,
        presetKey: presetKeyOf(row),
        detectOnly:
          row?.mode === 'detect_only' && row.detectOnlyUntil !== null && row.detectOnlyThen !== null
            ? {
                until: row.detectOnlyUntil.toISOString(),
                then: row.detectOnlyThen,
                ended: row.detectOnlyUntil.getTime() <= now.getTime(),
              }
            : null,
      },
      firstCopy:
        firstCopy === null
          ? null
          : {
              detectionId: firstCopy.publicId,
              receivedAt: firstCopy.receivedAt,
              verdict: firstCopy.verdict,
              lagMs: firstCopy.lagMs,
              source: firstCopy.source,
              policyState: firstCopy.policyState,
              remediationState: firstCopy.remediationState,
            },
      recentFailedCopies: failed,
    };
    return computeDomainOnboarding(input) as DomainOnboardingResponse;
  }

  // ---- scope (B6) ----------------------------------------------------------------------------

  /** `GET /api-mode/domains/{domainId}/scope`. */
  async getScope(scope: TenantScope, rawId: unknown): Promise<DomainScopeView> {
    const domain = await this.repository.domain(scope, parsePublicId(rawId, 'domainId'));
    if (domain === null) throw domainNotFound();
    return this.scopeView(scope, domain);
  }

  private async scopeView(
    scope: TenantScope,
    domain: OnboardingDomainRow,
    tx?: Tx,
  ): Promise<DomainScopeView> {
    const [settings, stats] = await Promise.all([
      this.repository.settings(scope, [domain.id], tx),
      this.repository.mailboxStats(scope, [domain.id], tx),
    ]);
    const setting = settings.get(domain.id) ?? null;
    const stat = stats.get(domain.id) ?? ApiModeOnboardingRepository.emptyStats();
    const kind = setting?.scopeKind ?? 'all';
    const departmentIds =
      kind === 'departments' ? departmentIdsOf(setting?.scopeDepartmentIds) : [];
    const departments = await this.repository.departments(scope, departmentIds, tx);
    return {
      domainId: domain.publicId,
      kind,
      departments: departmentIds.map((id) => {
        const d = departments.find((x) => x.publicId === id);
        return { id, name: d?.name ?? null, memberCount: d?.memberCount ?? 0 };
      }),
      selectedMailboxes: stat.selected,
      inScope: stat.inScope,
      excluded: stat.excluded,
      recomputePending: setting?.scopeRecomputeRequestedAt != null,
      rowVersion: setting?.rowVersion ?? null,
      updatedAt: setting?.updatedAt.toISOString() ?? null,
    };
  }

  /** `PUT /api-mode/domains/{domainId}/scope` (keyed; CAS on `rowVersion`). */
  async putScope(
    principal: Principal,
    scope: TenantScope,
    input: { domainId: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<DomainScopeChangeView>> {
    const domainId = parsePublicId(input.domainId, 'domainId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(PutDomainScopeBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.scopePut;
    return this.idempotency.execute<DomainScopeChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: domainId,
        fingerprint: requestFingerprint({ operation, resourceId: domainId, body }),
      },
      async (tx) => {
        try {
          return {
            statusCode: 200,
            body: await this.applyScope(tx, principal, scope, domainId, body, sourceIp),
          };
        } catch (error) {
          if (isUniqueViolation(error)) throw scopeConflict(null);
          throw error;
        }
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  private async applyScope(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    domainPublicId: string,
    body: ReturnType<typeof PutDomainScopeBodySchema.parse>,
    sourceIp: string | null,
  ): Promise<DomainScopeChangeView> {
    const domain = await this.repository.lockDomain(tx, scope, domainPublicId);
    if (domain === null) throw domainNotFound();
    const current = await this.repository.lockSettings(tx, scope, domain.id);
    const requestedDepartments =
      body.scope.kind === 'departments' ? body.scope.departmentIds.map((d) => d.toLowerCase()) : [];
    const known = await this.repository.lockDepartments(tx, scope, requestedDepartments);
    const mailboxIds = body.scope.kind === 'mailboxes' ? (body.mailboxIds ?? []) : [];
    const matched = await this.repository.domainMailboxIds(tx, scope, domain.id, mailboxIds);
    const refusal = checkScopeChange({
      effectiveMode: effectiveMode(domain),
      currentRowVersion: current?.rowVersion ?? null,
      expectedRowVersion: body.expectedRowVersion,
      scope: body.scope,
      knownDepartmentIds: known,
      mailboxIds,
      domainMailboxMatches: matched.length,
    });
    if (refusal !== null) throw scopeError(refusal);
    const now = this.now();
    const departmentIds = storedDepartmentIds(body.scope);
    const ok = await this.repository.writeSettings(
      tx,
      scope,
      domain.id,
      current?.rowVersion ?? null,
      {
        scopeKind: body.scope.kind,
        scopeDepartmentIds: departmentIds,
        now,
        updatedByUserId: principal.kind === 'user' ? principal.userId : null,
      },
    );
    if (!ok) throw scopeConflict(current?.rowVersion ?? null);
    const selection = await this.repository.replaceSelection(tx, scope, domain.id, matched);
    const fromKind = current?.scopeKind ?? 'all';
    const fromDepartments = departmentIdsOf(current?.scopeDepartmentIds).sort();
    const changed =
      current === null ||
      fromKind !== body.scope.kind ||
      fromDepartments.join(',') !== [...(departmentIds ?? [])].sort().join(',') ||
      // A `mailboxes` write replaces the selection (counted as a change).
      body.scope.kind === 'mailboxes';
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: API_MODE_AUDIT.scopeUpdated,
        resourceType: API_MODE_RESOURCES.domainSettings,
        resourceId: domain.publicId,
        sourceIp,
        metadata: {
          domainId: domain.publicId,
          domainName: domain.name,
          from: fromKind,
          to: body.scope.kind,
          departments: departmentIds?.length ?? 0,
          mailboxes: selection.selected,
          created: current === null,
          reason: body.reason,
        },
      },
      tx,
    );
    const view = await this.scopeView(scope, domain, tx);
    return { ...view, created: current === null, changed };
  }
}

function scopeError(refusal: ScopeRefusal) {
  switch (refusal.code) {
    case 'api_mode_scope_domain_not_api':
      return scopeDomainNotApi(refusal.effectiveMode);
    case 'api_mode_scope_conflict':
      return scopeConflict(refusal.currentRowVersion);
    case 'api_mode_scope_department_invalid':
      return scopeDepartmentInvalid(refusal.departmentIds);
    case 'api_mode_scope_mailbox_invalid':
      return scopeMailboxInvalid(refusal.invalid);
  }
}
