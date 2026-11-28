import 'server-only';
import type { OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import { paginate } from '../generator';
import { apiError, ok, type FixtureHandlers, type FixtureResponse } from '../types';
import {
  apiModeConnectionRow,
  apiModeSettingsOf,
  apiModeStateOf,
  effectiveRemediationOf,
} from './api-mode';
import {
  MINUTE,
  bodyOf,
  domainViewOf,
  domainsOf,
  findDomain,
  guarded,
  idempotent,
} from './domains';
import { effectiveMode, organizationModeView, planOf } from './protection-modes';
import { providerConnectionsOf } from './provider-connections';
import { departmentsOf } from './users';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of API-mode parity and onboarding (step API-4 WP6, docs/plan/steps/38-api-mode-
 * parity-onboarding.md A10, B6, B8): protection by mode (static capability matrix, per-domain
 * facts and gap codes with cursor paging), the domain onboarding state (six steps computed from
 * the domain, its linked provider connection, the journal sources, feeds, scope, remediation
 * policy and the first copy) and the mailbox scope (GET and PUT with CAS and Idempotency-Key).
 * Mirrors the api's pure rules in a simplified form; synthetic only, per organization.
 */

export const API_MODE_ONBOARDING_OPERATIONS: readonly OperationId[] = [
  'ApiModeOnboardingController_protectionCoverage_v1',
  'ApiModeOnboardingController_domainOnboarding_v1',
  'ApiModeOnboardingController_getScope_v1',
  'ApiModeOnboardingController_putScope_v1',
  'DomainsController_providerOwnershipCheck_v1',
];

type Coverage = SuccessBody<'ApiModeOnboardingController_protectionCoverage_v1'>;
type CoverageItem = Coverage['items'][number];
type Onboarding = SuccessBody<'ApiModeOnboardingController_domainOnboarding_v1'>;
type OnboardingStep = Onboarding['steps'][number];
type Hint = Onboarding['firstCopy']['hints'][number];
type ScopeView = SuccessBody<'ApiModeOnboardingController_getScope_v1'>;
type ScopeKind = ScopeView['kind'];

interface ScopeRow {
  kind: ScopeKind;
  departmentIds: string[];
  selected: Set<string>;
  rowVersion: number;
  updatedAt: string;
}

interface OnboardingFixtureState {
  scopes: Map<string, ScopeRow>;
  idempotency: Map<string, FixtureResponse>;
}

const store = globalThis as typeof globalThis & {
  __egDevFixtureApiModeOnboarding?: OnboardingFixtureState;
};
const state: OnboardingFixtureState = (store.__egDevFixtureApiModeOnboarding ??= {
  scopes: new Map(),
  idempotency: new Map(),
});

export function resetApiModeOnboardingFixtures(): void {
  state.scopes.clear();
  state.idempotency.clear();
}

/** First-copy hints appear after this many minutes of waiting (API_MODE_FIRST_COPY_HINT…). */
export const FIRST_COPY_HINT_AFTER_MINUTES = 10;
const MAILBOX_PROFILE = {
  microsoft_365: 'm365.mailbox_remediation',
  google_workspace: 'google.mailbox_remediation',
} as const;
const MAIL_FLOW_PROFILE = {
  microsoft_365: 'm365.mail_flow',
  google_workspace: 'google.mail_flow',
} as const;

const CAPABILITIES: Coverage['capabilities'] = (
  [
    ['pre_delivery_blocking', 'yes', 'no', 'yes', 'api_acts_after_delivery'],
    ['hold_for_review', 'yes', 'partial', 'yes', 'api_review_in_quarantine_folder'],
    ['post_delivery_removal', 'partial', 'yes', 'yes', 'inline_release_only'],
    ['retroactive_clawback', 'no', 'yes', 'yes', 'inline_needs_mailbox_access'],
    ['internal_mail', 'partial', 'yes', 'yes', 'inline_sees_relayed_internal_only'],
    ['outbound_dlp_enforce', 'yes', 'no', 'yes', 'api_outbound_already_sent'],
    ['outbound_dlp_detect', 'yes', 'yes', 'yes', null],
    ['tenant_policies', 'yes', 'partial', 'yes', 'api_post_delivery_actions_only'],
    ['url_rewriting', 'yes', 'no', 'yes', 'api_no_message_edits'],
    ['message_tagging', 'yes', 'yes', 'yes', 'inline_headers_api_category_label'],
    ['user_reports', 'no', 'yes', 'yes', 'reports_need_report_mailbox'],
    ['alerts_webhooks', 'yes', 'yes', 'yes', null],
  ] as const
).map(([code, inline, api, hybrid, noteCode]) => ({ code, inline, api, hybrid, noteCode }));

function scopeOf(domainId: string): ScopeRow | null {
  return state.scopes.get(domainId) ?? null;
}

/** The mailbox's scope state from the domain's scope (the worker's evaluation, simplified). */
function inScope(domainId: string, mailboxId: string, address: string, orgId: string): boolean {
  const scope = scopeOf(domainId);
  if (!scope || scope.kind === 'all') return true;
  if (scope.kind === 'mailboxes') return scope.selected.has(mailboxId);
  // Departments: every second mailbox is a member of the first listed department (synthetic).
  return scope.departmentIds.length > 0 && departmentsOf(orgId).length > 0 && address < 'e';
}

/** The provider connection a domain is linked to (8.2 links). */
function linkedConnection(organizationId: string, domainId: string) {
  return (
    providerConnectionsOf(organizationId).find(
      (c) => c.status !== 'disabled' && c.domains.some((d) => d.id === domainId),
    ) ??
    providerConnectionsOf(organizationId).find((c) => c.domains.some((d) => d.id === domainId)) ??
    null
  );
}

function domainFacts(organizationId: string, domainId: string) {
  const api = apiModeStateOf(organizationId);
  const mailboxes = api.mailboxes.filter(
    (m) => m.domain?.id === domainId && m.status !== 'deleted',
  );
  const scoped = mailboxes.filter((m) => inScope(domainId, m.id, m.address, organizationId));
  const connection = linkedConnection(organizationId, domainId);
  const row = connection ? apiModeConnectionRow(organizationId, connection.id) : null;
  const copies = api.detections
    .filter((d) => mailboxes.some((m) => m.id === d.mailboxId) && d.direction !== 'outbound')
    .sort((a, b) => a.receivedAt.localeCompare(b.receivedAt));
  return { mailboxes, scoped, connection, row, copies, detections: api.detections };
}

function coverageItem(organizationId: string, domainId: string): CoverageItem | null {
  const entry = findDomain(organizationId, domainId);
  if (!entry) return null;
  const d = entry.domain;
  const mode = d.protectionMode.effective;
  const inline = mode !== 'api';
  const apiSide = mode !== 'inline';
  const gaps: CoverageItem['gaps'] = [];
  const mx = entry.checks.mx === 'valid' ? true : entry.checks.mx === 'pending' ? null : false;
  if (inline) {
    if (mx !== true) gaps.push('inline_mx_not_at_gateway');
    if (d.status !== 'active') gaps.push('inline_not_active');
  }
  let apiView: CoverageItem['api'] = null;
  if (apiSide) {
    const f = domainFacts(organizationId, domainId);
    const c = f.connection;
    const grant =
      c?.grants.find((g) => g.profile === MAILBOX_PROFILE[c.provider] && g.status !== 'revoked')
        ?.status ?? null;
    const access = grant === 'active' ? 'active' : grant === 'revoked' ? 'revoked' : 'missing';
    const sources = f.row?.journalSources ?? [];
    const journal = sources.some((s) => s.verified && s.status !== 'disabled')
      ? 'verified'
      : sources.some((s) => s.status === 'pending_verification')
        ? 'pending'
        : 'missing';
    const feedsActive = f.scoped.filter((m) => m.feedStatus === 'active').length;
    const feeds = !f.row?.feedsEnabled
      ? 'off'
      : f.scoped.length > 0 && feedsActive >= Math.ceil(f.scoped.length * 0.9)
        ? 'active'
        : 'partial';
    const remediation = effectiveRemediationOf(organizationId, domainId);
    const settings = apiModeSettingsOf(organizationId);
    const gap = f.scoped.filter((m) => m.coverage === 'gap').length;
    if (c === null || c.status === 'disabled') gaps.push('api_no_connection');
    if (access !== 'active') gaps.push('api_no_mailbox_access');
    if (journal !== 'verified' && feeds === 'off') gaps.push('api_no_intake');
    if (gap > 0) gaps.push('api_coverage_gaps');
    if (mode === 'api' && mx === true) gaps.push('api_mx_points_to_gateway');
    if (remediation.mode === 'detect_only') gaps.push('api_detect_only');
    if (!settings.policyEvaluationEnabled) gaps.push('api_policy_evaluation_off');
    const seen = f.mailboxes
      .map((m) => m.journalLastSeenAt)
      .filter((v): v is string => v !== null)
      .sort();
    apiView = {
      applies: true,
      connection: c
        ? {
            id: c.id,
            provider: c.provider,
            health: f.row?.health.status ?? 'unknown',
            mailboxAccess: access,
          }
        : null,
      intake: { journal, feeds },
      scope: scopeOf(domainId)?.kind ?? 'all',
      mailboxes: {
        inScope: f.scoped.length,
        covered: f.scoped.filter((m) => m.coverage === 'covered').length,
        gap,
        total: f.mailboxes.length > 0 ? f.mailboxes.length : null,
      },
      remediation: {
        source: remediation.source,
        mode: remediation.mode,
        detectOnlyUntil: remediation.detectOnly?.until ?? null,
      },
      policyEvaluation: settings.policyEvaluationEnabled,
      lastCopyAt: seen.at(-1) ?? null,
    };
  }
  return {
    domainId: d.id,
    name: d.name,
    status: d.status,
    effectiveMode: mode,
    inherited: d.protectionMode.inherited,
    inline: {
      applies: inline,
      inboundEnabled: d.inboundEnabled,
      outboundEnabled: d.outboundEnabled,
      mxPointsToGateway: mx,
    },
    api: apiView,
    gaps,
  };
}

const step = (
  key: OnboardingStep['key'],
  status: OnboardingStep['status'],
  blockers: OnboardingStep['blockers'] = [],
  nextAction: OnboardingStep['nextAction'] = null,
): OnboardingStep => ({ key, status, blockers, nextAction });

function onboardingOf(organizationId: string, domainId: string): Onboarding | null {
  const entry = findDomain(organizationId, domainId);
  if (!entry) return null;
  // Reading the domain view settles a due provider answer (the scheduler's win).
  const d = domainViewOf(organizationId, entry);
  const mode = d.protectionMode.effective;
  const owned = d.status === 'verified' || d.status === 'active' || d.status === 'suspended';
  const f = domainFacts(organizationId, domainId);
  const c = f.connection;
  const grantOf = (profile: string) =>
    c?.grants.find((g) => g.profile === profile && g.status !== 'revoked')?.status ?? null;
  const connection = c
    ? {
        id: c.id,
        provider: c.provider,
        bound: c.tenantId !== null,
        status: c.status,
        mailFlowGrant: grantOf(MAIL_FLOW_PROFILE[c.provider]),
        mailboxAccessGrant: grantOf(MAILBOX_PROFILE[c.provider]),
      }
    : null;
  const sources = (f.row?.journalSources ?? []).map((s) => ({
    id: s.id,
    status: s.status as 'pending_verification' | 'active' | 'paused' | 'disabled',
    health: s.health as 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused',
    verified: s.verified,
  }));
  const feeds = {
    enabled: f.row?.feedsEnabled ?? false,
    mode: f.row?.feedMode ?? ('poll' as const),
    activeMailboxes: f.scoped.filter((m) => m.feedStatus === 'active').length,
    inScopeMailboxes: f.scoped.length,
  };
  const feedsDone =
    feeds.enabled &&
    feeds.inScopeMailboxes > 0 &&
    feeds.activeMailboxes >= Math.ceil(feeds.inScopeMailboxes * 0.9);
  const verifiedJournal = sources.some((s) => s.verified && s.status !== 'disabled');
  const remediation = effectiveRemediationOf(organizationId, domainId);
  const first =
    f.copies.find((copy) =>
      inScope(domainId, copy.mailboxId, copy.mailboxAddress, organizationId),
    ) ?? null;
  let steps: OnboardingStep[];
  if (mode === 'inline') {
    steps = (['ownership', 'connect', 'intake', 'mailboxes', 'action', 'review'] as const).map(
      (key) => step(key, 'skipped'),
    );
  } else {
    const ownership = owned
      ? step('ownership', 'done')
      : d.status === 'failed'
        ? step('ownership', 'blocked', ['ownership_failed'], 'restart_verification')
        : step(
            'ownership',
            'in_progress',
            [],
            d.ownership.providerCheck?.status === 'pending'
              ? null
              : d.ownership.providerCheckAvailable
                ? 'verify_through_provider'
                : 'verify_ownership',
          );
    const connect =
      connection === null
        ? step('connect', 'not_started', [], 'link_connection')
        : connection.status === 'disabled'
          ? step('connect', 'blocked', ['connection_disabled'], 'enable_connection')
          : connection.bound && connection.mailboxAccessGrant === 'active'
            ? step('connect', 'done')
            : step(
                'connect',
                'in_progress',
                [
                  ...(connection.bound ? [] : (['connection_not_bound'] as const)),
                  ...(connection.mailboxAccessGrant === 'active'
                    ? []
                    : (['mailbox_access_missing'] as const)),
                ],
                connection.bound ? 'grant_mailbox_access' : 'complete_binding',
              );
    const intake =
      connection === null
        ? step('intake', 'blocked', ['connection_missing'], 'link_connection')
        : verifiedJournal || feedsDone
          ? step('intake', 'done')
          : sources.some((s) => s.status === 'pending_verification')
            ? step('intake', 'in_progress', [], 'verify_journal_source')
            : feeds.enabled
              ? step('intake', 'in_progress', [], 'wait_for_feeds')
              : step('intake', 'not_started', [], 'set_up_journal');
    const mailboxes =
      connection === null
        ? step('mailboxes', 'blocked', ['connection_missing'], 'link_connection')
        : f.scoped.length > 0
          ? step('mailboxes', 'done')
          : f.mailboxes.length === 0
            ? step('mailboxes', 'not_started', [], 'sync_inventory')
            : step('mailboxes', 'in_progress', ['no_mailboxes_in_scope'], 'choose_mailboxes');
    const action =
      remediation.source === 'platform_default'
        ? step('action', 'not_started', [], 'choose_action')
        : step('action', 'done');
    const blockers: OnboardingStep['blockers'] = [];
    if (!owned) blockers.push(d.status === 'failed' ? 'ownership_failed' : 'ownership_pending');
    if (connection === null) blockers.push('connection_missing');
    else if (connection.status === 'disabled') blockers.push('connection_disabled');
    else if (!connection.bound) blockers.push('connection_not_bound');
    if (connection !== null && connection.mailboxAccessGrant !== 'active')
      blockers.push('mailbox_access_missing');
    const review =
      blockers.length > 0
        ? step('review', 'blocked', blockers)
        : d.status !== 'active'
          ? step('review', 'not_started', [], 'activate_domain')
          : first
            ? step('review', 'done')
            : step('review', 'in_progress', [], 'send_test_message');
    steps = [ownership, connect, intake, mailboxes, action, review];
  }
  const since = Date.parse(d.activatedAt ?? d.createdAt);
  const waited = Math.max(0, Math.floor((Date.now() - since) / MINUTE));
  const hints: Hint[] = [];
  if (!first && waited >= FIRST_COPY_HINT_AFTER_MINUTES) {
    const add = (code: Hint['code'], severity: Hint['severity'], link: string | null = null) =>
      hints.push({ code, severity, link });
    const connLink = c ? `/integrations/providers/${c.id}` : '/integrations/providers';
    if (d.status !== 'active') add('domain_not_active', 'warn', `/domains/${d.id}`);
    if (mode === 'inline') add('mode_not_api', 'warn', `/domains/${d.id}`);
    if (!connection) add('connection_missing', 'warn', connLink);
    else {
      if (!connection.bound) add('connection_not_bound', 'warn', connLink);
      if (connection.mailboxAccessGrant !== 'active')
        add('mailbox_access_missing', 'warn', connLink);
    }
    if (sources.length === 0)
      add('journal_source_missing', feeds.enabled ? 'info' : 'warn', '/journaling');
    if (!feeds.enabled && !verifiedJournal)
      add('feeds_disabled', 'info', '/api-mode?tab=connections');
    if (f.scoped.length === 0) add('no_mailboxes_in_scope', 'warn', `/domains/${d.id}`);
    add('send_test_message', 'info', null);
  }
  return {
    domainId: d.id,
    effectiveMode: mode,
    steps,
    ownership: {
      status: owned ? 'verified' : d.status === 'failed' ? 'failed' : 'pending',
      method: d.ownership.method,
      providerCheck: d.ownership.providerCheck
        ? {
            id: d.ownership.providerCheck.id,
            status: d.ownership.providerCheck.status,
            result: d.ownership.providerCheck.result,
            connectionId: d.ownership.providerCheck.connectionId,
            requestedAt: d.ownership.providerCheck.requestedAt,
            checkedAt: d.ownership.providerCheck.checkedAt,
            expiresAt: d.ownership.providerCheck.expiresAt,
          }
        : null,
      providerCheckAvailable: d.ownership.providerCheckAvailable,
    },
    connection,
    intake: {
      journalSources: sources.map(({ id, status, health }) => ({ id, status, health })),
      feeds,
    },
    scope: {
      kind: scopeOf(domainId)?.kind ?? 'all',
      inScope: f.scoped.length,
      excluded: f.mailboxes.length - f.scoped.length,
    },
    action: {
      source: remediation.source,
      mode: remediation.mode,
      presetKey: remediation.presetKey,
      detectOnly: remediation.detectOnly
        ? {
            until: remediation.detectOnly.until,
            then: remediation.detectOnly.then,
            ended: remediation.detectOnly.ended,
          }
        : null,
    },
    firstCopy: {
      status: first ? 'received' : 'waiting',
      copy: first
        ? {
            detectionId: first.id,
            receivedAt: first.receivedAt,
            verdict: first.verdict,
            lagMs: first.lagMs,
            source: first.source,
            policyState: first.policyState,
            remediationState: first.remediationState,
          }
        : null,
      waitingSinceMinutes: first ? null : waited,
      hints,
    },
  };
}

function scopeView(organizationId: string, domainId: string): ScopeView {
  const f = domainFacts(organizationId, domainId);
  const scope = scopeOf(domainId);
  const departments = departmentsOf(organizationId);
  return {
    domainId,
    kind: scope?.kind ?? 'all',
    departments: (scope?.departmentIds ?? []).map((id) => {
      const department = departments.find((x) => x.id === id);
      return { id, name: department?.name ?? null, memberCount: department?.memberCount ?? 0 };
    }),
    selectedMailboxes: scope?.selected.size ?? 0,
    inScope: f.scoped.length,
    excluded: f.mailboxes.length - f.scoped.length,
    recomputePending: false,
    rowVersion: scope?.rowVersion ?? null,
    updatedAt: scope?.updatedAt ?? null,
  };
}

const domainNotFound = () => apiError(404, 'domain_not_found', 'Domain not found');

export const fixtures: FixtureHandlers = {
  ApiModeOnboardingController_protectionCoverage_v1: guarded(
    'ApiModeOnboardingController_protectionCoverage_v1',
    (request, p) => {
      const view = organizationModeView(p.organizationId, planOf(p.organizationId));
      const filter = request.query.get('effectiveMode');
      const rows = domainsOf(p.organizationId)
        .filter((e) => !e.deleted)
        .map((e) => coverageItem(p.organizationId, e.domain.id))
        .filter((item): item is CoverageItem => item !== null)
        .filter((item) => !filter || item.effectiveMode === filter);
      const totals = { inline: 0, api: 0, hybrid: 0 };
      for (const e of domainsOf(p.organizationId).filter((x) => !x.deleted))
        totals[effectiveMode(p.organizationId, e.domain.protectionMode.configured)] += 1;
      const page = paginate(rows, request.query, 'items') as {
        items: CoverageItem[];
        nextCursor: string | null;
      };
      return ok('ApiModeOnboardingController_protectionCoverage_v1', {
        entitled: view.entitled,
        organizationMode: view.mode,
        totals,
        capabilities: CAPABILITIES,
        items: page.items,
        nextCursor: page.nextCursor,
      });
    },
  ),
  ApiModeOnboardingController_domainOnboarding_v1: guarded(
    'ApiModeOnboardingController_domainOnboarding_v1',
    (request, p) => {
      const view = onboardingOf(p.organizationId, request.params.domainId ?? '');
      return view ? ok('ApiModeOnboardingController_domainOnboarding_v1', view) : domainNotFound();
    },
  ),
  ApiModeOnboardingController_getScope_v1: guarded(
    'ApiModeOnboardingController_getScope_v1',
    (request, p) => {
      const entry = findDomain(p.organizationId, request.params.domainId);
      return entry
        ? ok(
            'ApiModeOnboardingController_getScope_v1',
            scopeView(p.organizationId, entry.domain.id),
          )
        : domainNotFound();
    },
  ),
  ApiModeOnboardingController_putScope_v1: guarded(
    'ApiModeOnboardingController_putScope_v1',
    (request, p) =>
      idempotent(state.idempotency, request, () => {
        const entry = findDomain(p.organizationId, request.params.domainId);
        if (!entry) return domainNotFound();
        const domainId = entry.domain.id;
        if (entry.domain.protectionMode.effective === 'inline')
          return apiError(409, 'api_mode_scope_domain_not_api', 'The domain is not in API mode');
        const body = bodyOf<RequestBody<'ApiModeOnboardingController_putScope_v1'>>(request);
        const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
        if (!reason || reason.length > 500)
          return apiError(400, 'validation_failed', ['reason: 1 to 500 characters']);
        const kind = body.scope?.kind;
        if (kind !== 'all' && kind !== 'departments' && kind !== 'mailboxes')
          return apiError(400, 'validation_failed', ['scope.kind: all, departments or mailboxes']);
        if (kind === 'mailboxes' && !Array.isArray(body.mailboxIds))
          return apiError(400, 'validation_failed', ['mailboxIds: required for kind mailboxes']);
        if (kind !== 'mailboxes' && body.mailboxIds !== undefined)
          return apiError(400, 'validation_failed', ['mailboxIds: only for kind mailboxes']);
        const departmentIds =
          kind === 'departments' && 'departmentIds' in body.scope! ? body.scope.departmentIds : [];
        if (kind === 'departments' && (departmentIds.length === 0 || departmentIds.length > 20))
          return apiError(400, 'validation_failed', ['scope.departmentIds: 1 to 20']);
        const known = new Set(departmentsOf(p.organizationId).map((d) => d.id));
        if (departmentIds.some((id) => !known.has(id)))
          return apiError(
            422,
            'api_mode_scope_department_invalid',
            'A department does not belong to the organization',
          );
        const own = new Set(
          apiModeStateOf(p.organizationId)
            .mailboxes.filter((m) => m.domain?.id === domainId)
            .map((m) => m.id),
        );
        if ((body.mailboxIds ?? []).some((id) => !own.has(id)))
          return apiError(
            422,
            'api_mode_scope_mailbox_invalid',
            'A mailbox does not belong to the domain',
          );
        const current = scopeOf(domainId);
        if ((body.expectedRowVersion ?? null) !== (current?.rowVersion ?? null))
          return apiError(409, 'api_mode_scope_conflict', 'expectedRowVersion is not current', {
            currentRowVersion: current?.rowVersion ?? null,
          });
        const next: ScopeRow = {
          kind,
          departmentIds,
          selected: new Set(kind === 'mailboxes' ? body.mailboxIds : []),
          rowVersion: (current?.rowVersion ?? 0) + 1,
          updatedAt: new Date().toISOString(),
        };
        const changed =
          !current ||
          current.kind !== next.kind ||
          current.departmentIds.join() !== next.departmentIds.join() ||
          [...current.selected].sort().join() !== [...next.selected].sort().join();
        state.scopes.set(domainId, changed ? next : current);
        return ok('ApiModeOnboardingController_putScope_v1', {
          ...scopeView(p.organizationId, domainId),
          created: current === null,
          changed,
        });
      }),
  ),
};
