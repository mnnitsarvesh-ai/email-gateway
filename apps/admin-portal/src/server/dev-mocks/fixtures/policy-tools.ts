import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { apiError, ok, type FixtureHandlers, type FixtureRequest } from '../types';
import { FIXTURE_MESSAGES, fixtureMessage } from './messages';
import { POLICY_CATALOG_SNAPSHOT } from './policy-catalog.data';
import {
  cannedViolations,
  DSL,
  findPolicy,
  findVersion,
  firstPathContaining,
  hasOverrideRules,
  INVALID_LITERAL,
  isRecord,
  policyOrg,
  referencesOf,
  ruleCountOf,
  seededPolicyId,
  sha256,
  type PolicyOrgState,
} from './policy-store';
import { withPrincipal, type Principal } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * The policy tools of dev fixture mode (step 7.3 design B15): the catalogue (the verbatim
 * snapshot with the runtime's time zones), and **canned** answers of validate, test, the sample
 * dry-run and the per-round dry-run. They conform to the OpenAPI schemas and never evaluate a
 * policy: validate is valid unless the document contains `EXAMPLE_INVALID`; test and dry-run
 * name the first rule of the target as decisive and say in the explanation that the answer is
 * canned. The real decisions come from the api only (ADR-0063 decision 2).
 */

type TestResponse = SuccessBody<'PolicyToolsController_test_v1'>;
type TestResult = TestResponse['result'];
type Disposition = TestResult['disposition'];
type SampleResponse = SuccessBody<'PolicyToolsController_sampleDryRun_v1'>;
type SampleItem = SampleResponse['items'][number];
type ActionType = TestResult['actions'][number]['type'];
type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;

const INLINE_POLICY_ID = '00000000-0000-7000-8000-000000000000';
const DAY = 86_400_000;
const SAMPLE_MAX = POLICY_CATALOG_SNAPSHOT.limits.dryRunSampleMax ?? 50;
const SAMPLES_PER_MINUTE = POLICY_CATALOG_SNAPSHOT.limits.dryRunSamplesPerMinute ?? 6;
const HISTORY_DAYS = POLICY_CATALOG_SNAPSHOT.limits.historyRangeDays ?? 31;
const CANNED_NOTE =
  'Dev fixture: this answer is canned; the fixture never evaluates policies. Run against the api for real decisions.';

/** The time zones of this runtime plus `UTC` (what the api lists for its own runtime). */
export function runtimeTimeZones(): string[] {
  return [...new Set([...Intl.supportedValuesOf('timeZone'), 'UTC'])].sort();
}

/** The catalogue served in fixture mode: the snapshot with the runtime's time zones. */
export function fixtureCatalog(): SuccessBody<'PolicyToolsController_catalog_v1'> {
  return { ...POLICY_CATALOG_SNAPSHOT, timeZones: runtimeTimeZones() };
}

const bodyOf = (request: FixtureRequest): Record<string, unknown> =>
  isRecord(request.body) ? request.body : {};

/** The canned validate answer (design B15). */
export function cannedValidate(
  definition: unknown,
): SuccessBody<'PolicyToolsController_validate_v1'> {
  const violations = cannedViolations(definition);
  const valid = violations.length === 0;
  return {
    dslVersion: DSL,
    valid,
    violations,
    referenceViolations: [],
    ruleCount: valid ? ruleCountOf(definition) : null,
    hasOverrideRules: valid ? hasOverrideRules(definition) : null,
    references: valid ? referencesOf(definition) : null,
    definitionSha256: valid ? sha256(definition) : null,
  };
}

const DISPOSITION_OF: Readonly<Record<string, Disposition>> = {
  ALLOW: 'allow',
  REQUIRE_APPROVAL: 'require_approval',
  QUARANTINE: 'quarantine',
  REJECT: 'reject',
};

interface ResolvedTarget {
  kind: 'active' | 'platform' | 'version' | 'inline';
  policyId: string | null;
  versionNo: number | null;
  definition: unknown;
}

function resolveTarget(
  state: PolicyOrgState,
  target: unknown,
): ResolvedTarget | { error: ReturnType<typeof apiError> } {
  if (target === undefined || target === 'active') {
    return { kind: 'active', policyId: null, versionNo: null, definition: null };
  }
  if (target === 'platform') {
    return { kind: 'platform', policyId: null, versionNo: null, definition: null };
  }
  if (isRecord(target) && 'definition' in target) {
    const violations = cannedViolations(target.definition);
    if (violations.length > 0) {
      return {
        error: apiError(400, 'policy_definition_invalid', 'The definition is invalid', {
          violations: violations.map((v) => ({ ...v, path: v.path })),
        }),
      };
    }
    return {
      kind: 'inline',
      policyId: INLINE_POLICY_ID,
      versionNo: 1,
      definition: target.definition,
    };
  }
  if (isRecord(target) && typeof target.policyId === 'string') {
    const policy = findPolicy(state, target.policyId);
    const version = policy ? findVersion(policy, String(target.versionNo)) : null;
    if (!policy || !version) {
      return { error: apiError(404, 'policy_version_not_found', 'Policy version not found') };
    }
    return {
      kind: 'version',
      policyId: policy.id,
      versionNo: version.versionNo,
      definition: version.definition,
    };
  }
  return { error: apiError(400, 'validation_failed', ['target: invalid target']) };
}

interface CannedRule {
  index: number;
  id: string;
  disposition: Disposition;
  actionTypes: ActionType[];
  actions: Array<Record<string, unknown>>;
  override: boolean;
  field: string | null;
  op: string | null;
}

/** The first rule of a definition by priority (named decisive by the canned answers). */
function firstRule(definition: unknown): CannedRule | null {
  if (!isRecord(definition) || !Array.isArray(definition.rules)) return null;
  const rules = (definition.rules as unknown[])
    .map((rule: unknown, index) => ({ rule, index }))
    .filter((r): r is { rule: Record<string, unknown>; index: number } => isRecord(r.rule))
    .sort(
      (a, b) =>
        (typeof a.rule.priority === 'number' ? a.rule.priority : 0) -
        (typeof b.rule.priority === 'number' ? b.rule.priority : 0),
    );
  const first = rules[0];
  if (!first) return null;
  const actions = Array.isArray(first.rule.actions) ? first.rule.actions.filter(isRecord) : [];
  const actionTypes = actions
    .map((a) => a.type)
    .filter((t): t is ActionType => typeof t === 'string');
  const dispositionAction = actionTypes.find((t) => DISPOSITION_OF[t]);
  let leaf: Record<string, unknown> | null = isRecord(first.rule.when) ? first.rule.when : null;
  while (leaf && !('field' in leaf)) {
    const next: unknown = leaf.all ?? leaf.any ?? leaf.not;
    leaf = Array.isArray(next)
      ? isRecord(next[0])
        ? next[0]
        : null
      : isRecord(next)
        ? next
        : null;
  }
  return {
    index: first.index,
    id: typeof first.rule.id === 'string' ? first.rule.id : 'rule',
    disposition: dispositionAction ? (DISPOSITION_OF[dispositionAction] ?? 'allow') : 'allow',
    actionTypes,
    actions,
    override: first.rule.override === true,
    field: typeof leaf?.field === 'string' ? leaf.field : null,
    op: typeof leaf?.op === 'string' ? leaf.op : null,
  };
}

function cannedResult(
  state: PolicyOrgState,
  target: ResolvedTarget,
  facts: Record<string, unknown>,
): TestResult {
  const rule = target.definition ? firstRule(target.definition) : null;
  const direction: TestResult['round']['direction'] =
    facts.direction === 'outbound' || facts.direction === 'internal' ? facts.direction : 'inbound';
  const ref = rule && target.policyId ? `${target.policyId}#${target.versionNo}/${rule.id}` : null;
  const disposition: Disposition = rule ? rule.disposition : 'allow';
  const paramsOf = (action: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(action).filter(
        (entry): entry is [string, string | number | boolean] =>
          entry[0] !== 'type' &&
          (typeof entry[1] === 'string' ||
            typeof entry[1] === 'number' ||
            typeof entry[1] === 'boolean'),
      ),
    );
  const rules =
    isRecord(target.definition) && Array.isArray(target.definition.rules)
      ? target.definition.rules.filter(isRecord)
      : [];
  return {
    status: 'evaluated',
    round: { trigger: 'scanned', direction, lifecycleRound: 0, scanId: null },
    disposition,
    finalVerdict: 'clean',
    riskScore: 40,
    decisive:
      rule && ref
        ? {
            source: 'tenant_rule',
            policyPublicId: target.policyId,
            versionNo: target.versionNo,
            ruleId: rule.id,
            reason: 'policy.rule.matched',
          }
        : {
            source: 'platform_default',
            policyPublicId: null,
            versionNo: null,
            ruleId: null,
            reason: 'policy.platform_default',
          },
    actions:
      rule && ref
        ? rule.actions
            .filter(
              (a): a is Record<string, unknown> & { type: ActionType } =>
                typeof a.type === 'string',
            )
            .map((a) => ({
              type: a.type,
              params: paramsOf(a),
              origin: 'tenant_rule' as const,
              ruleRefs: [ref],
              applicability: 'applies' as const,
            }))
        : [
            {
              type: 'ALLOW',
              params: {},
              origin: 'platform_default',
              ruleRefs: [],
              applicability: 'applies',
            },
          ],
    delivery: null,
    notices: { senderNonDelivery: false },
    matchedRules:
      rule && ref && target.policyId && target.versionNo
        ? [
            {
              ref,
              policyPublicId: target.policyId,
              versionNo: target.versionNo,
              ruleId: rule.id,
              disposition: rule.actionTypes.some((t) => DISPOSITION_OF[t])
                ? rule.disposition
                : null,
              actionTypes: rule.actionTypes,
              override: rule.override,
            },
          ]
        : [],
    trace:
      target.policyId && target.versionNo
        ? rules
            .map((r, i) => ({ r, i }))
            .slice(0, 200)
            .map(({ r, i }) => {
              const id = typeof r.id === 'string' ? r.id : `rule-${i + 1}`;
              const decisive = rule?.index === i;
              return {
                ref: `${target.policyId}#${target.versionNo}/${id}`,
                result: decisive ? ('matched' as const) : ('not_evaluated' as const),
                at: decisive ? 'when' : null,
                path: decisive ? `rules[${i}].when` : null,
                field: (decisive ? rule.field : null) as TestResult['trace'][number]['field'],
                op: (decisive ? rule.op : null) as TestResult['trace'][number]['op'],
              };
            })
        : [],
    traceTruncated: false,
    floor: { disposition: null, tag: false, reasons: [] },
    recommendation: {
      disposition: 'allow',
      tag: false,
      levelOnly: false,
      riskAction: 'deliver',
      revisions: [0],
    },
    override: null,
    clamps: [],
    reasonCodes: [rule ? 'policy.rule.matched' : 'policy.platform_default'],
    explanation: {
      lines: [],
      text: rule
        ? `Decided by rule ${rule.id}: ${disposition}. ${CANNED_NOTE}`
        : `No tenant rule decided; the platform default allowed the message. ${CANNED_NOTE}`,
    },
    versions: {
      dsl: DSL,
      evaluator: 'policy-eval/2',
      input: POLICY_CATALOG_SNAPSHOT.versions.input as TestResult['versions']['input'],
      platformDefault: POLICY_CATALOG_SNAPSHOT.platformDefault.id,
      snapshotSha256: sha256({ generation: state.generation, target: target.kind }),
      generation: String(state.generation),
      tzdata: '2026e',
      policies:
        target.policyId && target.versionNo
          ? [
              {
                policyPublicId: target.policyId,
                versionNo: target.versionNo,
                definitionSha256: sha256(target.definition),
              },
            ]
          : [],
    },
    inputSha256: sha256(facts),
  };
}

function testHandler(request: FixtureRequest, p: Principal) {
  const state = policyOrg(p.organizationId);
  const body = bodyOf(request);
  const facts = isRecord(body.facts) ? body.facts : {};
  if (firstPathContaining(facts, INVALID_LITERAL) !== null) {
    return apiError(400, 'policy_test_facts_invalid', [
      `facts.${firstPathContaining(facts, INVALID_LITERAL) ?? ''}: not accepted (dev fixture)`,
    ]);
  }
  const target = resolveTarget(state, body.target);
  if ('error' in target) return target.error;
  const result = cannedResult(state, target, facts);
  const response: TestResponse = {
    result,
    recipientSplit: false,
    recipientDecisions: [],
    lifecycleDisposition: result.disposition,
    invalidVersions: [],
  };
  return ok('PolicyToolsController_test_v1', response);
}

/** Per-principal fixed window of the sample dry-run (the route limit, `429 scope: route`). */
const sampleWindows = new Map<string, { start: number; count: number }>();

function sampleHandler(request: FixtureRequest, p: Principal) {
  const now = Date.now();
  const window = sampleWindows.get(p.userId);
  if (!window || now - window.start >= 60_000) {
    sampleWindows.set(p.userId, { start: now, count: 1 });
  } else if (window.count >= SAMPLES_PER_MINUTE) {
    const retryAfter = Math.max(1, Math.ceil((window.start + 60_000 - now) / 1000));
    return {
      ...apiError(429, 'rate_limited', 'Too many sample dry-runs', { scope: 'route' }),
      headers: { 'retry-after': String(retryAfter) },
    };
  } else {
    window.count += 1;
  }
  const state = policyOrg(p.organizationId);
  const body = bodyOf(request);
  const sample = isRecord(body.sample) ? body.sample : {};
  const to = typeof sample.to === 'string' ? Date.parse(sample.to) : now;
  const from = typeof sample.from === 'string' ? Date.parse(sample.from) : to - 7 * DAY;
  const limit = typeof sample.limit === 'number' ? sample.limit : Math.min(25, SAMPLE_MAX);
  const problems: string[] = [];
  if (!Number.isFinite(from) || !Number.isFinite(to))
    problems.push('sample.from: an ISO date-time');
  else if (from >= to) problems.push('sample.from: must be before sample.to');
  else if (to - from > HISTORY_DAYS * DAY)
    problems.push(`sample: the range is at most ${HISTORY_DAYS} days`);
  if (!Number.isInteger(limit) || limit < 1 || limit > SAMPLE_MAX) {
    problems.push(`sample.limit: between 1 and ${SAMPLE_MAX}`);
  }
  if (problems.length > 0) return apiError(400, 'validation_failed', problems);
  const target = resolveTarget(state, body.target);
  if ('error' in target) return target.error;
  const rule = target.definition ? firstRule(target.definition) : null;
  const direction = typeof sample.direction === 'string' ? sample.direction : null;
  const tenantPolicy = seededPolicyId(p.organizationId, 'inbound-threats');
  const selected = FIXTURE_MESSAGES.filter((m) => {
    const t = Date.parse(m.detail.receivedAt);
    return t >= from && t < to && (!direction || m.detail.direction === direction);
  }).slice(0, limit);
  const items: SampleItem[] = selected.map((m, i) => {
    const e = m.evaluations[0];
    const storedDisposition = e?.disposition ?? 'allow';
    const tenant = e?.decisive.source === 'tenant_rule';
    const stored = {
      disposition: storedDisposition,
      source: e?.decisive.source ?? 'platform_default',
      policyId: tenant ? tenantPolicy : null,
      versionNo: tenant ? (e?.decisive.versionNo ?? null) : null,
      ruleId: tenant ? (e?.decisive.ruleId ?? null) : null,
      evaluatedAt: e?.evaluatedAt ?? m.detail.receivedAt,
    };
    const notComplete = i % 13 === 12;
    // Canned: the active set reproduces the stored decision; another target "changes" every
    // fourth item to its first rule (deterministic data that exercises the UI, not a decision).
    const changed = !notComplete && target.kind !== 'active' && i % 4 === 1;
    const dryRun = notComplete
      ? null
      : changed
        ? {
            disposition:
              (rule?.disposition ?? 'allow') === storedDisposition
                ? storedDisposition === 'allow'
                  ? 'quarantine'
                  : 'allow'
                : (rule?.disposition ?? 'allow'),
            lifecycleDisposition: rule?.disposition ?? 'allow',
            source: rule ? ('tenant_rule' as const) : ('platform_default' as const),
            policyId: rule ? target.policyId : null,
            versionNo: rule ? target.versionNo : null,
            ruleId: rule?.id ?? null,
            matchedRuleCount: rule ? 1 : 0,
            actionTypes: rule?.actionTypes ?? ['ALLOW'],
            recipientSplit: false,
            overrideApplied: false,
          }
        : {
            disposition: stored.disposition,
            lifecycleDisposition: stored.disposition,
            source: stored.source,
            policyId: stored.policyId,
            versionNo: stored.versionNo,
            ruleId: stored.ruleId,
            matchedRuleCount: tenant ? 1 : 0,
            actionTypes: e?.actions.map((a) => a.type) ?? ['ALLOW'],
            recipientSplit: false,
            overrideApplied: false,
          };
    const dispositionChanged = dryRun !== null && dryRun.disposition !== stored.disposition;
    const decisiveChanged =
      dryRun !== null &&
      (dryRun.source !== stored.source ||
        dryRun.policyId !== stored.policyId ||
        dryRun.ruleId !== stored.ruleId);
    return {
      messageId: m.detail.id,
      receivedAt: m.detail.receivedAt,
      direction: m.detail.direction,
      lifecycleRound: e?.lifecycleRound ?? 0,
      scanId: m.rounds[0]?.scanId ?? String(900_000 + i),
      trigger: 'scanned',
      outcome: notComplete ? 'not_complete' : 'evaluated',
      stored,
      dryRun,
      dispositionChanged,
      decisiveChanged,
    };
  });
  const evaluated = items.filter((item) => item.dryRun !== null);
  const count = (pick: (item: SampleItem) => string | undefined) => ({
    allow: evaluated.filter((item) => pick(item) === 'allow').length,
    require_approval: evaluated.filter((item) => pick(item) === 'require_approval').length,
    quarantine: evaluated.filter((item) => pick(item) === 'quarantine').length,
    reject: evaluated.filter((item) => pick(item) === 'reject').length,
  });
  const transitions = new Map<string, number>();
  for (const item of evaluated) {
    if (item.dryRun && item.dispositionChanged) {
      const key = `${item.stored.disposition}>${item.dryRun.disposition}`;
      transitions.set(key, (transitions.get(key) ?? 0) + 1);
    }
  }
  const response: SampleResponse = {
    target: { kind: target.kind, policyId: target.policyId, versionNo: target.versionNo },
    window: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
    limit,
    evaluated: evaluated.length,
    skipped: items.length - evaluated.length,
    truncated: false,
    exhausted: selected.length < limit,
    summary: {
      changed: evaluated.filter((item) => item.dispositionChanged).length,
      unchanged: evaluated.filter((item) => !item.dispositionChanged).length,
      stored: count((item) => item.stored.disposition),
      dryRun: count((item) => item.dryRun?.disposition),
      transitions: [...transitions.entries()]
        .map(([key, n]) => {
          const [fromD, toD] = key.split('>') as [Disposition, Disposition];
          return { from: fromD, to: toD, count: n };
        })
        .sort((a, b) => b.count - a.count),
    },
    items,
    invalidVersions: [],
  };
  return ok('PolicyToolsController_sampleDryRun_v1', response);
}

function messageDryRunHandler(request: FixtureRequest, p: Principal) {
  const message = fixtureMessage(request.params.messageId ?? '');
  if (!message) return apiError(404, 'message_not_found', 'Message not found');
  const round = message.rounds.find((r: ScanRound) => r.scanId === request.params.scanId);
  if (!round) return apiError(404, 'scan_not_found', 'Scan not found');
  if (round.status === 'pending' || round.status === 'running') {
    return apiError(409, 'scan_round_not_complete', 'The round is still running', {
      status: round.status,
    });
  }
  const state = policyOrg(p.organizationId);
  const body = bodyOf(request);
  const target = resolveTarget(state, body.target);
  if ('error' in target) return target.error;
  const stored = message.evaluations.find((e) => e.round.scanId === round.scanId) ?? null;
  const {
    lifecycleRound,
    trigger,
    direction,
    finalAction,
    actionStatuses,
    deliveredObject,
    evaluatedAt,
    durationUs,
    recipientSplit,
    recipientDecisions,
    ...storedResult
  } = stored ?? ({} as Partial<NonNullable<typeof stored>>);
  void lifecycleRound;
  void trigger;
  void direction;
  void finalAction;
  void actionStatuses;
  void deliveredObject;
  void evaluatedAt;
  void durationUs;
  void recipientSplit;
  void recipientDecisions;
  const reproducible = target.kind === 'active' && stored !== null;
  const result: TestResult =
    reproducible && 'status' in storedResult
      ? storedResult
      : cannedResult(state, target, { direction: message.detail.direction });
  return ok('PolicyMessagesController_dryRun_v1', {
    result,
    recipientSplit: false,
    recipientDecisions: [],
    lifecycleDisposition: result.disposition,
    invalidVersions: [],
    stored,
    reproducible,
  });
}

export const toolFixtures: FixtureHandlers = {
  PolicyToolsController_catalog_v1: (request) =>
    withPrincipal(request, () => ok('PolicyToolsController_catalog_v1', fixtureCatalog())),
  PolicyToolsController_validate_v1: (request) =>
    withPrincipal(request, () => {
      const body = bodyOf(request);
      if (!isRecord(body.definition)) {
        return apiError(400, 'validation_failed', ['definition: must be a JSON object']);
      }
      return ok('PolicyToolsController_validate_v1', cannedValidate(body.definition));
    }),
  PolicyToolsController_test_v1: (request) =>
    withPrincipal(request, (p) => testHandler(request, p)),
  PolicyToolsController_sampleDryRun_v1: (request) =>
    withPrincipal(request, (p) => sampleHandler(request, p)),
  PolicyMessagesController_dryRun_v1: (request) =>
    withPrincipal(request, (p) => messageDryRunHandler(request, p)),
};
