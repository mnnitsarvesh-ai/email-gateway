import { BEC_RULES, type EngineName } from '@email-gateway/security-contracts';
import { canonicalJson, sha256Hex } from './canonical';
import { renderExplanation } from './explanation';
import {
  HARD_BLOCK_VERDICT_PRIORITY,
  hardBlockReasonCode,
  RISK_HARD_BLOCKS,
  type RiskHardBlockDefinition,
  type RiskHardBlockId,
} from './hard-blocks';
import type { ScoringInput } from './input';
import type { EffectiveProfile } from './profile-schema';
import {
  isPlatformProfileId,
  RISK_DEFAULT_PLATFORM_PROFILE_ID,
  RISK_PLATFORM_PROFILES,
} from './profile';
import type { ResolvedProfile } from './profile';
import {
  engineReasonCode,
  levelReasonCode,
  RISK_AI_RAISE_ONLY_CODE,
  RISK_SANDBOX_INCLUDED_CODE,
  RISK_SCORING_ERROR_CODE,
  RISK_UNMAPPED_CODE,
  signalReasonCode,
} from './reason-codes';
import {
  type ExplanationLine,
  MAX_CONTRIBUTION_CODES,
  MAX_CONTRIBUTIONS,
  MAX_EXPLANATION_LINES,
  MAX_UNMAPPED_CODES,
  type RiskResult,
  type TrustStatus,
} from './result';
import {
  engineFailedSignal,
  engineUnknownSignal,
  isInformationalAssertion,
  RISK_GROUP_DEFINITIONS,
  RISK_ROW_MISSING_CODES,
  RISK_SIGNAL_GROUPS,
  RISK_SIGNALS,
  type RiskSignalDefinition,
  type RiskSignalGroup,
  signalForAssertion,
} from './signals';
import {
  levelRank,
  maxLevel,
  RISK_INPUT_VERSION,
  RISK_SCORER_VERSION,
  RISK_SIGNAL_MAP_VERSION,
  type RiskAction,
  type RiskLevel,
  type RiskVerdict,
  strictestAction,
} from './vocabulary';

/**
 * The scorer `risk-score/1` (step 5.1 R2–R11; ADR-0041). A pure function of
 * `(ScoringInput, ResolvedProfile)` with integer arithmetic only (points on 0–1000, factors in
 * permille, floor after every multiplication): no clock, no randomness, no I/O. Never throws for
 * a schema-valid input and profile (property-tested).
 */

const MAX_TOP_SIGNAL_LINES = 5;
const MAX_REASON_CODES = 32;

/** Rule codes of `bec-map/1` (the deterministic rules; R9 uses only the active ones). */
const BEC_RULE_CODES: ReadonlySet<string> = new Set(Object.values(BEC_RULES).map((r) => r.code));

const DLP_BINDING: Readonly<Record<string, RiskAction>> = {
  allow: 'deliver',
  alert: 'tag',
  require_approval: 'require_approval',
  quarantine: 'quarantine',
  block: 'block',
};

const SIGNAL_ORDER = new Map(RISK_SIGNALS.map((s, i) => [s.id, i]));
const GROUP_ORDER = new Map(RISK_SIGNAL_GROUPS.map((g, i) => [g, i]));

const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Level of `score` under `thresholds` (R4). */
export function levelForScore(score: number, t: EffectiveProfile['thresholds']): RiskLevel {
  if (score >= t.critical) return 'critical';
  if (score >= t.high) return 'high';
  if (score >= t.medium) return 'medium';
  if (score >= t.low) return 'low';
  return 'none';
}

const thresholdOf = (level: RiskLevel, t: EffectiveProfile['thresholds']): number =>
  level === 'none' ? 0 : t[level];

const permille = (value: number, factor: number): number => Math.floor((value * factor) / 1000);

interface FiredSignal {
  def: RiskSignalDefinition;
  assertions: Set<string>;
}

interface FailureEntry {
  engine: EngineName;
  status: 'timeout' | 'error' | 'missing' | 'row_missing' | 'unknown';
  weight: number;
}

function profileReasonCodes(resolved: ResolvedProfile): string[] {
  const codes = [resolved.source === 'tenant' ? 'risk.profile.tenant' : 'risk.profile.platform'];
  switch (resolved.fallback) {
    case 'invalid':
    case 'base_profile_retired':
      codes.push('risk.profile.invalid_fallback');
      break;
    case 'missing':
      codes.push('risk.profile.missing_fallback');
      break;
    case 'foreign':
      codes.push('risk.profile.foreign_fallback');
      break;
    default:
      break;
  }
  return codes;
}

function profileLine(resolved: ResolvedProfile): ExplanationLine {
  const params: ExplanationLine['params'] = {
    source: resolved.source,
    base: resolved.profile.base,
  };
  if (resolved.versionNo !== null) params.versionNo = resolved.versionNo;
  if (resolved.fallback !== null) params.fallback = resolved.fallback;
  return { code: 'profile', params };
}

function versionsOf(resolved: ResolvedProfile): RiskResult['versions'] {
  return {
    scorer: RISK_SCORER_VERSION,
    signalMap: RISK_SIGNAL_MAP_VERSION,
    input: RISK_INPUT_VERSION,
    profile: {
      source: resolved.source,
      id: resolved.id,
      versionNo: resolved.versionNo,
      sha256: resolved.sha256,
    },
  };
}

function boundedLines(lines: ExplanationLine[]): ExplanationLine[] {
  if (lines.length <= MAX_EXPLANATION_LINES) return lines;
  // Keep the profile line (always last) and drop the excess before it.
  const last = lines[lines.length - 1]!;
  return [...lines.slice(0, MAX_EXPLANATION_LINES - 1), last];
}

const engineView = (input: ScoringInput | null): RiskResult['engines'] =>
  (input?.engines ?? []).map((e) => ({
    engine: e.engine,
    required: e.required,
    status: e.status,
    outcome: e.outcome,
    errorCode: e.errorCode,
    engineVersion: e.engineVersion,
    settingsVersion: e.settingsVersion,
    attempts: e.attempts,
  }));

function evidenceOf(input: ScoringInput | null, unmapped: string[], aiRaiseOnly: boolean) {
  return {
    auth: input?.auth ?? null,
    dlp: input?.dlp
      ? {
          action: input.dlp.action,
          coverage: input.dlp.coverage,
          maxSeverity: input.dlp.maxSeverity,
        }
      : null,
    bec: input?.bec
      ? { deterministicVerdict: input.bec.deterministicVerdict, verdict: input.bec.verdict }
      : null,
    sandbox: input?.sandbox ? { outcome: input.sandbox.outcome } : null,
    unmappedCodes: unmapped,
    aiRaiseOnly,
  };
}

/** Scores one round (R2–R11). */
export function scoreRisk(input: ScoringInput, resolved: ResolvedProfile): RiskResult {
  const profile = resolved.profile;
  const t = profile.thresholds;
  const direction = input.envelope.direction;

  // (a)+(b) Collect assertions and map them to signals.
  const fired = new Map<string, FiredSignal>();
  const unmapped = new Set<string>();
  let arcTrusted = false;

  const fire = (def: RiskSignalDefinition, assertion: string): void => {
    if (!def.directions.includes(direction)) return;
    const existing = fired.get(def.id);
    if (existing) existing.assertions.add(assertion);
    else fired.set(def.id, { def, assertions: new Set([assertion]) });
  };
  const fireById = (id: string, assertion: string): void => {
    const def = signalForAssertion(assertion);
    if (def && def.id === id) fire(def, assertion);
  };
  const collect = (engine: string, code: string): void => {
    const assertion = `${engine}:${code}`;
    const def = signalForAssertion(assertion);
    if (def) {
      fire(def, assertion);
      return;
    }
    if (isInformationalAssertion(engine, code)) {
      if (assertion === 'rspamd:auth.dmarc_fail_arc_trusted') arcTrusted = true;
      return;
    }
    unmapped.add(assertion);
  };

  const failures: FailureEntry[] = [];
  const unknownEngines: EngineName[] = [];
  const failureWeight = profile.failures.engineFailureWeight;
  const unknownWeight = profile.failures.unknownWeight;

  for (const e of input.engines) {
    if (e.status === 'definite') {
      let codes: readonly string[] = e.reasonCodes;
      if (e.engine === 'bec' && input.bec) {
        codes = [
          ...input.bec.activeRuleCodes,
          ...e.reasonCodes.filter((c) => !BEC_RULE_CODES.has(c)),
        ];
      }
      for (const code of codes) collect(e.engine, code);
      if (e.required && e.outcome === 'unknown') {
        unknownEngines.push(e.engine);
        fireById(engineUnknownSignal(e.engine), `${e.engine}:outcome.unknown`);
      }
    } else if (e.required && (e.status === 'failed' || e.status === 'missing')) {
      const status =
        e.status === 'missing' ? 'missing' : e.outcome === 'timeout' ? 'timeout' : 'error';
      failures.push({ engine: e.engine, status, weight: failureWeight });
      fireById(engineFailedSignal(e.engine), `${e.engine}:status.${e.status}`);
    }
  }
  for (const [engine, code] of Object.entries(RISK_ROW_MISSING_CODES) as [
    keyof typeof RISK_ROW_MISSING_CODES,
    string,
  ][]) {
    const e = input.engines.find((x) => x.engine === engine);
    if (e && e.status === 'definite' && e.reasonCodes.includes(code)) {
      failures.push({ engine, status: 'row_missing', weight: failureWeight });
    }
  }
  for (const engine of unknownEngines) {
    failures.push({ engine, status: 'unknown', weight: unknownWeight });
  }

  const dlpEntry = input.engines.find((e) => e.engine === 'dlp');
  if (input.dlp && dlpEntry?.status === 'definite') {
    const { action, maxSeverity, coverage } = input.dlp;
    if (action === 'alert' || action === 'require_approval' || action === 'quarantine') {
      collect('dlp', `action.${action}`);
    }
    if (maxSeverity === 'critical' || maxSeverity === 'high' || maxSeverity === 'medium') {
      collect('dlp', `severity.${maxSeverity}`);
    }
    if (coverage === 'partial') collect('dlp', 'coverage.partial');
  }

  const sandbox = input.revision === 1 ? input.sandbox : null;
  if (sandbox) {
    if (
      sandbox.outcome === 'suspicious' ||
      sandbox.outcome === 'timeout' ||
      sandbox.outcome === 'error'
    ) {
      collect('sandbox', `outcome.${sandbox.outcome}`);
    }
    for (const code of sandbox.reasonCodes) collect('sandbox', code);
  }

  const has = (id: string): boolean => fired.has(id);

  // (c) Hard blocks, before trust.
  const hardBlockFires: Readonly<Record<RiskHardBlockId, boolean>> = {
    'hb.malware_attachment': has('attachment_malware'),
    'hb.malware_url': has('url_known_malware'),
    'hb.malware_sandbox': sandbox !== null && sandbox.outcome === 'malicious',
    'hb.dlp_block': input.dlp !== null && input.dlp.action === 'block',
    'hb.known_phishing': has('url_known_phishing'),
    'hb.tenant_domain_spoof':
      direction === 'inbound' && has('auth_tenant_domain_spoof') && has('auth_dmarc_reject'),
    'hb.url_tenant_blocked': has('url_tenant_blocked'),
    'hb.bec_malicious': input.bec !== null && input.bec.deterministicVerdict === 'malicious',
    'hb.dmarc_reject': direction === 'inbound' && has('auth_dmarc_reject'),
  };
  const hardBlocks: { def: RiskHardBlockDefinition; action: RiskAction }[] = [];
  for (const def of RISK_HARD_BLOCKS) {
    if (!hardBlockFires[def.id]) continue;
    const setting = profile.hardBlocks[def.id];
    const enabled = def.control === 'locked' ? true : setting.enabled;
    if (!enabled) continue;
    const action = def.allowedActions.includes(setting.action) ? setting.action : def.defaultAction;
    hardBlocks.push({ def, action });
  }
  const hardBlockIds = new Set(hardBlocks.map((h) => h.def.id));

  // R7 trust.
  const authFailureFired = [...fired.values()].some(
    (f) => f.def.group === 'auth_dmarc' || f.def.group === 'auth_other',
  );
  let trustStatus: TrustStatus;
  if (profile.trust.mode === 'off') trustStatus = 'off';
  else if (!input.bec || input.bec.trustedSender === 'none') trustStatus = 'not_trusted';
  else if (input.bec.trustedSender === 'unauthenticated') trustStatus = 'denied_unauthenticated';
  else if (direction !== 'inbound') trustStatus = 'not_trusted';
  else if (!input.auth || input.auth.dmarc !== 'pass') trustStatus = 'denied_unauthenticated';
  else if (authFailureFired) trustStatus = 'denied_auth_failure';
  else trustStatus = 'applied';
  const trustApplied = trustStatus === 'applied';
  const trustFactor = trustApplied ? profile.trust.contentFactorPermille : 1000;

  // (d) Signals and groups.
  const signalWeight = (def: RiskSignalDefinition): number =>
    def.weightFrom === 'failures.engineFailureWeight'
      ? failureWeight
      : def.weightFrom === 'failures.unknownWeight'
        ? unknownWeight
        : def.weight;

  const firedList = [...fired.values()].sort(
    (a, b) => (SIGNAL_ORDER.get(a.def.id) ?? 0) - (SIGNAL_ORDER.get(b.def.id) ?? 0),
  );
  const contributions: RiskResult['contributions'] = [];
  const groups: RiskResult['groups'] = [];
  let pointsRemoved = 0;
  let sum = 0;
  for (const g of RISK_SIGNAL_GROUPS) {
    const members = firedList.filter((f) => f.def.group === g);
    if (members.length === 0) continue;
    const def = RISK_GROUP_DEFINITIONS[g];
    const multiplier = def.locked ? 1000 : profile.groupMultipliersPermille[g];
    const cap = def.capFromProfile ? profile.failures.groupCap : def.cap;
    const reduced = trustApplied && members.some((m) => m.def.trustReducible);
    const values: number[] = [];
    const untrusted: number[] = [];
    for (const m of members) {
      const w = signalWeight(m.def);
      const v = trustApplied && m.def.trustReducible ? permille(w, trustFactor) : w;
      values.push(v);
      untrusted.push(w);
      contributions.push({
        signal: m.def.id,
        group: g,
        weight: w,
        codes: [...m.assertions].sort(compareText).slice(0, MAX_CONTRIBUTION_CODES),
        applied: permille(v, multiplier),
      });
    }
    const combine = (xs: number[]): number =>
      def.rule === 'max' ? Math.max(...xs) : xs.reduce((a, b) => a + b, 0);
    const raw = combine(values);
    const capTo = (x: number): number => (cap === null ? x : Math.min(x, cap));
    const total = capTo(permille(raw, multiplier));
    const totalUntrusted = capTo(permille(combine(untrusted), multiplier));
    pointsRemoved += totalUntrusted - total;
    sum += total;
    groups.push({
      group: g,
      rule: def.rule,
      raw,
      multiplierPermille: multiplier,
      trustFactorPermille: reduced ? trustFactor : null,
      cap,
      total,
    });
  }
  contributions.sort((a, b) => b.applied - a.applied || compareText(a.signal, b.signal));
  const boundedContributions = contributions.slice(0, MAX_CONTRIBUTIONS);

  // (e) Score.
  let score = Math.min(1000, sum);
  const scoreLevel = levelForScore(score, t);

  // (f) Floors.
  const floors: RiskResult['floors'] = [];
  const failed =
    failures.some((f) => f.status !== 'unknown') || input.round.outcome === 'scan_failed';
  const engineMalicious = input.engines.some(
    (e) =>
      (e.engine === 'rspamd' || e.engine === 'attachment' || e.engine === 'url') &&
      e.status === 'definite' &&
      e.outcome === 'malicious',
  );
  const becMaliciousFloor =
    input.bec !== null &&
    input.bec.deterministicVerdict === 'malicious' &&
    !hardBlockIds.has('hb.bec_malicious');
  if (engineMalicious || becMaliciousFloor) {
    floors.push({ source: 'engine_malicious', level: profile.floors.engineMalicious });
  }
  if (input.bec !== null && input.bec.deterministicVerdict === 'suspicious') {
    floors.push({ source: 'bec_suspicious', level: profile.floors.becSuspicious });
  }
  if (failed) floors.push({ source: 'engine_failure', level: profile.failures.minLevel });
  if (!failed && unknownEngines.length > 0) {
    floors.push({ source: 'engine_unknown', level: profile.failures.unknownMinLevel });
  }
  if (hardBlocks.length > 0) floors.push({ source: 'hard_block', level: 'critical' });

  let level = scoreLevel;
  for (const floor of floors) level = maxLevel(level, floor.level);
  if (levelRank(level) > levelRank(scoreLevel)) score = Math.max(score, thresholdOf(level, t));
  if (hardBlocks.length > 0) {
    level = 'critical';
    score = Math.max(score, t.critical);
  }
  score = Math.min(1000, score);

  // (g) Verdict.
  const unmappedList = [...unmapped].sort(compareText);
  let verdict: RiskVerdict;
  if (hardBlocks.length > 0) {
    const ranked = [...hardBlocks].sort(
      (a, b) =>
        HARD_BLOCK_VERDICT_PRIORITY.indexOf(a.def.verdict) -
          HARD_BLOCK_VERDICT_PRIORITY.indexOf(b.def.verdict) ||
        RISK_HARD_BLOCKS.indexOf(a.def) - RISK_HARD_BLOCKS.indexOf(b.def),
    );
    verdict = ranked[0]!.def.verdict;
  } else if (levelRank(level) >= levelRank('low')) {
    let top: { group: RiskSignalGroup; total: number } | null = null;
    for (const g of groups) {
      if (g.total <= 0) continue;
      if (
        top === null ||
        g.total > top.total ||
        (g.total === top.total &&
          (GROUP_ORDER.get(g.group) ?? 0) < (GROUP_ORDER.get(top.group) ?? 0))
      ) {
        top = { group: g.group, total: g.total };
      }
    }
    verdict =
      top !== null
        ? RISK_GROUP_DEFINITIONS[top.group].verdict
        : failed || unknownEngines.length > 0
          ? 'unknown'
          : 'suspicious';
  } else {
    const complete =
      input.round.outcome === 'scanned' &&
      input.engines.every(
        (e) =>
          !e.required ||
          e.status === 'skipped' ||
          (e.status === 'definite' && e.outcome !== 'unknown'),
      ) &&
      failures.length === 0 &&
      !groups.some(
        (g) =>
          g.group === 'coverage' || g.group === 'engine_failure' || g.group === 'engine_unknown',
      ) &&
      !input.engines.some((e) => e.reasonCodes.some((c) => c.startsWith('risk.input.'))) &&
      unmappedList.length === 0 &&
      (sandbox === null || sandbox.outcome === 'clean' || sandbox.outcome === 'suspicious');
    verdict = complete ? 'clean' : 'unknown';
  }

  // (h) Recommended action.
  let action: RiskAction = profile.actions[level];
  if (failed) action = strictestAction(action, profile.failures.action);
  // An unknown result is never treated as clean (§2.0-1), so it never recommends `deliver`.
  if (unknownEngines.length > 0) action = strictestAction(action, profile.failures.unknownAction);
  if (input.dlp) action = strictestAction(action, DLP_BINDING[input.dlp.action] ?? 'block');
  for (const h of hardBlocks) action = strictestAction(action, h.action);
  const aiRaiseOnly =
    input.bec !== null &&
    input.bec.aiRaised &&
    (input.bec.deterministicVerdict === 'clean' || input.bec.deterministicVerdict === 'unknown');
  if (aiRaiseOnly && profile.ai.tagOnAiOnlyRaise) action = strictestAction(action, 'tag');

  // (i) Reason codes.
  const head: string[] = hardBlocks.map((h) => hardBlockReasonCode(h.def.id));
  for (const e of input.engines) {
    if (e.required && e.status === 'failed') {
      head.push(engineReasonCode(e.engine, e.outcome === 'timeout' ? 'timeout' : 'error'));
    } else if (e.required && e.status === 'missing') {
      head.push(engineReasonCode(e.engine, 'missing'));
    } else if (e.status === 'definite') {
      for (const c of e.reasonCodes) if (c.startsWith('risk.input.')) head.push(c);
      if (e.required && e.outcome === 'unknown') head.push(engineReasonCode(e.engine, 'unknown'));
    }
  }
  if (
    sandbox &&
    (sandbox.outcome === 'timeout' || sandbox.outcome === 'error' || sandbox.outcome === 'unknown')
  ) {
    head.push(engineReasonCode('sandbox', sandbox.outcome));
  }
  head.push(levelReasonCode(level));

  const tail: string[] = [];
  if (trustStatus === 'applied') tail.push('risk.trust.applied');
  else if (trustStatus === 'denied_unauthenticated') tail.push('risk.trust.denied_unauthenticated');
  else if (trustStatus === 'denied_auth_failure') tail.push('risk.trust.denied_auth_failure');
  for (const floor of floors) {
    if (floor.source !== 'hard_block') tail.push(`risk.floor.${floor.source}`);
  }
  if (aiRaiseOnly) tail.push(RISK_AI_RAISE_ONLY_CODE);
  tail.push(...profileReasonCodes(resolved));
  if (sandbox) tail.push(RISK_SANDBOX_INCLUDED_CODE);

  const signalCodes = contributions
    .filter((c) => c.applied > 0)
    .map((c) => signalReasonCode(c.signal));
  if (unmappedList.length > 0) signalCodes.push(RISK_UNMAPPED_CODE);
  const uniqueHead = [...new Set(head)];
  const uniqueTail = [...new Set(tail)].filter((c) => !uniqueHead.includes(c));
  const room = Math.max(0, MAX_REASON_CODES - uniqueHead.length - uniqueTail.length);
  const reasonCodes = [
    ...new Set([...uniqueHead, ...signalCodes.slice(0, room), ...uniqueTail]),
  ].slice(0, MAX_REASON_CODES);

  // Explanation.
  const lines: ExplanationLine[] = [{ code: 'summary', params: { score, level, action } }];
  for (const h of hardBlocks) {
    lines.push({
      code: 'hard_block',
      params: { indicator: h.def.id.slice('hb.'.length), verdict: h.def.verdict, action: h.action },
    });
  }
  for (const f of failures) {
    if (f.status === 'unknown') {
      lines.push({ code: 'engine_unknown', params: { engine: f.engine, points: f.weight } });
    } else if (f.status === 'row_missing') {
      lines.push({
        code: 'input_missing',
        params: { input: f.engine === 'rspamd' ? 'authentication' : f.engine },
      });
    } else {
      lines.push({
        code: 'engine_failure',
        params: { engine: f.engine, status: f.status, points: f.weight },
      });
    }
  }
  for (const c of contributions.filter((x) => x.applied > 0).slice(0, MAX_TOP_SIGNAL_LINES)) {
    const engines = [...new Set(c.codes.map((code) => code.slice(0, code.indexOf(':'))))];
    lines.push({
      code: 'top_signal',
      params: { signal: c.signal, group: c.group, points: c.applied, engines: engines.join('+') },
    });
  }
  if (unmappedList.length > 0) {
    lines.push({ code: 'unmapped_codes', params: { count: unmappedList.length } });
  }
  if (arcTrusted) lines.push({ code: 'arc_trusted', params: {} });
  if (trustStatus === 'applied') {
    lines.push({ code: 'trust_applied', params: { factor: trustFactor, removed: pointsRemoved } });
  } else if (trustStatus === 'denied_unauthenticated' || trustStatus === 'denied_auth_failure') {
    lines.push({ code: 'trust_denied', params: { status: trustStatus } });
  }
  for (const floor of floors) {
    lines.push({ code: 'floor', params: { source: floor.source, level: floor.level } });
  }
  if (aiRaiseOnly) {
    lines.push({
      code: 'ai_raise_only',
      params: { tagged: profile.ai.tagOnAiOnlyRaise ? 'yes' : 'no' },
    });
  }
  if (sandbox) lines.push({ code: 'sandbox', params: { outcome: sandbox.outcome } });
  lines.push(profileLine(resolved));
  const explanationLines = boundedLines(lines);

  return {
    status: 'scored',
    score,
    level,
    verdict,
    recommendedAction: action,
    hardBlocks: hardBlocks.map((h) => ({ id: h.def.id, verdict: h.def.verdict, action: h.action })),
    reasonCodes,
    contributions: boundedContributions,
    groups,
    engines: engineView(input),
    failures,
    floors,
    trust: {
      status: trustStatus,
      factorPermille: trustFactor,
      reducedGroups: groups.filter((g) => g.trustFactorPermille !== null).map((g) => g.group),
      pointsRemoved,
    },
    evidence: evidenceOf(input, unmappedList.slice(0, MAX_UNMAPPED_CODES), aiRaiseOnly),
    explanation: { lines: explanationLines, text: renderExplanation(explanationLines) },
    versions: versionsOf(resolved),
    inputSha256: sha256Hex(canonicalJson(input)),
  };
}

export const SCORING_ERROR_REASONS = [
  'input_invalid',
  'scorer_exception',
  'profile_error',
] as const;
export type ScoringErrorReason = (typeof SCORING_ERROR_REASONS)[number];

const UNAVAILABLE_INPUT_SHA = sha256Hex('risk-input/unavailable');

/**
 * The fail-safe error result (R13): `status = error`, score = `thresholds.high` of the platform
 * default, level `high`, verdict `unknown`, action `quarantine`, reason `risk.scoring_error`.
 * `inputSha256` is the input's hash when one exists, else SHA-256 of `risk-input/unavailable`.
 */
export function scoringErrorResult(
  input: ScoringInput | null,
  resolved: ResolvedProfile,
  reason: ScoringErrorReason,
): RiskResult {
  const platformId = isPlatformProfileId(resolved.profile.base)
    ? resolved.profile.base
    : RISK_DEFAULT_PLATFORM_PROFILE_ID;
  const score = RISK_PLATFORM_PROFILES[platformId].thresholds.high;
  let inputSha256 = UNAVAILABLE_INPUT_SHA;
  if (input !== null) {
    try {
      inputSha256 = sha256Hex(canonicalJson(input));
    } catch {
      inputSha256 = UNAVAILABLE_INPUT_SHA;
    }
  }
  const lines: ExplanationLine[] = [
    { code: 'summary', params: { score, level: 'high', action: 'quarantine' } },
    { code: 'scoring_error', params: { reason } },
    profileLine(resolved),
  ];
  return {
    status: 'error',
    score,
    level: 'high',
    verdict: 'unknown',
    recommendedAction: 'quarantine',
    hardBlocks: [],
    reasonCodes: [
      RISK_SCORING_ERROR_CODE,
      levelReasonCode('high'),
      ...profileReasonCodes(resolved),
    ],
    contributions: [],
    groups: [],
    engines: engineView(input),
    failures: [],
    floors: [],
    trust: { status: 'not_trusted', factorPermille: 1000, reducedGroups: [], pointsRemoved: 0 },
    evidence: evidenceOf(input, [], false),
    explanation: { lines, text: renderExplanation(lines) },
    versions: versionsOf(resolved),
    inputSha256,
  };
}
