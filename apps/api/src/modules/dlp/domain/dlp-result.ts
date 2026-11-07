import {
  DLP_AADHAAR_STATES,
  DLP_MAX_COVERAGE_ENTRIES,
  DLP_MAX_EXCEPTIONS_APPLIED,
  DLP_MAX_FINDINGS,
  DLP_MAX_MATCHED_RULES,
  type DlpCategoryAggregate,
  type DlpCoverageEntry,
  type DlpFindingView,
  type DlpPolicyView,
  type DlpResultView,
  dlpCategoryAggregateSchema,
  dlpCoverageEntrySchema,
  dlpFindingViewSchema,
  dlpPolicyViewSchema,
  dlpResultViewSchema,
} from '@email-gateway/security-contracts';

/**
 * Pure mapping of the stored `dlp_scan_results` row to the masked views of the scans read API
 * (step 4.5 D20) and the incidents list (D21). Stored JSON is parsed defensively: every entry is
 * picked (known keys only) and validated with the security-contracts view sub-schemas; an entry
 * that fails (a masked value that looks raw, an unknown code, an unmapped id) is dropped, never
 * passed through. Internal ids (decimal strings or numbers, as the worker stores the policy
 * snapshot) and public ids (UUIDs) are both accepted and mapped to **this organization's**
 * public ids; unmapped ids are dropped. Never raw values, context text, offsets, dictionary
 * terms, pattern text or durations.
 */

/** The columns of a stored result the views need (no duration, no direction-only fields). */
export interface DlpResultRowInput {
  scanId: bigint;
  engineVersion: string;
  rulesVersion: string;
  settingsVersion: string;
  policyVersion: string;
  extractorVersion: string;
  verdict: DlpResultView['verdict'];
  action: DlpResultView['action'];
  actionSource: DlpResultView['actionSource'];
  matchedPolicyId: bigint | null;
  matchedRuleId: bigint | null;
  coverage: DlpResultView['coverage'];
  coverageDetail: unknown;
  categories: unknown;
  findings: unknown;
  policy: unknown;
  evidenceStatus: DlpResultView['evidence']['status'];
}

/** The evidence row state of a round (never its key or content). */
export interface DlpEvidenceStateInput {
  scanId: bigint;
  expiresAt: Date;
  purgedAt: Date | null;
}

export const DLP_ID_KINDS = ['policy', 'rule', 'exception', 'pattern', 'dictionary'] as const;
export type DlpIdKind = (typeof DLP_ID_KINDS)[number];

/** References found in stored results, per kind: internal ids and public ids to verify. */
export type DlpRefs = Record<DlpIdKind, { internal: Set<string>; public: Set<string> }>;

/** Internal id → public id, and the verified public ids, of this organization's rows. */
export type DlpIdMaps = Record<DlpIdKind, { byInternal: Map<string, string>; known: Set<string> }>;

export const emptyRefs = (): DlpRefs =>
  Object.fromEntries(
    DLP_ID_KINDS.map((k) => [k, { internal: new Set<string>(), public: new Set<string>() }]),
  ) as DlpRefs;

export const NO_DLP_IDS: DlpIdMaps = Object.freeze(
  Object.fromEntries(
    DLP_ID_KINDS.map((k) => [k, { byInternal: new Map<string, string>(), known: new Set() }]),
  ),
) as DlpIdMaps;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DECIMAL = /^[1-9][0-9]{0,19}$/;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const arrayOf = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** An id as stored: a decimal internal id (string, number or bigint) or a UUID; else null. */
function idOf(value: unknown): { internal: string } | { public: string } | null {
  if (typeof value === 'bigint' && value > 0n) return { internal: value.toString() };
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) {
    return { internal: String(value) };
  }
  if (typeof value !== 'string') return null;
  if (DECIMAL.test(value)) return { internal: value };
  if (UUID.test(value)) return { public: value.toLowerCase() };
  return null;
}

function addRef(refs: DlpRefs, kind: DlpIdKind, value: unknown): void {
  const id = idOf(value);
  if (id === null) return;
  if ('internal' in id) refs[kind].internal.add(id.internal);
  else refs[kind].public.add(id.public);
}

/** The ids a stored result references (the repository resolves them per kind). */
export function collectRefs(
  rows: readonly DlpResultRowInput[],
  refs: DlpRefs = emptyRefs(),
): DlpRefs {
  for (const row of rows) {
    if (row.matchedPolicyId !== null) refs.policy.internal.add(row.matchedPolicyId.toString());
    if (row.matchedRuleId !== null) refs.rule.internal.add(row.matchedRuleId.toString());
    for (const finding of arrayOf(row.findings)) {
      if (!isRecord(finding)) continue;
      addRef(refs, 'pattern', finding.customPatternId);
      addRef(refs, 'dictionary', finding.dictionaryId);
    }
    if (!isRecord(row.policy)) continue;
    const { winner, matched, exceptionsApplied } = row.policy;
    if (isRecord(winner)) {
      addRef(refs, 'policy', winner.policyId);
      addRef(refs, 'rule', winner.ruleId);
    }
    for (const entry of arrayOf(matched)) {
      if (!isRecord(entry)) continue;
      addRef(refs, 'policy', entry.policyId);
      addRef(refs, 'rule', entry.ruleId);
    }
    for (const id of arrayOf(exceptionsApplied)) addRef(refs, 'exception', id);
  }
  return refs;
}

/** This organization's public id of a stored id, or undefined (dropped). */
export function mapId(ids: DlpIdMaps, kind: DlpIdKind, value: unknown): string | undefined {
  const id = idOf(value);
  if (id === null) return undefined;
  if ('internal' in id) return ids[kind].byInternal.get(id.internal);
  return ids[kind].known.has(id.public) ? id.public : undefined;
}

const twoDecimals = (value: unknown): unknown =>
  typeof value === 'number' && Number.isFinite(value) ? Math.round(value * 100) / 100 : value;

function pick(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) return {};
  const out: Record<string, unknown> = {};
  for (const key of keys)
    if (value[key] !== undefined && value[key] !== null) out[key] = value[key];
  return out;
}

const SOURCE_KEYS = ['kind', 'partIndex', 'path'] as const;
const FINDING_KEYS = [
  'detector',
  'code',
  'category',
  'severity',
  'confidence',
  'count',
  'capped',
] as const;

/** One stored finding as the D20 view, or null when it does not validate (dropped). */
export function findingOf(value: unknown, ids: DlpIdMaps): DlpFindingView | null {
  if (!isRecord(value)) return null;
  const candidate: Record<string, unknown> = {
    ...pick(value, FINDING_KEYS),
    confidence: twoDecimals(value.confidence ?? value.maxConfidence),
    capped: value.capped === true,
    sources: arrayOf(value.sources).map((s) => pick(s, SOURCE_KEYS)),
    masked: arrayOf(value.masked),
  };
  if (value.customPatternId !== undefined && value.customPatternId !== null) {
    const id = mapId(ids, 'pattern', value.customPatternId);
    if (id === undefined) return null;
    candidate.customPatternId = id;
  }
  if (value.dictionaryId !== undefined && value.dictionaryId !== null) {
    const id = mapId(ids, 'dictionary', value.dictionaryId);
    if (id === undefined) return null;
    candidate.dictionaryId = id;
  }
  const parsed = dlpFindingViewSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

export function findingsOf(value: unknown, ids: DlpIdMaps): DlpFindingView[] {
  const out: DlpFindingView[] = [];
  for (const entry of arrayOf(value)) {
    const finding = findingOf(entry, ids);
    if (finding !== null) out.push(finding);
    if (out.length >= DLP_MAX_FINDINGS) break;
  }
  return out;
}

const COVERAGE_KEYS = [
  'source',
  'partIndex',
  'path',
  'format',
  'status',
  'reasons',
  'chars',
  'truncated',
] as const;

/**
 * The stored coverage detail: a JSON array of entries, or an object holding the entries
 * (`entries`, `sources` or `detail`) and the Aadhaar state (`aadhaar`, D17).
 */
export function coverageOf(value: unknown): {
  entries: DlpCoverageEntry[];
  aadhaar: (typeof DLP_AADHAAR_STATES)[number] | null;
} {
  const list = Array.isArray(value)
    ? value
    : isRecord(value)
      ? arrayOf(value.entries ?? value.sources ?? value.detail)
      : [];
  const aadhaar =
    isRecord(value) && (DLP_AADHAAR_STATES as readonly unknown[]).includes(value.aadhaar)
      ? (value.aadhaar as (typeof DLP_AADHAAR_STATES)[number])
      : null;
  const entries: DlpCoverageEntry[] = [];
  for (const entry of list) {
    const parsed = dlpCoverageEntrySchema.safeParse({
      ...pick(entry, COVERAGE_KEYS),
      truncated: isRecord(entry) && entry.truncated === true,
    });
    if (parsed.success) entries.push(parsed.data);
    if (entries.length >= DLP_MAX_COVERAGE_ENTRIES) break;
  }
  return { entries, aadhaar };
}

export function categoriesOf(value: unknown): DlpCategoryAggregate[] {
  const seen = new Set<string>();
  const out: DlpCategoryAggregate[] = [];
  for (const entry of arrayOf(value)) {
    const parsed = dlpCategoryAggregateSchema.safeParse({
      ...pick(entry, ['category', 'count', 'maxSeverity']),
      maxConfidence: twoDecimals(isRecord(entry) ? entry.maxConfidence : undefined),
    });
    if (!parsed.success || seen.has(parsed.data.category)) continue;
    seen.add(parsed.data.category);
    out.push(parsed.data);
  }
  return out;
}

/** The policy section (D20) with this organization's public ids only. */
export function policyOf(row: DlpResultRowInput, ids: DlpIdMaps): DlpPolicyView {
  const stored = isRecord(row.policy) ? row.policy : {};
  const matched: DlpPolicyView['matched'] = [];
  for (const entry of arrayOf(stored.matched)) {
    if (!isRecord(entry)) continue;
    const policyId = mapId(ids, 'policy', entry.policyId);
    const ruleId = mapId(ids, 'rule', entry.ruleId);
    if (policyId === undefined || ruleId === undefined) continue;
    const parsed = dlpPolicyViewSchema.shape.matched.element.safeParse({
      policyId,
      ruleId,
      action: entry.action,
      mode: entry.mode,
    });
    if (parsed.success) matched.push(parsed.data);
    if (matched.length >= DLP_MAX_MATCHED_RULES) break;
  }
  const exceptionsApplied: string[] = [];
  for (const id of arrayOf(stored.exceptionsApplied)) {
    const mapped = mapId(ids, 'exception', id);
    if (mapped !== undefined && !exceptionsApplied.includes(mapped)) exceptionsApplied.push(mapped);
    if (exceptionsApplied.length >= DLP_MAX_EXCEPTIONS_APPLIED) break;
  }
  let winner: DlpPolicyView['winner'] = null;
  if (row.actionSource === 'tenant_policy') {
    const storedWinner = isRecord(stored.winner) ? stored.winner : {};
    const policyId =
      mapId(ids, 'policy', storedWinner.policyId) ??
      (row.matchedPolicyId === null ? undefined : mapId(ids, 'policy', row.matchedPolicyId));
    const ruleId =
      mapId(ids, 'rule', storedWinner.ruleId) ??
      (row.matchedRuleId === null ? undefined : mapId(ids, 'rule', row.matchedRuleId));
    if (policyId !== undefined && ruleId !== undefined) winner = { policyId, ruleId };
  }
  return { winner, matched, exceptionsApplied };
}

const toSecond = (value: Date): string =>
  new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString();

/**
 * The `dlp` section of one round (D20) for a caller holding `dlp:read`, or null when the stored
 * row does not form a valid view (shown as null rather than partially).
 */
export function dlpResultViewOf(
  row: DlpResultRowInput,
  evidence: DlpEvidenceStateInput | null,
  ids: DlpIdMaps,
): DlpResultView | null {
  const findings = findingsOf(row.findings, ids);
  const coverage = coverageOf(row.coverageDetail);
  const aadhaar =
    coverage.aadhaar ?? (findings.some((f) => f.detector === 'NI2') ? 'enabled' : 'disabled');
  const purged =
    row.evidenceStatus === 'stored' && (evidence === null || evidence.purgedAt !== null);
  const parsed = dlpResultViewSchema.safeParse({
    engineVersion: row.engineVersion,
    rulesVersion: row.rulesVersion,
    settingsVersion: row.settingsVersion,
    policyVersion: row.policyVersion,
    extractorVersion: row.extractorVersion,
    verdict: row.verdict,
    action: row.action,
    actionSource: row.actionSource,
    coverage: row.coverage,
    coverageDetail: coverage.entries,
    aadhaar,
    categories: categoriesOf(row.categories),
    findings,
    policy: policyOf(row, ids),
    evidence: {
      status: row.evidenceStatus,
      expiresAt:
        row.evidenceStatus === 'stored' && evidence !== null ? toSecond(evidence.expiresAt) : null,
      purged,
    },
  });
  return parsed.success ? parsed.data : null;
}
