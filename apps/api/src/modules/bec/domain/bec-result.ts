import {
  AI_FEATURE_NAMES,
  type BecAiAssessmentView,
  type BecAiShadowAssessmentView,
  becAiAssessmentViewSchema,
  becAiShadowAssessmentViewSchema,
  becInputsSchema,
  type BecInputs,
  BEC_MAX_AI_ASSESSMENTS,
  BEC_MAX_AI_SHADOW_ASSESSMENTS,
  BEC_MAX_EVIDENCE_ITEMS,
  BEC_MAX_RULES,
  becRuleEntrySchema,
  type BecRuleEntry,
  becRuleEvidenceSchema,
  type BecRuleEvidence,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * Pure, defensive readers of the stored `bec_scan_results` JSON (step 4.4 B14, B15): every value
 * is validated against the `@email-gateway/security-contracts` sub-schemas and invalid entries
 * are dropped, never passed through raw. Used by the scans read API (B15), the feedback route
 * (result codes, From identity) and the retraining export (B11). Never returns span text,
 * response hashes, AI durations or history hashes (the schemas have no such fields; extra keys
 * are picked away before validation).
 */

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** Keeps only the given keys of a JSON object. */
function pick(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  return Object.fromEntries(keys.filter((k) => k in value).map((k) => [k, value[k]]));
}

const EVIDENCE_KEYS = Object.keys(becRuleEvidenceSchema.shape);

/** Internal id → public id of the tenant's profiles, trusted senders and suppressions. */
export interface BecIdMaps {
  executive: ReadonlyMap<string, string>;
  vendor: ReadonlyMap<string, string>;
  trusted: ReadonlyMap<string, string>;
  suppression: ReadonlyMap<string, string>;
}

export const NO_ID_MAPS: BecIdMaps = Object.freeze({
  executive: new Map(),
  vendor: new Map(),
  trusted: new Map(),
  suppression: new Map(),
});

const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;
const asDecimal = (value: unknown): string | null => {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return String(value);
  if (typeof value === 'string' && DECIMAL_ID.test(value)) return value;
  return null;
};

/** Internal (decimal) ids referenced by stored evidence, per kind (to map them to public ids). */
export interface ReferencedIds {
  executive: Set<string>;
  vendor: Set<string>;
  trusted: Set<string>;
  suppression: Set<string>;
}

const evidenceItems = (rule: unknown): unknown[] => {
  if (!isRecord(rule)) return [];
  const evidence = rule.evidence;
  if (Array.isArray(evidence)) return evidence;
  return evidence === undefined || evidence === null ? [] : [evidence];
};

/** Collects the decimal ids of `profile`, `trusted` and `suppression` evidence in stored rules. */
export function referencedIds(rules: unknown, into?: ReferencedIds): ReferencedIds {
  const out: ReferencedIds = into ?? {
    executive: new Set(),
    vendor: new Set(),
    trusted: new Set(),
    suppression: new Set(),
  };
  if (!Array.isArray(rules)) return out;
  for (const rule of rules.slice(0, BEC_MAX_RULES)) {
    for (const item of evidenceItems(rule).slice(0, BEC_MAX_EVIDENCE_ITEMS)) {
      if (!isRecord(item)) continue;
      const profile = item.profile;
      if (isRecord(profile)) {
        const id = asDecimal(profile.id);
        if (id && profile.kind === 'executive') out.executive.add(id);
        if (id && profile.kind === 'vendor') out.vendor.add(id);
      }
      const trusted = isRecord(item.trusted) ? asDecimal(item.trusted.id) : null;
      if (trusted) out.trusted.add(trusted);
      const suppression = isRecord(item.suppression) ? asDecimal(item.suppression.id) : null;
      if (suppression) out.suppression.add(suppression);
    }
  }
  return out;
}

/** Replaces internal ids by public ids; an id that does not map is removed with its key. */
function mapIds(item: Record<string, unknown>, ids: BecIdMaps): Record<string, unknown> {
  const out = { ...item };
  if (isRecord(out.profile)) {
    const decimal = asDecimal(out.profile.id);
    if (decimal !== null) {
      const map = out.profile.kind === 'vendor' ? ids.vendor : ids.executive;
      const publicId = map.get(decimal);
      if (publicId === undefined) delete out.profile;
      else out.profile = { ...out.profile, id: publicId };
    }
  }
  for (const [key, map] of [
    ['trusted', ids.trusted],
    ['suppression', ids.suppression],
  ] as const) {
    const ref = out[key];
    if (!isRecord(ref)) continue;
    const decimal = asDecimal(ref.id);
    if (decimal === null) continue;
    const publicId = map.get(decimal);
    if (publicId === undefined) delete out[key];
    else out[key] = { id: publicId };
  }
  return out;
}

/** A fired rule as the read API shows it: B15 entry with its evidence entries (≤ 5). */
export type BecRuleView = Omit<BecRuleEntry, 'evidence'> & { evidence: BecRuleEvidence[] };

/**
 * The stored `rules` JSON as rule views (≤ 32): evidence may be stored as one object (B15) or
 * as an array of ≤ 5 objects (B6, `@email-gateway/bec` FiredRule); each evidence entry is
 * validated on its own and dropped when invalid; a rule whose id, code, category, severity or
 * weight is invalid is dropped; a rule id fires at most once.
 */
export function rulesOf(value: unknown, ids: BecIdMaps = NO_ID_MAPS): BecRuleView[] {
  if (!Array.isArray(value)) return [];
  const out: BecRuleView[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (!isRecord(raw)) continue;
    const head = becRuleEntrySchema.safeParse({
      ...pick(raw, ['id', 'code', 'category', 'severity', 'weight', 'suppressed']),
      suppressed: raw.suppressed ?? null,
      evidence: {},
    });
    if (!head.success || seen.has(head.data.id)) continue;
    seen.add(head.data.id);
    const evidence: BecRuleEvidence[] = [];
    for (const item of evidenceItems(raw)) {
      const picked = pick(item, EVIDENCE_KEYS);
      if (picked === null) continue;
      const parsed = becRuleEvidenceSchema.safeParse(dropNulls(mapIds(picked, ids)));
      if (parsed.success) evidence.push(parsed.data);
      if (evidence.length >= BEC_MAX_EVIDENCE_ITEMS) break;
    }
    const { evidence: _ignored, ...rest } = head.data;
    out.push({ ...rest, evidence });
    if (out.length >= BEC_MAX_RULES) break;
  }
  return out;
}

/** Top-level null values of evidence are absent values (WP2 omits them; tolerate either). */
function dropNulls(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== null));
}

/** The reason codes of the fired rules of a stored result (any suppression state). */
export function ruleCodesOf(value: unknown): string[] {
  return [...new Set(rulesOf(value).map((rule) => rule.code))];
}

/** The input states, or null when the stored value is invalid. */
export function inputsOf(value: unknown): BecInputs | null {
  const parsed = becInputsSchema.safeParse(pick(value, ['auth', 'url', 'text', 'history']));
  return parsed.success ? parsed.data : null;
}

const ASSESSMENT_KEYS = [
  'layer',
  'mode',
  'provider',
  'modelId',
  'modelVersion',
  'promptTemplateVersion',
  'status',
  'labels',
  'confidence',
  'indicators',
  'citedFeatures',
  'spans',
];

/** Fills the fields WP3 may leave implicit (layer from `kind`, provider of the local layer). */
function assessmentInput(raw: unknown, mode: 'active' | 'shadow'): Record<string, unknown> | null {
  if (!isRecord(raw)) return null;
  const layer = raw.layer ?? raw.kind;
  return {
    ...pick(raw, ASSESSMENT_KEYS),
    layer,
    mode: raw.mode ?? mode,
    provider: raw.provider ?? (layer === 'local' ? 'local' : undefined),
    promptTemplateVersion: raw.promptTemplateVersion ?? null,
    confidence: raw.confidence ?? null,
    labels: raw.labels ?? [],
    indicators: raw.indicators ?? [],
    citedFeatures: raw.citedFeatures ?? [],
    spans: raw.spans ?? [],
  };
}

/** Applied assessments (≤ 2) with their `effect`; never the response hash or duration. */
export function appliedAssessmentsOf(value: unknown): BecAiAssessmentView[] {
  if (!Array.isArray(value)) return [];
  const out: BecAiAssessmentView[] = [];
  for (const raw of value) {
    const input = assessmentInput(raw, 'active');
    if (input === null) continue;
    const parsed = becAiAssessmentViewSchema.safeParse({
      ...input,
      effect: isRecord(raw) ? raw.effect : undefined,
    });
    if (parsed.success) out.push(parsed.data);
    if (out.length >= BEC_MAX_AI_ASSESSMENTS) break;
  }
  return out;
}

/** Shadow assessments (≤ 3), without `effect`. */
export function shadowAssessmentsOf(value: unknown): BecAiShadowAssessmentView[] {
  if (!Array.isArray(value)) return [];
  const out: BecAiShadowAssessmentView[] = [];
  for (const raw of value) {
    const parsed = becAiShadowAssessmentViewSchema.safeParse(assessmentInput(raw, 'shadow'));
    if (parsed.success) out.push(parsed.data);
    if (out.length >= BEC_MAX_AI_SHADOW_ASSESSMENTS) break;
  }
  return out;
}

/** The stored AI feature vector: known feature names with finite numbers or booleans only. */
export function featuresOf(value: unknown): Record<string, number | boolean> {
  if (!isRecord(value)) return {};
  const out: Record<string, number | boolean> = {};
  for (const name of AI_FEATURE_NAMES) {
    const v = value[name];
    if (typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))) out[name] = v;
  }
  return out;
}

const identityEntrySchema = z.object({
  address: z.string().min(3).max(320).nullable().optional(),
  domain: z.string().max(253).nullable().optional(),
  registrableDomain: z.string().max(253).nullable().optional(),
});

/** The From address and registrable domain of the stored identity summary (B14), if any. */
export function fromIdentityOf(value: unknown): {
  address: string | null;
  registrableDomain: string | null;
} {
  const from = isRecord(value) ? value.from : null;
  const parsed = identityEntrySchema.safeParse(from);
  if (!parsed.success) return { address: null, registrableDomain: null };
  return {
    address: parsed.data.address?.toLowerCase() ?? null,
    registrableDomain: parsed.data.registrableDomain?.toLowerCase() ?? null,
  };
}

const thresholdsSchema = z.object({
  suspicious: z.number().int().min(0).max(100),
  malicious: z.number().int().min(0).max(100),
});

/**
 * The thresholds of a result: `scan_engine_results.evidence.thresholds` of the bec final row
 * when the engine recorded them; otherwise the suspicious threshold is the final row's
 * `required_score` (B6: `requiredScore = suspiciousScore`) and the malicious threshold unknown.
 */
export function thresholdsOf(
  evidence: unknown,
  requiredScore: number | null,
): { suspicious: number | null; malicious: number | null } {
  const parsed = thresholdsSchema.safeParse(isRecord(evidence) ? evidence.thresholds : undefined);
  if (parsed.success && parsed.data.suspicious < parsed.data.malicious) return parsed.data;
  const suspicious =
    requiredScore !== null && Number.isInteger(requiredScore) && requiredScore >= 0
      ? requiredScore
      : null;
  return { suspicious, malicious: null };
}
