import { Deadline } from '@email-gateway/bec';
import {
  DLP_MASK_STYLES,
  DLP_PATTERN_VALIDATORS,
  DLP_TENANT_SEVERITIES,
  type DlpMaskStyle,
  type DlpPatternValidator,
  type DlpTenantSeverity,
} from '@email-gateway/security-contracts';
import { RE2JS } from 're2js';
import { readDataFile } from '../data';
import { validatePatternValue } from '../validators';

/**
 * Customer-defined patterns (step 4.5 D9): RE2 semantics through `re2js` (pure JS, linear-time
 * automata, no backtracking), validated at create/update, at the api test endpoint and again
 * when the worker loads them. A pattern, its matches and the test sample are tenant data: they
 * are never logged, and rejection codes carry no part of them.
 *
 * The wall-clock cost probe (step 6, `pattern_too_slow`) depends on the load of the process that
 * runs it, so it is a write-time gate of the api only. The worker re-validates with the
 * deterministic steps (`costProbe: false`) and compiles each row version once per process
 * (`CompiledPatternCache`): a pattern the api accepted cannot flip to invalid with the worker's
 * load (closer review, 2026-11-08).
 */

export const DLP_CUSTOM_PATTERN_CODES = [
  'pattern_syntax',
  'pattern_unsupported',
  'pattern_too_complex',
  'pattern_matches_empty',
  'pattern_too_broad',
  'pattern_too_slow',
  'pattern_invalid_options',
] as const;
export type DlpCustomPatternCode = (typeof DLP_CUSTOM_PATTERN_CODES)[number];

export const DLP_CUSTOM_PATTERN_DEFAULTS = Object.freeze({
  maxLength: 256,
  probeMaxMs: 50,
  /** Counted repetition bound `{n,m}`: m ≤ 100. */
  maxRepeat: 100,
  /** Product of nested counted repetitions ≤ 1 000. */
  maxRepetitionProduct: 1000,
  /** More matches than this on the probe corpus → `pattern_too_broad`. */
  maxProbeMatches: 50,
  maxContextKeywords: 20,
  maxKeywordChars: 64,
  maxMatchesPerPattern: 1000,
});

export interface CustomPatternInput {
  pattern: string;
  caseInsensitive: boolean;
  validator?: DlpPatternValidator;
  contextKeywords?: readonly string[];
  requireContext?: boolean;
}

export interface CustomPatternLimits {
  maxLength?: number;
  probeMaxMs?: number;
  /** Monotonic clock in milliseconds (tests inject one). */
  now?: () => number;
  /**
   * Run the wall-clock cost probe (step 6). Default true (api create/update/test). The worker
   * passes false: its load must not decide whether a stored pattern is valid.
   */
  costProbe?: boolean;
  /** Probe corpus text (tests inject one; default: the packaged `data/probe-corpus.txt`). */
  probeCorpus?: string;
}

export interface PatternComplexity {
  repetitionProduct: number;
  length: number;
}

export interface CompiledPattern {
  re: RE2JS;
  input: Required<
    Pick<CustomPatternInput, 'pattern' | 'caseInsensitive' | 'validator' | 'requireContext'>
  > & {
    contextKeywords: readonly string[];
  };
  complexity: PatternComplexity;
}

export type CompileResult =
  | { ok: true; compiled: CompiledPattern }
  | { ok: false; code: DlpCustomPatternCode; complexity?: PatternComplexity };

let probe: string | null = null;
/** The packaged probe corpus (≈ 64 KiB of ordinary text without sensitive values). */
export function probeCorpus(): string {
  probe ??= readDataFile('probe-corpus.txt');
  return probe;
}

/**
 * Constructs RE2 refuses or this platform does not accept: backreferences, lookaround,
 * atomic groups, possessive quantifiers, named backreferences, conditionals. Checked on the
 * pattern text before compilation so the code is `pattern_unsupported`, not `pattern_syntax`.
 */
export function hasUnsupportedConstruct(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i]!;
    if (c === '\\') {
      const n = pattern[i + 1];
      if (n !== undefined && /[1-9]/.test(n)) return true;
      if (n === 'k' || n === 'g') return true;
      i += 1;
      continue;
    }
    if (c === '(' && pattern[i + 1] === '?') {
      const rest = pattern.slice(i + 2, i + 5);
      if (/^(?:=|!|<=|<!|>|\(|P=|P>|&|R|\d)/.test(rest)) return true;
    }
    if ((c === '*' || c === '+' || c === '?' || c === '}') && pattern[i + 1] === '+') {
      // `a++`, `a*+`, `a?+`, `a{2}+` (possessive); `\++` was consumed as an escape above.
      return true;
    }
  }
  return false;
}

/**
 * Own parse of counted repetitions (D9 step 3): returns the largest repeat bound and the
 * largest product of nested counted repetitions, or null when a bound is malformed (left to the
 * compiler). `*`, `+` and `?` do not count (RE2 runs them linearly).
 */
export function repetitionComplexity(pattern: string): { maxRepeat: number; product: number } {
  // One frame per open group: the largest nested product seen inside it.
  const stack: number[] = [1];
  let maxRepeat = 0;
  let product = 1;
  // Nested product of the previous atom (a closed group carries its inner product).
  let previous = 1;
  let inClass = false;
  const fold = () => {
    const top = stack.length - 1;
    stack[top] = Math.max(stack[top]!, previous);
    product = Math.max(product, previous);
    previous = 1;
  };
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i]!;
    if (inClass) {
      if (c === '\\') i += 1;
      else if (c === ']') inClass = false;
      continue;
    }
    if (c === '{') {
      const close = pattern.indexOf('}', i);
      const m =
        close > i ? /^([0-9]{1,6})(?:,([0-9]{0,6}))?$/.exec(pattern.slice(i + 1, close)) : null;
      if (m) {
        const low = Number(m[1]);
        const high = m[2] === undefined || m[2] === '' ? low : Number(m[2]);
        const bound = Math.max(low, high, 1);
        maxRepeat = Math.max(maxRepeat, bound);
        previous *= bound;
        fold();
        i = close;
        continue;
      }
    }
    fold();
    if (c === '\\') {
      i += 1;
    } else if (c === '[') {
      inClass = true;
      if (pattern[i + 1] === '^') i += 1;
      if (pattern[i + 1] === ']') i += 1;
    } else if (c === '(') {
      stack.push(1);
    } else if (c === ')') {
      previous = stack.length > 1 ? stack.pop()! : 1;
    }
  }
  fold();
  return { maxRepeat, product: Math.max(product, ...stack) };
}

const countMatches = (re: RE2JS, text: string, cap: number): { count: number; empty: boolean } => {
  const m = re.matcher(text);
  let count = 0;
  let empty = false;
  while (count <= cap && m.find()) {
    if (m.end() === m.start()) {
      empty = true;
      break;
    }
    count += 1;
  }
  return { count, empty };
};

/**
 * Validates and compiles a tenant pattern (D9 steps 1–7). The order of the checks is fixed so
 * a given pattern always yields the same code.
 */
export function compileCustomPattern(
  input: CustomPatternInput,
  limits: CustomPatternLimits = {},
): CompileResult {
  const maxLength = limits.maxLength ?? DLP_CUSTOM_PATTERN_DEFAULTS.maxLength;
  const probeMaxMs = limits.probeMaxMs ?? DLP_CUSTOM_PATTERN_DEFAULTS.probeMaxMs;
  const now = limits.now ?? (() => performance.now());
  const { pattern } = input;
  const validator = input.validator ?? 'none';
  const keywords = input.contextKeywords ?? [];
  // 1. length and options
  if (typeof pattern !== 'string' || pattern.length < 1 || pattern.length > maxLength) {
    return { ok: false, code: 'pattern_syntax' };
  }
  // 7 (options are checked early: they need no compilation)
  if (
    !(DLP_PATTERN_VALIDATORS as readonly string[]).includes(validator) ||
    keywords.length > DLP_CUSTOM_PATTERN_DEFAULTS.maxContextKeywords ||
    keywords.some(
      (k) =>
        typeof k !== 'string' ||
        k.trim().length < 1 ||
        k.length > DLP_CUSTOM_PATTERN_DEFAULTS.maxKeywordChars,
    ) ||
    (input.requireContext === true && keywords.length === 0)
  ) {
    return { ok: false, code: 'pattern_invalid_options' };
  }
  const complexity: PatternComplexity = { repetitionProduct: 1, length: pattern.length };
  // 2. unsupported constructs, then RE2 syntax
  if (hasUnsupportedConstruct(pattern))
    return { ok: false, code: 'pattern_unsupported', complexity };
  // 3. counted repetition bounds (own parse, before the compiler's own 1 000 limit)
  const repetition = repetitionComplexity(pattern);
  complexity.repetitionProduct = repetition.product;
  if (
    repetition.maxRepeat > DLP_CUSTOM_PATTERN_DEFAULTS.maxRepeat ||
    repetition.product > DLP_CUSTOM_PATTERN_DEFAULTS.maxRepetitionProduct
  ) {
    return { ok: false, code: 'pattern_too_complex', complexity };
  }
  let re: RE2JS;
  try {
    re = RE2JS.compile(pattern, input.caseInsensitive ? RE2JS.CASE_INSENSITIVE : 0);
  } catch {
    return { ok: false, code: 'pattern_syntax', complexity };
  }
  // 4. empty match
  if (re.matcher('').find()) return { ok: false, code: 'pattern_matches_empty', complexity };
  // 5 + 6. breadth and cost probes on the packaged corpus
  const corpus = limits.probeCorpus ?? probeCorpus();
  const costProbe = limits.costProbe ?? true;
  const started = costProbe ? now() : 0;
  const probeResult = countMatches(re, corpus, DLP_CUSTOM_PATTERN_DEFAULTS.maxProbeMatches);
  const elapsed = costProbe ? now() - started : 0;
  if (probeResult.empty) return { ok: false, code: 'pattern_matches_empty', complexity };
  if (probeResult.count > DLP_CUSTOM_PATTERN_DEFAULTS.maxProbeMatches) {
    return { ok: false, code: 'pattern_too_broad', complexity };
  }
  if (costProbe && elapsed > probeMaxMs) {
    return { ok: false, code: 'pattern_too_slow', complexity };
  }
  return {
    ok: true,
    compiled: {
      re,
      input: {
        pattern,
        caseInsensitive: input.caseInsensitive,
        validator,
        requireContext: input.requireContext ?? false,
        contextKeywords: [...keywords],
      },
      complexity,
    },
  };
}

/** A tenant pattern as loaded by the worker (public id). */
export interface TenantPatternInput extends CustomPatternInput {
  id: string;
  version: number;
  severity: DlpTenantSeverity;
  baseConfidence: number;
  maskStyle: DlpMaskStyle;
}

export interface LoadedPattern {
  id: string;
  version: number;
  severity: DlpTenantSeverity;
  baseConfidence: number;
  maskStyle: DlpMaskStyle;
  compiled: CompiledPattern;
}

/**
 * Compile results per stored row version (D9 "compiled once per row version"), kept across
 * tenant-data reloads. The key holds the row's public id, its version and every input that
 * changes the compilation, so an edited row is never served from a stale entry. Bounded: the
 * oldest entry is evicted first. In memory only; never logged.
 */
export class CompiledPatternCache {
  private readonly entries = new Map<string, CompileResult>();

  constructor(private readonly maxEntries = 10_000) {}

  get size(): number {
    return this.entries.size;
  }

  static key(p: TenantPatternInput, maxLength: number | undefined): string {
    return JSON.stringify([
      p.id,
      p.version,
      maxLength ?? null,
      p.pattern,
      p.caseInsensitive,
      p.validator ?? 'none',
      p.contextKeywords ?? [],
      p.requireContext ?? false,
    ]);
  }

  get(key: string): CompileResult | undefined {
    return this.entries.get(key);
  }

  set(key: string, result: CompileResult): void {
    if (this.entries.has(key)) this.entries.delete(key);
    this.entries.set(key, result);
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }
}

/**
 * Compiles a tenant's stored patterns at load: one that no longer validates is skipped and
 * reported (`dlp.custom.pattern_invalid`, partial coverage, never clean). With a `cache`, each
 * row version is compiled once per process and later loads reuse the result.
 */
export function loadTenantPatterns(
  patterns: readonly TenantPatternInput[],
  limits: CustomPatternLimits = {},
  cache?: CompiledPatternCache,
): { loaded: LoadedPattern[]; invalid: string[] } {
  const loaded: LoadedPattern[] = [];
  const invalid: string[] = [];
  const sorted = [...patterns].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const compile = (p: TenantPatternInput): CompileResult => {
    if (!cache) return compileCustomPattern(p, limits);
    const key = CompiledPatternCache.key(p, limits.maxLength);
    const hit = cache.get(key);
    if (hit) return hit;
    const result = compileCustomPattern(p, limits);
    cache.set(key, result);
    return result;
  };
  for (const p of sorted) {
    const valid =
      (DLP_TENANT_SEVERITIES as readonly string[]).includes(p.severity) &&
      (DLP_MASK_STYLES as readonly string[]).includes(p.maskStyle) &&
      p.baseConfidence >= 0.5 &&
      p.baseConfidence <= 1;
    const result = valid ? compile(p) : null;
    if (!result?.ok) {
      invalid.push(p.id);
      continue;
    }
    loaded.push({
      id: p.id,
      version: p.version,
      severity: p.severity,
      baseConfidence: p.baseConfidence,
      maskStyle: p.maskStyle,
      compiled: result.compiled,
    });
  }
  return { loaded, invalid };
}

export interface PatternMatch {
  start: number;
  end: number;
  value: string;
  validated: boolean;
}

/**
 * Matches of one compiled pattern in `text` (≤ `maxMatches`, chunked so the deadline is checked
 * between chunks; a match is owned by the chunk where it starts). A match failing the
 * pattern's validator is reported with `validated: false` (not a finding).
 */
export function findPatternMatches(
  pattern: CompiledPattern,
  text: string,
  options: { maxMatches?: number; chunkChars?: number; overlap?: number; deadline?: Deadline } = {},
): { matches: PatternMatch[]; capped: boolean } {
  const maxMatches = options.maxMatches ?? DLP_CUSTOM_PATTERN_DEFAULTS.maxMatchesPerPattern;
  const chunk = options.chunkChars ?? 65_536;
  const overlap = options.overlap ?? 512;
  const deadline = options.deadline ?? Deadline.none();
  const matches: PatternMatch[] = [];
  let capped = false;
  for (let from = 0; from < text.length && !capped; from += chunk) {
    deadline.check(true);
    const to = Math.min(text.length, from + chunk + overlap);
    const m = pattern.re.matcher(text.slice(from, to));
    while (m.find()) {
      const start = from + m.start();
      const end = from + m.end();
      if (end <= start) break;
      if (start >= from + chunk) break;
      if (matches.length >= maxMatches) {
        capped = true;
        break;
      }
      const value = text.slice(start, end);
      matches.push({
        start,
        end,
        value,
        validated: validatePatternValue(pattern.input.validator, value),
      });
    }
  }
  return { matches, capped };
}

export const DLP_PATTERN_TEST_MAX_SAMPLE = 4096;
export const DLP_PATTERN_TEST_MAX_MATCHES = 50;

export interface PatternTestResult {
  valid: boolean;
  code?: DlpCustomPatternCode | 'sample_too_long';
  complexity: PatternComplexity;
  matches: {
    start: number;
    end: number;
    masked: string;
    validated: boolean;
    contextMatched: boolean;
  }[];
}

/**
 * The pattern test endpoint (`POST /api/v1/dlp/patterns/test`, D9): validates the pattern and
 * returns ≤ 50 masked matches of the sample (≤ 4 096 characters). Persists nothing; the
 * caller never logs the sample or the pattern.
 */
export function testCustomPattern(
  input: CustomPatternInput & { maskStyle?: DlpMaskStyle },
  sample: string,
  limits: CustomPatternLimits & { window?: number } = {},
): PatternTestResult {
  const length = typeof input.pattern === 'string' ? input.pattern.length : 0;
  if (typeof sample !== 'string' || sample.length > DLP_PATTERN_TEST_MAX_SAMPLE) {
    return {
      valid: false,
      code: 'sample_too_long',
      complexity: { repetitionProduct: 1, length },
      matches: [],
    };
  }
  const result = compileCustomPattern(input, limits);
  if (!result.ok) {
    return {
      valid: false,
      code: result.code,
      complexity: result.complexity ?? { repetitionProduct: 1, length },
      matches: [],
    };
  }
  const window = limits.window ?? 64;
  const keywords = result.compiled.input.contextKeywords.map((k) => k.toLowerCase());
  const lower = sample.toLowerCase();
  const { matches } = findPatternMatches(result.compiled, sample, {
    maxMatches: DLP_PATTERN_TEST_MAX_MATCHES,
  });
  return {
    valid: true,
    complexity: result.compiled.complexity,
    matches: matches.map((m) => {
      const compact = m.value.replace(/[^0-9A-Za-z]/g, '').toUpperCase() || m.value;
      const around = lower.slice(Math.max(0, m.start - window), m.end + window);
      return {
        start: m.start,
        end: m.end,
        masked:
          input.maskStyle === 'full'
            ? '*'.repeat(Math.min(Math.max(compact.length, 1), 60))
            : '*'.repeat(Math.min(Math.max(compact.length - 4, 0), 60)) + compact.slice(-4),
        validated: m.validated,
        contextMatched: keywords.some((k) => around.includes(k)),
      };
    }),
  };
}
