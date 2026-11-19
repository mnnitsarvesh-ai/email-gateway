/**
 * Per-tenant ATO settings `ato-settings/1` (step 8.4 §4.3): a strict input schema where every key is
 * optional, the defaults (`DEFAULT_ATO_SETTINGS`), the bounds (`ATO_SETTINGS_BOUNDS`), the cross-field
 * rules (bands ordered, incident threshold ≥ medium band, weak-only cap < threshold ≤ strong floor,
 * valid unique CIDRs with IPv4 ≥ /8 and IPv6 ≥ /32, valid unique SOC e-mails, automation only for
 * catalogue types, rule parameters against each rule's bounds), the resolver used by every reader,
 * changed-path diffs for the audit row and a canonical JSON + SHA-256 for `settings_sha256`.
 *
 * Storage decision: `ato_settings.settings` holds the tenant's **explicit** values (normalized,
 * canonical key order, always with `mode`), resolved against the defaults on read, so an engineering
 * default can be improved without rewriting tenant rows; the version row keeps the same JSON.
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { ATO_RULES, ruleByCode, ruleDefaults, ruleParamsSchema } from './rules/catalogue';
import { parseCidr } from './net';
import {
  AUTOMATABLE_ACTION_TYPES,
  AUTOMATION_MODES,
  RESPONSE_CATALOGUE,
  type AutomatableActionType,
  type AutomationMode,
} from './responses';
import { DEFAULT_HALF_LIFE_MINUTES, SIGNAL_CATEGORIES, type SignalCategory } from './taxonomy';

/** Numeric bounds of every tunable setting (inclusive). */
export const ATO_SETTINGS_BOUNDS = Object.freeze({
  learningDays: { min: 0, max: 60 },
  band: { min: 10, max: 95 },
  incidentThreshold: { min: 30, max: 90 },
  weakOnlyCap: { min: 20, max: 89 },
  strongFloor: { min: 40, max: 95 },
  incidentReopenCooldownMinutes: { min: 0, max: 10080 },
  categoryMultiplierPermille: { min: 500, max: 2000 },
  halfLifeMinutes: { min: 60, max: 43200 },
  ruleWeight: { min: 0, max: 100 },
  networks: { max: 100 },
  ipv4MinPrefix: 8,
  ipv6MinPrefix: 32,
  windowDays: { min: 7, max: 90 },
  minActiveDays: { min: 1, max: 30 },
  minEvents: { min: 1, max: 10000 },
  volumeK: { min: 2, max: 20 },
  impossibleTravelKmh: { min: 300, max: 2000 },
  minDistanceKm: { min: 100, max: 5000 },
  maxAccuracyRadiusKm: { min: 10, max: 1000 },
  throttleMinutes: { min: 1, max: 1440 },
  digestHourLocal: { min: 0, max: 23 },
  socEmails: { max: 5 },
  maxAutomaticPerHour: { min: 0, max: 100 },
  durationMinutes: { min: 15, max: 10080 },
});

export const ATO_MODES = ['monitor', 'enforce', 'off'] as const;
export type AtoMode = (typeof ATO_MODES)[number];
const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export interface AutomationActionSettings {
  mode: AutomationMode;
  minLevel: 'high' | 'critical';
  durationMinutes: number;
}

export interface ResolvedRuleSettings {
  enabled: boolean;
  weight: number;
  params: Record<string, number>;
}

export interface ResolvedAtoSettings {
  mode: AtoMode;
  learningDays: number;
  scoring: {
    bands: { medium: number; high: number; critical: number };
    incidentThreshold: number;
    weakOnlyCap: number;
    strongFloor: number;
    incidentReopenCooldownMinutes: number;
    categoryMultipliers: Record<SignalCategory, number>;
    halfLifeMinutes: Record<SignalCategory, number>;
  };
  rules: Record<string, ResolvedRuleSettings>;
  ipReputation: {
    useLocalFeed: boolean;
    useDnsbl: boolean;
    trustedNetworks: string[];
    blockedNetworks: string[];
  };
  baselines: { windowDays: number; minActiveDays: number; minEvents: number; volumeK: number };
  geo: { impossibleTravelKmh: number; minDistanceKm: number; maxAccuracyRadiusKm: number };
  notifications: {
    incidentMinSeverity: (typeof SEVERITIES)[number];
    throttleMinutes: number;
    digest: { daily: boolean; weekly: boolean; hourLocal: number };
    socEmails: string[];
    includeOrganizationContact: boolean;
  };
  automation: { maxAutomaticPerHour: number } & Record<
    AutomatableActionType,
    AutomationActionSettings
  >;
  restrictions: { defaultMode: 'reject' | 'defer'; defaultDurationMinutes: number };
}

const categoryRecord = (value: number): Record<SignalCategory, number> =>
  Object.fromEntries(SIGNAL_CATEGORIES.map((c) => [c, value])) as Record<SignalCategory, number>;

function defaultAutomation(): ResolvedAtoSettings['automation'] {
  const out: Record<string, unknown> = { maxAutomaticPerHour: 10 };
  for (const type of AUTOMATABLE_ACTION_TYPES) {
    out[type] = {
      mode: RESPONSE_CATALOGUE[type].impact === 'low' ? 'automatic' : 'recommend',
      minLevel: 'critical',
      durationMinutes: 240,
    } satisfies AutomationActionSettings;
  }
  return out as ResolvedAtoSettings['automation'];
}

/** The defaults of `ato-settings/1` (§4.3; brief defaults for bands). Frozen deep. */
export const DEFAULT_ATO_SETTINGS: Readonly<ResolvedAtoSettings> = deepFreeze({
  mode: 'monitor',
  learningDays: 14,
  scoring: {
    bands: { medium: 30, high: 50, critical: 75 },
    incidentThreshold: 50,
    weakOnlyCap: 45,
    strongFloor: 60,
    incidentReopenCooldownMinutes: 60,
    categoryMultipliers: categoryRecord(1000),
    halfLifeMinutes: { ...DEFAULT_HALF_LIFE_MINUTES },
  },
  rules: Object.fromEntries(
    ATO_RULES.map((r) => [
      r.code,
      { enabled: true, weight: r.defaultWeight, params: ruleDefaults(r) },
    ]),
  ),
  ipReputation: { useLocalFeed: true, useDnsbl: true, trustedNetworks: [], blockedNetworks: [] },
  baselines: { windowDays: 28, minActiveDays: 7, minEvents: 30, volumeK: 6 },
  geo: { impossibleTravelKmh: 900, minDistanceKm: 500, maxAccuracyRadiusKm: 500 },
  notifications: {
    incidentMinSeverity: 'high',
    throttleMinutes: 15,
    digest: { daily: true, weekly: true, hourLocal: 8 },
    socEmails: [],
    includeOrganizationContact: true,
  },
  automation: defaultAutomation(),
  restrictions: { defaultMode: 'reject', defaultDurationMinutes: 240 },
});

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

const int = (b: { min: number; max: number }) => z.number().int().min(b.min).max(b.max);
const B = ATO_SETTINGS_BOUNDS;

const categoryInput = (b: { min: number; max: number }) =>
  z
    .strictObject(
      Object.fromEntries(SIGNAL_CATEGORIES.map((c) => [c, int(b).optional()])) as Record<
        SignalCategory,
        z.ZodOptional<z.ZodNumber>
      >,
    )
    .optional();

const cidrList = z
  .array(z.string().min(1).max(49))
  .max(B.networks.max)
  .superRefine((list, ctx) => {
    const seen = new Set<string>();
    list.forEach((text, i) => {
      const parsed = parseCidr(text, {
        minV4Prefix: B.ipv4MinPrefix,
        minV6Prefix: B.ipv6MinPrefix,
      });
      if (!parsed) {
        ctx.addIssue({
          code: 'custom',
          path: [i],
          message: 'Expected a CIDR (IPv4 /8 or longer, IPv6 /32 or longer)',
        });
        return;
      }
      if (seen.has(parsed.cidr)) {
        ctx.addIssue({ code: 'custom', path: [i], message: 'Duplicate network' });
      }
      seen.add(parsed.cidr);
    });
  });

const automationActionInput = z
  .strictObject({
    mode: z.enum(AUTOMATION_MODES).optional(),
    minLevel: z.enum(['high', 'critical']).optional(),
    durationMinutes: int(B.durationMinutes).optional(),
  })
  .optional();

const ruleInput = z.strictObject({
  enabled: z.boolean().optional(),
  weight: int(B.ruleWeight).optional(),
  params: z.record(z.string(), z.unknown()).optional(),
});

const inputShape = z.strictObject({
  mode: z.enum(ATO_MODES).optional(),
  learningDays: int(B.learningDays).optional(),
  scoring: z
    .strictObject({
      bands: z
        .strictObject({
          medium: int(B.band).optional(),
          high: int(B.band).optional(),
          critical: int(B.band).optional(),
        })
        .optional(),
      incidentThreshold: int(B.incidentThreshold).optional(),
      weakOnlyCap: int(B.weakOnlyCap).optional(),
      strongFloor: int(B.strongFloor).optional(),
      incidentReopenCooldownMinutes: int(B.incidentReopenCooldownMinutes).optional(),
      categoryMultipliers: categoryInput(B.categoryMultiplierPermille),
      halfLifeMinutes: categoryInput(B.halfLifeMinutes),
    })
    .optional(),
  rules: z.record(z.string().max(64), ruleInput).optional(),
  ipReputation: z
    .strictObject({
      useLocalFeed: z.boolean().optional(),
      useDnsbl: z.boolean().optional(),
      trustedNetworks: cidrList.optional(),
      blockedNetworks: cidrList.optional(),
    })
    .optional(),
  baselines: z
    .strictObject({
      windowDays: int(B.windowDays).optional(),
      minActiveDays: int(B.minActiveDays).optional(),
      minEvents: int(B.minEvents).optional(),
      volumeK: int(B.volumeK).optional(),
    })
    .optional(),
  geo: z
    .strictObject({
      impossibleTravelKmh: int(B.impossibleTravelKmh).optional(),
      minDistanceKm: int(B.minDistanceKm).optional(),
      maxAccuracyRadiusKm: int(B.maxAccuracyRadiusKm).optional(),
    })
    .optional(),
  notifications: z
    .strictObject({
      incidentMinSeverity: z.enum(SEVERITIES).optional(),
      throttleMinutes: int(B.throttleMinutes).optional(),
      digest: z
        .strictObject({
          daily: z.boolean().optional(),
          weekly: z.boolean().optional(),
          hourLocal: int(B.digestHourLocal).optional(),
        })
        .optional(),
      socEmails: z.array(z.email().max(320)).max(B.socEmails.max).optional(),
      includeOrganizationContact: z.boolean().optional(),
    })
    .optional(),
  automation: z
    .strictObject({
      maxAutomaticPerHour: int(B.maxAutomaticPerHour).optional(),
      ...(Object.fromEntries(
        AUTOMATABLE_ACTION_TYPES.map((t) => [t, automationActionInput]),
      ) as Record<AutomatableActionType, typeof automationActionInput>),
    })
    .optional(),
  restrictions: z
    .strictObject({
      defaultMode: z.enum(['reject', 'defer']).optional(),
      defaultDurationMinutes: int(B.durationMinutes).optional(),
    })
    .optional(),
});

export type AtoSettingsInput = z.infer<typeof inputShape>;

/** Merges an (already shape-valid) input over the defaults. */
export function mergeAtoSettings(input: AtoSettingsInput): ResolvedAtoSettings {
  const d = DEFAULT_ATO_SETTINGS;
  const rules: Record<string, ResolvedRuleSettings> = {};
  for (const r of ATO_RULES) {
    const base = d.rules[r.code]!;
    const over = input.rules?.[r.code];
    rules[r.code] = {
      enabled: over?.enabled ?? base.enabled,
      weight: over?.weight ?? base.weight,
      params: { ...base.params, ...((over?.params ?? {}) as Record<string, number>) },
    };
  }
  const automation = {
    maxAutomaticPerHour: input.automation?.maxAutomaticPerHour ?? d.automation.maxAutomaticPerHour,
  } as ResolvedAtoSettings['automation'];
  for (const type of AUTOMATABLE_ACTION_TYPES) {
    automation[type] = { ...d.automation[type], ...(input.automation?.[type] ?? {}) };
  }
  return {
    mode: input.mode ?? d.mode,
    learningDays: input.learningDays ?? d.learningDays,
    scoring: {
      bands: { ...d.scoring.bands, ...(input.scoring?.bands ?? {}) },
      incidentThreshold: input.scoring?.incidentThreshold ?? d.scoring.incidentThreshold,
      weakOnlyCap: input.scoring?.weakOnlyCap ?? d.scoring.weakOnlyCap,
      strongFloor: input.scoring?.strongFloor ?? d.scoring.strongFloor,
      incidentReopenCooldownMinutes:
        input.scoring?.incidentReopenCooldownMinutes ?? d.scoring.incidentReopenCooldownMinutes,
      categoryMultipliers: {
        ...d.scoring.categoryMultipliers,
        ...stripUndefined(input.scoring?.categoryMultipliers),
      },
      halfLifeMinutes: {
        ...d.scoring.halfLifeMinutes,
        ...stripUndefined(input.scoring?.halfLifeMinutes),
      },
    },
    rules,
    ipReputation: {
      useLocalFeed: input.ipReputation?.useLocalFeed ?? d.ipReputation.useLocalFeed,
      useDnsbl: input.ipReputation?.useDnsbl ?? d.ipReputation.useDnsbl,
      trustedNetworks: canonicalCidrs(
        input.ipReputation?.trustedNetworks ?? d.ipReputation.trustedNetworks,
      ),
      blockedNetworks: canonicalCidrs(
        input.ipReputation?.blockedNetworks ?? d.ipReputation.blockedNetworks,
      ),
    },
    baselines: { ...d.baselines, ...stripUndefined(input.baselines) },
    geo: { ...d.geo, ...stripUndefined(input.geo) },
    notifications: {
      incidentMinSeverity:
        input.notifications?.incidentMinSeverity ?? d.notifications.incidentMinSeverity,
      throttleMinutes: input.notifications?.throttleMinutes ?? d.notifications.throttleMinutes,
      digest: { ...d.notifications.digest, ...stripUndefined(input.notifications?.digest) },
      socEmails: (input.notifications?.socEmails ?? d.notifications.socEmails).map((e) =>
        e.toLowerCase(),
      ),
      includeOrganizationContact:
        input.notifications?.includeOrganizationContact ??
        d.notifications.includeOrganizationContact,
    },
    automation,
    restrictions: { ...d.restrictions, ...stripUndefined(input.restrictions) },
  };
}

function stripUndefined<T extends object>(value: T | undefined): Partial<T> {
  if (!value) return {};
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>;
}

const canonicalCidrs = (list: readonly string[]): string[] =>
  list.map((c) => parseCidr(c)?.cidr ?? c);

/** Cross-field rules of §4.3 on the merged settings; returns issues (path, message). */
export function crossFieldIssues(
  input: AtoSettingsInput,
  merged: ResolvedAtoSettings,
): Array<{ path: (string | number)[]; message: string }> {
  const issues: Array<{ path: (string | number)[]; message: string }> = [];
  const { bands, incidentThreshold, weakOnlyCap, strongFloor } = merged.scoring;
  if (!(bands.medium < bands.high && bands.high < bands.critical)) {
    issues.push({
      path: ['scoring', 'bands'],
      message: 'Bands must satisfy medium < high < critical',
    });
  }
  if (incidentThreshold < bands.medium) {
    issues.push({
      path: ['scoring', 'incidentThreshold'],
      message: 'The incident threshold must be at least the medium band',
    });
  }
  if (!(weakOnlyCap < incidentThreshold && incidentThreshold <= strongFloor)) {
    issues.push({
      path: ['scoring'],
      message: 'Must satisfy weakOnlyCap < incidentThreshold <= strongFloor',
    });
  }
  const emails = merged.notifications.socEmails;
  if (new Set(emails).size !== emails.length) {
    issues.push({ path: ['notifications', 'socEmails'], message: 'Duplicate SOC e-mail' });
  }
  for (const [code, over] of Object.entries(input.rules ?? {})) {
    const rule = ruleByCode(code);
    if (!rule) {
      issues.push({ path: ['rules', code], message: 'Unknown rule code' });
      continue;
    }
    if (over.params !== undefined) {
      const parsed = ruleParamsSchema(rule).safeParse(over.params);
      if (!parsed.success) {
        for (const issue of parsed.error.issues) {
          issues.push({
            path: [
              'rules',
              code,
              'params',
              ...issue.path.map((p) => (typeof p === 'symbol' ? String(p) : p)),
            ],
            message: issue.message,
          });
        }
      }
    }
  }
  return issues;
}

/**
 * `atoSettingsSchema`: the strict input of `ato-settings/1` (every key optional) with the cross-field
 * rules checked on the input merged over the defaults.
 */
export const atoSettingsSchema = inputShape.superRefine((input, ctx) => {
  let merged: ResolvedAtoSettings;
  try {
    merged = mergeAtoSettings(input);
  } catch {
    ctx.addIssue({ code: 'custom', path: [], message: 'Malformed settings' });
    return;
  }
  for (const issue of crossFieldIssues(input, merged)) {
    ctx.addIssue({ code: 'custom', path: issue.path, message: issue.message });
  }
});

/**
 * The normalized stored form: the explicit input with canonical CIDRs, lower-cased e-mails, rule
 * params as numbers and `mode` always present (the policy-engine reads `$.mode`).
 */
export function normalizeAtoSettings(input: AtoSettingsInput): AtoSettingsInput {
  const out = JSON.parse(JSON.stringify(input)) as AtoSettingsInput;
  out.mode = input.mode ?? DEFAULT_ATO_SETTINGS.mode;
  if (out.ipReputation?.trustedNetworks) {
    out.ipReputation.trustedNetworks = canonicalCidrs(out.ipReputation.trustedNetworks);
  }
  if (out.ipReputation?.blockedNetworks) {
    out.ipReputation.blockedNetworks = canonicalCidrs(out.ipReputation.blockedNetworks);
  }
  if (out.notifications?.socEmails) {
    out.notifications.socEmails = out.notifications.socEmails.map((e) => e.toLowerCase());
  }
  return JSON.parse(canonicalSettingsJson(out)) as AtoSettingsInput;
}

/**
 * Resolves a stored settings value: valid → merged over the defaults; anything else (malformed,
 * written by a newer version) → the defaults with `invalid: true` (readers never fail on settings).
 */
export function resolveAtoSettings(stored: unknown): {
  settings: ResolvedAtoSettings;
  invalid: boolean;
} {
  const parsed = atoSettingsSchema.safeParse(stored ?? {});
  if (!parsed.success) return { settings: mergeAtoSettings({}), invalid: true };
  return { settings: mergeAtoSettings(parsed.data), invalid: false };
}

/** JSON with object keys sorted at every depth (arrays keep their order). */
export function canonicalSettingsJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
        .map((k) => [k, sortKeys((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
}

/** SHA-256 (hex) of the canonical JSON (`ato_settings.settings_sha256`). */
export function settingsSha256(value: unknown): string {
  return createHash('sha256').update(canonicalSettingsJson(value), 'utf8').digest('hex');
}

/**
 * Dotted paths whose values differ between two settings objects (leaves; arrays compared whole),
 * sorted. Used for the audit row of a settings change.
 */
export function settingsDiffPaths(a: unknown, b: unknown): string[] {
  const out: string[] = [];
  const walk = (x: unknown, y: unknown, path: string): void => {
    const xo = x !== null && typeof x === 'object' && !Array.isArray(x);
    const yo = y !== null && typeof y === 'object' && !Array.isArray(y);
    if (xo && yo) {
      const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
      for (const k of keys) {
        walk(
          (x as Record<string, unknown>)[k],
          (y as Record<string, unknown>)[k],
          path ? `${path}.${k}` : k,
        );
      }
      return;
    }
    if (canonicalSettingsJson(x) !== canonicalSettingsJson(y)) out.push(path || '$');
  };
  walk(a, b, '');
  return out.sort();
}

/** Whether the tenant is in its learning period (`learningDays` after ATO was enabled). */
export function isLearning(
  settings: Pick<ResolvedAtoSettings, 'learningDays'>,
  learningStartedAt: Date,
  now: Date,
): boolean {
  return now.getTime() < learningStartedAt.getTime() + settings.learningDays * 86_400_000;
}
