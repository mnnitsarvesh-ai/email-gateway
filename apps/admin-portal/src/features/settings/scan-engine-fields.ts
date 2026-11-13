import { z } from 'zod';
import type { ListItem } from '@/lib/api/types';
import { formatBytes, formatNumber, humanize } from '@/lib/format';

/** One engine entry of `GET /scan-settings` (discriminated by `engine`). */
export type EngineView = ListItem<'ScanSettingsController_list_v1'>;
export type EngineName = EngineView['engine'];

export const ENGINE_LABELS: Record<EngineName, string> = {
  rspamd: 'Spam filter (Rspamd)',
  attachment: 'Attachments',
  url: 'URLs',
  bec: 'Business email compromise',
  dlp: 'Data loss prevention',
  sandbox: 'Attachment sandbox',
};

export type FieldKind =
  | {
      readonly kind: 'number';
      readonly min?: number;
      readonly max?: number;
      readonly integer: boolean;
      readonly bytes?: boolean;
    }
  | { readonly kind: 'select'; readonly options: readonly string[] }
  | { readonly kind: 'boolean'; readonly allowed?: readonly boolean[] }
  | { readonly kind: 'domains'; readonly maxItems?: number }
  | { readonly kind: 'multi'; readonly options: readonly string[] };

export interface EngineField {
  /** Dotted path inside the engine's override object, e.g. `rewrite.expiryDays`. */
  readonly path: string;
  readonly label: string;
  readonly help?: string;
  readonly field: FieldKind;
}

type Range = { min: number; max: number };
const int = (r?: Range): FieldKind => ({ kind: 'number', integer: true, min: r?.min, max: r?.max });
const dec = (r?: Range): FieldKind => ({
  kind: 'number',
  integer: false,
  min: r?.min,
  max: r?.max,
});
const select = (options: readonly string[]): FieldKind => ({ kind: 'select', options });

/**
 * The tenant-settable fields of each engine, mirroring the override schemas of the snapshot
 * (`GET /scan-settings` `override`); bounds and options come from the engine's `bounds`.
 */
export function engineFields(view: EngineView): EngineField[] {
  switch (view.engine) {
    case 'rspamd': {
      const b = view.bounds;
      return [
        {
          path: 'spamScore',
          label: 'Spam score threshold',
          help: 'At most two decimals; must stay above the suspicious score.',
          field: dec(b.spamScore),
        },
        {
          path: 'suspiciousScore',
          label: 'Suspicious score threshold',
          field: dec(b.suspiciousScore),
        },
        {
          path: 'phishingVerdict',
          label: 'Verdict for phishing symbols',
          help: 'May only be raised above the platform value.',
          field: select(b.phishingVerdict),
        },
        {
          path: 'dmarcRejectVerdict',
          label: 'Verdict for DMARC reject',
          field: select(b.dmarcRejectVerdict),
        },
        {
          path: 'authFailureVerdict',
          label: 'Verdict for authentication failures',
          field: select(b.authFailureVerdict),
        },
      ];
    }
    case 'attachment': {
      const b = view.bounds;
      return [
        {
          path: 'maxAttachmentBytes',
          label: 'Largest attachment scanned (bytes)',
          field: {
            kind: 'number',
            integer: true,
            min: b.maxAttachmentBytes.min,
            max: b.maxAttachmentBytes.max,
            bytes: true,
          },
        },
        {
          path: 'deniedTypes',
          label: 'Denied file types',
          help: 'Added to the platform list; platform-denied types stay denied.',
          field: { kind: 'multi', options: b.deniedTypes },
        },
        {
          path: 'allowedTypes',
          label: 'Allowed file types',
          help: `At most ${b.maxAllowedTypes} types; empty means every type not denied.`,
          field: { kind: 'multi', options: b.allowedTypes },
        },
        {
          path: 'deniedTypeVerdict',
          label: 'Verdict for denied types',
          field: select(b.deniedTypeVerdict),
        },
        {
          path: 'typeMismatchVerdict',
          label: 'Verdict for type mismatches',
          field: select(b.typeMismatchVerdict),
        },
        {
          path: 'encryptedArchiveVerdict',
          label: 'Verdict for encrypted archives',
          field: select(b.encryptedArchiveVerdict),
        },
      ];
    }
    case 'url': {
      const b = view.bounds;
      return [
        {
          path: 'allowedDomains',
          label: 'Allowed domains',
          help: 'One registrable domain per line.',
          field: { kind: 'domains', maxItems: b.allowedDomains.maxItems },
        },
        {
          path: 'blockedDomains',
          label: 'Blocked domains',
          help: 'One registrable domain per line.',
          field: { kind: 'domains', maxItems: b.blockedDomains.maxItems },
        },
        { path: 'scanTimeFetch', label: 'Fetch URLs at scan time', field: select(b.scanTimeFetch) },
        {
          path: 'lookalike.extraProtectedDomains',
          label: 'Extra domains protected from lookalikes',
          field: { kind: 'domains', maxItems: b.lookalike.extraProtectedDomains.maxItems },
        },
        {
          path: 'rewrite.enabled',
          label: 'Rewrite links',
          field: { kind: 'boolean', allowed: b.rewrite.enabled },
        },
        {
          path: 'rewrite.directions',
          label: 'Rewrite in these directions',
          field: { kind: 'multi', options: b.rewrite.directions },
        },
        {
          path: 'rewrite.expiryDays',
          label: 'Rewritten links expire after (days)',
          field: int(b.rewrite.expiryDays),
        },
        {
          path: 'rewrite.excludedDomains',
          label: 'Domains never rewritten',
          field: { kind: 'domains', maxItems: b.rewrite.excludedDomains.maxItems },
        },
        {
          path: 'rewrite.dkimSignedPolicy',
          label: 'DKIM-signed messages',
          field: select(b.rewrite.dkimSignedPolicy),
        },
        {
          path: 'rewrite.plainText',
          label: 'Rewrite links in plain text parts',
          field: { kind: 'boolean' },
        },
        {
          path: 'click.suspicious',
          label: 'At click: suspicious URLs',
          field: select(b.click.suspicious),
        },
        { path: 'click.unknown', label: 'At click: unknown URLs', field: select(b.click.unknown) },
        {
          path: 'click.allowContinue',
          label: 'Let users continue past a warning',
          field: { kind: 'boolean' },
        },
        {
          path: 'dynamicInspection',
          label: 'Dynamic (browser) inspection',
          field: { kind: 'boolean', allowed: b.dynamicInspection },
        },
      ];
    }
    case 'bec': {
      const b = view.bounds;
      return [
        { path: 'suspiciousScore', label: 'Suspicious score', field: int(b.suspiciousScore) },
        { path: 'maliciousScore', label: 'Malicious score', field: int(b.maliciousScore) },
        {
          path: 'freemailExtraDomains',
          label: 'Extra free-mail domains',
          field: { kind: 'domains', maxItems: b.freemailExtraDomains.maxItems },
        },
        {
          path: 'history.enabled',
          label: 'Keep sender history',
          field: { kind: 'boolean', allowed: b.history.enabled },
        },
        {
          path: 'history.retentionDays',
          label: 'Sender history retention (days)',
          field: int(b.history.retentionDays),
        },
        { path: 'ai.localModel', label: 'Local model', field: select(b.ai.localModel) },
        { path: 'ai.llm', label: 'Language model', field: select(b.ai.llm) },
        {
          path: 'ai.llmDailyCallLimit',
          label: 'Language model calls per day',
          field: int(b.ai.llmDailyCallLimit),
        },
        {
          path: 'ai.raiseConfidence',
          label: 'Confidence to raise a verdict',
          field: dec(b.ai.raiseConfidence),
        },
      ];
    }
    case 'dlp': {
      const b = view.bounds;
      return [
        {
          path: 'inboundEnabled',
          label: 'Inspect inbound mail',
          field: { kind: 'boolean', allowed: b.inboundEnabled },
        },
        ...b.thresholds.categories.map((category) => ({
          path: `thresholds.${category}`,
          label: `Confidence threshold: ${humanize(category)}`,
          field: dec({ min: b.thresholds.min, max: b.thresholds.max }),
        })),
        {
          path: 'disabledDetectors',
          label: 'Disabled detectors',
          field: { kind: 'multi', options: b.disabledDetectors },
        },
        { path: 'defaultPolicy', label: 'Default policy', field: select(b.defaultPolicy) },
        {
          path: 'evidence.enabled',
          label: 'Keep evidence',
          field: { kind: 'boolean', allowed: b.evidence.enabled },
        },
        {
          path: 'evidence.retentionDays',
          label: 'Evidence retention (days)',
          field: int(b.evidence.retentionDays),
        },
      ];
    }
    case 'sandbox': {
      const b = view.bounds;
      return [
        {
          path: 'enabled',
          label: 'Send attachments to the sandbox',
          field: { kind: 'boolean', allowed: b.enabled },
        },
        { path: 'fileTypes', label: 'File types', field: { kind: 'multi', options: b.fileTypes } },
        {
          path: 'maxSampleBytes',
          label: 'Largest sample (bytes)',
          field: {
            kind: 'number',
            integer: true,
            min: b.maxSampleBytes.min,
            max: b.maxSampleBytes.max,
            bytes: true,
          },
        },
        {
          path: 'browserAnalysis',
          label: 'Browser analysis',
          field: { kind: 'boolean', allowed: b.browserAnalysis },
        },
      ];
    }
  }
}

export function getPath(source: unknown, path: string): unknown {
  let node: unknown = source;
  for (const part of path.split('.')) {
    if (node === null || typeof node !== 'object') return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return node;
}

export function setPath(target: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split('.');
  let node = target;
  for (const part of parts.slice(0, -1)) {
    const next = node[part];
    if (next === null || typeof next !== 'object') node[part] = {};
    node = node[part] as Record<string, unknown>;
  }
  node[parts[parts.length - 1] as string] = value;
}

/** Form keys cannot contain dots (react-hook-form paths): `rewrite.expiryDays` → `rewrite__expiryDays`. */
export const fieldKey = (path: string) => path.replace(/\./g, '__');

const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

export function parseDomains(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

/** The value schema of a field while its override is on (form value → api value). */
export function valueSchema(def: EngineField): z.ZodType<unknown> {
  const f = def.field;
  switch (f.kind) {
    case 'number': {
      let n = z.number({ message: 'Enter a number' });
      if (f.integer) n = n.int('Enter a whole number');
      if (f.min !== undefined) n = n.min(f.min, `At least ${formatNumber(f.min)}`);
      if (f.max !== undefined) n = n.max(f.max, `At most ${formatNumber(f.max)}`);
      return z.preprocess(
        (v) => (typeof v === 'string' ? (v.trim() === '' ? undefined : Number(v)) : v),
        n,
      );
    }
    case 'select':
      return z.enum(f.options as [string, ...string[]], { message: 'Choose a value' });
    case 'boolean':
      return z.boolean().refine((v) => !f.allowed || f.allowed.includes(v), {
        message: 'The platform does not allow this value',
      });
    case 'multi':
      return z.array(z.enum(f.options as [string, ...string[]]));
    case 'domains':
      return z
        .string()
        .transform(parseDomains)
        .pipe(
          z
            .array(z.string().regex(DOMAIN, 'Each line must be a domain such as example.com'))
            .max(f.maxItems ?? 10_000, `At most ${f.maxItems ?? 10_000} domains`),
        );
  }
}

export interface FieldState {
  on: boolean;
  value: unknown;
}
export type EngineFormValues = Record<string, FieldState>;

/** The form's initial state: overridden paths are on; the effective value is shown either way. */
export function engineFormDefaults(view: EngineView): EngineFormValues {
  const out: EngineFormValues = {};
  for (const def of engineFields(view)) {
    const overridden = getPath(view.override, def.path);
    const effective = getPath(view.effective, def.path) ?? getPath(view.platform, def.path);
    const value = overridden !== undefined ? overridden : effective;
    out[fieldKey(def.path)] = {
      on: overridden !== undefined,
      value:
        def.field.kind === 'domains'
          ? Array.isArray(value)
            ? value.join('\n')
            : ''
          : def.field.kind === 'multi'
            ? Array.isArray(value)
              ? [...(value as string[])]
              : []
            : def.field.kind === 'number'
              ? typeof value === 'number'
                ? String(value)
                : ''
              : value,
    };
  }
  return out;
}

/** zod schema of the engine form (strict): fields whose override is off are not validated. */
export function engineFormSchema(view: EngineView) {
  const shape: Record<string, z.ZodType<FieldState>> = {};
  for (const def of engineFields(view)) {
    const schema = valueSchema(def);
    shape[fieldKey(def.path)] = z
      .object({ on: z.boolean(), value: z.unknown() })
      .strict()
      .superRefine((state, ctx) => {
        if (!state.on) return;
        const result = schema.safeParse(state.value);
        if (!result.success)
          ctx.addIssue({
            code: 'custom',
            path: ['value'],
            message: result.error.issues[0]?.message ?? 'Invalid value',
          });
      });
  }
  return z.object(shape).strict();
}

/** The override object `PUT /scan-settings/{engine}` takes: only the fields switched on. */
export function engineSettingsBody(
  view: EngineView,
  values: EngineFormValues,
): Record<string, unknown> {
  const settings: Record<string, unknown> = {};
  for (const def of engineFields(view)) {
    const state = values[fieldKey(def.path)];
    if (!state?.on) continue;
    setPath(settings, def.path, valueSchema(def).parse(state.value));
  }
  return settings;
}

/** Display of a value (read-only summaries). */
export function formatSetting(def: EngineField, value: unknown): string {
  if (value === undefined || value === null) return 'Not set';
  if (typeof value === 'boolean') return value ? 'On' : 'Off';
  if (typeof value === 'number')
    return def.field.kind === 'number' && def.field.bytes
      ? formatBytes(value)
      : formatNumber(value);
  if (Array.isArray(value)) return value.length === 0 ? 'None' : value.map(String).join(', ');
  if (typeof value === 'string') return def.field.kind === 'select' ? humanize(value) : value;
  return JSON.stringify(value);
}
