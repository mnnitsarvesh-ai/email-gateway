import { z } from 'zod';

/**
 * The engine registry catalog (docs/plan/steps/09-rspamd.md S4, ADR-0026). Data only: the api
 * lists engines and their settings from it without depending on the worker; the email-worker's
 * adapter registry (`scanning/registry.ts`) pairs every entry with an adapter.
 */

/**
 * Pipeline stages of the security engines (ADR-0026, amended by ADR-0028: ClamAV and YARA are
 * components of the one `attachment` stage, step 4.2 A1).
 */
export const SECURITY_STAGES = ['antispam', 'attachment', 'url', 'bec', 'dlp', 'sandbox'] as const;
export type SecurityStage = (typeof SECURITY_STAGES)[number];
export const securityStageSchema = z.enum(SECURITY_STAGES);

/**
 * Every engine name the platform knows (4.1 registers `rspamd`, 4.2 `attachment`; 4.3–4.6 add the
 * rest). `clamav` and `yara` were never registered or stored: they are components of the
 * `attachment` engine (step 4.2 A1, ADR-0028).
 */
export const ENGINE_NAMES = ['rspamd', 'attachment', 'url', 'bec', 'dlp', 'sandbox'] as const;
export type EngineName = (typeof ENGINE_NAMES)[number];
export const engineNameSchema = z.enum(ENGINE_NAMES);

/** Shape of an engine name in events and rows (`scan_engine_results.engine` is VARCHAR(32)). */
export const ENGINE_NAME_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

export interface EngineCatalogEntry {
  readonly name: EngineName;
  readonly stage: SecurityStage;
  /** The engine's RabbitMQ work queue (a `QueueName` of `@email-gateway/event-contracts`). */
  readonly queue: string;
  /** Required for every round when enabled on the platform (`SCAN_ENGINES`). */
  readonly requiredByDefault: boolean;
  /** Whether a tenant may switch the engine off; required engines never are (4.1, 4.2). */
  readonly tenantMayDisable: boolean;
  readonly description: string;
}

/** The registered engines (step 4.1: Rspamd; step 4.2: the attachment engine, A1). */
export const ENGINE_CATALOG: readonly EngineCatalogEntry[] = Object.freeze([
  Object.freeze({
    name: 'rspamd',
    stage: 'antispam',
    queue: 'scan.spam',
    requiredByDefault: true,
    tenantMayDisable: false,
    description:
      'Rspamd: spam, phishing, reputation, Bayes, fuzzy hashes and SPF/DKIM/DMARC/ARC (step 4.1)',
  } as const),
  Object.freeze({
    name: 'attachment',
    stage: 'attachment',
    queue: 'scan.attachment',
    requiredByDefault: true,
    tenantMayDisable: false,
    description:
      'Attachments: file type, known-threat hashes, ClamAV, YARA, archive limits (step 4.2)',
  } as const),
]);

export const isEngineName = (value: string): value is EngineName =>
  (ENGINE_NAMES as readonly string[]).includes(value);

/** The catalog entry of `name`, or undefined when the engine is not registered. */
export function engineCatalogEntry(name: string): EngineCatalogEntry | undefined {
  return ENGINE_CATALOG.find((entry) => entry.name === name);
}

/**
 * Parses the platform's enabled engines (`SCAN_ENGINES`, a comma-separated list, default
 * `rspamd,attachment` from step 4.2). Throws on an empty list, a duplicate or a name that is not in the catalog, so a
 * misconfigured worker refuses to start instead of scanning with fewer engines.
 */
export function parseEnabledEngines(value: string): EngineName[] {
  const names = value
    .split(',')
    .map((name) => name.trim())
    .filter((name) => name.length > 0);
  if (names.length === 0) throw new Error('No scan engine is enabled');
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) throw new Error(`Scan engine listed twice: ${name}`);
    seen.add(name);
    if (!engineCatalogEntry(name)) throw new Error(`Scan engine not in the catalog: ${name}`);
  }
  return names as EngineName[];
}

/**
 * The required engines of a new round (S4): catalog entries enabled on the platform with
 * `requiredByDefault`, minus those the tenant disabled where `tenantMayDisable` allows it (a
 * tenant can never disable an engine whose entry forbids it). Catalog order, so the snapshot in
 * `email_scans.required_engines` is deterministic.
 */
export function requiredEngines(
  enabled: readonly string[],
  tenantDisabled: readonly string[] = [],
): EngineName[] {
  return ENGINE_CATALOG.filter(
    (entry) =>
      entry.requiredByDefault &&
      enabled.includes(entry.name) &&
      !(entry.tenantMayDisable && tenantDisabled.includes(entry.name)),
  ).map((entry) => entry.name);
}
