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
 * Every engine name the platform knows (4.1 registers `rspamd`, 4.2 `attachment`, 4.3 `url`;
 * 4.4–4.6 add the rest). `clamav` and `yara` were never registered or stored: they are components of the
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
  /**
   * Engines whose final results of the same round this engine reads (step 4.4 B2, ADR-0033).
   * Absent or empty: a stage-1 engine, triggered by `mail.message.parsed.v1` /
   * `mail.message.rescan_requested.v1`. Non-empty: a stage-2 engine, triggered by
   * `mail.message.scan_stage_ready.v1` once every dependency in the round's required set has its
   * final row. Depth 1 only: a dependency never has dependencies itself (`validateCatalog`).
   */
  readonly dependsOn?: readonly EngineName[];
  /**
   * Step 4.6 X10 (ADR-0040 decision 1): absent or `synchronous` — a round engine (in
   * `SCAN_ENGINES`, aggregated into the round verdict when required). `asynchronous` — the round
   * never waits for it and its finals are excluded from the round aggregation; it is never
   * required, has no dependencies, no engine depends on it, and it is enabled by its own switch
   * (`SANDBOX_ENABLED`), never through `SCAN_ENGINES`. `queue` then names where its work is
   * dispatched.
   */
  readonly mode?: 'synchronous' | 'asynchronous';
  readonly description: string;
}

/**
 * The registered engines (step 4.1: Rspamd; step 4.2: the attachment engine, A1; step 4.3: the URL
 * engine, U1; step 4.4: the phishing/BEC engine, B1, a stage-2 engine depending on `rspamd` and
 * `url`; step 4.5: the DLP engine, D1, a stage-1 engine without dependencies; step 4.6: the
 * sandbox engine, X10, asynchronous and never required).
 */
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
  Object.freeze({
    name: 'url',
    stage: 'url',
    queue: 'scan.url',
    requiredByDefault: true,
    tenantMayDisable: false,
    description:
      'URLs: extraction, normalization, reputation, lookalikes, redirect chains, rewriting (step 4.3)',
  } as const),
  Object.freeze({
    name: 'bec',
    stage: 'bec',
    queue: 'scan.bec',
    requiredByDefault: true,
    tenantMayDisable: false,
    dependsOn: Object.freeze(['rspamd', 'url'] as const),
    description:
      'Phishing and BEC: sender identity, impersonation, lookalikes, payment/urgency cues, credential links, communication history; optional AI layer (step 4.4)',
  } as const),
  Object.freeze({
    name: 'dlp',
    stage: 'dlp',
    queue: 'scan.dlp',
    requiredByDefault: true,
    tenantMayDisable: false,
    description:
      'Data loss prevention: card, bank, national id, passport, personal, confidential, source code, credential, financial and tenant patterns; attachment text extraction; outbound policy actions (step 4.5)',
  } as const),
  Object.freeze({
    name: 'sandbox',
    stage: 'sandbox',
    queue: 'scan.sandbox',
    requiredByDefault: false,
    tenantMayDisable: true,
    mode: 'asynchronous',
    description:
      'Sandbox: static analysis and (when an approved isolation backend exists) detonation of suspicious/unknown attachments; asynchronous, never required (step 4.6)',
  } as const),
]);

export const isEngineName = (value: string): value is EngineName =>
  (ENGINE_NAMES as readonly string[]).includes(value);

/** The catalog entry of `name`, or undefined when the engine is not registered. */
export function engineCatalogEntry(name: string): EngineCatalogEntry | undefined {
  return ENGINE_CATALOG.find((entry) => entry.name === name);
}

/** Whether `entry` is an asynchronous engine (step 4.6 X10): `mode: 'asynchronous'`. */
export function isAsynchronousEntry(entry: Pick<EngineCatalogEntry, 'mode'>): boolean {
  return entry.mode === 'asynchronous';
}

/**
 * Whether the engine `name` is an asynchronous engine of `catalog` (default `ENGINE_CATALOG`;
 * step 4.6 X10). False for an unknown name.
 */
export function isAsynchronousEngine(
  name: string,
  catalog: readonly EngineCatalogEntry[] = ENGINE_CATALOG,
): boolean {
  const entry = catalog.find((e) => e.name === name);
  return entry !== undefined && isAsynchronousEntry(entry);
}

/** Whether `entry` is a stage-2 engine (step 4.4 B2): it declares at least one dependency. */
export function isStage2Engine(entry: Pick<EngineCatalogEntry, 'dependsOn'>): boolean {
  return (entry.dependsOn?.length ?? 0) > 0;
}

/** Names of the stage-2 engines of `catalog` (default `ENGINE_CATALOG`), in catalog order. */
export function stage2Engines(
  catalog: readonly EngineCatalogEntry[] = ENGINE_CATALOG,
): EngineName[] {
  return catalog.filter(isStage2Engine).map((entry) => entry.name);
}

/**
 * Validates the engine dependencies of `catalog` (step 4.4 B2): every dependency is an engine of
 * the catalog, no engine depends on itself or lists a dependency twice, and the depth is 1 (a
 * dependency declares no dependencies itself, so a stage-2 engine is triggered by stage-1
 * engines only). Step 4.6 X10: an asynchronous engine is not required by default, declares no
 * dependencies, and no engine depends on it. Throws an `Error` naming the engine; returns
 * nothing for a valid catalog. The email-worker calls it at start and a unit test calls it on
 * `ENGINE_CATALOG`.
 */
export function validateCatalog(catalog: readonly EngineCatalogEntry[] = ENGINE_CATALOG): void {
  const byName = new Map<string, EngineCatalogEntry>();
  for (const entry of catalog) {
    if (byName.has(entry.name))
      throw new Error(`Engine listed twice in the catalog: ${entry.name}`);
    byName.set(entry.name, entry);
  }
  for (const entry of catalog) {
    if (isAsynchronousEntry(entry)) {
      if (entry.requiredByDefault) {
        throw new Error(`Asynchronous engine ${entry.name} cannot be required by default`);
      }
      if ((entry.dependsOn?.length ?? 0) > 0) {
        throw new Error(`Asynchronous engine ${entry.name} cannot declare dependencies`);
      }
    }
    const deps = entry.dependsOn ?? [];
    if (new Set(deps).size !== deps.length) {
      throw new Error(`Engine ${entry.name} lists a dependency twice`);
    }
    for (const dependency of deps) {
      if (dependency === entry.name) throw new Error(`Engine ${entry.name} depends on itself`);
      const target = byName.get(dependency);
      if (!target) {
        throw new Error(
          `Engine ${entry.name} depends on ${dependency}, which is not in the catalog`,
        );
      }
      if (isAsynchronousEntry(target)) {
        throw new Error(
          `Engine ${entry.name} depends on ${dependency}, which is an asynchronous engine`,
        );
      }
      if (isStage2Engine(target)) {
        throw new Error(
          `Engine ${entry.name} depends on ${dependency}, which has dependencies itself (depth > 1)`,
        );
      }
    }
  }
}

/**
 * Parses the platform's enabled engines (`SCAN_ENGINES`, a comma-separated list, default
 * `rspamd,attachment,url,bec,dlp` from step 4.5). Throws on an empty list, a duplicate, a name
 * that is not in the catalog or an asynchronous engine (step 4.6 X10: `SCAN_ENGINES` lists
 * synchronous round engines only; the sandbox is enabled by `SANDBOX_ENABLED`), so a
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
    const entry = engineCatalogEntry(name);
    if (!entry) throw new Error(`Scan engine not in the catalog: ${name}`);
    if (isAsynchronousEntry(entry)) {
      throw new Error(
        `Scan engine ${name} is asynchronous and cannot be listed in SCAN_ENGINES (it has its own switch)`,
      );
    }
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
