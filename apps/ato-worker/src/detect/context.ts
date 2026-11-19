import {
  classifyIp,
  hmacKey,
  resolveAtoSettings,
  type AtoStore,
  type AtoWindows,
  type ResolvedAtoSettings,
} from '@email-gateway/ato-detection';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { Enricher, IpEnrichment } from '../enrichment/enricher';
import type { AtoEventResult, AtoEventSource, AtoMetrics } from '../metrics/ato-metrics';
import type { OrgContextCache } from '../reads/org-context';
import type { AtoDb, Tx } from '../shared/db';
import type {
  AfterCommit,
  DetectionPipeline,
  DetectOutcome,
  DetectRequest,
  PreparedDetection,
} from './pipeline';

/** Settings of the platform IP campaign windows (D8). */
export interface CampaignConfig {
  windowMinutes: number;
  minAccounts: number;
  flagHours: number;
}

/** Everything the source handlers share. */
export interface DetectDeps {
  db: AtoDb;
  prisma: PrismaClient;
  orgs: OrgContextCache;
  store: AtoStore;
  windows: AtoWindows;
  enricher: Enricher;
  pipeline: DetectionPipeline;
  metrics: AtoMetrics | null;
  logger: Logger;
  now: () => Date;
  hmacKey: string;
  campaign: CampaignConfig;
  allowDocumentationRanges: boolean;
  /** Restricts processing to these organizations (integration suites); undefined = all. */
  organizationIds?: readonly bigint[];
}

/**
 * Runs a detection under a ledger row (`processOnce`, D3) in one writer transaction with
 * `ATO_TX_TIMEOUT_MS`, then the after-commit work; records duration and lag metrics.
 */
export async function runLedgered(
  deps: DetectDeps,
  input: {
    consumer: string;
    eventId: string;
    source: AtoEventSource;
    occurredAt: Date;
  },
  fn: (tx: Tx, after: AfterCommit[]) => Promise<AtoEventResult | void>,
): Promise<AtoEventResult> {
  const started = performance.now();
  const after: AfterCommit[] = [];
  const outcome = await deps.db.once(input.consumer, input.eventId, (tx) => fn(tx, after));
  deps.metrics?.dbSeconds.observe({ query: 'ledger_tx' }, (performance.now() - started) / 1000);
  if (outcome.status === 'duplicate') return 'duplicate';
  for (const task of after) {
    try {
      await task();
    } catch (error) {
      // After-commit work is best effort (novelty marks, last success, metrics).
      deps.logger.debug({ errName: (error as Error)?.name }, 'ato after-commit task failed');
    }
  }
  const seconds = (performance.now() - started) / 1000;
  deps.metrics?.detectionDuration.observe({ source: input.source }, seconds);
  deps.metrics?.detectionLag.observe(
    { source: input.source },
    Math.max(0, (deps.now().getTime() - input.occurredAt.getTime()) / 1000),
  );
  return outcome.result ?? 'processed';
}

/**
 * Platform-wide failure window of an IP (D8): every portal and SMTP authentication failure of
 * every organization (also without ATO) counts against `accountMember` (an HMAC, no tenant
 * identity). Only routable addresses count (a private or loopback address is a proxy hop or a
 * container network, never an attack source shared across tenants).
 */
export async function recordPlatformFailure(
  deps: DetectDeps,
  eventKey: string,
  ip: string,
  accountMember: string,
  at: Date,
): Promise<void> {
  if (!classifyIp(ip, { allowDocumentationRanges: deps.allowDocumentationRanges }).geolocatable) {
    return;
  }
  const member = hmacKey(deps.hmacKey, 'ip-account', accountMember).slice(0, 32);
  const result = await deps.windows.recordAuthFailure(eventKey, ip, member, at, deps.campaign);
  if (result.newlyFlagged) deps.metrics?.ipCampaignsFlagged.inc();
}

export const FAILURE_OUTCOMES = new Set([
  'failure',
  'locked',
  'mfa_failure',
  'rate_limited',
  'throttled',
  'blocked',
]);

/** Budget of the enrichment of one event (reputation providers have their own timeouts). */
export const ENRICH_TIMEOUT_MS = 5000;

/**
 * The organization's resolved settings read outside a transaction (enrichment needs the tenant's
 * reputation switches and networks before the writer transaction starts; network lookups never
 * run inside a transaction). Defaults when the row does not exist yet.
 */
export async function settingsOutside(
  deps: DetectDeps,
  organizationId: bigint,
): Promise<ResolvedAtoSettings> {
  const loaded = await deps.store.loadSettings(deps.prisma, organizationId);
  return loaded?.settings ?? resolveAtoSettings(null).settings;
}

/** Enriches client IPs outside the transaction (GeoIP, reputation, campaign flags, networks). */
export async function enrichOutside(
  deps: DetectDeps,
  organizationId: bigint,
  ips: readonly (string | null)[],
): Promise<Map<string, IpEnrichment>> {
  if (ips.every((ip) => ip === null)) return new Map();
  const settings = await settingsOutside(deps, organizationId);
  return deps.enricher.enrichIps(
    organizationId,
    ips,
    settings,
    AbortSignal.timeout(ENRICH_TIMEOUT_MS),
  );
}

/**
 * A ledgered detection of one or more accounts (D3): a duplicate is recognised before any work;
 * the unlocked phase (`prepare`) runs outside the transaction; the short ledger transaction
 * commits every account's rows in order (`onCommitted` adds after-commit work).
 */
export async function detectLedgered(
  deps: DetectDeps,
  ledger: { consumer: string; eventId: string; source: AtoEventSource; occurredAt: Date },
  requests: readonly DetectRequest[],
  onCommitted?: (outcomes: DetectOutcome[], after: AfterCommit[]) => void,
): Promise<AtoEventResult> {
  if (await deps.db.processed(ledger.consumer, ledger.eventId)) return 'duplicate';
  const prepared: PreparedDetection[] = [];
  const started = performance.now();
  for (const req of requests) prepared.push(await deps.pipeline.prepare(deps.prisma, req));
  deps.metrics?.dbSeconds.observe({ query: 'prepare' }, (performance.now() - started) / 1000);
  return runLedgered(deps, ledger, async (tx, after) => {
    const outcomes: DetectOutcome[] = [];
    for (const p of prepared) outcomes.push(await deps.pipeline.commit(tx, p, after));
    onCommitted?.(outcomes, after);
  });
}
