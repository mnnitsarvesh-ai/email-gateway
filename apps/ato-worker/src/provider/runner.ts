import { Prisma } from '@email-gateway/database';
import {
  normalizeProviderEvent,
  PROVIDER_STREAMS,
  ProviderAdapterError,
  providerEventSchema,
  providerPageKey,
  sha256Hex,
  type AtoStore,
  type IdentityProviderAdapter,
  type ProviderEvent,
  type ProviderIngestPage,
  type ProviderRegistry,
  type ProviderStream,
} from '@email-gateway/ato-detection';
import type { AtoAccount } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { enrichOutside, runLedgered, type DetectDeps } from '../detect/context';
import { authObservation } from '../detect/login.handler';
import type { AfterCommit, DetectionPipeline } from '../detect/pipeline';
import type { IpEnrichment } from '../enrichment/enricher';
import type { AtoMetrics } from '../metrics/ato-metrics';
import { atoEnabled, type OrgContext } from '../reads/org-context';
import { big, LEDGERS, orgFilter, type Tx } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';

/** Integrations claimed per pass (each runs its streams' pages sequentially). */
export const PROVIDER_CLAIM_BATCH = 5;
const INGEST_TIMEOUT_MS = 30_000;
const MAX_BACKOFF_MS = 3_600_000;

interface Claimed {
  id: bigint;
  organizationId: bigint;
  provider: string;
  cursors: Record<string, string>;
  consecutiveFailures: number;
}

/**
 * The provider ingestion runner (`provider` role, D15). Claims due `ato_provider_integrations`
 * (`FOR UPDATE SKIP LOCKED`, `status = 'active'`, `next_poll_at <= now`; the claim leases the row
 * for one poll interval), fetches pages of every supported stream (≤ `ATO_PROVIDER_MAX_PAGES_PER_POLL`)
 * and processes each page in one transaction under `processOnce('ato-worker.provider',
 * providerPageKey(integration, stream, cursorBefore))`: identity mapping (`ato_account_identities`;
 * unknown identities resolved by primary e-mail to a `mailbox` account), detection through the same
 * pipeline, cursor update. Failures back off exponentially; `status = 'error'` after
 * `ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES`. Idle in 8.4 production (no adapters, no integrations).
 */
export class ProviderRunner {
  constructor(
    private readonly deps: DetectDeps & {
      pipelineRef: DetectionPipeline;
      registry: ProviderRegistry;
      store: AtoStore;
      metrics: AtoMetrics | null;
      logger: Logger;
      config: {
        pollIntervalSeconds: number;
        maxPagesPerPoll: number;
        maxConsecutiveFailures: number;
      };
    },
  ) {}

  /** One pass; true when more integrations may be due. */
  async runOnce(): Promise<boolean> {
    if (this.deps.registry.size === 0) return false;
    const claimed = await this.claim();
    for (const c of claimed) await this.poll(c);
    return claimed.length === PROVIDER_CLAIM_BATCH;
  }

  private async claim(): Promise<Claimed[]> {
    const now = this.deps.now();
    const lease = new Date(now.getTime() + this.deps.config.pollIntervalSeconds * 1000);
    return this.deps.db.transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
        SELECT id FROM ato_provider_integrations
        WHERE status = 'active' AND next_poll_at <= ${now}
          ${orgFilter('organization_id', this.deps.organizationIds)}
        ORDER BY next_poll_at, id
        LIMIT ${PROVIDER_CLAIM_BATCH}
        FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      const ids = rows.map((r) => big(r.id));
      await tx.atoProviderIntegration.updateMany({
        where: { id: { in: ids } },
        data: { nextPollAt: lease },
      });
      const full = await tx.atoProviderIntegration.findMany({ where: { id: { in: ids } } });
      return full.map((r) => ({
        id: r.id,
        organizationId: r.organizationId,
        provider: r.provider,
        cursors:
          r.cursors && typeof r.cursors === 'object' && !Array.isArray(r.cursors)
            ? Object.fromEntries(
                Object.entries(r.cursors as Record<string, unknown>).filter(
                  (e): e is [string, string] => typeof e[1] === 'string',
                ),
              )
            : {},
        consecutiveFailures: r.consecutiveFailures,
      }));
    });
  }

  private async poll(c: Claimed): Promise<void> {
    const adapter = this.deps.registry.get(c.provider);
    if (!adapter) {
      await this.failure(c, 'adapter_unavailable', undefined);
      return;
    }
    const org = await this.deps.orgs.get(c.organizationId);
    if (!atoEnabled(org)) return; // leased; polled again when the feature is back
    const started = performance.now();
    const streams = PROVIDER_STREAMS.filter((s) => adapter.capabilities().streams[s]?.supported);
    try {
      let retryAfterMs: number | undefined;
      outer: for (const stream of streams) {
        let cursor = c.cursors[stream] ?? null;
        for (let page = 0; page < this.deps.config.maxPagesPerPoll; page++) {
          const result = await this.ingest(adapter, stream, cursor);
          await this.processPage(org, c, adapter, stream, cursor, result);
          cursor = result.cursor;
          c.cursors[stream] = cursor;
          if (result.retryAfterMs !== undefined) {
            retryAfterMs = result.retryAfterMs;
            break outer;
          }
          if (!result.hasMore) break;
        }
      }
      const now = this.deps.now();
      await this.deps.prisma.atoProviderIntegration.updateMany({
        where: { id: c.id, organizationId: c.organizationId },
        data: {
          consecutiveFailures: 0,
          lastErrorCode: null,
          lastSuccessAt: now,
          ...(retryAfterMs !== undefined && {
            nextPollAt: new Date(now.getTime() + Math.max(retryAfterMs, 1000)),
          }),
        },
      });
    } catch (error) {
      const retryAfter = error instanceof ProviderAdapterError ? error.retryAfterMs : undefined;
      this.deps.logger.warn(
        { integrationId: c.id.toString(), provider: c.provider, ...errorFields(error) },
        'ato provider ingestion failed',
      );
      await this.failure(c, errorCode(error, 'provider_error'), retryAfter);
    } finally {
      this.deps.metrics?.providerPollSeconds.observe(
        { provider: c.provider.slice(0, 32) },
        (performance.now() - started) / 1000,
      );
    }
  }

  private async ingest(
    adapter: IdentityProviderAdapter,
    stream: ProviderStream,
    cursor: string | null,
  ): Promise<ProviderIngestPage> {
    try {
      const page = await adapter.ingest(stream, cursor, AbortSignal.timeout(INGEST_TIMEOUT_MS));
      this.deps.metrics?.providerOperations.inc({
        provider: adapter.kind,
        operation: 'ingest',
        outcome: 'ok',
      });
      return page;
    } catch (error) {
      this.deps.metrics?.providerOperations.inc({
        provider: adapter.kind,
        operation: 'ingest',
        outcome: error instanceof ProviderAdapterError && error.retryable ? 'retryable' : 'failed',
      });
      throw error;
    }
  }

  /** Backoff, `status = 'error'` after the configured consecutive failures (D15). */
  private async failure(c: Claimed, code: string, retryAfterMs: number | undefined): Promise<void> {
    const failures = c.consecutiveFailures + 1;
    const now = this.deps.now();
    const backoff = Math.min(
      MAX_BACKOFF_MS,
      this.deps.config.pollIntervalSeconds * 1000 * 2 ** Math.min(failures, 12),
    );
    await this.deps.prisma.atoProviderIntegration.updateMany({
      where: { id: c.id, organizationId: c.organizationId },
      data: {
        consecutiveFailures: failures,
        lastErrorCode: code.slice(0, 64),
        nextPollAt: new Date(now.getTime() + Math.max(backoff, retryAfterMs ?? 0)),
        ...(failures >= this.deps.config.maxConsecutiveFailures && { status: 'error' }),
      },
    });
    c.consecutiveFailures = failures;
  }

  private async processPage(
    org: OrgContext,
    c: Claimed,
    adapter: IdentityProviderAdapter,
    stream: ProviderStream,
    cursorBefore: string | null,
    page: ProviderIngestPage,
  ): Promise<void> {
    const valid: ProviderEvent[] = [];
    for (const raw of page.events) {
      const parsed = providerEventSchema.safeParse(raw);
      if (parsed.success && parsed.data.provider === adapter.kind) valid.push(parsed.data);
      else this.deps.metrics?.events.inc({ source: 'provider', result: 'error' });
    }
    const enriched = await enrichOutside(
      this.deps,
      org.id,
      valid.map((e) => (e.stream === 'sign_ins' ? (e.ip ?? null) : null)),
    );
    const result = await runLedgered(
      this.deps,
      {
        consumer: LEDGERS.provider,
        eventId: providerPageKey(c.id, stream, cursorBefore),
        source: 'provider',
        occurredAt: valid[0] ? new Date(valid[0].occurredAt) : this.deps.now(),
      },
      async (tx, after) => {
        for (const event of valid) {
          await this.processEvent(tx, after, org, event, enriched);
        }
        // The cursor moves with the page (same transaction as its effects).
        await tx.$executeRaw`
          UPDATE ato_provider_integrations
          SET cursors = JSON_SET(COALESCE(cursors, JSON_OBJECT()), ${`$.${stream}`}, ${page.cursor}),
              row_version = row_version + 1
          WHERE id = ${c.id} AND organization_id = ${org.id}`;
      },
    );
    this.deps.metrics?.events.inc({ source: 'provider', result }, Math.max(1, valid.length));
  }

  private async processEvent(
    tx: Tx,
    after: AfterCommit[],
    org: OrgContext,
    event: ProviderEvent,
    enriched: Map<string, IpEnrichment>,
  ): Promise<void> {
    const account = await this.mapIdentity(tx, org.id, event);
    if (!account || !account.address) {
      this.deps.metrics?.events.inc({ source: 'provider', result: 'unattributed' });
      return;
    }
    const occurredAt = new Date(event.occurredAt);
    const signIn = event.stream === 'sign_ins';
    const en = signIn && event.ip ? (enriched.get(event.ip) ?? null) : null;
    await this.deps.pipelineRef.run(
      tx,
      {
        org,
        subject: { kind: 'mailbox', address: account.address },
        observation: ({ baseline }) => {
          const base = normalizeProviderEvent(event, { knownDomains: baseline.externalDomains });
          if (base.type !== 'auth') return base;
          return {
            ...authObservation({
              key: base.key,
              source: 'idp_sign_in',
              channel: 'idp',
              outcome: base.outcome,
              failureCode: base.failureCode,
              occurredAt,
              enriched: en,
              device: base.device,
              breachListed: null,
            }),
          };
        },
        authEvent: signIn
          ? {
              source: 'idp_sign_in',
              channel: 'idp',
              outcome:
                event.outcome === 'success'
                  ? 'success'
                  : event.outcome === 'interrupted'
                    ? 'mfa_required'
                    : 'failure',
              failureCode: event.failureCode ?? null,
              occurredAt,
              ip: en?.ip ?? null,
              ipPrefix: en?.ipPrefix ?? null,
              geo: en?.geo ?? null,
              reputation: en?.reputation ?? null,
              device: null,
              mechanism: null,
              sourceRef: `prov:${event.stream}`.slice(0, 64),
              dedupeKey: sha256Hex(`prov|${event.provider}|${event.stream}|${event.eventId}`),
            }
          : null,
        activity: signIn
          ? () =>
              event.outcome === 'success'
                ? {
                    at: occurredAt,
                    authSuccess: 1,
                    ipPrefix: en?.ipPrefix
                      ? { p: en.ipPrefix, cc: en.geo.country, asn: en.geo.asn }
                      : null,
                  }
                : { at: occurredAt, authFailure: 1 }
          : null,
        success:
          signIn && event.outcome === 'success'
            ? { geo: en?.geo ?? null, trusted: en?.trustedNetwork ?? false }
            : null,
      },
      after,
    );
  }

  /** `ato_account_identities` (D15): mapped identity, else the primary e-mail's mailbox account. */
  private async mapIdentity(
    tx: Tx,
    organizationId: bigint,
    event: ProviderEvent,
  ): Promise<AtoAccount | null> {
    const hash = sha256Hex(event.identity.externalId);
    const now = this.deps.now();
    const mapped = await tx.atoAccountIdentity.findUnique({
      where: {
        organizationId_provider_externalIdHash: {
          organizationId,
          provider: event.provider,
          externalIdHash: hash,
        },
      },
    });
    if (mapped) {
      if (mapped.organizationId !== organizationId) return null;
      await tx.atoAccountIdentity.update({ where: { id: mapped.id }, data: { lastSeenAt: now } });
      const account = await tx.atoAccount.findUnique({ where: { id: mapped.accountId } });
      return account && account.organizationId === organizationId ? account : null;
    }
    const address = (event.identity.primaryEmail ?? event.identity.userPrincipalName ?? '')
      .trim()
      .toLowerCase();
    if (!address.includes('@')) return null;
    const account = await this.deps.store.ensureAccount(tx, {
      organizationId,
      subject: { kind: 'mailbox', address },
      at: now,
    });
    try {
      await tx.atoAccountIdentity.create({
        data: {
          organizationId,
          accountId: account.id,
          provider: event.provider,
          externalId: event.identity.externalId.slice(0, 128),
          externalIdHash: hash,
          userPrincipalName: event.identity.userPrincipalName?.slice(0, 320) ?? null,
          firstSeenAt: now,
          lastSeenAt: now,
        },
      });
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002')) {
        throw error;
      }
    }
    return account;
  }
}
