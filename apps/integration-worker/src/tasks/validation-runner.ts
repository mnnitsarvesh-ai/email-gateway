import { randomUUID } from 'node:crypto';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  checksForRun,
  type ProviderValidationKind,
  summarizeResults,
  validationOutcome,
  validationResultsSchema,
} from '@email-gateway/provider-integrations';
import { type CheckCode, checkResult, type CheckResult, type CheckRunner } from '../checks/checks';
import { type ConnectionView, loadConnection } from '../checks/context';
import type { IntegrationMetrics } from '../metrics/integration-metrics';
import { orgFilter, systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';

/** Lease of a running validation (D10: 120 s). */
export const VALIDATION_LEASE_MS = 120_000;
/** A run whose worker died this often is failed instead of retried. */
export const VALIDATION_MAX_ATTEMPTS = 3;
/** Upper bound of one run's checks (inside the lease). */
export const VALIDATION_DEADLINE_MS = 100_000;

type RunStatus = 'passed' | 'warning' | 'failed' | 'expired' | 'cancelled';

interface ClaimedRun {
  id: bigint;
  organizationId: bigint;
}

/** Results within `provider-validation/1` bounds (≤ 64 entries, ≤ 64 KiB). */
export function boundResults(results: readonly CheckResult[]): CheckResult[] {
  let out = results.slice(0, 64);
  while (out.length > 0 && !validationResultsSchema.safeParse(out).success) {
    out = out.slice(0, out.length - 1);
  }
  return out;
}

/**
 * D10 (tasks role): validation runs. `queued` runs (and `running` runs whose lease expired) are
 * claimed with `FOR UPDATE SKIP LOCKED` and a 120 s lease; every check of the run's kind
 * executes; when the run needs the outbound probe (kind `full`/`outbound`, outbound mode not
 * `off`), it waits as `awaiting_probe` with the other results stored, and completes when an
 * observation of its probe token exists (the smtp-adapter records it, I8) or expires (the
 * maintenance role). The probe token is created by the api with the run (it returns the address
 * once); the worker sees only its SHA-256. Completion writes the results, the summary, the
 * status (`validationOutcome`) and the audit row in one transaction. Re-running a claimed run is
 * idempotent: the results are recomputed and the row is written once.
 */
export class ValidationRunner {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: {
      checks: CheckRunner;
      metrics: IntegrationMetrics;
      logger: Logger;
      now: () => Date;
      probeTtlSeconds: number;
      organizationIds?: readonly bigint[];
    },
  ) {}

  async runOnce(limit: number, signal: AbortSignal): Promise<number> {
    const claimed = await this.claim(limit);
    for (const run of claimed) {
      if (signal.aborted) break;
      await this.execute(run, signal).catch((error: unknown) => {
        this.options.logger.warn(
          { runId: run.id.toString(), ...errorFields(error) },
          'validation run failed unexpectedly; retried after the lease',
        );
      });
    }
    return claimed.length;
  }

  async claim(limit: number): Promise<ClaimedRun[]> {
    const now = this.options.now();
    const until = new Date(now.getTime() + VALIDATION_LEASE_MS);
    return this.writer.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
        SELECT id, organization_id FROM provider_validation_runs
         WHERE (status = 'queued' OR (status = 'running' AND claimed_until < ${now}))
           ${orgFilter('organization_id', this.options.organizationIds)}
         ORDER BY created_at, id
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      const ids = rows.map((r) => BigInt(r.id));
      await tx.$executeRaw`
        UPDATE provider_validation_runs
           SET status = 'running', claimed_until = ${until}, attempts = attempts + 1,
               started_at = COALESCE(started_at, ${now}), updated_at = ${now}
         WHERE id IN (${Prisma.join(ids)})`;
      return rows.map((r) => ({ id: BigInt(r.id), organizationId: BigInt(r.organization_id) }));
    });
  }

  async execute(
    claimed: ClaimedRun,
    signal: AbortSignal,
  ): Promise<RunStatus | 'awaiting_probe' | null> {
    const run = await this.writer.providerValidationRun.findFirst({
      where: { id: claimed.id, organizationId: claimed.organizationId, status: 'running' },
      select: {
        id: true,
        publicId: true,
        connectionId: true,
        kind: true,
        attempts: true,
        probeTokenSha256: true,
        probeExpiresAt: true,
        createdAt: true,
      },
    });
    if (!run) return null;
    const connection = await loadConnection(this.writer, run.connectionId);
    if (
      !connection ||
      connection.organizationId !== claimed.organizationId ||
      connection.status === 'disabled'
    ) {
      return this.complete(claimed, run, connection, 'cancelled', []);
    }
    if (run.attempts > VALIDATION_MAX_ATTEMPTS) {
      return this.complete(claimed, run, connection, 'failed', [
        checkResult('credentials.token', '', 'error', { reason: 'attempts_exhausted' }),
      ]);
    }
    const specs = checksForRun(run.kind, connection.provider);
    const codes = specs
      .map((s) => s.code as string)
      .filter((c): c is CheckCode => c !== 'outbound.probe');
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(VALIDATION_DEADLINE_MS)]);
    const results = await this.options.checks.run(connection, codes, deadline);
    if (signal.aborted) return null;
    if (!specs.some((s) => s.code === 'outbound.probe')) {
      return this.finish(claimed, run, connection, results);
    }
    if (connection.outboundMode === 'off') {
      results.push(checkResult('outbound.probe', '', 'skipped', { reason: 'outbound_off' }));
      return this.finish(claimed, run, connection, results);
    }
    if (!run.probeTokenSha256) {
      results.push(checkResult('outbound.probe', '', 'fail', { reason: 'probe_not_requested' }));
      return this.finish(claimed, run, connection, results);
    }
    const observed = await this.probeResult(claimed, run);
    if (observed) return this.finish(claimed, run, connection, [...results, observed]);
    // Wait for the probe (interim results visible to the portal while it polls).
    const bounded = boundResults(results);
    await this.writer.providerValidationRun.updateMany({
      where: { id: run.id, organizationId: claimed.organizationId, status: 'running' },
      data: {
        status: 'awaiting_probe',
        claimedUntil: null,
        results: bounded as unknown as Prisma.InputJsonValue,
        summary: { ...summarizeResults(bounded) },
        probeExpiresAt:
          run.probeExpiresAt ??
          new Date(run.createdAt.getTime() + this.options.probeTtlSeconds * 1000),
      },
    });
    return 'awaiting_probe';
  }

  /**
   * `awaiting_probe` runs whose probe arrived: completes them (tasks role). Observations are
   * matched by token hash and connection (the adapter links them only while the run is
   * `awaiting_probe`; earlier ones are linked here).
   */
  async completeProbes(limit: number): Promise<number> {
    const rows = await this.writer.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
      SELECT r.id, r.organization_id FROM provider_validation_runs r
       WHERE r.status = 'awaiting_probe'
         AND EXISTS (SELECT 1 FROM provider_probe_observations o
                      WHERE o.token_sha256 = r.probe_token_sha256 AND o.connection_id = r.connection_id
                        AND (r.probe_expires_at IS NULL OR o.received_at <= r.probe_expires_at))
         ${orgFilter('r.organization_id', this.options.organizationIds)}
       ORDER BY r.id LIMIT ${limit}`;
    let done = 0;
    for (const row of rows) {
      const claimed = { id: BigInt(row.id), organizationId: BigInt(row.organization_id) };
      const run = await this.writer.providerValidationRun.findFirst({
        where: { id: claimed.id, organizationId: claimed.organizationId, status: 'awaiting_probe' },
        select: {
          id: true,
          publicId: true,
          connectionId: true,
          kind: true,
          results: true,
          probeTokenSha256: true,
          probeExpiresAt: true,
        },
      });
      if (!run) continue;
      const probe = await this.probeResult(claimed, run);
      if (!probe) continue;
      const connection = await loadConnection(this.writer, run.connectionId);
      const previous = Array.isArray(run.results) ? (run.results as unknown as CheckResult[]) : [];
      if (
        (await this.finish(claimed, run, connection, [...previous, probe], 'awaiting_probe')) !==
        null
      ) {
        done += 1;
      }
    }
    return done;
  }

  /** Runs whose probe address expired (maintenance role): `expired`, `outbound.probe` fails. */
  async expireProbes(limit: number): Promise<number> {
    const now = this.options.now();
    const rows = await this.writer.providerValidationRun.findMany({
      where: {
        status: 'awaiting_probe',
        probeExpiresAt: { lt: now },
        ...(this.options.organizationIds
          ? { organizationId: { in: [...this.options.organizationIds] } }
          : {}),
      },
      select: {
        id: true,
        organizationId: true,
        publicId: true,
        connectionId: true,
        kind: true,
        results: true,
      },
      take: limit,
      orderBy: { id: 'asc' },
    });
    let done = 0;
    for (const run of rows) {
      const claimed = { id: run.id, organizationId: run.organizationId };
      const connection = await loadConnection(this.writer, run.connectionId);
      const previous = Array.isArray(run.results) ? (run.results as unknown as CheckResult[]) : [];
      const results = [
        ...previous,
        checkResult('outbound.probe', '', 'fail', { reason: 'probe_expired' }),
      ];
      if (
        (await this.complete(claimed, run, connection, 'expired', results, 'awaiting_probe')) !==
        null
      ) {
        done += 1;
      }
    }
    return done;
  }

  private async probeResult(
    claimed: ClaimedRun,
    run: {
      id: bigint;
      connectionId: bigint;
      probeTokenSha256: string | null;
      probeExpiresAt: Date | null;
    },
  ): Promise<CheckResult | null> {
    if (!run.probeTokenSha256) return null;
    const observations = await this.writer.providerProbeObservation.findMany({
      where: {
        tokenSha256: run.probeTokenSha256,
        connectionId: run.connectionId,
        organizationId: claimed.organizationId,
        ...(run.probeExpiresAt ? { receivedAt: { lte: run.probeExpiresAt } } : {}),
      },
      orderBy: { receivedAt: 'desc' },
      take: 10,
    });
    if (observations.length === 0) return null;
    await this.writer.providerProbeObservation.updateMany({
      where: { id: { in: observations.map((o) => o.id) }, validationRunId: null },
      data: { validationRunId: run.id },
    });
    const chosen = observations.find((o) => o.proofResult === 'pass') ?? observations[0]!;
    return checkResult('outbound.probe', '', chosen.proofResult === 'pass' ? 'pass' : 'fail', {
      proofResult: chosen.proofResult,
      failureCode: chosen.failureCode,
      tenantHeader: chosen.tenantHeader,
      dkim: chosen.dkim,
      envelopeFromDomain: chosen.envelopeFromDomain,
      tlsProtocol: chosen.tlsProtocol,
      receivedAt: chosen.receivedAt.toISOString(),
      observations: observations.length,
    });
  }

  private async finish(
    claimed: ClaimedRun,
    run: { id: bigint; publicId: string; kind: ProviderValidationKind },
    connection: ConnectionView | null,
    results: CheckResult[],
    from: 'running' | 'awaiting_probe' = 'running',
  ): Promise<RunStatus | null> {
    const status: RunStatus = connection
      ? validationOutcome({
          kind: run.kind,
          provider: connection.provider,
          outboundMode: connection.outboundMode,
          results,
        })
      : 'cancelled';
    return this.complete(claimed, run, connection, status, results, from);
  }

  private async complete(
    claimed: ClaimedRun,
    run: { id: bigint; publicId: string; kind: ProviderValidationKind },
    connection: ConnectionView | null,
    status: RunStatus,
    results: CheckResult[],
    from: 'running' | 'awaiting_probe' = 'running',
  ): Promise<RunStatus | null> {
    const now = this.options.now();
    const bounded = boundResults(results);
    const summary = summarizeResults(bounded);
    const written = await this.writer.$transaction(async (tx) => {
      const updated = await tx.providerValidationRun.updateMany({
        where: { id: run.id, organizationId: claimed.organizationId, status: from },
        data: {
          status,
          results: bounded as unknown as Prisma.InputJsonValue,
          summary: { ...summary },
          claimedUntil: null,
          completedAt: now,
        },
      });
      if (updated.count !== 1) return false;
      if (connection) {
        await systemAudit(tx, {
          organizationId: claimed.organizationId,
          action: 'integration.validation_completed',
          resourceId: connection.publicId,
          correlationId: randomUUID(),
          metadata: {
            connectionId: connection.publicId,
            provider: connection.provider,
            runId: run.publicId,
            kind: run.kind,
            status,
            summary: { ...summary },
            failingChecks: [
              ...new Set(
                bounded
                  .filter((r) => r.status === 'fail' || r.status === 'error')
                  .map((r) => r.code),
              ),
            ].slice(0, 16),
          },
          at: now,
        });
      }
      return true;
    });
    if (!written) return null;
    this.options.metrics.validationRuns.inc({ kind: run.kind, result: status });
    return status;
  }
}
