import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type {
  IntegrationProvider,
  Prisma,
  ProviderActorType,
  ProviderValidationKind,
  ProviderValidationStatus,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;
type Reader = PrismaReadService['client'];

const runSelect = {
  id: true,
  publicId: true,
  kind: true,
  status: true,
  requestedByType: true,
  requestedById: true,
  probeExpiresAt: true,
  summary: true,
  startedAt: true,
  completedAt: true,
  createdAt: true,
} satisfies Prisma.ProviderValidationRunSelect;

export type ValidationRunRow = Prisma.ProviderValidationRunGetPayload<{ select: typeof runSelect }>;

export interface ValidationRunDetailRow extends ValidationRunRow {
  results: Prisma.JsonValue | null;
  observations: Array<{
    receivedAt: Date;
    clientIp: string;
    tlsProtocol: string | null;
    envelopeFromDomain: string;
    headerFromDomain: string | null;
    tenantHeader: string;
    dkim: string;
    dkimDomains: Prisma.JsonValue;
    proofResult: string;
    failureCode: string | null;
  }>;
}

export interface HealthCheckRow {
  checkCode: string;
  subject: string;
  status: 'pass' | 'warn' | 'fail' | 'skipped' | 'error';
  severity: 'info' | 'warning' | 'critical';
  evidence: Prisma.JsonValue | null;
  firstFailedAt: Date | null;
  checkedAt: Date;
}

export interface HealthEventRow {
  fromStatus: 'unknown' | 'healthy' | 'warning' | 'critical';
  toStatus: 'unknown' | 'healthy' | 'warning' | 'critical';
  failingChecks: Prisma.JsonValue;
  createdAt: Date;
}

export interface RelayActivity {
  accepted: number;
  proofFailed: number;
  tempFailed: number;
  probes: number;
}

export interface EgressSetRow {
  provider: IntegrationProvider;
  version: number;
  publishedAt: Date | null;
  importedAt: Date;
  rangeCount: number;
}

/**
 * Validation runs and probe evidence, health checks and transitions, relay counters (tenant
 * rows, step 8.2 §3) and the active egress range sets (platform rows). The probe token is never
 * read back: only its SHA-256 is written (D10).
 */
@Injectable()
export class ProviderRunsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  insertRun(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      connectionId: bigint;
      kind: ProviderValidationKind;
      requestedByType: ProviderActorType;
      requestedById: string | null;
      probeTokenSha256: string | null;
      probeExpiresAt: Date | null;
    },
  ): Promise<ValidationRunRow> {
    return tx.providerValidationRun.create({
      data: { organizationId: scope.organizationId, status: 'queued', ...data },
      select: runSelect,
    });
  }

  listRuns(
    scope: TenantScope,
    connectionId: bigint,
    page: {
      take: number;
      beforeId?: bigint;
      kinds?: ProviderValidationKind[];
      statuses?: ProviderValidationStatus[];
    },
  ): Promise<Array<ValidationRunRow & { id: bigint }>> {
    return this.reader.client.providerValidationRun.findMany({
      where: tenantWhere(scope, {
        connectionId,
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.kinds && { kind: { in: page.kinds } }),
        ...(page.statuses && { status: { in: page.statuses } }),
      }),
      select: runSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  async findRun(
    scope: TenantScope,
    connectionId: bigint,
    publicId: string,
  ): Promise<ValidationRunDetailRow | null> {
    const row = await this.reader.client.providerValidationRun.findFirst({
      where: tenantWhere(scope, { connectionId, publicId }),
      select: {
        ...runSelect,
        results: true,
        probeObservations: {
          select: {
            receivedAt: true,
            clientIp: true,
            tlsProtocol: true,
            envelopeFromDomain: true,
            headerFromDomain: true,
            tenantHeader: true,
            dkim: true,
            dkimDomains: true,
            proofResult: true,
            failureCode: true,
          },
          orderBy: { id: 'asc' },
          take: 20,
        },
      },
    });
    if (!row) return null;
    const { probeObservations, ...run } = row;
    return { ...run, observations: probeObservations };
  }

  /** Status of the newest `full` run of a connection (null: none). */
  async latestFullRunStatus(
    scope: TenantScope,
    connectionId: bigint,
    client: Tx | Reader = this.reader.client,
  ): Promise<ProviderValidationStatus | null> {
    const row = await client.providerValidationRun.findFirst({
      where: tenantWhere(scope, { connectionId, kind: 'full' as const }),
      select: { status: true },
      orderBy: { id: 'desc' },
    });
    return row?.status ?? null;
  }

  /** Whether a probe of the connection passed the proof since `since` (activation, D13). */
  async probePassedSince(
    tx: Tx,
    scope: TenantScope,
    connectionId: bigint,
    since: Date,
  ): Promise<boolean> {
    const row = await tx.providerProbeObservation.findFirst({
      where: tenantWhere(scope, {
        connectionId,
        proofResult: 'pass' as const,
        receivedAt: { gte: since },
      }),
      select: { id: true },
    });
    return row !== null;
  }

  healthChecks(scope: TenantScope, connectionId: bigint): Promise<HealthCheckRow[]> {
    return this.reader.client.providerHealthCheck.findMany({
      where: tenantWhere(scope, { connectionId }),
      select: {
        checkCode: true,
        subject: true,
        status: true,
        severity: true,
        evidence: true,
        firstFailedAt: true,
        checkedAt: true,
      },
      orderBy: [{ checkCode: 'asc' }, { subject: 'asc' }],
      take: 500,
    });
  }

  healthEvents(scope: TenantScope, connectionId: bigint, take: number): Promise<HealthEventRow[]> {
    return this.reader.client.providerHealthEvent.findMany({
      where: tenantWhere(scope, { connectionId }),
      select: { fromStatus: true, toStatus: true, failingChecks: true, createdAt: true },
      orderBy: { id: 'desc' },
      take,
    });
  }

  /** Relay counters of the connection since `since` (hour buckets). */
  async relayActivity(
    scope: TenantScope,
    connectionId: bigint,
    since: Date,
  ): Promise<RelayActivity> {
    const rows = await this.reader.client.providerRelayCounter.findMany({
      where: tenantWhere(scope, { connectionId, hourStart: { gte: since } }),
      select: { accepted: true, proofFailed: true, tempFailed: true, probes: true },
    });
    return rows.reduce<RelayActivity>(
      (sum, r) => ({
        accepted: sum.accepted + r.accepted,
        proofFailed: sum.proofFailed + r.proofFailed,
        tempFailed: sum.tempFailed + r.tempFailed,
        probes: sum.probes + r.probes,
      }),
      { accepted: 0, proofFailed: 0, tempFailed: 0, probes: 0 },
    );
  }

  /** The active egress range set per provider (platform data, reader). */
  activeEgressSets(): Promise<EgressSetRow[]> {
    return this.reader.client.providerEgressRangeSet.findMany({
      where: { status: 'active' },
      select: {
        provider: true,
        version: true,
        publishedAt: true,
        importedAt: true,
        rangeCount: true,
      },
    });
  }
}
