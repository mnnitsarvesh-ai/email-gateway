/**
 * In-memory doubles of the step 8.6 journaling repository for the e2e suite: journal intake
 * sources (with the stored address and header-token hashes, so rotation and reveal can be
 * checked against the derived values), daily counters, the facts of the rules (8.2 connections,
 * verified and linked domains, provider egress ranges) and the status counts. Nothing here is
 * used by production code.
 */
/* eslint-disable @typescript-eslint/no-this-alias -- the doubles close over the world's state */
import type { TestingModuleBuilder } from '@nestjs/testing';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { ApiModeStatusService } from '../../src/tenancy/api-mode-status.service';
import {
  type ConnectionRef,
  type CounterRow,
  JournalingRepository,
  type SourceCreate,
  type SourceRow,
  type SourceUpdate,
} from '../../src/modules/journaling/repositories/journaling.repository';

const copy = <T>(value: T): T => structuredClone(value);

/** A stored source: the api row plus the hash columns the api writes but never reads back. */
export interface StoredSource extends Omit<SourceRow, 'providerConnection'> {
  addressHash: string;
  headerTokenHash: string | null;
  previousAddressHash: string | null;
  previousHeaderTokenHash: string | null;
}

export class JournalingWorld {
  sources: StoredSource[] = [];
  counters: Array<CounterRow & { organizationId: bigint; sourceId: bigint }> = [];
  connections: Array<ConnectionRef & { organizationId: bigint }> = [];
  /** Verified domains per organization, and those linked to a connection. */
  domains: Array<{
    organizationId: bigint;
    name: string;
    verified: boolean;
    connectionId: bigint | null;
  }> = [];
  egressRanges: string[] = ['40.92.0.0/15', '52.100.0.0/14'];
  intents: Array<{ organizationId: bigint; status: string; createdAt: Date }> = [];
  /** Step API-1 D6: organizations where API mode is active (entitles intake without archiving). */
  apiModeActive = new Set<bigint>();
  private nextId = 9000n;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  reset(): void {
    this.sources = [];
    this.counters = [];
    this.connections = [];
    this.domains = [];
    this.egressRanges = ['40.92.0.0/15', '52.100.0.0/14'];
    this.intents = [];
    this.apiModeActive.clear();
  }

  addConnection(
    organizationId: bigint,
    patch: Partial<ConnectionRef> = {},
  ): ConnectionRef & { organizationId: bigint } {
    const row = {
      id: this.id(),
      organizationId,
      publicId: crypto.randomUUID(),
      displayName: 'Contoso tenant',
      provider: 'microsoft_365' as const,
      status: 'active' as const,
      activeTenantKey: 'microsoft_365:11111111-2222-3333-4444-555555555555',
      externalTenantId: '11111111-2222-3333-4444-555555555555',
      ...patch,
    };
    this.connections.push(row);
    return row;
  }

  private rowOf(s: StoredSource): SourceRow {
    const connection =
      s.providerConnectionId === null
        ? null
        : (this.connections.find((c) => c.id === s.providerConnectionId) ?? null);
    const {
      addressHash: _a,
      headerTokenHash: _h,
      previousAddressHash: _pa,
      previousHeaderTokenHash: _ph,
      ...row
    } = s;
    return copy<SourceRow>({
      ...row,
      providerConnection: connection === null ? null : { publicId: connection.publicId },
    });
  }

  double(): Partial<Record<keyof JournalingRepository, unknown>> {
    const w = this;
    const own = (scope: TenantScope) => scope.organizationId;
    const find = (scope: TenantScope, publicId: string) =>
      w.sources.find((s) => s.organizationId === own(scope) && s.publicId === publicId);
    return {
      list: (
        scope: TenantScope,
        page: {
          take: number;
          beforeId?: bigint;
          statuses?: string[];
          kinds?: string[];
          health?: string[];
        },
      ) =>
        Promise.resolve(
          w.sources
            .filter((s) => s.organizationId === own(scope))
            .filter((s) => page.beforeId === undefined || s.id < page.beforeId)
            .filter((s) => !page.statuses || page.statuses.includes(s.status))
            .filter((s) => !page.kinds || page.kinds.includes(s.kind))
            .filter((s) => !page.health || page.health.includes(s.healthStatus))
            .sort((a, b) => (a.id < b.id ? 1 : -1))
            .slice(0, page.take)
            .map((s) => w.rowOf(s)),
        ),
      byPublicId: (scope: TenantScope, publicId: string) => {
        const s = find(scope, publicId);
        return Promise.resolve(s ? w.rowOf(s) : null);
      },
      lock: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const s = find(scope, publicId);
        return Promise.resolve(s ? w.rowOf(s) : null);
      },
      countLive: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          w.sources.filter((s) => s.organizationId === own(scope) && s.status !== 'disabled')
            .length,
        ),
      nameTaken: (_tx: unknown, scope: TenantScope, name: string, exceptId?: bigint) =>
        Promise.resolve(
          w.sources.some(
            (s) => s.organizationId === own(scope) && s.displayName === name && s.id !== exceptId,
          ),
        ),
      create: (_tx: unknown, scope: TenantScope, data: SourceCreate) => {
        const now = new Date();
        w.sources.push({
          id: w.id(),
          publicId: data.publicId,
          organizationId: own(scope),
          kind: data.kind,
          displayName: data.displayName,
          status: 'pending_verification',
          providerConnectionId: data.providerConnectionId,
          networks: data.networks as never,
          requireTls: data.requireTls,
          clientCertFingerprints: data.clientCertFingerprints,
          maxMessageBytes: data.maxMessageBytes,
          silenceAlertMinutes: data.silenceAlertMinutes,
          addressVersion: 1,
          previousValidUntil: null,
          verifiedAt: null,
          lastAcceptedAt: null,
          lastRefusedAt: null,
          lastRefusalCode: null,
          healthStatus: 'unknown',
          healthChangedAt: null,
          attestations: null,
          disabledAt: null,
          rowVersion: 1,
          createdAt: now,
          updatedAt: now,
          addressHash: data.addressHash,
          headerTokenHash: data.headerTokenHash,
          previousAddressHash: null,
          previousHeaderTokenHash: null,
        });
        return Promise.resolve();
      },
      update: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        rowVersion: number,
        data: SourceUpdate,
      ) => {
        const s = w.sources.find((x) => x.organizationId === own(scope) && x.id === id);
        if (!s || s.rowVersion !== rowVersion) return Promise.resolve(false);
        const { disabledByUserId: _d, ...rest } = data;
        Object.assign(s, rest, { rowVersion: s.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(true);
      },
      counters: (scope: TenantScope, sourceId: bigint, fromDay: Date) =>
        Promise.resolve(
          copy(
            w.counters
              .filter(
                (c) =>
                  c.organizationId === own(scope) &&
                  c.sourceId === sourceId &&
                  c.day.getTime() >= fromDay.getTime(),
              )
              .sort((a, b) => b.day.getTime() - a.day.getTime()),
          ),
        ),
      connectionByPublicId: (scope: TenantScope, publicId: string) => {
        const c = w.connections.find(
          (x) => x.organizationId === own(scope) && x.publicId === publicId,
        );
        if (!c) return Promise.resolve(null);
        const { organizationId: _o, ...ref } = c;
        return Promise.resolve(copy(ref));
      },
      connectionById: (scope: TenantScope, id: bigint) => {
        const c = w.connections.find((x) => x.organizationId === own(scope) && x.id === id);
        if (!c) return Promise.resolve(null);
        const { organizationId: _o, ...ref } = c;
        return Promise.resolve(copy(ref));
      },
      verifiedDomainCount: (scope: TenantScope) =>
        Promise.resolve(
          w.domains.filter((d) => d.organizationId === own(scope) && d.verified).length,
        ),
      linkedVerifiedDomainCount: (scope: TenantScope, connectionId: bigint) =>
        Promise.resolve(
          w.domains.filter(
            (d) => d.organizationId === own(scope) && d.verified && d.connectionId === connectionId,
          ).length,
        ),
      verifiedDomainNames: (scope: TenantScope, connectionId: bigint | null) =>
        Promise.resolve(
          w.domains
            .filter(
              (d) =>
                d.organizationId === own(scope) &&
                d.verified &&
                (connectionId === null || d.connectionId === connectionId),
            )
            .map((d) => d.name),
        ),
      providerEgressRanges: () => Promise.resolve([...w.egressRanges]),
      intentCounts: (scope: TenantScope) => {
        const mine = w.intents.filter((i) => i.organizationId === own(scope));
        const byStatus: Record<string, number> = {};
        for (const i of mine) byStatus[i.status] = (byStatus[i.status] ?? 0) + 1;
        const pending = mine
          .filter((i) => i.status === 'pending')
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
        return Promise.resolve({ byStatus, oldestPendingAt: pending[0]?.createdAt ?? null });
      },
      sourceCounts: (scope: TenantScope) => {
        const byStatus: Record<string, number> = {};
        const byHealth: Record<string, number> = {};
        for (const s of w.sources.filter((x) => x.organizationId === own(scope))) {
          byStatus[s.status] = (byStatus[s.status] ?? 0) + 1;
          if (s.status !== 'disabled')
            byHealth[s.healthStatus] = (byHealth[s.healthStatus] ?? 0) + 1;
        }
        return Promise.resolve({ byStatus, byHealth });
      },
      dayTotals: (scope: TenantScope, day: Date) => {
        const rows = w.counters.filter(
          (c) => c.organizationId === own(scope) && c.day.getTime() === day.getTime(),
        );
        const sum = (k: keyof CounterRow) =>
          rows.reduce((n, r) => n + Number(r[k] as number | bigint), 0);
        return Promise.resolve({
          day,
          accepted: sum('accepted'),
          duplicates: sum('duplicates'),
          bytes: BigInt(sum('bytes')),
          refusedAddress: sum('refusedAddress'),
          refusedNetwork: sum('refusedNetwork'),
          refusedTls: sum('refusedTls'),
          refusedSize: sum('refusedSize'),
          refusedRate: sum('refusedRate'),
          refusedUnavailable: sum('refusedUnavailable'),
          droppedProof: sum('droppedProof'),
          unwrapFailed: sum('unwrapFailed'),
        });
      },
    };
  }
}

/** Overrides the journaling repository and the API-mode status with the world's doubles. */
export function overrideJournaling(
  builder: TestingModuleBuilder,
  world: JournalingWorld,
): TestingModuleBuilder {
  return builder
    .overrideProvider(JournalingRepository)
    .useValue(world.double())
    .overrideProvider(ApiModeStatusService)
    .useValue({
      isActive: (organizationId: bigint) =>
        Promise.resolve(world.apiModeActive.has(organizationId)),
    });
}
