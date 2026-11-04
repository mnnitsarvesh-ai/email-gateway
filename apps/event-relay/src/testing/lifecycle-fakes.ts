import { MetricsService } from '@email-gateway/common';
import type {
  MessageState,
  TransitionOutcome,
  TransitionRequest,
} from '@email-gateway/message-lifecycle';
import { LifecycleRelayMetrics } from '../lifecycle/lifecycle-metrics';
import type {
  CheckCandidatesQuery,
  ExpiryCandidatesQuery,
  LifecycleCandidate,
  LifecycleStore,
  StuckCountQuery,
} from '../lifecycle/lifecycle-store';

/** Unit-test fakes of the lifecycle jobs' collaborators (not used by production code). */

export function newLifecycleMetrics(): { metrics: LifecycleRelayMetrics; service: MetricsService } {
  const service = new MetricsService({ service: 'event-relay-test' });
  return { metrics: new LifecycleRelayMetrics(service), service };
}

export const NOW = new Date('2026-11-04T10:00:00.000Z');
const HOUR = 3_600_000;

export interface FakeMessage extends LifecycleCandidate {
  organizationId: bigint;
}

let nextId = 1000n;

export function fakeMessage(
  state: MessageState,
  ageHours: number,
  overrides: Partial<FakeMessage> = {},
): FakeMessage {
  const id = overrides.id ?? nextId++;
  return {
    id,
    receivedAt: new Date(NOW.getTime() - (ageHours + 1) * HOUR),
    organizationId: 42n,
    state,
    version: 3,
    statusChangedAt: new Date(NOW.getTime() - ageHours * HOUR),
    ...overrides,
  };
}

/** In-memory `email_messages` with the store's query semantics (clock `NOW`). */
export class FakeLifecycleStore implements LifecycleStore {
  readonly rows: FakeMessage[] = [];
  readonly queries: (ExpiryCandidatesQuery | CheckCandidatesQuery | StuckCountQuery)[] = [];
  fail: Error | undefined;

  add(...rows: FakeMessage[]): this {
    this.rows.push(...rows);
    return this;
  }

  expiryCandidates(query: ExpiryCandidatesQuery): Promise<LifecycleCandidate[]> {
    this.queries.push(query);
    if (this.fail) return Promise.reject(this.fail);
    const before = NOW.getTime() - query.olderThanSeconds * 1000;
    const since = NOW.getTime() - query.lookbackDays * 24 * HOUR;
    return Promise.resolve(
      this.rows
        .filter(
          (r) =>
            r.state === query.state &&
            r.statusChangedAt.getTime() < before &&
            r.statusChangedAt.getTime() >= since &&
            Number(r.id % BigInt(query.shard.count)) === query.shard.index,
        )
        .sort((a, b) => a.statusChangedAt.getTime() - b.statusChangedAt.getTime())
        .slice(0, query.limit)
        .map((r) => ({ ...r })),
    );
  }

  checkCandidates(query: CheckCandidatesQuery): Promise<LifecycleCandidate[]> {
    this.queries.push(query);
    if (this.fail) return Promise.reject(this.fail);
    const before = NOW.getTime() - query.olderThanSeconds * 1000;
    const since = NOW.getTime() - query.lookbackHours * HOUR;
    const after = query.after;
    return Promise.resolve(
      this.rows
        .filter(
          (r) =>
            r.state === query.state &&
            r.statusChangedAt.getTime() < before &&
            r.statusChangedAt.getTime() >= since &&
            (after === null ||
              r.statusChangedAt.getTime() > after.statusChangedAt.getTime() ||
              (r.statusChangedAt.getTime() === after.statusChangedAt.getTime() && r.id > after.id)),
        )
        .sort(
          (a, b) =>
            a.statusChangedAt.getTime() - b.statusChangedAt.getTime() || (a.id < b.id ? -1 : 1),
        )
        .slice(0, query.limit)
        .map((r) => ({ ...r })),
    );
  }

  countStuck(query: StuckCountQuery): Promise<number> {
    this.queries.push(query);
    if (this.fail) return Promise.reject(this.fail);
    const before = NOW.getTime() - query.olderThanSeconds * 1000;
    return Promise.resolve(
      Math.min(
        query.cap,
        this.rows.filter((r) => r.state === query.state && r.statusChangedAt.getTime() < before)
          .length,
      ),
    );
  }

  /**
   * The transition service's verdict on an expiry request against these rows: `applied` when
   * the version still matches, else `stale/version_mismatch`.
   */
  readonly transition = (request: TransitionRequest): Promise<TransitionOutcome> => {
    this.requests.push(request);
    if (this.transitionFail) return Promise.reject(this.transitionFail);
    const row = this.rows.find((r) => r.id === request.message.id);
    if (!row) return Promise.resolve({ result: 'not_found' });
    const snapshot = {
      state: row.state,
      version: row.version,
      round: 0,
      statusChangedAt: row.statusChangedAt,
      statusReason: null,
      direction: 'outbound' as const,
      emlObjectKey: 'org/42/eml/x.eml',
    };
    if (request.expectedVersion !== undefined && request.expectedVersion !== row.version) {
      return Promise.resolve({ result: 'stale', why: 'version_mismatch', snapshot });
    }
    const from = row.state;
    row.state = request.to;
    row.version += 1;
    return Promise.resolve({
      result: 'applied',
      from,
      to: request.to,
      version: row.version,
      round: 0,
      historyId: 1n,
      stateEventId: '0190f0a0-0000-7000-8000-000000000001',
      snapshot: { ...snapshot, state: request.to, version: row.version },
    });
  };

  readonly requests: TransitionRequest[] = [];
  transitionFail: Error | undefined;
}
