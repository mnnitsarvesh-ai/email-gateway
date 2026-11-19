/**
 * `FakeIdentityProviderAdapter` (test kit; step 8.4 D15): a scriptable local adapter that passes the
 * provider contract kit and lets the worker tests drive scripted events, failures, throttling and
 * pending confirmations without any real identity provider. Registered by the worker only with
 * `ATO_PROVIDER_FAKE_ENABLED=true` in local/ci (`ProviderRegistry.registerFake`).
 */
import { createHash } from 'node:crypto';
import {
  ProviderAdapterError,
  type IdentityProviderAdapter,
  type ProviderActionRequest,
  type ProviderActionResult,
  type ProviderActionType,
  type ProviderCapabilities,
  type ProviderEvent,
  type ProviderIdentityRef,
  type ProviderIngestPage,
  type ProviderStream,
} from '../provider';

export interface FakeProviderOptions {
  capabilities?: ProviderCapabilities;
  /** Events per page (default 2). */
  pageSize?: number;
  /** Confirmation polls before a `polling` action is confirmed (default 1). */
  pollsUntilConfirmed?: number;
  identities?: Record<string, ProviderIdentityRef>;
}

export const FAKE_PROVIDER_CAPABILITIES: ProviderCapabilities = {
  streams: {
    sign_ins: { supported: true, latencySeconds: 0 },
    risk_events: { supported: true },
    oauth_consents: { supported: true },
    mailbox_audit: { supported: true },
    forwarding_changes: { supported: true },
    delegation_changes: { supported: true },
    session_events: { supported: true },
  },
  actions: {
    revoke_sessions: { supported: true, rollback: false, confirmation: 'synchronous' },
    require_mfa: { supported: true, rollback: true, confirmation: 'polling' },
    remove_forwarding_rule: { supported: true, rollback: true, confirmation: 'synchronous' },
    require_password_reset: { supported: false, rollback: false, confirmation: 'synchronous' },
  },
};

type Failure = { code: string; retryable: boolean; retryAfterMs?: number };

export class FakeIdentityProviderAdapter implements IdentityProviderAdapter {
  readonly kind = 'fake' as const;
  readonly version = 'fake/1';
  private readonly caps: ProviderCapabilities;
  private readonly pageSize: number;
  private readonly pollsUntilConfirmed: number;
  private readonly events = new Map<ProviderStream, ProviderEvent[]>();
  private readonly failures: Partial<
    Record<'ingest' | 'execute' | 'confirm' | 'health' | 'rollback', Failure[]>
  > = {};
  private readonly throttles = new Map<ProviderStream, number>();
  private readonly executed = new Map<string, ProviderActionResult>();
  private readonly polls = new Map<string, number>();
  private readonly identities: Record<string, ProviderIdentityRef>;
  /** Number of real (non-idempotent-replay) effects per action type. */
  readonly effects: Partial<Record<ProviderActionType, number>> = {};
  readonly rollbacks: string[] = [];

  constructor(options: FakeProviderOptions = {}) {
    this.caps = options.capabilities ?? FAKE_PROVIDER_CAPABILITIES;
    this.pageSize = options.pageSize ?? 2;
    this.pollsUntilConfirmed = options.pollsUntilConfirmed ?? 1;
    this.identities = { ...(options.identities ?? {}) };
    const declaresRollback = Object.values(this.caps.actions).some((a) => a?.rollback);
    if (!declaresRollback) (this as { rollback?: unknown }).rollback = undefined;
  }

  capabilities(): ProviderCapabilities {
    return JSON.parse(JSON.stringify(this.caps)) as ProviderCapabilities;
  }

  /** Appends scripted events to a stream (served in order, `pageSize` per page). */
  script(stream: ProviderStream, events: ProviderEvent[]): this {
    this.events.set(stream, [...(this.events.get(stream) ?? []), ...events]);
    return this;
  }

  /** Makes the next call of an operation fail with a classified error. */
  failNext(op: 'ingest' | 'execute' | 'confirm' | 'health' | 'rollback', failure: Failure): this {
    (this.failures[op] ??= []).push(failure);
    return this;
  }

  /** The next ingest of a stream answers an empty page with `retryAfterMs` (throttling). */
  throttleNext(stream: ProviderStream, retryAfterMs: number): this {
    this.throttles.set(stream, retryAfterMs);
    return this;
  }

  addIdentity(address: string, identity: ProviderIdentityRef): this {
    this.identities[address.toLowerCase()] = identity;
    return this;
  }

  private takeFailure(op: keyof FakeIdentityProviderAdapter['failures']): void {
    const f = this.failures[op]?.shift();
    if (f) throw new ProviderAdapterError(f.code, f.retryable, f.retryAfterMs);
  }

  health(signal: AbortSignal): Promise<{ ok: boolean; code?: string }> {
    void signal;
    const f = this.failures.health?.shift();
    if (f) return Promise.resolve({ ok: false, code: f.code });
    return Promise.resolve({ ok: true });
  }

  ingest(
    stream: ProviderStream,
    cursor: string | null,
    signal: AbortSignal,
  ): Promise<ProviderIngestPage> {
    void signal;
    try {
      this.takeFailure('ingest');
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new Error('ingest failed'));
    }
    if (!this.caps.streams[stream]?.supported) {
      return Promise.reject(new ProviderAdapterError('stream_unsupported', false));
    }
    const offset = cursor === null ? 0 : Number(cursor);
    const throttle = this.throttles.get(stream);
    if (throttle !== undefined) {
      this.throttles.delete(stream);
      return Promise.resolve({
        events: [],
        cursor: String(offset),
        hasMore: true,
        retryAfterMs: throttle,
      });
    }
    const all = this.events.get(stream) ?? [];
    const page = all.slice(offset, offset + this.pageSize);
    const next = offset + page.length;
    return Promise.resolve({ events: page, cursor: String(next), hasMore: next < all.length });
  }

  resolveIdentity(address: string, signal: AbortSignal): Promise<ProviderIdentityRef | null> {
    void signal;
    return Promise.resolve(this.identities[address.toLowerCase()] ?? null);
  }

  private reference(key: string): string {
    return `fake-${createHash('sha256').update(key).digest('hex').slice(0, 24)}`;
  }

  execute(request: ProviderActionRequest, signal: AbortSignal): Promise<ProviderActionResult> {
    void signal;
    const known = this.executed.get(request.idempotencyKey);
    if (known) return Promise.resolve(known);
    const cap = this.caps.actions[request.type];
    if (!cap?.supported) return Promise.resolve({ status: 'unsupported' });
    const f = this.failures.execute?.shift();
    if (f) return Promise.resolve({ status: 'failed', code: f.code, retryable: f.retryable });
    this.effects[request.type] = (this.effects[request.type] ?? 0) + 1;
    const providerReference = this.reference(request.idempotencyKey);
    const result: ProviderActionResult =
      cap.confirmation === 'polling'
        ? { status: 'pending', providerReference, pollAfterMs: 1000 }
        : { status: 'confirmed', providerReference, confirmedAt: new Date().toISOString() };
    this.executed.set(request.idempotencyKey, result);
    return Promise.resolve(result);
  }

  confirm(
    ref: { type: ProviderActionType; providerReference: string },
    signal: AbortSignal,
  ): Promise<ProviderActionResult> {
    void signal;
    if (!this.caps.actions[ref.type]?.supported) return Promise.resolve({ status: 'unsupported' });
    const f = this.failures.confirm?.shift();
    if (f) return Promise.resolve({ status: 'failed', code: f.code, retryable: f.retryable });
    const n = (this.polls.get(ref.providerReference) ?? 0) + 1;
    this.polls.set(ref.providerReference, n);
    if (n < this.pollsUntilConfirmed) {
      return Promise.resolve({
        status: 'pending',
        providerReference: ref.providerReference,
        pollAfterMs: 1000,
      });
    }
    return Promise.resolve({
      status: 'confirmed',
      providerReference: ref.providerReference,
      confirmedAt: new Date().toISOString(),
    });
  }

  rollback?(
    request: Omit<ProviderActionRequest, 'params'> & { providerReference: string },
    signal: AbortSignal,
  ): Promise<ProviderActionResult> {
    void signal;
    if (!this.caps.actions[request.type]?.rollback)
      return Promise.resolve({ status: 'unsupported' });
    const f = this.failures.rollback?.shift();
    if (f) return Promise.resolve({ status: 'failed', code: f.code, retryable: f.retryable });
    if (!this.rollbacks.includes(request.idempotencyKey))
      this.rollbacks.push(request.idempotencyKey);
    return Promise.resolve({
      status: 'confirmed',
      providerReference: `${request.providerReference}-rb`,
      confirmedAt: new Date().toISOString(),
    });
  }
}
