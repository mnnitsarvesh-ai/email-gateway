import { type HandleOutcome, NonRetryableError } from '@email-gateway/common';
import {
  adapterSupports,
  isProviderActionType,
  ProviderAdapterError,
  sha256Hex,
  type AtoStore,
  type IdentityProviderAdapter,
  type ProviderActionResult,
  type ProviderIdentityRef,
  type ProviderRegistry,
} from '@email-gateway/ato-detection';
import type { AtoResponseAction, PrismaClient } from '@email-gateway/database';
import { atoResponseRequestedV1, type EventEnvelope } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { AtoMetrics } from '../metrics/ato-metrics';
import { type AtoDb, LEDGERS } from '../shared/db';
import { errorFields, InconsistentReadError } from '../shared/errors';

/** Attempts of a retryable provider failure before the action is `failed` (queue maxAttempts). */
export const RESPONSE_MAX_ATTEMPTS = 10;
/**
 * A provider action with no progress for this long is settled `provider_retry_exhausted` by the
 * maintenance role: the `ato.responses` retry age (24 h, topology v13) plus an hour of margin. A
 * delivery that fails outside the provider result (a database error, an inconsistent read) uses a
 * queue attempt without counting on the action, so the queue may dead-letter it while the action
 * is still `approved`.
 */
export const RESPONSE_STALE_AFTER_MS = 25 * 3_600_000;
/** Budget of one provider call (never inside a database transaction). */
export const PROVIDER_CALL_TIMEOUT_MS = 30_000;

/** A retryable provider failure: the queue retries the delivery (hold, 5 s–60 s, 10 attempts). */
export class ProviderRetryError extends Error {
  constructor(readonly code: string) {
    super(`provider retry: ${code}`);
    this.name = 'ProviderRetryError';
  }
}

/**
 * The identity of an account at a provider (D15): a mapped `ato_account_identities` row, else the
 * adapter's resolution of the mailbox address (persisted for the next action).
 */
export async function providerIdentity(
  prisma: PrismaClient,
  adapter: IdentityProviderAdapter,
  action: Pick<AtoResponseAction, 'organizationId' | 'accountId'>,
  signal: AbortSignal,
): Promise<ProviderIdentityRef | null> {
  const mapped = await prisma.atoAccountIdentity.findFirst({
    where: {
      organizationId: action.organizationId,
      accountId: action.accountId,
      provider: adapter.kind,
    },
    orderBy: { lastSeenAt: 'desc' },
  });
  if (mapped && mapped.organizationId === action.organizationId) {
    return {
      provider: adapter.kind,
      externalId: mapped.externalId,
      ...(mapped.userPrincipalName ? { userPrincipalName: mapped.userPrincipalName } : {}),
    };
  }
  const account = await prisma.atoAccount.findUnique({
    where: { id: action.accountId },
    select: { organizationId: true, address: true },
  });
  if (!account || account.organizationId !== action.organizationId || !account.address) return null;
  const resolved = await adapter.resolveIdentity(account.address, signal);
  if (!resolved) return null;
  const now = new Date();
  await prisma.atoAccountIdentity.upsert({
    where: {
      organizationId_provider_externalIdHash: {
        organizationId: action.organizationId,
        provider: adapter.kind,
        externalIdHash: sha256Hex(resolved.externalId),
      },
    },
    create: {
      organizationId: action.organizationId,
      accountId: action.accountId,
      provider: adapter.kind,
      externalId: resolved.externalId.slice(0, 128),
      externalIdHash: sha256Hex(resolved.externalId),
      userPrincipalName: resolved.userPrincipalName?.slice(0, 320) ?? null,
      firstSeenAt: now,
      lastSeenAt: now,
    },
    update: { lastSeenAt: now },
  });
  return resolved;
}

/** Classifies an adapter exception as a provider result (never a success). */
export function failedResult(error: unknown): ProviderActionResult {
  if (error instanceof ProviderAdapterError) {
    return { status: 'failed', code: error.code.slice(0, 64), retryable: error.retryable };
  }
  if ((error as { name?: unknown })?.name === 'TimeoutError') {
    return { status: 'failed', code: 'provider_timeout', retryable: true };
  }
  return { status: 'failed', code: 'provider_error', retryable: true };
}

/**
 * `ato.responses` (respond role, D13, D15): executes a provider action (or its rollback) through
 * the `ProviderRegistry` with `idempotencyKey = action public id`, outside any transaction, then
 * records the result through `AtoStore.completeProviderAction` under the ledger
 * (`ato-worker.respond`). `confirmed` → `succeeded`; `pending` → `executing` (the maintenance role
 * polls `confirm`); a retryable failure is retried by the queue (attempts on the action) and ends
 * `failed` at the last attempt; no adapter, integration, identity or capability → `unsupported`
 * (never executed, never claimed).
 */
export class RespondConsumer {
  constructor(
    private readonly deps: {
      db: AtoDb;
      prisma: PrismaClient;
      store: AtoStore;
      registry: ProviderRegistry;
      metrics: AtoMetrics | null;
      logger: Logger;
      organizationIds?: readonly bigint[];
    },
  ) {}

  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    const parsed = atoResponseRequestedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const p = parsed.data;
    const orgId = BigInt(event.organizationId);
    if (this.deps.organizationIds !== undefined && !this.deps.organizationIds.includes(orgId)) {
      return 'handled';
    }
    const action = await this.deps.prisma.atoResponseAction.findUnique({
      where: { id: BigInt(p.actionId) },
    });
    if (!action) return 'handled';
    if (action.organizationId !== orgId || action.publicId !== p.actionPublicId) {
      throw new InconsistentReadError('ato_response_action');
    }
    const settled =
      p.phase === 'execute'
        ? action.status !== 'approved' && action.status !== 'executing'
        : action.status !== 'rollback_requested';
    // A redelivery of a settled action, or an `executing` one the maintenance role polls.
    if (settled || (p.phase === 'execute' && action.status === 'executing')) return 'duplicate';

    const started = performance.now();
    const result = await this.call(action, p.phase);
    const durationMs = performance.now() - started;
    const final =
      result.status !== 'failed' ||
      !result.retryable ||
      action.attempts + 1 >= RESPONSE_MAX_ATTEMPTS;
    this.deps.metrics?.providerOperations.inc({
      provider: action.provider.slice(0, 32),
      operation: p.phase === 'execute' ? 'execute' : 'rollback',
      outcome: result.status,
    });
    if (!final) {
      // Logged as retry_scheduled (attempts + 1) without a ledger row, then retried by the queue.
      await this.deps.db.transaction((tx) =>
        this.deps.store.completeProviderAction(tx, {
          organizationId: orgId,
          actionId: action.id,
          phase: p.phase,
          result,
          final: false,
          durationMs,
        }),
      );
      throw new ProviderRetryError(result.status === 'failed' ? result.code : 'retry');
    }
    const outcome = await this.deps.db.once(LEDGERS.respond, event.eventId, (tx) =>
      this.deps.store.completeProviderAction(tx, {
        organizationId: orgId,
        actionId: action.id,
        phase: p.phase,
        result,
        final: true,
        durationMs,
      }),
    );
    if (outcome.status === 'processed') {
      this.deps.metrics?.responses.inc({
        action: action.actionType,
        outcome: outcome.result.status,
      });
    }
    return outcome.status === 'duplicate' ? 'duplicate' : 'handled';
  };

  private async call(
    action: AtoResponseAction,
    phase: 'execute' | 'rollback',
  ): Promise<ProviderActionResult> {
    const adapter = this.deps.registry.get(action.provider);
    if (!adapter || !isProviderActionType(action.actionType)) return { status: 'unsupported' };
    const integration = await this.deps.prisma.atoProviderIntegration.findFirst({
      where: { organizationId: action.organizationId, provider: action.provider, status: 'active' },
      select: { id: true, organizationId: true },
    });
    if (!integration || integration.organizationId !== action.organizationId) {
      return { status: 'unsupported' };
    }
    if (!adapterSupports(adapter, action.actionType)) return { status: 'unsupported' };
    const signal = AbortSignal.timeout(PROVIDER_CALL_TIMEOUT_MS);
    try {
      const identity = await providerIdentity(this.deps.prisma, adapter, action, signal);
      if (!identity) return { status: 'unsupported' };
      if (phase === 'execute') {
        return await adapter.execute(
          {
            actionPublicId: action.publicId,
            idempotencyKey: action.publicId,
            type: action.actionType,
            identity,
            params: (action.params ?? {}) as Record<string, string | number | boolean>,
          },
          signal,
        );
      }
      if (!adapter.rollback || !action.providerReference) return { status: 'unsupported' };
      const declared = adapter.capabilities().actions[action.actionType]?.rollback === true;
      if (!declared) return { status: 'unsupported' };
      return await adapter.rollback(
        {
          actionPublicId: action.publicId,
          idempotencyKey: `${action.publicId}:rollback`,
          type: action.actionType,
          identity,
          providerReference: action.providerReference,
        },
        signal,
      );
    } catch (error) {
      this.deps.logger.warn(
        { actionPublicId: action.publicId, ...errorFields(error) },
        'ato provider action failed',
      );
      return failedResult(error);
    }
  }
}
