import {
  isProviderActionType,
  sha256Hex,
  type ProviderActionResult,
  type ProviderIdentityRef,
} from '@email-gateway/ato-detection';
import type {
  AtoProviderIntegration,
  AtoResponseAction,
  PrismaClient,
} from '@email-gateway/database';
import { domainOf, isReportStale, type IdpAdapter } from '@email-gateway/idp-adapters';
import type { Logger } from '@email-gateway/logger';
import type { IdpMetrics } from '../metrics/idp-metrics';
import { directoryDomainsOf, healthDetailOf, type IdpRegistry } from '../provider/idp-runtime';
import { MysqlActionStateStore } from '../provider/stores';
import { isTransientDbFailure } from '../provider/transient';
import { errorFields, InconsistentReadError } from '../shared/errors';
import { selectIntegration } from './integration-selector';

/** A provider result with the 8.5 details recorded on the action (`completeProviderAction`). */
export interface IdpCallOutcome {
  result: ProviderActionResult;
  detail: {
    resultCode?: string | null;
    providerStatus?: 'unconfirmed';
    integrationId?: bigint | null;
  };
}

/** Budget of one provider call (never inside a database transaction). */
export const IDP_ACTION_TIMEOUT_MS = 60_000;

const unsupported = (code: string, integrationId: bigint | null = null): IdpCallOutcome => ({
  result: { status: 'unsupported' },
  detail: { resultCode: code, integrationId },
});
const failed = (code: string, integrationId: bigint | null = null): IdpCallOutcome => ({
  result: { status: 'failed', code, retryable: false },
  detail: { integrationId },
});

/**
 * The adapter parameters of an action (D9.7): a `remove_forwarding_rule` stored without an item
 * or scope (an automated or recommendation-based request) acts on every external forwarding item
 * of the mailbox (`scope: 'all_external'`); other parameters pass through unchanged.
 */
export function providerParams(
  type: string,
  stored: unknown,
): Record<string, string | number | boolean> {
  const params =
    stored !== null && typeof stored === 'object' && !Array.isArray(stored)
      ? (stored as Record<string, string | number | boolean>)
      : {};
  if (
    type === 'remove_forwarding_rule' &&
    params.itemId === undefined &&
    params.scope === undefined
  ) {
    return { ...params, scope: 'all_external' };
  }
  return params;
}

/** Classifies an adapter exception as a provider result (never a success). */
function failure(error: unknown): ProviderActionResult {
  const e = error as { code?: unknown; retryable?: unknown; name?: unknown };
  if (typeof e?.code === 'string' && /^[a-z0-9_]{1,64}$/.test(e.code)) {
    const retryable =
      typeof e.retryable === 'boolean'
        ? e.retryable
        : ['throttled', 'provider_unavailable', 'rate_budget'].includes(e.code);
    return { status: 'failed', code: e.code, retryable };
  }
  if (e?.name === 'TimeoutError')
    return { status: 'failed', code: 'provider_timeout', retryable: true };
  return { status: 'failed', code: 'provider_error', retryable: true };
}

/**
 * Provider actions on the step 8.5 adapters (D9, ADR-0085) for the `respond` and `maintenance`
 * roles: integration selection (D9.2), the linked-domain guard (inv. 4), the integration status,
 * the effective capability (D6; a missing or stale probe is left to the adapter, which re-probes
 * before its first step), the identity (mapped row of the integration, else
 * `adapter.resolveIdentity(address)`, upserted with `integration_id`), then `execute`, `rollback`
 * or `confirm`. The adapter's `provider_state.resultCode` (`already_in_state`,
 * `restored_previous_state_noop`, `partial`, …) becomes the action's `result_code`.
 */
export class IdpActionExecutor {
  constructor(
    private readonly deps: {
      prisma: PrismaClient;
      registry: IdpRegistry;
      metrics: IdpMetrics | null;
      logger: Logger;
      now: () => Date;
      healthIntervalSeconds: number;
    },
  ) {}

  private adapter(integration: AtoProviderIntegration): IdpAdapter | null {
    try {
      return (this.deps.registry.adapterFor(integration) as IdpAdapter | undefined) ?? null;
    } catch (error) {
      this.deps.logger.warn(
        { integrationId: integration.id.toString(), ...errorFields(error) },
        'ato idp adapter unavailable',
      );
      return null;
    }
  }

  private async resultCodeOf(action: AtoResponseAction): Promise<string | null> {
    const state = await new MysqlActionStateStore(this.deps.prisma, action.organizationId).load(
      action.publicId,
    );
    return state?.resultCode ?? null;
  }

  /** `execute` or `rollback` from `ato.responses`. */
  async call(action: AtoResponseAction, phase: 'execute' | 'rollback'): Promise<IdpCallOutcome> {
    if (!isProviderActionType(action.actionType)) return unsupported('not_a_provider_action');
    const account = await this.deps.prisma.atoAccount.findUnique({
      where: { id: action.accountId },
      select: { organizationId: true, kind: true, address: true },
    });
    if (!account) return unsupported('not_a_mailbox_account');
    if (account.organizationId !== action.organizationId) {
      throw new InconsistentReadError('ato_account');
    }
    const selection = await selectIntegration(this.deps.prisma, action, account);
    if (!selection.ok) {
      return selection.outcome === 'unsupported'
        ? unsupported(selection.code, action.integrationId)
        : failed(selection.code, action.integrationId);
    }
    const integration = selection.integration;
    const adapter = this.adapter(integration);
    if (!adapter) return failed('adapter_unavailable', integration.id);
    const type = action.actionType;
    const report = healthDetailOf(integration.healthDetail);
    const fresh = !isReportStale(report, this.deps.now(), this.deps.healthIntervalSeconds);
    const caps = adapter.capabilities().actions[type];
    if (phase === 'execute' && fresh && caps?.supported !== true) {
      return unsupported('capability_unavailable', integration.id);
    }
    if (phase === 'rollback' && (!adapter.rollback || !action.providerReference)) {
      return unsupported('rollback_not_available', integration.id);
    }
    const signal = AbortSignal.timeout(IDP_ACTION_TIMEOUT_MS);
    let result: ProviderActionResult;
    try {
      const identity = await this.identity(adapter, integration, action, account.address!, signal);
      if (!identity) return unsupported('identity_not_found', integration.id);
      // Defence in depth (inv. 4): the resolved identity must be in a linked domain too (the
      // adapter checks the directory user's own address again before any write).
      const identityDomain = domainOf(identity.primaryEmail ?? identity.userPrincipalName);
      if (identityDomain !== null && !this.linked(integration, identityDomain)) {
        return failed('domain_not_linked', integration.id);
      }
      result =
        phase === 'execute'
          ? await adapter.execute(
              {
                actionPublicId: action.publicId,
                idempotencyKey: action.publicId,
                type,
                identity,
                params: providerParams(type, action.params),
              },
              signal,
            )
          : await adapter.rollback!(
              {
                actionPublicId: action.publicId,
                idempotencyKey: `${action.publicId}:rollback`,
                type,
                identity,
                providerReference: action.providerReference!,
              },
              signal,
            );
    } catch (error) {
      // A database outage (identity mapping, the adapter's state store) is not a provider
      // failure: rethrown, so the queue or the maintenance loop retries it without counting an
      // attempt (step AI-4 D14).
      if (isTransientDbFailure(error, 'adapter')) throw error;
      this.deps.logger.warn(
        { actionPublicId: action.publicId, ...errorFields(error) },
        'ato idp provider action failed',
      );
      result = failure(error);
    }
    const code = result.status === 'failed' ? null : await this.resultCodeOf(action);
    return {
      result,
      detail: {
        integrationId: integration.id,
        ...(code ? { resultCode: code } : {}),
        ...(result.status === 'unsupported' && !code
          ? { resultCode: 'capability_unavailable' }
          : {}),
      },
    };
  }

  private linked(integration: AtoProviderIntegration, domain: string): boolean {
    return directoryDomainsOf(integration.directoryDomains).includes(domain);
  }

  /**
   * The read-back confirmation of a `pending` action (maintenance role, D9.4). After
   * `ATO_IDP_CONFIRM_TIMEOUT_MINUTES` without confirmation the action ends `failed`,
   * `provider_status = 'unconfirmed'`, `result_code = 'confirmation_timeout'` (the effect may still
   * happen; never claimed).
   */
  async confirm(
    action: AtoResponseAction,
    timeoutMinutes: number,
    phase: 'execute' | 'rollback',
  ): Promise<IdpCallOutcome> {
    let since = action.executedAt ?? action.updatedAt;
    if (phase === 'rollback') {
      // The rollback's own start: its first log row (`ato_response_action_logs`, phase rollback).
      const first = await this.deps.prisma.atoResponseActionLog.findFirst({
        where: { organizationId: action.organizationId, actionId: action.id, phase: 'rollback' },
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true },
      });
      since = first?.createdAt ?? action.updatedAt;
    }
    if (this.deps.now().getTime() - since.getTime() > timeoutMinutes * 60_000) {
      this.deps.metrics?.action({
        provider: action.provider,
        action: action.actionType,
        outcome: 'timeout',
      });
      return {
        result: { status: 'failed', code: 'confirmation_timeout', retryable: false },
        detail: { providerStatus: 'unconfirmed', resultCode: 'confirmation_timeout' },
      };
    }
    if (action.integrationId === null || !action.providerReference) {
      return failed('integration_disabled');
    }
    const integration = await this.deps.prisma.atoProviderIntegration.findFirst({
      where: { id: action.integrationId, organizationId: action.organizationId },
    });
    if (!integration || integration.status === 'disabled') {
      return failed('integration_disabled', action.integrationId);
    }
    if (integration.organizationId !== action.organizationId) {
      throw new InconsistentReadError('ato_provider_integrations');
    }
    const adapter = this.adapter(integration);
    if (!adapter || !isProviderActionType(action.actionType)) {
      return failed('adapter_unavailable', integration.id);
    }
    let result: ProviderActionResult;
    try {
      result = await adapter.confirm(
        { type: action.actionType, providerReference: action.providerReference },
        AbortSignal.timeout(IDP_ACTION_TIMEOUT_MS),
      );
    } catch (error) {
      if (isTransientDbFailure(error, 'adapter')) throw error; // D14: retried by the loop
      result = failure(error);
    }
    const code = result.status === 'confirmed' ? await this.resultCodeOf(action) : null;
    return {
      result,
      detail: { integrationId: integration.id, ...(code ? { resultCode: code } : {}) },
    };
  }

  /** The identity of the account at the integration's directory (D9.2), persisted when resolved. */
  private async identity(
    adapter: IdpAdapter,
    integration: AtoProviderIntegration,
    action: AtoResponseAction,
    address: string,
    signal: AbortSignal,
  ): Promise<ProviderIdentityRef | null> {
    const mapped = await this.deps.prisma.atoAccountIdentity.findFirst({
      where: {
        organizationId: action.organizationId,
        accountId: action.accountId,
        provider: integration.provider,
        integrationId: integration.id,
      },
      orderBy: { lastSeenAt: 'desc' },
    });
    if (mapped) {
      if (mapped.organizationId !== action.organizationId) {
        throw new InconsistentReadError('ato_account_identities');
      }
      return {
        provider: adapter.kind,
        externalId: mapped.externalId,
        ...(mapped.userPrincipalName ? { userPrincipalName: mapped.userPrincipalName } : {}),
        primaryEmail: address,
      };
    }
    const resolved = await adapter.resolveIdentity(address, signal);
    if (!resolved) return null;
    const now = this.deps.now();
    const externalIdHash = sha256Hex(resolved.externalId);
    const domain = domainOf(resolved.primaryEmail ?? address);
    await this.deps.prisma.atoAccountIdentity.upsert({
      where: {
        organizationId_provider_externalIdHash: {
          organizationId: action.organizationId,
          provider: adapter.kind,
          externalIdHash,
        },
      },
      create: {
        organizationId: action.organizationId,
        accountId: action.accountId,
        provider: adapter.kind,
        externalId: resolved.externalId.slice(0, 128),
        externalIdHash,
        userPrincipalName: resolved.userPrincipalName?.slice(0, 320) ?? null,
        firstSeenAt: now,
        lastSeenAt: now,
        integrationId: integration.id,
        primaryEmailDomain: domain,
        directoryStatus: 'active',
        directoryStatusAt: now,
      },
      update: { lastSeenAt: now, integrationId: integration.id },
    });
    return resolved;
  }
}
