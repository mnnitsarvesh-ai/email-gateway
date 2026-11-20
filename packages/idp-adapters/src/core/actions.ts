/**
 * Shared helpers of provider-confirmed response actions (design note D9, ADR-0085), used by both
 * adapters: provider references, pre-state persistence, confirmation polling intervals and the
 * mapping of classified provider errors onto port results.
 *
 * - A provider reference is `<prefix>:<action>:<actionPublicId>` (≤ 128). `confirm(ref)` receives
 *   only the action type and the reference, so the reference must lead back to the action's
 *   stored state (`ActionStateStore` is keyed by the action public id; deviation WP1-7).
 * - Pre-state is captured once, before the first write, and reused by every retry: a retried
 *   write after a timeout never re-reads the (possibly already changed) state as "pre".
 */
import type { ProviderActionResult, ProviderActionType } from '../port/ato-port';
import { PROVIDER_ACTION_TYPES } from '../port/ato-port';
import {
  validateActionState,
  type ActionStateStore,
  type ProviderActionState,
} from '../port/state-ports';
import { ProviderCallError, toProviderCallError } from './errors';
import type { IdpMetricsSink } from './http';

/** Confirmation polling (D9.4): 10 s doubling to 5 min. */
export const CONFIRM_POLL_MIN_MS = 10_000;
export const CONFIRM_POLL_MAX_MS = 300_000;

/** Result codes the adapters store in `provider_state.resultCode` (8.4 `result_code`). */
export const ACTION_RESULT_CODES = [
  'already_in_state',
  'restored_previous_state_noop',
  'requires_exchange_admin',
  'rollback_not_available',
  'not_configured',
  'action_disabled',
  'capability_unavailable',
  'partial',
] as const;
export type ActionResultCode = (typeof ACTION_RESULT_CODES)[number];

/** Failure codes of action results that are not HTTP classifications (D9). */
export const ACTION_FAILURE_CODES = [
  'identity_not_found',
  'domain_not_linked',
  'on_premises_managed',
  'missing_privileged_role',
  'item_not_found',
  'invalid_request',
  'unknown_reference',
  'partial',
] as const;

const ACTION_ID = /^[A-Za-z0-9-]{1,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidActionPublicId(value: string): boolean {
  return ACTION_ID.test(value);
}

/** Graph `client-request-id` of an action's requests: the action public id when it is a UUID. */
export function actionRequestId(actionPublicId: string): string | undefined {
  return UUID.test(actionPublicId) ? actionPublicId.toLowerCase() : undefined;
}

export function providerReference(
  prefix: string,
  type: ProviderActionType,
  actionPublicId: string,
): string {
  return `${prefix}:${type}:${actionPublicId}`.slice(0, 128);
}

/** Parses a reference of this adapter; `null` for another prefix or a malformed value. */
export function parseProviderReference(
  prefix: string,
  reference: string,
): { type: ProviderActionType; actionPublicId: string } | null {
  if (reference.length > 128 || !reference.startsWith(`${prefix}:`)) return null;
  const rest = reference.slice(prefix.length + 1);
  const separator = rest.indexOf(':');
  if (separator <= 0) return null;
  const type = rest.slice(0, separator);
  const actionPublicId = rest.slice(separator + 1);
  if (!(PROVIDER_ACTION_TYPES as readonly string[]).includes(type)) return null;
  if (!isValidActionPublicId(actionPublicId)) return null;
  return { type: type as ProviderActionType, actionPublicId };
}

/** Poll interval after `checks` read-backs: 10 s, 20 s, 40 s, … capped at 5 min. */
export function confirmPollAfterMs(checks: number): number {
  const exponent = Math.max(0, Math.min(checks, 10));
  return Math.min(CONFIRM_POLL_MAX_MS, CONFIRM_POLL_MIN_MS * 2 ** exponent);
}

export type PreValues = ProviderActionState['pre'];

/** Persists action state through the port (validated, ≤ 2 KiB). */
export class ActionStateWriter {
  constructor(
    private readonly store: ActionStateStore,
    private readonly actionPublicId: string,
    private readonly clock: () => Date,
  ) {}

  load(): Promise<ProviderActionState | null> {
    return this.store.load(this.actionPublicId);
  }

  async save(
    state: Omit<ProviderActionState, 'v' | 'at'> & { at?: string },
  ): Promise<ProviderActionState> {
    const full = validateActionState({
      ...state,
      v: 1,
      at: state.at ?? this.clock().toISOString(),
    });
    await this.store.save(this.actionPublicId, full);
    return full;
  }
}

export function confirmed(reference: string, clock: () => Date): ProviderActionResult {
  return { status: 'confirmed', providerReference: reference, confirmedAt: clock().toISOString() };
}

export function pending(reference: string, checks: number): ProviderActionResult {
  return {
    status: 'pending',
    providerReference: reference,
    pollAfterMs: confirmPollAfterMs(checks),
  };
}

export function failed(code: string, retryable: boolean): ProviderActionResult {
  return { status: 'failed', code: code.slice(0, 64), retryable };
}

/** A coded action failure raised inside an action body (`identity_not_found`, …). */
export class ActionFailure extends Error {
  constructor(
    readonly code: string,
    readonly retryable = false,
  ) {
    super(code);
    this.name = 'ActionFailure';
  }
}

/** Maps anything thrown by an action onto a `failed` result (never throws, never leaks). */
export function failureResult(error: unknown): ProviderActionResult {
  if (error instanceof ActionFailure) return failed(error.code, error.retryable);
  const failure = toProviderCallError(error);
  return failed(failure.code, failure.retryable);
}

/** Runs an action body, recording the outcome metric; errors become `failed` results. */
export async function runAction(
  labels: { provider: string; action: ProviderActionType; metrics?: IdpMetricsSink },
  body: () => Promise<{ result: ProviderActionResult; resultCode?: string }>,
): Promise<ProviderActionResult> {
  let result: ProviderActionResult;
  let resultCode: string | undefined;
  try {
    ({ result, resultCode } = await body());
  } catch (error) {
    result = failureResult(error);
  }
  const outcome =
    result.status === 'confirmed' && resultCode === 'already_in_state'
      ? 'already_in_state'
      : result.status;
  labels.metrics?.action?.({ provider: labels.provider, action: labels.action, outcome });
  return result;
}

/**
 * 403 on a write whose permission the grant demonstrably holds means the app lacks a directory
 * role for this target (privileged user, D5): `missing_privileged_role`, never success.
 */
export function refinePermissionFailure(error: unknown, permissionObserved: boolean): unknown {
  if (
    error instanceof ProviderCallError &&
    (error.code === 'missing_permission' || error.code === 'forbidden') &&
    permissionObserved
  ) {
    return new ProviderCallError('missing_privileged_role', {
      status: error.status,
      retryable: false,
      providerCode: error.providerCode,
    });
  }
  return error;
}
