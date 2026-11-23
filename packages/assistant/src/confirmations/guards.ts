import { valueAtPath } from './digest';
import type { ConfirmationSpec } from './specs';

/**
 * Proposal guards (step AI-3 D3, ADR-0093 amendment AI-3 (j); invariant I12 "no self-service of
 * authority through chat"): server-side refusals of a write proposal that depend on who the
 * target is or what the change touches. They only add refusals: the api's own no-escalation
 * rules stay the authority (I13). The executor evaluates the `before_read` guards right after the
 * schema check (no loopback call at all when one refuses: decision `denied_guard`); the proposer
 * evaluates the `after_read` guards on the precondition target; the confirm route evaluates both
 * again (refusal `403 assistant_action_not_allowed`).
 *
 * Messages are fixed server-authored English and never contain an argument value.
 */

export const GUARD_MESSAGES = {
  self: 'Changes to your own account, roles, status, MFA or sessions are not available in chat. Ask another administrator, or use your account pages in the portal.',
  assistant_feature:
    'The assistant cannot turn itself on or off for an organization. Use the Organizations page in the portal.',
  assistant_configure:
    'The assistant cannot change who may configure it. Change roles that grant assistant:configure in the portal.',
} as const;
export type GuardMessageKey = keyof typeof GUARD_MESSAGES;

export type ProposalGuard =
  /** The argument (a user public id) must not be the caller (case-insensitive UUID compare). */
  | { kind: 'not_self_user'; arg: string }
  /** The argument must not take one of these values (case-insensitive compare). */
  | { kind: 'deny_values'; arg: string; values: readonly string[]; message: GuardMessageKey }
  /**
   * No permission of `permissions` may be added or removed: the new set is the argument, the old
   * set the precondition target's `beforeField` (no `beforeField`: the old set is empty, e.g. a
   * role being created). With `beforeField` it is an `after_read` guard.
   */
  | {
      kind: 'deny_permission_change';
      arg: 'body.permissions';
      beforeField?: 'permissions';
      permissions: readonly string[];
      message: GuardMessageKey;
    };

export type GuardKind = ProposalGuard['kind'];

export interface GuardInput {
  /** The final arguments (validated; refs resolved; CAS placeholder or injected value). */
  args: Readonly<Record<string, unknown>>;
  /** The caller (the confirming principal at confirm time). */
  principalUserPublicId: string;
  /** The raw precondition body, or the selected item (`targetOf`); null before the read. */
  read: unknown;
}

export interface GuardRefusal {
  guard: GuardKind;
  message: string;
}

export type GuardPhase = 'before_read' | 'after_read';

/** The phase a guard is evaluated in. */
export function guardPhase(guard: ProposalGuard): GuardPhase {
  return guard.kind === 'deny_permission_change' && guard.beforeField !== undefined
    ? 'after_read'
    : 'before_read';
}

const normalized = (value: unknown): string | null =>
  typeof value === 'string' ? value.trim().toLowerCase() : null;

/** The strings of an array value (`null` when the value is not an array of strings). */
function stringSet(value: unknown): Set<string> | null {
  if (!Array.isArray(value)) return null;
  const items: unknown[] = value;
  return items.every((item): item is string => typeof item === 'string') ? new Set(items) : null;
}

function refuses(guard: ProposalGuard, input: GuardInput): boolean {
  switch (guard.kind) {
    case 'not_self_user': {
      const target = normalized(valueAtPath(input.args, guard.arg));
      const self = normalized(input.principalUserPublicId);
      return target !== null && self !== null && target.length > 0 && target === self;
    }
    case 'deny_values': {
      const value = normalized(valueAtPath(input.args, guard.arg));
      return value !== null && guard.values.some((denied) => denied.toLowerCase() === value);
    }
    case 'deny_permission_change': {
      let before = new Set<string>();
      if (guard.beforeField !== undefined) {
        // Fail closed: an after-read guard without a readable old set refuses.
        const read = stringSet(valueAtPath(input.read, guard.beforeField));
        if (read === null) return true;
        before = read;
      }
      const raw = valueAtPath(input.args, guard.arg);
      // An omitted permission list changes nothing; a malformed one is the schema check's job,
      // but is treated as touching every guarded permission (fail closed).
      const after = raw === undefined ? before : stringSet(raw);
      if (after === null) return true;
      return guard.permissions.some(
        (permission) => before.has(permission) !== after.has(permission),
      );
    }
  }
}

/**
 * The first refusal of the spec's guards of the given phase, or null. `before_read` evaluates
 * `not_self_user`, `deny_values` and `deny_permission_change` without `beforeField` (no read
 * needed); `after_read` evaluates `deny_permission_change` with `beforeField` on `input.read`.
 */
export function guardRefusal(
  spec: Pick<ConfirmationSpec, 'guards'>,
  input: GuardInput,
  phase: GuardPhase,
): GuardRefusal | null {
  for (const guard of spec.guards ?? []) {
    if (guardPhase(guard) !== phase) continue;
    if (!refuses(guard, input)) continue;
    return { guard: guard.kind, message: GUARD_MESSAGES[guardMessageKey(guard)] };
  }
  return null;
}

/** The message key of a guard (`not_self_user` always refuses with `self`). */
export function guardMessageKey(guard: ProposalGuard): GuardMessageKey {
  return guard.kind === 'not_self_user' ? 'self' : guard.message;
}

/**
 * The refusal message of a stored `denied_guard` execution (step AI-3 D12): the execution row
 * keeps the decision, not the message, so the api derives it from the spec of the operation.
 * This is exact because every spec's guards share one message key (a registry consistency
 * rule); null when the spec has no guards or (never, by that rule) mixes keys.
 */
export function guardMessageOf(spec: Pick<ConfirmationSpec, 'guards'> | undefined): string | null {
  const keys = new Set((spec?.guards ?? []).map(guardMessageKey));
  const [key] = keys;
  return keys.size === 1 && key !== undefined ? GUARD_MESSAGES[key] : null;
}

/** The argument paths a guard reads (registry consistency: each must exist in the write's schema). */
export function guardArgumentPaths(guard: ProposalGuard): string[] {
  return [guard.arg];
}

/** Short matrix note of a guard (`guard: not self`). */
export function guardNote(guard: ProposalGuard): string {
  switch (guard.kind) {
    case 'not_self_user':
      return 'guard: not self';
    case 'deny_values':
      return `guard: ${guard.arg} ≠ ${guard.values.join('/')}`;
    case 'deny_permission_change':
      return `guard: no change of ${guard.permissions.join('/')}`;
  }
}
