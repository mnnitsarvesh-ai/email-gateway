import type { AuthzRequirement } from './decorators';
import type { Principal } from './principal';

/**
 * The authorization predicate of the api (step 1.3 D9, step 6.1 D2), shared by the global
 * `PermissionsGuard` and the AI assistant's tool pre-filter (step AI-1 D5, ADR-0091): one
 * implementation, so the assistant never offers a tool the guard would refuse and never decides
 * differently. Pure: no I/O, no clock.
 *
 * Checks, in the guard's order: MFA enrollment restriction, `@UserOnly()`, `@RequireMfa()`, then
 * the `all` / `any` / `authenticated` requirement. The first failing check names the refusal.
 */

/** The route flags the guard reads next to the requirement. */
export interface AuthorizationFlags {
  /** `@UserOnly()`: API keys are refused. */
  userOnly: boolean;
  /** `@RequireMfa()`: the session must be MFA-authenticated. */
  requireMfa: boolean;
  /** `@AllowDuringMfaEnrollment()`: reachable before the user enrolled in a required MFA. */
  allowDuringMfaEnrollment: boolean;
}

export type AuthorizationRefusal =
  'forbidden' | 'mfa_required' | 'mfa_enrollment_required' | 'user_required';

export type AuthorizationDecision = { ok: true } | { ok: false; code: AuthorizationRefusal };

/** The guard's messages of each refusal (steps 1.2/1.3, coded since step 6.1 D2). */
export const AUTHORIZATION_MESSAGES: Readonly<Record<AuthorizationRefusal, string>> = {
  forbidden: 'Forbidden',
  mfa_required: 'MFA required',
  mfa_enrollment_required: 'MFA enrollment required',
  user_required: 'This operation requires a user',
};

const ALLOWED: AuthorizationDecision = Object.freeze({ ok: true });
const refuse = (code: AuthorizationRefusal): AuthorizationDecision => ({ ok: false, code });

/** Whether the principal holds the permissions of the requirement (`all` / `any` / any principal). */
export function holdsRequirement(
  permissions: ReadonlySet<string>,
  requirement: AuthzRequirement,
): boolean {
  if (requirement.mode === 'authenticated') return true;
  if (requirement.mode === 'all') return requirement.permissions.every((p) => permissions.has(p));
  return requirement.permissions.some((p) => permissions.has(p));
}

/** The full decision of `PermissionsGuard` for an authenticated principal on a protected route. */
export function satisfiesRequirement(
  principal: Principal,
  requirement: AuthzRequirement,
  flags: AuthorizationFlags,
): AuthorizationDecision {
  if (
    principal.kind === 'user' &&
    principal.mfaEnrollmentRequired &&
    !flags.allowDuringMfaEnrollment
  ) {
    return refuse('mfa_enrollment_required');
  }
  if (principal.kind === 'api_key' && flags.userOnly) return refuse('user_required');
  if (flags.requireMfa && !(principal.kind === 'user' && principal.mfaAuthenticated)) {
    return refuse('mfa_required');
  }
  return holdsRequirement(principal.permissions, requirement) ? ALLOWED : refuse('forbidden');
}
