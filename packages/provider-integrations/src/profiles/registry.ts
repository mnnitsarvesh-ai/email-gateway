import { AUTH_METHODS_BY_PROVIDER, INTEGRATION_PROVIDERS } from '../types';
import { isWritePermission, mailFlowDenyReason } from './deny-list';
import { PERMISSION_PURPOSES, type PermissionProfile } from './types';

/** Thrown at module load when a profile violates the registry rules (a programming error). */
export class PermissionProfileError extends Error {
  override readonly name = 'PermissionProfileError';
}

const KEY = /^[a-z0-9]+(?:\.[a-z0-9_]+)+$/;
const CONFIG_KEY = /^[A-Z][A-Z0-9_]{2,127}$/;

const registry: PermissionProfile[] = [];

/**
 * Every registered profile, in registration order (D6). The array grows only through
 * `registerPermissionProfiles` (array concatenation at module load: 8.2's mail-flow profiles,
 * then 8.5's `profiles/ato.ts`).
 */
export const PERMISSION_PROFILES: readonly PermissionProfile[] = registry;

/** The validation every profile passes before registration; returns the problems found. */
export function validatePermissionProfile(profile: PermissionProfile): string[] {
  const problems: string[] = [];
  if (!KEY.test(profile.key) || profile.key.length > 48) {
    problems.push('key must be a dotted lower-case name of at most 48 characters');
  }
  if (!Number.isInteger(profile.version) || profile.version < 1 || profile.version > 65_535) {
    problems.push('version must be an integer between 1 and 65535');
  }
  if (!INTEGRATION_PROVIDERS.includes(profile.provider)) problems.push('unknown provider');
  if (!PERMISSION_PURPOSES.includes(profile.purpose)) problems.push('unknown purpose');
  if (profile.permissions.length === 0) problems.push('permissions must not be empty');
  if (new Set(profile.permissions).size !== profile.permissions.length) {
    problems.push('permissions must be unique');
  }
  if (profile.permissions.some((p) => typeof p !== 'string' || p.length === 0 || p.length > 256)) {
    problems.push('every permission must be a non-empty string of at most 256 characters');
  }
  const allowed = AUTH_METHODS_BY_PROVIDER[profile.provider] ?? [];
  if (profile.authMethods.length === 0) problems.push('authMethods must not be empty');
  for (const method of profile.authMethods) {
    if (!allowed.includes(method))
      problems.push(`auth method ${method} is not valid for the provider`);
  }
  const keys = Object.values(profile.platformApp).filter((v): v is string => v !== undefined);
  if (keys.some((k) => !CONFIG_KEY.test(k))) {
    problems.push('platformApp must name configuration keys (UPPER_SNAKE_CASE), never values');
  }
  if (profile.purpose === 'mail_flow') {
    if (!profile.readOnly) problems.push('mail_flow profiles must be read-only (I3)');
    for (const permission of profile.permissions) {
      const reason = mailFlowDenyReason(profile.provider, permission);
      if (reason) problems.push(`denied for mail_flow: ${reason}`);
    }
  }
  if (profile.readOnly) {
    for (const permission of profile.permissions) {
      if (isWritePermission(profile.provider, permission)) {
        problems.push(`read-only profile declares the write permission ${permission}`);
      }
    }
  }
  if (!profile.title.trim() || !profile.description.trim()) {
    problems.push('title and description are required');
  }
  return problems;
}

/**
 * Registers profiles (D6). Refuses invalid profiles and duplicate keys; registering the very
 * same object twice is a no-op (module re-evaluation in tests).
 */
export function registerPermissionProfiles(profiles: readonly PermissionProfile[]): void {
  const pending: PermissionProfile[] = [];
  for (const profile of profiles) {
    const existing =
      registry.find((p) => p.key === profile.key) ?? pending.find((p) => p.key === profile.key);
    if (existing === profile) continue;
    if (existing)
      throw new PermissionProfileError(`permission profile ${profile.key} is already registered`);
    const problems = validatePermissionProfile(profile);
    if (problems.length > 0) {
      throw new PermissionProfileError(`permission profile ${profile.key}: ${problems.join('; ')}`);
    }
    pending.push(profile);
  }
  registry.push(...pending);
}

export function profileByKey(key: string): PermissionProfile | undefined {
  return registry.find((p) => p.key === key);
}

/** The profile or a `PermissionProfileError` (unknown keys are programming or data errors). */
export function requireProfile(key: string): PermissionProfile {
  const profile = profileByKey(key);
  if (!profile) throw new PermissionProfileError(`unknown permission profile ${key}`);
  return profile;
}

/** Profiles of one provider and, optionally, one purpose. */
export function profilesFor(
  provider: PermissionProfile['provider'],
  purpose?: PermissionProfile['purpose'],
): PermissionProfile[] {
  return registry.filter((p) => p.provider === provider && (!purpose || p.purpose === purpose));
}

/** The `<provider>.mail_flow` profile of a provider. */
export function mailFlowProfileFor(provider: PermissionProfile['provider']): PermissionProfile {
  const profile = registry.find((p) => p.provider === provider && p.purpose === 'mail_flow');
  if (!profile) throw new PermissionProfileError(`no mail_flow profile for ${provider}`);
  return profile;
}

/** Missing and excess permissions of a grant (reporting only; D3.4, check `permissions.granted`). */
export function comparePermissions(
  profile: PermissionProfile,
  observed: readonly string[],
): { missing: string[]; excess: string[] } {
  const norm = (p: string) => p.trim().toLowerCase();
  const want = new Set(profile.permissions.map(norm));
  const have = new Set(observed.map(norm));
  // Permissions of another resource never appear in the token (`notInToken`, step 8.5).
  const unobservable = new Set((profile.notInToken ?? []).map(norm));
  return {
    missing: profile.permissions.filter((p) => !have.has(norm(p)) && !unobservable.has(norm(p))),
    excess: [...new Set(observed.map((p) => p.trim()))]
      .filter((p) => p && !want.has(norm(p)))
      .sort(),
  };
}
