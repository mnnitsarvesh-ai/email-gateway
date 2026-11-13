import { operations } from '@/lib/api/operations.gen';
import type { PermissionRequirement } from '@/lib/api/operation-types';
import type { OperationId } from '@/lib/api/types';

/**
 * Permission evaluation mirroring the api's guards (`x-eg-permissions`, design P11): every
 * requirement must hold; `all` needs each permission, `any` at least one. Operations without
 * requirements are authenticated-only (or public). UI only: the api stays authoritative.
 */
export function satisfies(
  requirements: readonly PermissionRequirement[] | null,
  granted: readonly string[] | ReadonlySet<string>,
): boolean {
  if (!requirements || requirements.length === 0) return true;
  const set = granted instanceof Set ? granted : new Set(granted as readonly string[]);
  return requirements.every((requirement) =>
    requirement.mode === 'any'
      ? requirement.permissions.some((p) => set.has(p))
      : requirement.permissions.every((p) => set.has(p)),
  );
}

export function canPerform(
  operationId: OperationId,
  granted: readonly string[] | ReadonlySet<string>,
): boolean {
  return satisfies(operations[operationId].permissions, granted);
}

/** A gate is satisfied when the user may perform ANY of its operations. */
export function passesGate(
  gate: readonly OperationId[] | 'authenticated',
  granted: readonly string[] | ReadonlySet<string>,
): boolean {
  if (gate === 'authenticated') return true;
  return gate.some((operationId) => canPerform(operationId, granted));
}

/** Human-readable requirement, e.g. `report:read` or `organization:read or platform:organizations`. */
export function describeRequirement(operationId: OperationId): string[] {
  const requirements = operations[operationId].permissions;
  if (!requirements) return [];
  return requirements.map((r) => r.permissions.join(r.mode === 'any' ? ' or ' : ' and '));
}
