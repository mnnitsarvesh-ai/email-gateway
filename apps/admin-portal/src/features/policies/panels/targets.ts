import type { RequestBody } from '@/lib/api/types';

/**
 * What a test or dry-run evaluates (design B7, B8): the saved draft or version
 * (`{ policyId, versionNo }`, replacing the policy's active version in the active set), an
 * unsaved new policy (`{ definition }`, added to the active set), the active policies, or the
 * platform default alone. The server evaluates; the portal only names the target.
 */
export type PolicyTarget = NonNullable<RequestBody<'PolicyToolsController_test_v1'>['target']>;
export type TargetId = 'version' | 'inline' | 'active' | 'platform';

export interface TargetOption {
  readonly id: TargetId;
  readonly label: string;
  readonly description: string;
  /** Builds the target when the user runs; may save the draft first (`null` = stop). */
  readonly resolve: () => Promise<PolicyTarget | null>;
  /** The target saves the edited draft first ("Save and test", "Save and dry run"). */
  readonly needsSave?: boolean;
  /** Trace refs `<policyId>#<versionNo>[/<ruleId>]` of the edited document (Show in editor). */
  readonly editorRefPrefix?: string;
}

/**
 * The policy id the api evaluates an inline `{ definition }` target as (documented on the
 * `target` of `POST /policies/test` and `POST /policies/dry-run`: version 1 of this id).
 */
export const INLINE_TARGET_POLICY_ID = '00000000-0000-7000-8000-000000000000';

export const refPrefixOf = (policyId: string, versionNo: number) => `${policyId}#${versionNo}`;

/** Whether a trace or rule ref belongs to the document with this prefix. */
export const refBelongsTo =
  (prefix: string) =>
  (ref: string): boolean =>
    ref === prefix || ref.startsWith(`${prefix}/`);

export const ACTIVE_TARGET: TargetOption = {
  id: 'active',
  label: 'Active policies',
  description: 'The organization’s active policies as they are now.',
  resolve: () => Promise.resolve('active'),
};

export const PLATFORM_TARGET: TargetOption = {
  id: 'platform',
  label: 'Platform default only',
  description: 'The platform default alone, without any tenant policy (your settings apply).',
  resolve: () => Promise.resolve('platform'),
};
