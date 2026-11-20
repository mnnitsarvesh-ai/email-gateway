/**
 * State ports of the adapters (design note §5.2). WP4 implements them over Redis
 * (`RateBudget`) and MySQL (`ato_provider_mailbox_items`, `ato_response_actions.provider_state`);
 * the in-memory implementations in `src/testing/in-memory-stores.ts` back the library tests.
 */
import { z } from 'zod';
import type { ProviderIdentityRef } from './ato-port';

/** Rate-budget families (D7.5): one budget per integration and family. */
export const API_FAMILIES = [
  'graph',
  'o365',
  'google_reports',
  'google_directory',
  'gmail',
] as const;
export type ApiFamily = (typeof API_FAMILIES)[number];

export interface RateBudget {
  take(integrationId: string, family: ApiFamily, signal: AbortSignal): Promise<'ok' | 'exhausted'>;
}

export const MAILBOX_ITEM_KINDS = [
  'forwarding',
  'inbox_rule',
  'delegate',
  'mailbox_permission',
  'send_as',
] as const;
export type MailboxItemKind = (typeof MAILBOX_ITEM_KINDS)[number];

/** The change a row's `emitted_seq` page emitted (deviation WP1-3: column `last_change`). */
export type MailboxItemChange = 'added' | 'changed' | 'removed';

export interface MailboxItemRow {
  publicId: string;
  /** SHA-256(provider|externalId), `identity_external_id_hash`. */
  identityHash: string;
  kind: MailboxItemKind;
  itemHash: string;
  providerItemRef: string | null;
  targetDomain: string | null;
  traits: readonly string[];
  enabled: boolean | null;
  state: 'present' | 'removed';
  source: 'snapshot' | 'audit';
  firstSeenAt: string;
  lastSeenAt: string;
  removedAt: string | null;
  lastChange: MailboxItemChange;
  emittedSeq: bigint;
}

export interface MailboxItemWrite {
  kind: MailboxItemKind;
  itemHash: string;
  providerItemRef: string | null;
  targetDomain: string | null;
  traits: readonly string[];
  enabled: boolean | null;
  state: 'present' | 'removed';
  source: 'snapshot' | 'audit';
  firstSeenAt: string;
  lastSeenAt: string;
  removedAt: string | null;
  /**
   * The change this write records. `null` = unchanged (only `last_seen_at` moves; `emitted_seq`
   * and `last_change` keep their values). Non-null: `last_change` and `emitted_seq` are set.
   */
  change: MailboxItemChange | null;
}

export interface MailboxStateStore {
  /** Present items and items removed within 30 days of one identity. */
  load(integrationId: string, identityHash: string): Promise<MailboxItemRow[]>;
  write(
    integrationId: string,
    identity: ProviderIdentityRef,
    items: MailboxItemWrite[],
    emittedSeq: bigint,
  ): Promise<void>;
  /** Identities with `mailbox_refresh_requested_at` set, oldest request first. */
  priorityIdentities(integrationId: string, limit: number): Promise<ProviderIdentityRef[]>;
  clearPriority(integrationId: string, identityHashes: string[]): Promise<void>;
  itemByPublicId(integrationId: string, publicId: string): Promise<MailboxItemRow | null>;
}

/** Pre-state and progress of one provider action (≤ 2 KiB, ids/booleans/enums only). */
export const providerActionStateSchema = z.strictObject({
  v: z.literal(1),
  phase: z.enum(['pre', 'written', 'rollback_pre', 'rollback_written']),
  /** Provider pre-state (ids, booleans, enums; never an address). */
  pre: z.record(z.string().max(32), z.union([z.string().max(512), z.boolean(), z.number()])),
  at: z.iso.datetime(),
  /** Result code for 8.4's action row (`already_in_state`, `restored_previous_state_noop`, …). */
  resultCode: z
    .string()
    .regex(/^[a-z0-9_]{1,64}$/)
    .optional(),
  /** Number of read-back checks done by `confirm` (drives the 10 s → 5 min poll interval). */
  checks: z.number().int().min(0).max(10_000).optional(),
  /** Per-item outcomes of `remove_forwarding_rule` with several items (`all_external`). */
  items: z
    .array(
      z.strictObject({
        id: z.string().max(64),
        ref: z.string().max(255).nullable(),
        outcome: z.enum([
          'pending',
          'written',
          'confirmed',
          'already_in_state',
          'unsupported',
          'failed',
        ]),
        enabled: z.boolean().optional(),
        code: z
          .string()
          .regex(/^[a-z0-9_]{1,64}$/)
          .optional(),
      }),
    )
    .max(20)
    .optional(),
});
export type ProviderActionState = z.infer<typeof providerActionStateSchema>;

export const PROVIDER_ACTION_STATE_MAX_BYTES = 2048;

export interface ActionStateStore {
  load(actionPublicId: string): Promise<ProviderActionState | null>;
  /** ≤ 2 KiB, validated (`validateActionState`). */
  save(actionPublicId: string, state: ProviderActionState): Promise<void>;
}

/** Validates a state before it is saved (schema and the 2 KiB bound). */
export function validateActionState(state: ProviderActionState): ProviderActionState {
  const parsed = providerActionStateSchema.parse(state);
  if (Buffer.byteLength(JSON.stringify(parsed), 'utf8') > PROVIDER_ACTION_STATE_MAX_BYTES) {
    throw new Error('provider_state_too_large');
  }
  return parsed;
}
