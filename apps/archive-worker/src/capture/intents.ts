import { Prisma } from '@email-gateway/database';
import type { MessageDirection } from '@email-gateway/archive';
import type { Db } from '../shared/db';

/** One source of a capture intent (A2). */
export interface IntentUpsert {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  direction: MessageDirection;
  journal: boolean;
  policy: boolean;
  policyRuleRef: string | null;
  settingsGeneration: bigint;
  nextCheckAt: Date;
}

const RULE_REF_MAX = 128;
/** Skip reasons a later policy source overrides (A3: the policy source captures every category). */
const REOPENABLE = Prisma.join([
  'category_excluded',
  'archiving_disabled',
  'policy_archive_disabled',
]);

/**
 * Upserts intents on `(message_id, received_at)` (A2): the sources are OR-ed in, the first
 * policy rule ref is kept, and a new policy source re-opens an intent the journal source had
 * skipped (`category_excluded`, `archiving_disabled`: the policy overrides categories, A3) and
 * pulls a waiting `pending` intent's next check forward. `captured_open`, `closed`, `lost` and
 * `failed` intents keep their status (a policy source arriving after a capture is applied to the
 * record by the outcome refresh).
 */
export async function upsertIntents(db: Db, rows: readonly IntentUpsert[]): Promise<number> {
  if (rows.length === 0) return 0;
  const values = rows.map(
    (r) => Prisma.sql`(
      ${r.receivedAt}, ${r.organizationId}, ${r.messageId}, ${r.direction},
      ${r.journal ? 1 : 0}, ${r.policy ? 1 : 0}, ${r.policyRuleRef?.slice(0, RULE_REF_MAX) ?? null},
      'pending', ${r.nextCheckAt}, ${r.settingsGeneration}, NOW(3), NOW(3))`,
  );
  return db.$executeRaw`
    INSERT INTO archive_capture_intents
      (received_at, organization_id, message_id, direction, source_journal, source_policy,
       policy_rule_ref, status, next_check_at, settings_generation, created_at, updated_at)
    VALUES ${Prisma.join(values)} AS new
    ON DUPLICATE KEY UPDATE
      -- MySQL applies these assignments in order and later ones see earlier results: the
      -- conditions below read status / skip_reason / source_policy before they change.
      -- A policy source pulls a waiting or skipped intent forward (D20); any NEW source pulls a
      -- captured_open intent forward (when no replica holds its lease) so the outcome refresh
      -- adds it to the record within seconds instead of at the +1 h re-check (WP6 fix).
      next_check_at = IF((new.source_policy = 1 AND archive_capture_intents.source_policy = 0
                  AND archive_capture_intents.status IN ('pending', 'skipped'))
                  OR (((new.source_policy = 1 AND archive_capture_intents.source_policy = 0)
                    OR (new.source_journal = 1 AND archive_capture_intents.source_journal = 0))
                  AND archive_capture_intents.status = 'captured_open'
                  AND (archive_capture_intents.lease_until IS NULL
                    OR archive_capture_intents.lease_until < NOW(3))),
                  LEAST(archive_capture_intents.next_check_at, new.next_check_at),
                  archive_capture_intents.next_check_at),
      closed_at = IF(new.source_policy = 1 AND archive_capture_intents.source_policy = 0
                  AND archive_capture_intents.status = 'skipped'
                  AND archive_capture_intents.skip_reason IN (${REOPENABLE}),
                  NULL, archive_capture_intents.closed_at),
      status = IF(new.source_policy = 1 AND archive_capture_intents.source_policy = 0
                  AND archive_capture_intents.status = 'skipped'
                  AND archive_capture_intents.skip_reason IN (${REOPENABLE}),
                  'pending', archive_capture_intents.status),
      skip_reason = IF(new.source_policy = 1 AND archive_capture_intents.source_policy = 0
                  AND archive_capture_intents.status = 'pending'
                  AND archive_capture_intents.closed_at IS NULL
                  AND archive_capture_intents.skip_reason IN (${REOPENABLE}),
                  NULL, archive_capture_intents.skip_reason),
      source_journal = archive_capture_intents.source_journal OR new.source_journal,
      source_policy = archive_capture_intents.source_policy OR new.source_policy,
      policy_rule_ref = COALESCE(archive_capture_intents.policy_rule_ref, new.policy_rule_ref),
      updated_at = NOW(3)`;
}
