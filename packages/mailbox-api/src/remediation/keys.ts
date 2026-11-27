/**
 * Idempotency key of a remediation action (step API-2 §5 "Identifiers", R-I4, R5.5):
 * `action_key` = hex SHA-256 of `api-remediation/1\0<copyPublicId>\0<action>\0<generation>`.
 * Every writer inserts with `INSERT IGNORE` on the unique key, so repeated decisions and requests
 * within one generation collapse into one row.
 */
import { createHash } from 'node:crypto';
import { REMEDIATION_ACTION_KINDS, type RemediationActionKind } from './vocabulary';

export const REMEDIATION_ACTION_KEY_DOMAIN = 'api-remediation/1';
/** `generation` is a SMALLINT UNSIGNED column. */
export const REMEDIATION_MAX_GENERATION = 65_535;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function remediationActionKey(
  copyPublicId: string,
  action: RemediationActionKind,
  generation: number,
): string {
  if (!UUID.test(copyPublicId)) throw new RangeError('remediation_key_invalid_copy_id');
  if (!(REMEDIATION_ACTION_KINDS as readonly string[]).includes(action)) {
    throw new RangeError('remediation_key_invalid_action');
  }
  if (!Number.isInteger(generation) || generation < 0 || generation > REMEDIATION_MAX_GENERATION) {
    throw new RangeError('remediation_key_invalid_generation');
  }
  return createHash('sha256')
    .update(`${REMEDIATION_ACTION_KEY_DOMAIN}\0${copyPublicId}\0${action}\0${generation}`, 'utf8')
    .digest('hex');
}
