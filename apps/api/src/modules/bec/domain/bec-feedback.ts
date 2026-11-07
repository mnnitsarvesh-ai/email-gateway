import { isBecSuppressibleCode } from '@email-gateway/security-contracts';
import { feedbackCodesInvalid, suppressionNotAllowed } from '../bec.errors';
import type { BecFeedbackCreate } from '../dto/bec.schemas';
import { isFreemail } from './bec-inputs';

/** One suppression rule a feedback asks for (B11). */
export interface PlannedSuppression {
  reasonCode: string;
  senderScope: 'address' | 'domain';
  senderValue: string;
  expiresAt: Date;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Validates a feedback against its result (step 4.4 B11) and plans its suppressions, pure:
 *
 * - false positive: every disputed code must be a code of the result (`422
 *   feedback_codes_invalid`);
 * - `suppress` only on a false positive, only suppressible codes (B11 list) that the result
 *   carries, the sender taken from the scanned message's From (`bec_scan_results.identity`: the
 *   address, or its registrable domain), a free-mail domain scope refused, expiry `days` ahead
 *   (1–90, validated by the DTO) — every refusal is `422 suppression_not_allowed` with a reason.
 *
 * The per-tenant cap is checked by the service under the writer lock.
 */
export function planFeedback(
  body: BecFeedbackCreate,
  resultCodes: ReadonlySet<string>,
  from: { address: string | null; registrableDomain: string | null },
  now: Date,
): PlannedSuppression[] {
  if (body.kind === 'false_positive') {
    for (const code of body.reasonCodes ?? []) {
      if (!resultCodes.has(code)) throw feedbackCodesInvalid(code);
    }
  }
  if (body.suppress === undefined) return [];
  if (body.kind !== 'false_positive') throw suppressionNotAllowed('not_false_positive');
  for (const code of body.suppress.codes) {
    if (!isBecSuppressibleCode(code)) throw suppressionNotAllowed('code_not_suppressible', code);
    if (!resultCodes.has(code)) throw suppressionNotAllowed('code_not_in_result', code);
  }
  const senderValue = body.suppress.scope === 'address' ? from.address : from.registrableDomain;
  if (senderValue === null || senderValue.length === 0 || senderValue.length > 320) {
    throw suppressionNotAllowed('sender_unavailable');
  }
  if (body.suppress.scope === 'domain' && isFreemail(senderValue)) {
    throw suppressionNotAllowed('freemail_domain');
  }
  const expiresAt = new Date(now.getTime() + body.suppress.days * DAY_MS);
  return body.suppress.codes.map((reasonCode) => ({
    reasonCode,
    senderScope: body.suppress!.scope,
    senderValue,
    expiresAt,
  }));
}
