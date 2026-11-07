import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the BEC tenant data routes (step 4.4 B11, B18,
 * docs/plan/steps/12-phishing-bec.md). Ids, kinds, counts and limits only in the bodies; never
 * names, addresses or domains.
 */
export const BEC_EXECUTIVE_NOT_FOUND = 'bec_executive_not_found';
export const BEC_VENDOR_NOT_FOUND = 'bec_vendor_not_found';
export const BEC_TRUSTED_SENDER_NOT_FOUND = 'bec_trusted_sender_not_found';
export const BEC_SUPPRESSION_NOT_FOUND = 'bec_suppression_not_found';
export const BEC_SCAN_NOT_FOUND = 'scan_not_found';
export const BEC_RESULT_NOT_FOUND = 'bec_result_not_found';
export const EXECUTIVE_EXISTS = 'executive_exists';
export const VENDOR_EXISTS = 'vendor_exists';
export const TRUSTED_SENDER_EXISTS = 'trusted_sender_exists';
export const FEEDBACK_EXISTS = 'feedback_exists';
export const BEC_VERSION_CONFLICT = 'version_conflict';
export const BEC_LIMIT_REACHED = 'bec_limit_reached';
export const TRUSTED_DOMAIN_FREEMAIL = 'trusted_domain_freemail';
export const VENDOR_DOMAIN_FREEMAIL = 'vendor_domain_freemail';
export const SUPPRESSION_NOT_ALLOWED = 'suppression_not_allowed';
export const FEEDBACK_CODES_INVALID = 'feedback_codes_invalid';
export const INCONSISTENT_READ = 'inconsistent_read';

export type BecResource = 'executive' | 'vendor' | 'trusted_sender' | 'suppression';

const NOT_FOUND: Record<BecResource, [string, string]> = {
  executive: [BEC_EXECUTIVE_NOT_FOUND, 'Executive profile not found'],
  vendor: [BEC_VENDOR_NOT_FOUND, 'Vendor profile not found'],
  trusted_sender: [BEC_TRUSTED_SENDER_NOT_FOUND, 'Trusted sender not found'],
  suppression: [BEC_SUPPRESSION_NOT_FOUND, 'Suppression rule not found'],
};

/** Unknown id or another organization's id: never confirms existence. */
export const becNotFound = (resource: BecResource): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, NOT_FOUND[resource][0], NOT_FOUND[resource][1]);

export const becScanNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, BEC_SCAN_NOT_FOUND, 'Scan not found');

/** The scan has no `bec` result (not finalized yet, failed, or the engine did not run). */
export const becResultNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    BEC_RESULT_NOT_FOUND,
    'The scan has no BEC result to give feedback on',
  );

const EXISTS: Record<'executive' | 'vendor' | 'trusted_sender', [string, string]> = {
  executive: [EXECUTIVE_EXISTS, 'An executive profile with this normalized name exists'],
  vendor: [VENDOR_EXISTS, 'A vendor profile with this normalized name exists'],
  trusted_sender: [TRUSTED_SENDER_EXISTS, 'This trusted sender exists'],
};

/** The unique key (normalized name, or kind + value) is taken; `id` when known. */
export const becExists = (
  resource: 'executive' | 'vendor' | 'trusted_sender',
  id: string | null,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    EXISTS[resource][0],
    EXISTS[resource][1],
    id === null ? {} : { id },
  );

/** `version` is not the current version of the row. */
export const becVersionConflict = (currentVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    BEC_VERSION_CONFLICT,
    'The resource changed since version; read it and retry',
    { currentVersion },
  );

/** A per-organization cap (`BEC_MAX_*`, `BEC_SUPPRESSIONS_MAX_PER_TENANT`) would be exceeded. */
export const becLimitReached = (resource: string, limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    BEC_LIMIT_REACHED,
    'The organization reached its limit for this resource',
    { resource, limit },
  );

export const trustedDomainFreemail = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    TRUSTED_DOMAIN_FREEMAIL,
    'A free-mail domain cannot be a trusted sender domain; trust the address instead',
  );

export const vendorDomainFreemail = (index: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    VENDOR_DOMAIN_FREEMAIL,
    'A free-mail domain cannot be a vendor domain; list the vendor addresses as knownSenders',
    { index },
  );

/** Why a suppression block is refused (B11 bounds). */
export type SuppressionRefusal =
  | 'not_false_positive'
  | 'code_not_suppressible'
  | 'code_not_in_result'
  | 'sender_unavailable'
  | 'freemail_domain';

export const suppressionNotAllowed = (
  reason: SuppressionRefusal,
  code: string | null = null,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    SUPPRESSION_NOT_ALLOWED,
    'The suppression is not allowed (only suppressible codes of the result, for the From ' +
      'address or a non-free-mail domain, from a false-positive feedback)',
    code === null ? { reason } : { reason, reasonCode: code },
  );

/** A disputed code of a false positive is not one of the result's codes. */
export const feedbackCodesInvalid = (code: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    FEEDBACK_CODES_INVALID,
    'A disputed reason code is not a code of the BEC result',
    { reasonCode: code },
  );

/** One feedback per (scan, user, kind) (B11). */
export const feedbackExists = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    FEEDBACK_EXISTS,
    'You already recorded this kind of feedback for this scan',
  );

/** A writer read returned another row twice in a row (step 4.4 §6); retry later. */
export const inconsistentRead = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    INCONSISTENT_READ,
    'The database returned an inconsistent read; retry the request',
  );

/**
 * A read on the writer returned a row other than the one asked for (4.2 §6: Prisma may hand back
 * the reply of an abandoned statement). The service retries the transaction once, then answers
 * `503 inconsistent_read`.
 */
export class InconsistentBecReadError extends Error {
  constructor(readonly read: string) {
    super(`inconsistent read (${read})`);
    this.name = 'InconsistentBecReadError';
  }
}
