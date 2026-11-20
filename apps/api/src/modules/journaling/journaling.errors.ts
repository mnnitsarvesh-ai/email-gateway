import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the journaling routes (step 8.6 D11). Unknown source ids and ids of
 * another organization answer the same `404`. Details carry ids, versions, limits, codes and
 * indexes, never addresses, tokens or networks.
 */
export const JOURNAL_ERROR_CODES = {
  unavailable: 'journal_intake_unavailable',
  notEnabled: 'journal_intake_not_enabled',
  archivingNotEnabled: 'archiving_not_enabled',
  sourceNotFound: 'journal_intake_source_not_found',
  sourceConflict: 'journal_intake_source_conflict',
  networksInvalid: 'journal_intake_networks_invalid',
  connectionInvalid: 'journal_intake_connection_invalid',
  sourceLimit: 'journal_intake_source_limit',
  sourceDisabled: 'journal_intake_source_disabled',
  sourceNameTaken: 'journal_intake_source_name_taken',
  domainRequired: 'journal_intake_domain_required',
  attestationUnknown: 'journal_intake_attestation_unknown',
  inconsistentRead: INCONSISTENT_READ,
} as const;

const C = JOURNAL_ERROR_CODES;
type Code = (typeof JOURNAL_ERROR_CODES)[keyof typeof JOURNAL_ERROR_CODES];

const err = (
  status: HttpStatus,
  code: Code,
  message: string,
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException => new CodedHttpException(status, code, message, details);

export const journalIntakeUnavailable = (): CodedHttpException =>
  err(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.unavailable,
    'Journal intake is not configured on this platform (no intake domain)',
  );

export const journalIntakeNotEnabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.notEnabled,
    'Journal intake needs the plan features archiving and journal_intake',
  );

export const archivingNotEnabledForIntake = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.archivingNotEnabled,
    'Journal intake needs archiving enabled with a default retention policy',
  );

export const intakeSourceNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.sourceNotFound, 'Journal intake source not found');

export const intakeSourceConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.sourceConflict,
    'expectedRowVersion is not the current version of the intake source',
    { currentRowVersion },
  );

export const intakeNetworksInvalid = (
  issues: ReadonlyArray<{ code: string; index: number | null }>,
): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.networksInvalid,
    'The networks are invalid, too broad, private, duplicated or overlap a provider egress range',
    { issues: issues.map((i) => ({ code: i.code, index: i.index })) },
  );

export const intakeConnectionInvalid = (reason: string): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.connectionInvalid,
    'The provider connection cannot be used by this intake source',
    { reason },
  );

export const intakeSourceLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.sourceLimit,
    'The organization has the maximum number of journal intake sources',
    { limit },
  );

export const intakeSourceDisabled = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.sourceDisabled, 'The journal intake source is disabled');

export const intakeSourceNameTaken = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.sourceNameTaken,
    'A journal intake source with this name already exists',
  );

export const intakeDomainRequired = (reason: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.domainRequired,
    'Journal intake needs a TXT-verified domain (provider kinds: linked to the connection)',
    { reason },
  );

export const intakeAttestationUnknown = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.attestationUnknown,
    'Not an attestation code of this intake source kind',
  );
