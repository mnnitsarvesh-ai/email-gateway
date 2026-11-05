import { HttpStatus } from '@nestjs/common';
import type { SettingsViolation } from '@email-gateway/security-contracts';
import { CodedHttpException } from '../../http/coded-exception';

/** Stable error codes of the scan settings and training routes (step 4.1 S13, S16). */
export const SCAN_ENGINE_NOT_FOUND = 'scan_engine_not_found';
export const SCAN_SETTINGS_INVALID = 'scan_settings_invalid';
export const VERSION_CONFLICT = 'version_conflict';
export const ORGANIZATION_NOT_FOUND = 'organization_not_found';
export const CONTENT_UNAVAILABLE = 'content_unavailable';
export const RSPAMD_UNAVAILABLE = 'rspamd_unavailable';
export const SCAN_TRAINING_NOT_APPLICABLE = 'scan_training_not_applicable';

/** An engine that is not in ENGINE_CATALOG (or has no tenant settings). */
export const scanEngineNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, SCAN_ENGINE_NOT_FOUND, 'Scan engine not found');

/** The override breaks the platform bounds or rules; `violations` lists every problem. */
export const scanSettingsInvalid = (violations: readonly SettingsViolation[]): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    SCAN_SETTINGS_INVALID,
    'The settings are not allowed by the platform settings',
    {
      violations: violations.map((v) => ({ path: v.path, code: v.code, message: v.message })),
    },
  );

/** `expectedVersion` is not the current version of the engine's settings. */
export const versionConflict = (currentVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    VERSION_CONFLICT,
    'The settings changed since expectedVersion; read them and retry',
    { currentVersion },
  );

export const organizationNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, ORGANIZATION_NOT_FOUND, 'Organization not found');

/** The message's EML is missing from storage (expired, deleted) or not under its organization. */
export const contentUnavailable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    CONTENT_UNAVAILABLE,
    'The stored message is not available',
  );

/** The Rspamd controller is not configured, unreachable, timed out or failed. */
export const rspamdUnavailable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    RSPAMD_UNAVAILABLE,
    'The Rspamd controller is unavailable; retry later',
  );

/** Rspamd found nothing to hash in the message (fuzzy operations). */
export const scanTrainingNotApplicable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    SCAN_TRAINING_NOT_APPLICABLE,
    'Rspamd found no content it can hash in this message',
  );
