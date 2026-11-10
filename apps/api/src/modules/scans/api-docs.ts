import { ApiParam } from '@nestjs/swagger';
import { ApiCodedError } from '../../http/coded-exception';
import {
  CONTENT_UNAVAILABLE,
  FEATURE_NOT_ENABLED,
  HASH_EXISTS,
  INDICATOR_EXISTS,
  ORGANIZATION_NOT_FOUND,
  RESCAN_JOB_NOT_CANCELLABLE,
  RESCAN_JOB_NOT_FOUND,
  THREAT_HASH_NOT_FOUND,
  THREAT_INDICATOR_NOT_FOUND,
  RSPAMD_UNAVAILABLE,
  SCAN_ENGINE_NOT_FOUND,
  SCAN_SETTINGS_INVALID,
  SCAN_TRAINING_NOT_APPLICABLE,
  VERSION_CONFLICT,
} from './scans.errors';
import { MESSAGE_NOT_FOUND } from '../messages/messages.errors';

/** Permissions of the scan routes (seed catalog; `scan:settings_manage` and `platform:scan_training` are new in step 4.1, the last two in step 4.2). */
export const POLICY_READ = 'policy:read';
export const SCAN_SETTINGS_MANAGE = 'scan:settings_manage';
export const PLATFORM_SCAN_TRAINING = 'platform:scan_training';
/** Known-threat hash catalog (step 4.2 A16, A17) and threat indicators (step 4.3 U16). */
export const PLATFORM_THREAT_INTEL_MANAGE = 'platform:threat_intel_manage';
/** Bulk attachment rescan jobs (step 4.2 A13). */
export const PLATFORM_SCAN_RESCAN = 'platform:scan_rescan';

/** `{engine}` path parameter. */
export const ApiEngineParam = (): MethodDecorator =>
  ApiParam({
    name: 'engine',
    description:
      'Scan engine name with tenant settings: `rspamd` (step 4.1), `attachment` (step 4.2), ' +
      '`url` (step 4.3), `bec` (step 4.4), `dlp` (step 4.5), `sandbox` (step 4.6)',
  });

export const ApiScanEngineNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'The engine is not registered', [SCAN_ENGINE_NOT_FOUND]);

export const ApiVersionConflict = (): MethodDecorator =>
  ApiCodedError(
    409,
    '`expectedVersion` is not the current version; `currentVersion` is the version now',
    [VERSION_CONFLICT],
    { currentVersion: { type: 'integer', minimum: 0 } },
  );

/**
 * 409 of `PUT /scan-settings/{engine}`: a version conflict, or (step 4.6 X17) an override that
 * needs a plan feature the organization lacks (`sandbox.enabled = true` without
 * `attachment_sandbox`).
 */
export const ApiVersionOrFeatureConflict = (): MethodDecorator =>
  ApiCodedError(
    409,
    '`version_conflict`: `expectedVersion` is not the current version (`currentVersion` is the ' +
      'version now); `feature_not_enabled`: the override switches on a feature the ' +
      'organization’s plan does not include (`feature` names it, e.g. `attachment_sandbox` for ' +
      '`sandbox.enabled = true`)',
    [VERSION_CONFLICT, FEATURE_NOT_ENABLED],
    {
      currentVersion: { type: 'integer', minimum: 0 },
      feature: { type: 'string' },
    },
  );

export const ApiScanSettingsInvalid = (): MethodDecorator =>
  ApiCodedError(
    422,
    'The override breaks the platform settings: scores outside the bounds, suspiciousScore not ' +
      'below spamScore, a severity or verdict lowered below the platform value, ' +
      'maxAttachmentBytes outside [1 MiB, ATTACHMENT_MAX_BYTES], a platform-denied type on ' +
      'allowedTypes, an unknown file type, a URL domain that is not a registrable domain or ' +
      'host (IP literal, single label, public suffix), a domain both allowed and blocked, a ' +
      'fetch mode above the platform mode, an expiry outside [1, URL_TOKEN_MAX_EXPIRY_DAYS], ' +
      'rewriting or dynamic inspection switched on while the platform has it off, BEC ' +
      'thresholds or AI modes outside their bounds or caps, a BEC free-mail domain that is a ' +
      'public suffix, sandbox fileTypes outside the platform list, a sandbox maxSampleBytes ' +
      'outside [1, SANDBOX_MAX_SAMPLE_BYTES], sandbox browserAnalysis switched on while the ' +
      'platform has it off, or an unknown key',
    [SCAN_SETTINGS_INVALID],
    {
      violations: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            path: { type: 'string' },
            code: {
              type: 'string',
              enum: [
                'invalid',
                'unknown_key',
                'out_of_bounds',
                'threshold_order',
                'severity_lowered',
              ],
            },
            message: { type: 'string' },
          },
          required: ['path', 'code', 'message'],
        },
      },
    },
  );

export const ApiTrainingNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown organization, or no such message in that organization', [
    ORGANIZATION_NOT_FOUND,
    MESSAGE_NOT_FOUND,
  ]);

export const ApiContentUnavailable = (): MethodDecorator =>
  ApiCodedError(409, 'The stored message (EML) is no longer available', [CONTENT_UNAVAILABLE]);

export const ApiTrainingNotApplicable = (): MethodDecorator =>
  ApiCodedError(422, 'Fuzzy operation: Rspamd found no content it can hash', [
    SCAN_TRAINING_NOT_APPLICABLE,
  ]);

export const ApiRspamdUnavailable = (): MethodDecorator =>
  ApiCodedError(503, 'The Rspamd controller is not configured, unreachable, timed out or failed', [
    RSPAMD_UNAVAILABLE,
  ]);

export const ApiHashExists = (): MethodDecorator =>
  ApiCodedError(409, 'The SHA-256 is already in the catalog', [HASH_EXISTS]);

export const ApiThreatHashNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'The SHA-256 is not in the catalog', [THREAT_HASH_NOT_FOUND]);

export const ApiRescanJobNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'No rescan job with that id', [RESCAN_JOB_NOT_FOUND]);

export const ApiRescanOrganizationNotFound = (): MethodDecorator =>
  ApiCodedError(404, '`organizationId` names no organization', [ORGANIZATION_NOT_FOUND]);

export const ApiRescanJobNotCancellable = (): MethodDecorator =>
  ApiCodedError(
    409,
    'The job is not pending or running; `status` is its status now',
    [RESCAN_JOB_NOT_CANCELLABLE],
    { status: { type: 'string' } },
  );

export const ApiIndicatorExists = (): MethodDecorator =>
  ApiCodedError(
    409,
    'The normalized value is already a platform analyst indicator of that type; `id` names it',
    [INDICATOR_EXISTS],
    { id: { type: 'string' } },
  );

export const ApiThreatIndicatorNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'No platform threat indicator with that id', [THREAT_INDICATOR_NOT_FOUND]);
