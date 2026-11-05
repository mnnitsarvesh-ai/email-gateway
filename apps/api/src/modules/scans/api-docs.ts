import { ApiParam } from '@nestjs/swagger';
import { ApiCodedError } from '../../http/coded-exception';
import {
  CONTENT_UNAVAILABLE,
  ORGANIZATION_NOT_FOUND,
  RSPAMD_UNAVAILABLE,
  SCAN_ENGINE_NOT_FOUND,
  SCAN_SETTINGS_INVALID,
  SCAN_TRAINING_NOT_APPLICABLE,
  VERSION_CONFLICT,
} from './scans.errors';
import { MESSAGE_NOT_FOUND } from '../messages/messages.errors';

/** Permissions of the scan routes (seed catalog; the last two are new in step 4.1). */
export const POLICY_READ = 'policy:read';
export const SCAN_SETTINGS_MANAGE = 'scan:settings_manage';
export const PLATFORM_SCAN_TRAINING = 'platform:scan_training';

/** `{engine}` path parameter. */
export const ApiEngineParam = (): MethodDecorator =>
  ApiParam({ name: 'engine', description: 'Scan engine name (step 4.1: `rspamd`)' });

export const ApiScanEngineNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'The engine is not registered', [SCAN_ENGINE_NOT_FOUND]);

export const ApiVersionConflict = (): MethodDecorator =>
  ApiCodedError(
    409,
    '`expectedVersion` is not the current version; `currentVersion` is the version now',
    [VERSION_CONFLICT],
    { currentVersion: { type: 'integer', minimum: 0 } },
  );

export const ApiScanSettingsInvalid = (): MethodDecorator =>
  ApiCodedError(
    422,
    'The override breaks the platform settings: scores outside the bounds, suspiciousScore not ' +
      'below spamScore, a severity lowered below the platform value, or an unknown key',
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
