import { HttpStatus } from '@nestjs/common';
import type { BlockedReason } from '@email-gateway/url-security';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the webhook routes (step 6.2 §6.1, docs/plan/steps/19-webhooks-
 * notifications.md). Unknown ids and ids of another organization answer the same `404`.
 */
export const WEBHOOK_ERROR_CODES = {
  notFound: 'webhook_not_found',
  deliveryNotFound: 'webhook_delivery_not_found',
  replayNotFound: 'webhook_replay_not_found',
  notEnabled: 'webhooks_not_enabled',
  limitReached: 'webhook_limit_reached',
  versionConflict: 'webhook_version_conflict',
  notActive: 'webhook_not_active',
  replayInProgress: 'webhook_replay_in_progress',
  replayLimit: 'webhook_replay_limit',
  eventExpired: 'webhook_event_expired',
  urlNotAllowed: 'webhook_url_not_allowed',
  filterInvalid: 'webhook_filter_invalid',
  inconsistentRead: INCONSISTENT_READ,
} as const;

const C = WEBHOOK_ERROR_CODES;

export const webhookNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, C.notFound, 'Webhook not found');

export const webhookDeliveryNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, C.deliveryNotFound, 'Webhook delivery not found');

export const webhookReplayNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, C.replayNotFound, 'Webhook replay not found');

/** The organization's plan does not include the `webhooks` feature (W5). */
export const webhooksNotEnabled = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.FORBIDDEN,
    C.notEnabled,
    'Webhooks are not enabled for this organization',
  );

export const webhookLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.limitReached,
    'The organization has reached the maximum number of webhook subscriptions',
    { limit },
  );

export const webhookVersionConflict = (currentRowVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.versionConflict,
    'expectedRowVersion is not the current version of the webhook',
    { currentRowVersion },
  );

export const webhookNotActive = (status: string): CodedHttpException =>
  new CodedHttpException(HttpStatus.CONFLICT, C.notActive, 'The webhook is not active', {
    status,
  });

export const webhookReplayInProgress = (replayId: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.replayInProgress,
    'A replay of this webhook is already queued or running',
    { replayId },
  );

export const webhookReplayLimit = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.replayLimit,
    'The event was already replayed the maximum number of times for this webhook',
    { limit },
  );

export const webhookEventExpired = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.GONE,
    C.eventExpired,
    'The stored event is past its retention and can no longer be replayed',
  );

/** The endpoint URL breaks a rule of W6 (`reason`: a code, never the URL). */
export const webhookUrlNotAllowed = (reason: BlockedReason | 'format'): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.urlNotAllowed,
    'The endpoint URL is not allowed',
    { reason },
  );

/** A filter names a domain that is not one of the organization's (or is otherwise invalid). */
export const webhookFilterInvalid = (path: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.filterInvalid,
    'The subscription filters are invalid',
    { path },
  );
