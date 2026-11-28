import { ConflictException, HttpException, HttpStatus, NotFoundException } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

export const DOMAIN_NOT_FOUND = 'Domain not found';
export const DOMAIN_ALREADY_EXISTS = 'Domain already exists';
export const DOMAIN_OWNED_ELSEWHERE = 'Domain is already registered with another organization';
export const VERIFICATION_IN_PROGRESS = 'Verification already in progress';

export const domainNotFound = (): NotFoundException => new NotFoundException(DOMAIN_NOT_FOUND);
export const domainAlreadyExists = (): ConflictException =>
  new ConflictException(DOMAIN_ALREADY_EXISTS);

/**
 * `429` for a per-domain limit enforced by a service (§4). Carries the seconds until the
 * window resets; `RetryAfterInterceptor` turns it into the `Retry-After` header.
 */
export class DomainRateLimitedException extends HttpException {
  constructor(
    message: string,
    readonly retryAfterSeconds: number,
  ) {
    super(message, HttpStatus.TOO_MANY_REQUESTS);
  }
}

/** `429` for the per-domain manual verification limit (§4). */
export class TooManyVerificationsException extends DomainRateLimitedException {
  constructor(retryAfterSeconds: number) {
    super('Too many verification requests for this domain', retryAfterSeconds);
  }
}

/** `429` for the per-domain DKIM rotation limit (§4, D9). */
export class TooManyRotationsException extends DomainRateLimitedException {
  constructor(retryAfterSeconds: number) {
    super('Too many DKIM rotations for this domain', retryAfterSeconds);
  }
}

/** `PUT /domains/{id}/recipient-validation` for a mode the mail path does not implement (D3). */
export const RECIPIENT_MODE_NOT_IMPLEMENTED = 'Not implemented';
/** Enforcing an empty allow-list would reject every recipient of the domain (§4.1). */
export const ALLOW_LIST_EMPTY = 'Add recipients before enforcing the allow-list';
export const recipientLimitReached = (max: number): ConflictException =>
  new ConflictException(`Recipient limit reached: at most ${max} per domain`);

/** Step 8.6 D13 (ADR-0090): mail flow on a domain of an archive-only organization. */
export const MAIL_FILTERING_NOT_ENABLED = 'mail_filtering_not_enabled';
export const mailFilteringNotEnabled = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.FORBIDDEN,
    MAIL_FILTERING_NOT_ENABLED,
    'The organization has the archive-only service profile: mail filtering is not enabled',
  );

/** Step API-4 (B3): coded errors of `POST /domains/{id}/ownership/provider-check`. */
export const DOMAIN_PROVIDER_ERROR_CODES = {
  connectionUnavailable: 'domain_provider_connection_unavailable',
  notPending: 'domain_not_pending',
} as const;

/**
 * No bound, enabled provider connection with an active mail-flow grant (or the given one is not
 * such a connection; or several qualify and `connectionId` was not given: `candidates`).
 */
export const providerConnectionUnavailable = (
  reason: 'none' | 'not_capable' | 'connection_required',
  candidates: readonly string[] = [],
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DOMAIN_PROVIDER_ERROR_CODES.connectionUnavailable,
    'Ownership can be checked only through a bound Microsoft 365 / Google Workspace connection ' +
      'with an active mail-flow grant',
    { reason, ...(candidates.length > 0 && { candidates: candidates.slice(0, 10).join(',') }) },
  );

/** The domain is not waiting for ownership (`pending_verification` or `failed`). */
export const domainNotPending = (status: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DOMAIN_PROVIDER_ERROR_CODES.notPending,
    'Ownership is checked only for a domain that is pending verification',
    { status },
  );

/** `429` of the per-organization provider check window (B3). */
export class TooManyProviderChecksException extends DomainRateLimitedException {
  constructor(retryAfterSeconds: number) {
    super('Too many provider ownership checks for this organization', retryAfterSeconds);
  }
}
