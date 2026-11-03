import { ConflictException, HttpException, HttpStatus, NotFoundException } from '@nestjs/common';

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
