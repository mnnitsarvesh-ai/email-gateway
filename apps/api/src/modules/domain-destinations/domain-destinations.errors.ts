import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpStatus,
  UnprocessableEntityException,
} from '@nestjs/common';
import { getCorrelationId } from '@email-gateway/logger';
import type { Response } from 'express';
import type { DestinationRefusalReason } from './domain-destinations.constants';

export const DESTINATIONS_DOMAIN_DELETED = 'Domain is deleted';

/** Human-readable text per refusal reason (the `reason` itself is the stable contract). */
export const REFUSAL_MESSAGES: Readonly<Record<DestinationRefusalReason, string>> = {
  ip_not_public: 'Destination IP address is not publicly routable',
  metadata_address: 'Destination is a cloud metadata address',
  single_label: 'Destination host must be a fully qualified name',
  internal_suffix: 'Destination host is under an internal or refused suffix',
  gateway_host: 'Destination host is the gateway itself',
  invalid_host: 'Destination host is not a valid host name or IP address',
  port_not_allowed: 'Destination port is not allowed',
  host_not_allowed_for_provider: 'Destination host does not belong to the provider',
  duplicate_server: 'The same destination server is listed twice',
  provider_unavailable: 'The destination provider is not available',
  host_reserved_for_provider:
    'Destination host belongs to a provider preset; configure it with that provider',
  destination_tls_conflict:
    'Destination server is already in use on the platform with a different TLS policy; ' +
    'use the same TLS mode and verify names, or contact support',
};

/**
 * `422` refusal of a destination server (step 2.3 R3). The body carries the stable `reason`
 * and the request `field` it applies to (e.g. `servers.1.host`); input values are never echoed.
 */
export class DestinationRefusedException extends UnprocessableEntityException {
  constructor(
    readonly reason: DestinationRefusalReason,
    readonly field: string,
  ) {
    super(REFUSAL_MESSAGES[reason]);
  }
}

/** The 422 body of a destination refusal: the standard error body plus `reason` and `field`. */
export interface DestinationRefusalBody {
  statusCode: number;
  error: string;
  message: string;
  reason: DestinationRefusalReason;
  field: string;
  correlationId?: string;
}

/**
 * Renders DestinationRefusedException with its `reason` (the global AllExceptionsFilter keeps
 * only status and message). Scoped to the destination controllers.
 */
@Catch(DestinationRefusedException)
export class DestinationRefusalFilter implements ExceptionFilter<DestinationRefusedException> {
  catch(exception: DestinationRefusedException, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const status = HttpStatus.UNPROCESSABLE_ENTITY;
    const body: DestinationRefusalBody = {
      statusCode: status,
      error: HttpStatus[status],
      message: exception.message,
      reason: exception.reason,
      field: exception.field,
      correlationId: getCorrelationId(),
    };
    res.status(status).json(body);
  }
}
