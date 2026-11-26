import { ApiParam } from '@nestjs/swagger';
import { ApiCodedError } from '../../http/coded-exception';
import { API_MODE_ERROR_CODES as C } from './api-mode.errors';

/**
 * OpenAPI helpers of the API-mode routes (step API-1 D12). The keyed-mutation marker, the 2xx
 * response, the keyed 400/409/422 and the 403/503 shapes are the archive module's (one convention
 * for every transactional Idempotency-Key route); this file adds the API-mode ones.
 */
export {
  ApiArchiveConflicts as ApiModeConflicts,
  ApiArchiveResponse as ApiModeResponse,
  ApiArchiveUnavailable as ApiModeUnavailable,
  ApiArchiveUnprocessable as ApiModeUnprocessable,
  ApiKeyedErrors,
  ArchiveIdempotency as ApiModeIdempotency,
} from '../archive/api-docs';

/** The keyed-mutation rule shared by the operation descriptions. */
export const KEYED_RULE =
  ' Requires the Idempotency-Key header (transactional: the change, its audit row and the ' +
  'stored response commit together; a repeat with the same key returns the stored response with ' +
  '`Idempotency-Replayed: true`); rate class `sensitive`.';

/** `403` of the API-mode routes: permission (and the documented extra codes). */
export const ApiModeForbidden = (
  extra: readonly string[] = [],
  description = '',
): MethodDecorator =>
  ApiCodedError(403, 'Missing permission (`forbidden`)' + (description ? `, ${description}` : ''), [
    'forbidden',
    ...extra,
  ]);

export const ApiConnectionIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'connectionId',
    description: 'The 8.2 provider connection public id (UUID)',
    format: 'uuid',
  });

export const ApiMailboxIdParam = (): MethodDecorator =>
  ApiParam({ name: 'mailboxId', description: 'Mailbox public id (UUID)', format: 'uuid' });

export const ApiDetectionIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'detectionId',
    description: 'Detection (copy) public id (UUID)',
    format: 'uuid',
  });

export const ApiConnectionNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown provider connection, or one of another organization', [
    C.connectionNotFound,
  ]);

export const ApiMailboxNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown mailbox, or one of another organization', [C.mailboxNotFound]);

export const ApiDetectionNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown detection, or one of another organization', [C.detectionNotFound]);

export const ApiBadId = (): MethodDecorator =>
  ApiCodedError(400, 'The id is not a UUID (`validation_failed`)', ['validation_failed']);
