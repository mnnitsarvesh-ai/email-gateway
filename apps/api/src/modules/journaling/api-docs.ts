import { ApiParam } from '@nestjs/swagger';
import { ApiCodedError } from '../../http/coded-exception';
import { JOURNAL_ERROR_CODES as C } from './journaling.errors';

/**
 * OpenAPI helpers of the journaling routes (step 8.6 D11). The keyed-mutation marker, the 2xx
 * response, the keyed 400/409/422 and the 403/503 shapes are the archive module's (one
 * convention for both areas of the settings row); this file adds the journaling-specific ones.
 */
export {
  ApiArchiveConflicts as ApiJournalConflicts,
  ApiArchiveForbidden as ApiJournalForbidden,
  ApiArchiveResponse as ApiJournalResponse,
  ApiArchiveUnavailable as ApiJournalUnavailable,
  ApiArchiveUnprocessable as ApiJournalUnprocessable,
  ApiKeyedErrors,
  ArchiveIdempotency as JournalIdempotency,
} from '../archive/api-docs';

export const MFA_RULE =
  ' MFA-authenticated users only (`403 mfa_required`; API keys `403 user_required`).';

/** ADR-0057: the values shown once and redacted in the stored response. */
export const REDACTED_REPLAY_RULE =
  ' `address` and `headerToken` are in clear ONLY in this response: the stored response under ' +
  'the Idempotency-Key carries `null`, so a replay returns them redacted (ADR-0057; reveal ' +
  'them again with GET …?reveal=true).';

export const ApiSourceIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'sourceId',
    description: 'Journal intake source public id (UUID)',
    format: 'uuid',
  });

export const ApiSourceNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown intake source, or one of another organization', [C.sourceNotFound]);

export const ApiIntakeUnavailable = (): MethodDecorator =>
  ApiCodedError(
    503,
    'Journal intake is not configured on this platform (`journal_intake_unavailable`), the ' +
      'database returned an inconsistent read (`inconsistent_read`) or a dependency is down',
    [C.unavailable, C.inconsistentRead, 'service_unavailable'],
  );
