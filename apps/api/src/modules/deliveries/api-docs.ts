import { ApiParam } from '@nestjs/swagger';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { MessageIdParamSchema } from './dto/deliveries.schemas';

/** Permission of the delivery status routes (step 2.3 R13, seeded by WP1). */
export const DELIVERY_READ = 'delivery:read';

/** `{messageId}` path parameter: the message's registry public id. */
export const ApiMessageId = (): MethodDecorator =>
  ApiParam({ name: 'messageId', format: 'uuid', description: 'Message public id' });

/** Validates `{messageId}` as a UUID (`400` otherwise). */
export const messageIdPipe = new ZodValidationPipe(MessageIdParamSchema);

/** Delivery statuses as documented (R9.1). */
export const DELIVERY_STATUS_DOC =
  '`pending` (planned), `queued` (accepted by the gateway’s MTA), `deferred` (temporary ' +
  'failure, retried), `delivered` (the remote server answered 2xx), `bounced` (permanent ' +
  'failure), `expired` (gave up after retries), `failed` (refused by the gateway, see ' +
  '`failureReason`), `suppressed` (address on the suppression list), `unknown` (no signal; ' +
  'never guessed).';
