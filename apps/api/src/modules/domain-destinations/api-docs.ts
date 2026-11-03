import { ApiResponse } from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { DESTINATION_REFUSAL_REASONS } from './domain-destinations.constants';

/** The 422 body of a refused destination (DestinationRefusalFilter). */
const REFUSAL_SCHEMA: SchemaObject = {
  type: 'object',
  properties: {
    statusCode: { type: 'integer', enum: [422] },
    error: { type: 'string' },
    message: { type: 'string' },
    reason: { type: 'string', enum: [...DESTINATION_REFUSAL_REASONS] },
    field: {
      type: 'string',
      description: 'Request field the refusal applies to, e.g. `host`, `servers.1.host`',
    },
    correlationId: { type: 'string' },
  },
  required: ['statusCode', 'error', 'message', 'reason', 'field'],
};

/** Documents the 422 destination refusal with its stable `reason` values. */
export const ApiDestinationRefusal = (): MethodDecorator =>
  ApiResponse({
    status: 422,
    description:
      'Destination refused (step 2.3 R3). `reason`: ' +
      DESTINATION_REFUSAL_REASONS.map((reason) => `\`${reason}\``).join(', '),
    schema: REFUSAL_SCHEMA,
  });
