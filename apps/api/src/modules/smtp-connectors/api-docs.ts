import { ApiParam } from '@nestjs/swagger';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ConnectorIdParamSchema } from './dto/smtp-connectors.schemas';

/** Permissions of the connector routes (step 2.2 §4.1, seeded by WP1). */
export const CONNECTOR_READ = 'connector:read';
export const CONNECTOR_MANAGE = 'connector:manage';

/** `{id}` path parameter: the connector's public id. */
export const ApiConnectorId = (): MethodDecorator =>
  ApiParam({ name: 'id', format: 'uuid', description: 'SMTP connector public id' });

/** Validates `{id}` as a UUID (`400` otherwise). */
export const connectorIdPipe = new ZodValidationPipe(ConnectorIdParamSchema);

/** Shared-IP warning carried by the OpenAPI descriptions (D10, §8). */
export const SHARED_IP_WARNING =
  '**Warning:** never use `source_ip` connectors for shared-IP mail platforms such as ' +
  'Microsoft 365 or Google Workspace: every customer of that platform sends from the same ' +
  'addresses and could then send as your organization. Use `sasl` or `client_certificate` ' +
  'connectors for them.';
