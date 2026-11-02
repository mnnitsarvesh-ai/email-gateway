import { ApiParam } from '@nestjs/swagger';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { DomainIdParamSchema } from './dto/domains.schemas';

/** Permissions of the domain routes (D14). */
export const DOMAIN_READ = 'domain:read';
export const DOMAIN_MANAGE = 'domain:manage';
export const DOMAIN_DKIM_ROTATE = 'domain:dkim_rotate';

/** `{id}` path parameter: the domain's public id. */
export const ApiDomainId = (): MethodDecorator =>
  ApiParam({ name: 'id', format: 'uuid', description: 'Domain public id' });

/** Validates `{id}` as a UUID (`400` otherwise). */
export const domainIdPipe = new ZodValidationPipe(DomainIdParamSchema);
