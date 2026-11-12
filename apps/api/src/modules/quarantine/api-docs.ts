import {
  applyDecorators,
  createParamDecorator,
  type ExecutionContext,
  UseFilters,
} from '@nestjs/common';
import type { Request } from 'express';
import {
  IDEMPOTENCY_KEY_HEADER,
  parseIdempotencyKey,
} from '../../http/idempotency/idempotency-key';
import { ApiBearerAuth, ApiParam, ApiQuery, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { z } from 'zod';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApprovalIdSchema, EntryIdSchema, ReleaseIdSchema } from './dto/quarantine.schemas';

/** Shared class decorators of the quarantine controllers: tag, security schemes, coded errors. */
export const QuarantineController = (): ClassDecorator =>
  applyDecorators(
    ApiTags('quarantine'),
    ApiBearerAuth(ACCESS_TOKEN_SCHEME),
    ApiSecurity(API_KEY_SCHEME),
    UseFilters(CodedExceptionFilter),
  );

export const entryIdPipe = new ZodValidationPipe(EntryIdSchema);
export const approvalIdPipe = new ZodValidationPipe(ApprovalIdSchema);
export const releaseIdPipe = new ZodValidationPipe(ReleaseIdSchema);

export const ApiEntryId = (): MethodDecorator =>
  ApiParam({ name: 'entryId', format: 'uuid', description: 'Quarantine entry public id' });
export const ApiApprovalId = (): MethodDecorator =>
  ApiParam({ name: 'approvalId', format: 'uuid', description: 'Approval request public id' });

/** Query parameters from a zod object; `required` names the mandatory ones. */
export function ApiQueryOf(schema: z.ZodObject, required: readonly string[] = []): MethodDecorator {
  return applyDecorators(
    ...Object.entries(schema.shape).map(([name, field]) =>
      ApiQuery({
        name,
        required: required.includes(name),
        schema: zodToOpenApi(field as z.ZodType, { io: 'input' }),
      }),
    ),
  );
}

/** `Cache-Control: no-store` documented on a 200/202 response. */
export const NO_STORE_HEADER: Record<string, { schema: { type: 'string'; enum: string[] } }> = {
  'Cache-Control': { schema: { type: 'string', enum: ['no-store'] } },
};

/**
 * The validated `Idempotency-Key` header (missing → `400 idempotency_key_required`, malformed →
 * `400 idempotency_key_invalid`), resolved after the guards and before the handler.
 */
export const IdempotencyKey = createParamDecorator((_data: unknown, context: ExecutionContext) =>
  parseIdempotencyKey(context.switchToHttp().getRequest<Request>().headers[IDEMPOTENCY_KEY_HEADER]),
);

export const ApiEntryNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Entry not found (also another organization’s or another user’s entry)', [
    'quarantine_entry_not_found',
  ]);
export const ApiApprovalNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Approval request not found (also another organization’s)', [
    'quarantine_approval_not_found',
  ]);
export const ApiConflicts = (codes: readonly string[]): MethodDecorator =>
  ApiCodedError(409, 'Conflicts with the current state', codes);
export const ApiInconsistent = (): MethodDecorator =>
  ApiCodedError(503, 'A deciding read was inconsistent twice; retry', ['inconsistent_read']);
export const ApiForbiddenCodes = (codes: readonly string[]): MethodDecorator =>
  ApiCodedError(403, 'Not allowed for this entry or caller', codes);

/** Write conflicts of the entry mutations. */
export const ENTRY_WRITE_CONFLICTS = [
  'quarantine_state_conflict',
  'quarantine_version_conflict',
] as const;
export const RELEASE_CONFLICTS = [
  ...ENTRY_WRITE_CONFLICTS,
  'quarantine_rescan_required',
  'quarantine_hard_block_release_disabled',
] as const;
