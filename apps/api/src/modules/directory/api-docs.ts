import { applyDecorators, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiParam, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { INCONSISTENT_READ } from '../policies/policies.errors';
import {
  DEPARTMENT_CONFLICT,
  DEPARTMENT_IN_USE,
  DEPARTMENT_LIMIT_REACHED,
  DEPARTMENT_MEMBER_EXISTS,
  DEPARTMENT_MEMBER_LIMIT_REACHED,
  DEPARTMENT_MEMBER_NOT_FOUND,
  DEPARTMENT_NAME_TAKEN,
  DEPARTMENT_NOT_FOUND,
  MEMBER_ADDRESS_NOT_TENANT,
  MEMBER_USER_NOT_TENANT,
} from './directory.errors';
import { DepartmentIdSchema, MemberIdSchema } from './dto/directory.schemas';

/** Departments are directory data: the user permissions apply (step 5.2 P5, P22). */
export const USER_READ = 'user:read';
export const USER_MANAGE = 'user:manage';

export const DepartmentsController = (): ClassDecorator =>
  applyDecorators(
    ApiTags('departments'),
    ApiBearerAuth(ACCESS_TOKEN_SCHEME),
    ApiSecurity(API_KEY_SCHEME),
    UseFilters(CodedExceptionFilter),
  );

export const departmentIdPipe = new ZodValidationPipe(DepartmentIdSchema);
export const memberIdPipe = new ZodValidationPipe(MemberIdSchema);

export const ApiDepartmentId = (): MethodDecorator =>
  ApiParam({ name: 'departmentId', format: 'uuid', description: 'Department public id' });
export const ApiMemberId = (): MethodDecorator =>
  ApiParam({ name: 'memberId', format: 'uuid', description: 'Member public id' });

export const ApiDepartmentNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown department, or a department of another organization', [
    DEPARTMENT_NOT_FOUND,
  ]);
export const ApiMemberNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown department or member (or another organization’s)', [
    DEPARTMENT_NOT_FOUND,
    DEPARTMENT_MEMBER_NOT_FOUND,
  ]);

const TEXT: Record<string, string> = {
  [DEPARTMENT_NAME_TAKEN]: '`department_name_taken`: the name exists in the organization',
  [DEPARTMENT_LIMIT_REACHED]: '`department_limit_reached`: DEPARTMENT_MAX_PER_ORG (`limit`)',
  [DEPARTMENT_MEMBER_LIMIT_REACHED]:
    '`department_member_limit_reached`: DEPARTMENT_MAX_MEMBERS (`limit`)',
  [DEPARTMENT_MEMBER_EXISTS]: '`department_member_exists`: already a member',
  [DEPARTMENT_IN_USE]:
    '`department_in_use`: an active policy version references it (`policies[].policyId`)',
  [DEPARTMENT_CONFLICT]:
    '`department_conflict`: `expectedRowVersion` is not current (`currentRowVersion`)',
};

export const ApiDepartmentConflict = (codes: readonly string[]): MethodDecorator =>
  ApiCodedError(409, codes.map((c) => TEXT[c]).join('; '), [...codes], {
    limit: { type: 'integer', minimum: 1 },
    currentRowVersion: { type: 'integer', minimum: 1 },
    policies: {
      type: 'array',
      items: { type: 'object', properties: { policyId: { type: 'string', format: 'uuid' } } },
    },
  });

export const ApiMemberInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), `member_address_not_tenant` (the address is not in an ' +
      'active domain of the organization) or `member_user_not_tenant` (not a user of the ' +
      'organization)',
    [MEMBER_ADDRESS_NOT_TENANT, MEMBER_USER_NOT_TENANT],
  );

export const ApiDirectoryInconsistentRead = (): MethodDecorator =>
  ApiCodedError(503, 'The database returned an inconsistent read twice; retry the request', [
    INCONSISTENT_READ,
  ]);
