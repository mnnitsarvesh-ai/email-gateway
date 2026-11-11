import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the department routes (step 5.2 P5, P22). Bodies carry ids, limits and
 * row versions only (never addresses).
 */
export const DEPARTMENT_NOT_FOUND = 'department_not_found';
export const DEPARTMENT_MEMBER_NOT_FOUND = 'department_member_not_found';
export const DEPARTMENT_NAME_TAKEN = 'department_name_taken';
export const DEPARTMENT_LIMIT_REACHED = 'department_limit_reached';
export const DEPARTMENT_MEMBER_LIMIT_REACHED = 'department_member_limit_reached';
export const DEPARTMENT_MEMBER_EXISTS = 'department_member_exists';
export const DEPARTMENT_IN_USE = 'department_in_use';
export const DEPARTMENT_CONFLICT = 'department_conflict';
export const MEMBER_ADDRESS_NOT_TENANT = 'member_address_not_tenant';
export const MEMBER_USER_NOT_TENANT = 'member_user_not_tenant';

export const departmentNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, DEPARTMENT_NOT_FOUND, 'Department not found');

export const departmentMemberNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    DEPARTMENT_MEMBER_NOT_FOUND,
    'Department member not found',
  );

export const departmentNameTaken = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DEPARTMENT_NAME_TAKEN,
    'A department with this name exists in the organization',
  );

export const departmentLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DEPARTMENT_LIMIT_REACHED,
    'The organization reached its limit of departments',
    { limit },
  );

export const departmentMemberLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DEPARTMENT_MEMBER_LIMIT_REACHED,
    'The department reached its limit of members',
    { limit },
  );

export const departmentMemberExists = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DEPARTMENT_MEMBER_EXISTS,
    'The address or user is already a member of the department',
  );

/** An active policy version references the department (P5). */
export const departmentInUse = (policyIds: readonly string[]): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DEPARTMENT_IN_USE,
    'An active policy version references the department; change or disable the policy first',
    { policies: policyIds.slice(0, 20).map((policyId) => ({ policyId })) },
  );

export const departmentConflict = (current: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DEPARTMENT_CONFLICT,
    'The department changed since it was read; read it and retry',
    { currentRowVersion: current },
  );

export const memberAddressNotTenant = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    MEMBER_ADDRESS_NOT_TENANT,
    'The address is not in an active domain of the organization',
  );

export const memberUserNotTenant = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    MEMBER_USER_NOT_TENANT,
    'The user is not a user of the organization',
  );
