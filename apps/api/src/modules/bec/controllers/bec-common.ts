import { applyDecorators, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';

/** Shared class decorators of the BEC controllers: tag, security schemes, coded errors. */
export const BecController = (): ClassDecorator =>
  applyDecorators(
    ApiTags('bec'),
    ApiBearerAuth(ACCESS_TOKEN_SCHEME),
    ApiSecurity(API_KEY_SCHEME),
    UseFilters(CodedExceptionFilter),
  );
