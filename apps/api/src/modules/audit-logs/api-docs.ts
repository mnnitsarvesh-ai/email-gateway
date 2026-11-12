import { applyDecorators } from '@nestjs/common';
import { ApiQuery } from '@nestjs/swagger';
import { MAX_PAGE_LIMIT } from '../../http/pagination';
import { AUDIT_ACTOR_TYPES, AUDIT_SORTS } from './audit-logs.schemas';

const str = (maxLength: number) => ({ type: 'string' as const, maxLength });

/** Query parameters of the audit searches (the list schema is a transform, so listed here). */
export function ApiAuditQuery(platform: boolean): MethodDecorator {
  return applyDecorators(
    ...(platform
      ? [
          ApiQuery({
            name: 'organizationId',
            required: false,
            description: 'Target organization (public id); exactly one of this or `scope`',
            schema: { type: 'string', format: 'uuid' },
          }),
          ApiQuery({
            name: 'scope',
            required: false,
            description: '`platform`: rows without an organization (platform actions)',
            schema: { type: 'string', enum: ['platform'] },
          }),
        ]
      : []),
    ApiQuery({
      name: 'from',
      required: false,
      description: 'Inclusive (ISO 8601); default `to` − 7 days',
      schema: { type: 'string', format: 'date-time' },
    }),
    ApiQuery({
      name: 'to',
      required: false,
      description: 'Exclusive (ISO 8601); default now; at most API_AUDIT_MAX_RANGE_DAYS after from',
      schema: { type: 'string', format: 'date-time' },
    }),
    ApiQuery({
      name: 'action',
      required: false,
      description: 'Exact action (case-sensitive, like every audit filter)',
      schema: str(100),
    }),
    ApiQuery({
      name: 'actionPrefix',
      required: false,
      description: 'Action prefix `[a-z_]+.` (e.g. `quarantine.`); not with `action`',
      schema: { type: 'string', pattern: '^[a-z_]+\\.$', maxLength: 64 },
    }),
    ApiQuery({
      name: 'resourceType',
      required: false,
      description: 'Exact resource type (case-sensitive)',
      schema: str(64),
    }),
    ApiQuery({
      name: 'resourceId',
      required: false,
      description: 'Exact resource id (case-sensitive; public ids are lower case)',
      schema: str(64),
    }),
    ApiQuery({
      name: 'actorType',
      required: false,
      schema: { type: 'string', enum: [...AUDIT_ACTOR_TYPES] },
    }),
    ApiQuery({
      name: 'actorId',
      required: false,
      description: 'Public id of the acting user or API key (exact, case-sensitive)',
      schema: str(64),
    }),
    ApiQuery({
      name: 'sort',
      required: false,
      schema: { type: 'string', enum: [...AUDIT_SORTS], default: '-createdAt' },
    }),
    ApiQuery({
      name: 'limit',
      required: false,
      schema: { type: 'integer', minimum: 1, maximum: MAX_PAGE_LIMIT, default: 25 },
    }),
    ApiQuery({
      name: 'cursor',
      required: false,
      description: 'v1 cursor (`nextCursor` of the previous page, same filters and sort)',
      schema: { type: 'string', maxLength: 512 },
    }),
  );
}
