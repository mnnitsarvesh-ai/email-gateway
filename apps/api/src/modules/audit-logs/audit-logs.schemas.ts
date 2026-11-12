import { z } from 'zod';
import { defineListQuery, type FilterSpec } from '../../http/listing/list-query';

/** `GET /audit/logs` and `GET /platform/audit/logs` (step 6.1 §3.3, D3, D4, D11). */

export const AUDIT_ACTOR_TYPES = ['user', 'system', 'api_key'] as const;
export const AUDIT_SORTS = ['-createdAt', 'createdAt'] as const;
export type AuditSort = (typeof AUDIT_SORTS)[number];

/** `actionPrefix`: a resource name and its dot, e.g. `quarantine.` (matches `quarantine.*`). */
export const ACTION_PREFIX_PATTERN = /^[a-z_]+\.$/;

/** The allow-listed filters (D4); each maps to one column through `AUDIT_FILTER_COLUMNS`. */
export const AUDIT_FILTERS = {
  action: { type: 'string', maxLength: 100 },
  actionPrefix: { type: 'string', maxLength: 64 },
  resourceType: { type: 'string', maxLength: 64 },
  resourceId: { type: 'string', maxLength: 64 },
  actorType: { type: 'enum', values: AUDIT_ACTOR_TYPES },
  actorId: { type: 'string', maxLength: 64 },
} as const satisfies Record<string, FilterSpec>;

export const AuditLogsQuerySchema = defineListQuery({
  filters: AUDIT_FILTERS,
  sorts: AUDIT_SORTS,
  defaultSort: '-createdAt',
  range: true,
});
export type AuditLogsQuery = z.output<typeof AuditLogsQuerySchema>;

/** The platform route adds its target: `organizationId` (public id) XOR `scope=platform`. */
export const PlatformAuditLogsQuerySchema = defineListQuery({
  filters: {
    ...AUDIT_FILTERS,
    organizationId: { type: 'publicId' },
    scope: { type: 'enum', values: ['platform'] },
  },
  sorts: AUDIT_SORTS,
  defaultSort: '-createdAt',
  range: true,
});
export type PlatformAuditLogsQuery = z.output<typeof PlatformAuditLogsQuerySchema>;

export const AuditLogItemSchema = z.object({
  id: z.string().describe('Decimal row id'),
  createdAt: z.iso.datetime(),
  actor: z.object({
    type: z.enum(AUDIT_ACTOR_TYPES),
    id: z.string().nullable().describe('Public id of the user or API key; null for the system'),
  }),
  action: z.string().describe('`<resource>.<verb>`'),
  resourceType: z.string(),
  resourceId: z.string().nullable(),
  correlationId: z.string().nullable(),
  sourceIp: z.string().nullable(),
  metadata: z
    .record(z.string(), z.unknown())
    .nullable()
    .describe('Scrubbed context of the action (never credentials or message content)'),
});
export type AuditLogItem = z.output<typeof AuditLogItemSchema>;

export const AuditLogPageSchema = z.object({
  data: z.array(AuditLogItemSchema),
  nextCursor: z
    .string()
    .nullable()
    .describe('v1 cursor of the next page; a page may be short (scan budget) while non-null'),
});
export type AuditLogPage = z.output<typeof AuditLogPageSchema>;

export const AUDIT_LOG_PAGE_EXAMPLE: AuditLogPage = {
  data: [
    {
      id: '73019',
      createdAt: '2026-11-12T09:12:44.512Z',
      actor: { type: 'user', id: '01930c2e-7d1a-7000-8000-0000000000a1' },
      action: 'quarantine.entry_released',
      resourceType: 'quarantine_entry',
      resourceId: '01930c2e-7d1a-7000-8000-0000000000e7',
      correlationId: '6f1c0b52-1d2e-4c55-9a77-0b3f0e1a2c3d',
      sourceIp: '203.0.113.10',
      metadata: { requestId: '0b9c2a64-5d0e-4f1f-8a5b-2c3d4e5f6a7b', recipients: 1 },
    },
  ],
  nextCursor: null,
};
