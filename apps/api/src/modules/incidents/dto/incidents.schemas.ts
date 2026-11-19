import {
  SECURITY_INCIDENT_ORIGINS,
  SECURITY_INCIDENT_RESOLUTION_CODES,
  SECURITY_INCIDENT_SEVERITIES,
  SECURITY_INCIDENT_STATUSES,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing';

/**
 * Request and response schemas of the generic security incident routes (step 8.4 §5.2, D24).
 * Category-aware: `category` and `subject.type` are open strings in responses (ATP-4 appends
 * categories); requests accept the registered categories and validate category feedback with the
 * category's own schema. Public ids only; never a subject line or a recipient address.
 */

export const PublicIdSchema = z.uuid();
const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const severity = z.enum(SECURITY_INCIDENT_SEVERITIES);
const status = z.enum(SECURITY_INCIDENT_STATUSES);
const count = z.number().int().min(0);

const noteText = (min: number, max: number) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    // eslint-disable-next-line no-control-regex -- control characters except CR/LF/TAB are refused
    .regex(/^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$/, 'must not contain control characters');

/** A category or subject type (lower-case snake case). */
const code = z.string().regex(/^[a-z][a-z0-9_]{0,47}$/, 'must be a category code');

export const IncidentSummarySchema = z.object({
  id: PublicIdSchema,
  category: z.string(),
  subject: z.object({
    type: z.string(),
    id: z.string(),
    /** ATO: the account's address, user display name or connector name. */
    display: z.string().nullable(),
  }),
  origin: z.enum(SECURITY_INCIDENT_ORIGINS),
  status,
  severity,
  titleCode: z.string().nullable(),
  reasonCodes: z.array(z.string()),
  detectedAt: isoInstant,
  lastEvidenceAt: nullableInstant,
  evidenceCount: count,
  assigneeId: PublicIdSchema.nullable(),
  escalatedAt: nullableInstant,
  resolvedAt: nullableInstant,
  resolutionCode: z.enum(SECURITY_INCIDENT_RESOLUTION_CODES).nullable(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
});
export type IncidentSummaryView = z.infer<typeof IncidentSummarySchema>;

export const AllowedTransitionSchema = z.object({
  to: status,
  resolutionCodes: z.array(z.enum(SECURITY_INCIDENT_RESOLUTION_CODES)),
  noteRequired: z.boolean(),
});

export const IncidentDetailSchema = IncidentSummarySchema.extend({
  rowVersion: z.number().int().min(1),
  detectorVersion: z.string().nullable(),
  firstEvidenceAt: nullableInstant,
  assignedAt: nullableInstant,
  confirmedAt: nullableInstant,
  mitigatedAt: nullableInstant,
  resolution: z
    .object({
      code: z.enum(SECURITY_INCIDENT_RESOLUTION_CODES).nullable(),
      note: z.string().nullable(),
      resolvedAt: nullableInstant,
    })
    .nullable(),
  createdBy: z.object({ type: z.enum(['system', 'user', 'api_key']), id: z.string().nullable() }),
  /** Whether the caller holds the category's manage permission. */
  canManage: z.boolean(),
  /** Transitions the caller may request now (empty without the manage permission). */
  allowedTransitions: z.array(AllowedTransitionSchema),
  evidence: z.record(z.string(), count),
  /** The category's detail (ATO: account, scores, detection reason, IPs, geography, devices, counts, recommendations, responses). */
  detail: z.record(z.string(), z.unknown()),
});
export type IncidentDetailView = z.infer<typeof IncidentDetailSchema>;

export const TimelineEntrySchema = z.object({
  id: z.string(),
  at: isoInstant,
  type: z.string(),
  actor: z.object({ type: z.enum(['system', 'user', 'api_key']), id: z.string().nullable() }),
  fromStatus: status.nullable(),
  toStatus: status.nullable(),
  fromSeverity: severity.nullable(),
  toSeverity: severity.nullable(),
  note: z.string().nullable(),
  details: z.unknown().nullable(),
});
export type TimelineEntryView = z.infer<typeof TimelineEntrySchema>;

export const IncidentMessageSchema = z.object({
  id: PublicIdSchema.nullable(),
  receivedAt: isoInstant,
  direction: z.enum(['inbound', 'outbound', 'internal']),
  finalVerdict: z.string().nullable(),
  finalAction: z.string().nullable(),
  riskScore: count.nullable(),
  riskLevel: z.string().nullable(),
  recipientCount: count,
  externalDomainCount: count,
  findingCodes: z.array(z.string()),
});
export type IncidentMessageView = z.infer<typeof IncidentMessageSchema>;

const pageOf = <T extends z.ZodType>(item: T) =>
  z.object({ data: z.array(item), nextCursor: z.string().nullable() });
export const IncidentPageSchema = pageOf(IncidentSummarySchema);
export const TimelinePageSchema = pageOf(TimelineEntrySchema);
export const IncidentMessagePageSchema = pageOf(IncidentMessageSchema);
export type IncidentPage = z.infer<typeof IncidentPageSchema>;
export type TimelinePage = z.infer<typeof TimelinePageSchema>;
export type IncidentMessagePage = z.infer<typeof IncidentMessagePageSchema>;

/** `security-incident-report/1` (generic sections plus the category's sections). */
export const IncidentReportSchema = z.object({
  version: z.literal('security-incident-report/1'),
  generatedAt: isoInstant,
  incident: z.record(z.string(), z.unknown()),
  resolution: z.object({ code: z.string().nullable(), note: z.string().nullable() }).nullable(),
  timeline: z.array(z.record(z.string(), z.unknown())),
  notes: z.array(
    z.object({
      at: isoInstant,
      actorType: z.string(),
      actorId: z.string().nullable(),
      note: z.string(),
    }),
  ),
  evidence: z.record(z.string(), count),
  messages: z.array(
    z.object({
      messageId: z.string(),
      receivedAt: isoInstant,
      direction: z.string(),
      senderMasked: z.string().nullable(),
    }),
  ),
  truncated: z.boolean(),
  sections: z.array(z.object({ id: z.string(), title: z.string(), data: z.unknown() })),
});
export type IncidentReportView = z.infer<typeof IncidentReportSchema>;

// ---------------------------------------------------------------- requests

export const CreateIncidentBodySchema = z.strictObject({
  category: code,
  subject: z.strictObject({ type: code, id: PublicIdSchema }),
  severity: severity.optional(),
  reason: noteText(10, 4000),
});
export type CreateIncidentBody = z.infer<typeof CreateIncidentBodySchema>;

export const UpdateIncidentBodySchema = z
  .strictObject({
    expectedRowVersion: z.number().int().min(1),
    status: status.optional(),
    severity: severity.optional(),
    /** A user public id, or null to unassign. */
    assigneeId: PublicIdSchema.nullable().optional(),
    resolution: z
      .strictObject({
        code: z.enum(SECURITY_INCIDENT_RESOLUTION_CODES),
        note: noteText(10, 4000),
      })
      .optional(),
    note: noteText(1, 4000).optional(),
    /** The category's feedback (ATO: `{ trustedContexts[], dismissSignals }` with `false_positive`). */
    categoryFeedback: z.record(z.string(), z.unknown()).optional(),
  })
  .refine(
    (b) =>
      b.status !== undefined ||
      b.severity !== undefined ||
      b.assigneeId !== undefined ||
      b.note !== undefined,
    { message: 'Nothing to change: give status, severity, assigneeId or note' },
  );
export type UpdateIncidentBody = z.infer<typeof UpdateIncidentBodySchema>;

export const AddNoteBodySchema = z.strictObject({ note: noteText(1, 4000) });
export type AddNoteBody = z.infer<typeof AddNoteBodySchema>;

const IncidentListBaseSchema = defineListQuery({
  filters: {
    category: { type: 'string', maxLength: 48, maxValues: 10 },
    status: { type: 'enum', values: SECURITY_INCIDENT_STATUSES, maxValues: 6 },
    severity: { type: 'enum', values: SECURITY_INCIDENT_SEVERITIES, maxValues: 4 },
    assignee: { type: 'string', maxLength: 36 },
    subjectType: { type: 'string', maxLength: 48 },
    subjectId: { type: 'publicId' },
    origin: { type: 'enum', values: SECURITY_INCIDENT_ORIGINS },
  },
  sorts: ['-detectedAt', '-severity'],
  defaultSort: '-detectedAt',
});

/** The strict input shape and the output transform of the v1 list query (a pipe). */
const baseDef = (
  IncidentListBaseSchema as unknown as {
    _zod: { def: { in: { shape: Record<string, z.ZodType> }; out: z.ZodType } };
  }
)._zod.def;
const baseShape = baseDef.in.shape;
const baseOut = baseDef.out;

/**
 * `GET /incidents` query (§5.2 I1): the v1 list contract (`limit`, `cursor`, `sort`, typed
 * filters) plus the detection range `detectedFrom` (inclusive) / `detectedTo` (exclusive).
 */
export const IncidentListQuerySchema = z
  .strictObject({
    ...baseShape,
    detectedFrom: isoInstant.optional(),
    detectedTo: isoInstant.optional(),
  })
  .transform((raw, ctx) => {
    const { detectedFrom, detectedTo, ...rest } = raw as Record<string, unknown> & {
      detectedFrom?: string;
      detectedTo?: string;
    };
    // The fields are already parsed by the shape; only the list transform remains.
    const parsed = baseOut.safeParse(rest) as z.ZodSafeParseResult<
      z.output<typeof IncidentListBaseSchema>
    >;
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        ctx.addIssue({ code: 'custom', path: issue.path, message: issue.message });
      }
      return z.NEVER;
    }
    return {
      ...parsed.data,
      ...(detectedFrom !== undefined && { detectedFrom: new Date(detectedFrom) }),
      ...(detectedTo !== undefined && { detectedTo: new Date(detectedTo) }),
    };
  });
export type IncidentListQuery = z.output<typeof IncidentListQuerySchema>;

export const TimelineQuerySchema = defineListQuery({
  filters: {},
  sorts: ['at'],
  defaultSort: 'at',
});
export type TimelineQuery = z.output<typeof TimelineQuerySchema>;

export const MessagesQuerySchema = defineListQuery({
  filters: {},
  sorts: ['-receivedAt'],
  defaultSort: '-receivedAt',
});
export type MessagesQuery = z.output<typeof MessagesQuerySchema>;

export const PAGE_PARAMETERS: Record<string, string> = {
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};
