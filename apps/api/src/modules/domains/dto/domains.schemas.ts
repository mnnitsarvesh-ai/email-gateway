import {
  DomainNameError,
  MAX_DOMAIN_NAME_LENGTH,
  normalizeDomainName,
} from '@email-gateway/database';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/** Request and response shapes of `/domains` (§4 of docs/plan/steps/03-domain-onboarding.md). */

export const DomainIdParamSchema = z.uuid();

/** Every status a client can see (deleted domains are 404). */
export const VISIBLE_DOMAIN_STATUSES = [
  'pending_verification',
  'verified',
  'failed',
  'disabled',
  'active',
  'suspended',
] as const;
export const VisibleDomainStatusSchema = z.enum(VISIBLE_DOMAIN_STATUSES);

/**
 * Syntax of a domain name (D2) with the rules that do not depend on the deployment: the service
 * applies the environment-specific ones (test names, `DOMAIN_RESERVED_SUFFIXES`, the gateway's
 * own names). Keeps the input as given; the service normalizes it.
 */
const DomainNameInputSchema = z
  .string()
  .min(1)
  .max(MAX_DOMAIN_NAME_LENGTH)
  .superRefine((value, ctx) => {
    try {
      normalizeDomainName(value, { allowTestNames: true });
    } catch (err) {
      if (!(err instanceof DomainNameError)) throw err;
      ctx.addIssue({ code: 'custom', message: `${err.message} (${err.code})` });
    }
  })
  .describe('Domain name; IDN allowed (stored as punycode), one trailing dot ignored');

export const CreateDomainSchema = z.strictObject({
  name: DomainNameInputSchema,
  inboundEnabled: z.boolean().default(true),
  dkim: z
    .strictObject({
      ed25519: z.boolean().default(false).describe('Also create an Ed25519 key (RFC 8463)'),
    })
    .optional(),
});
export type CreateDomainInput = z.output<typeof CreateDomainSchema>;

export const ListDomainsQuerySchema = PageQuerySchema.extend({
  status: VisibleDomainStatusSchema.optional(),
  q: z
    .string()
    .trim()
    .toLowerCase()
    .min(1)
    .max(MAX_DOMAIN_NAME_LENGTH)
    .regex(/^[a-z0-9.-]+$/, 'must be a prefix of an ASCII (punycode) domain name')
    .optional()
    .describe('Prefix of the ASCII (punycode) domain name'),
}).strict();
export type ListDomainsQuery = z.output<typeof ListDomainsQuerySchema>;

const ReasonSchema = z.string().trim().min(1).max(512);

export const DomainStatusChangeSchema = z
  .strictObject({
    status: z.enum(['active', 'suspended']),
    reason: ReasonSchema.optional().describe('Required when suspending'),
  })
  .refine((v) => v.status !== 'suspended' || v.reason !== undefined, {
    message: 'is required when suspending',
    path: ['reason'],
  });
export type DomainStatusChangeInput = z.output<typeof DomainStatusChangeSchema>;

export const DkimAlgorithmSchema = z.enum(['rsa_2048', 'ed25519']);

export const RotateDkimSchema = z.strictObject({
  algorithm: DkimAlgorithmSchema.default('rsa_2048'),
});
export type RotateDkimInput = z.output<typeof RotateDkimSchema>;

/** `POST /domains/{id}/dkim/rotate` takes an optional body. */
export const OptionalRotateDkimSchema = z.preprocess(
  (value) => (value === undefined || value === null ? {} : value),
  RotateDkimSchema,
);

// ---- Responses ---------------------------------------------------------------------------

const IsoDate = z.iso.datetime();
const RecordStatusSchema = z.enum(['pending', 'valid', 'invalid', 'missing']);
const OutcomeSchema = z.enum(['valid', 'invalid', 'missing', 'indeterminate']);

export const DomainSummarySchema = z.object({
  id: z.uuid(),
  name: z.string().describe('ASCII (punycode) name'),
  unicodeName: z.string(),
  status: VisibleDomainStatusSchema,
  statusReason: z.string().nullable(),
  inboundEnabled: z.boolean(),
  outboundEnabled: z.boolean(),
  verifiedAt: IsoDate.nullable(),
  activatedAt: IsoDate.nullable(),
  lastCheckedAt: IsoDate.nullable(),
  nextCheckAt: IsoDate.nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});

export const DkimKeySchema = z.object({
  selector: z.string(),
  algorithm: DkimAlgorithmSchema,
  status: z.enum(['pending', 'active', 'rotating', 'retired', 'revoked']),
  host: z.string().describe('FQDN of the selector record'),
  createdAt: IsoDate,
  activatedAt: IsoDate.nullable(),
  retireAfter: IsoDate.nullable(),
  retiredAt: IsoDate.nullable(),
});

export const VerificationSchema = z.object({
  method: z.literal('dns_txt'),
  host: z.string(),
  value: z.string().describe('TXT value to publish at host'),
  status: z.enum(['pending', 'verified', 'failed', 'expired']),
  attempts: z.number().int(),
  lastCheckedAt: IsoDate.nullable(),
  lastOutcome: OutcomeSchema.nullable(),
  lastError: z.string().nullable(),
  expiresAt: IsoDate,
  verifiedAt: IsoDate.nullable(),
});

export const DomainDetailSchema = DomainSummarySchema.extend({
  statusChangedAt: IsoDate.nullable(),
  verification: VerificationSchema.nullable(),
  dkimKeys: z
    .array(DkimKeySchema)
    .describe('Non-retired keys and keys retired in the last 30 days'),
});

export const DnsRecordSchema = z.object({
  key: z
    .string()
    .describe('Stable record key: verification, mx:<host>, spf, dkim:<selector>, dmarc'),
  purpose: z.enum(['verification', 'mx', 'spf', 'dkim', 'dmarc', 'mta_sts', 'tls_rpt']),
  requirement: z.enum(['activation', 'inbound', 'outbound', 'recommended']),
  type: z.enum(['MX', 'TXT', 'CNAME']),
  host: z.string().describe('FQDN'),
  name: z.string().describe('Relative to the domain (@ for the apex)'),
  value: z.string(),
  priority: z.number().int().nullable().describe('MX only'),
  status: RecordStatusSchema,
  lastOutcome: OutcomeSchema.nullable(),
  observedValue: z.string().nullable(),
  lastCheckedAt: IsoDate.nullable(),
  lastError: z.string().nullable(),
  warnings: z.array(z.string()),
  instructions: z.string(),
});

export const CreatedDomainSchema = DomainDetailSchema.extend({
  dnsRecords: z.array(DnsRecordSchema),
});

export const DomainPageSchema = z.object({
  data: z.array(DomainSummarySchema),
  nextCursor: z.string().nullable(),
});

export const CleanupRecordSchema = z.object({
  type: z.literal('TXT'),
  host: z.string(),
  reason: z.literal('retired_dkim_selector'),
  retiredAt: IsoDate,
});

export const DnsRecordsResponseSchema = z.object({
  domainId: z.uuid(),
  records: z.array(DnsRecordSchema),
  cleanup: z.array(CleanupRecordSchema).describe('Records the customer can delete'),
});

const CheckSchema = z.object({
  status: RecordStatusSchema,
  lastOutcome: OutcomeSchema.nullable(),
  lastCheckedAt: IsoDate.nullable(),
  warnings: z.array(z.string()),
});

export const DomainStatusViewSchema = z.object({
  domainId: z.uuid(),
  name: z.string(),
  status: VisibleDomainStatusSchema,
  statusReason: z.string().nullable(),
  readyForActivation: z.boolean().describe('Ownership verified: the domain can be activated'),
  mailFlowReady: z.boolean().describe('Active and the MX points at the gateway'),
  lastCheckedAt: IsoDate.nullable(),
  nextCheckAt: IsoDate.nullable(),
  checkFailures: z.number().int(),
  checks: z.object({
    ownership: CheckSchema,
    mx: CheckSchema.extend({
      observed: z.array(
        z.object({ priority: z.number().int(), host: z.string(), pointsToGateway: z.boolean() }),
      ),
      propagation: z.array(z.object({ upstream: z.string(), outcome: OutcomeSchema })),
    }),
    spf: CheckSchema.extend({
      lookupCount: z.number().int().nullable(),
      recommendedValue: z.string(),
    }),
    dkim: CheckSchema.extend({
      selectors: z.array(
        z.object({
          selector: z.string(),
          algorithm: DkimAlgorithmSchema,
          keyStatus: z.enum(['pending', 'active', 'rotating', 'retired', 'revoked']),
          recordStatus: RecordStatusSchema,
        }),
      ),
    }),
    dmarc: CheckSchema.extend({
      stage: z.enum(['missing', 'none', 'quarantine', 'reject']),
      recommendedValue: z.string(),
      nextStep: z.string(),
    }),
  }),
});

export const RotateDkimResponseSchema = z.object({
  domainId: z.uuid(),
  key: DkimKeySchema,
  previous: DkimKeySchema.nullable(),
  dnsRecord: DnsRecordSchema,
  overlapDays: z.number().int(),
});

export type DomainSummary = z.output<typeof DomainSummarySchema>;
export type DomainDetail = z.output<typeof DomainDetailSchema>;
export type CreatedDomain = z.output<typeof CreatedDomainSchema>;
export type DnsRecordView = z.output<typeof DnsRecordSchema>;
export type DkimKeyView = z.output<typeof DkimKeySchema>;
export type CleanupRecordView = z.output<typeof CleanupRecordSchema>;
export type DnsRecordsResponse = z.output<typeof DnsRecordsResponseSchema>;
export type DomainStatusView = z.output<typeof DomainStatusViewSchema>;
export type RotateDkimResponse = z.output<typeof RotateDkimResponseSchema>;
