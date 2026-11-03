import { TLS_MODES } from '@email-gateway/mail-routing';
import { z } from 'zod';

/**
 * Request and response shapes of `/destination-providers` and `/domains/{id}/destinations`
 * (step 2.3 R13, docs/plan/steps/05-routing.md).
 */

/** Hard upper bound of custom servers per request; ROUTING_MAX_DESTINATIONS_PER_DOMAIN ≤ 10. */
export const MAX_CUSTOM_SERVERS = 10;

export const PROVIDERS = ['custom', 'microsoft_365', 'google_workspace'] as const;
export const ProviderSchema = z.enum(PROVIDERS);
export const TlsModeSchema = z.enum(TLS_MODES);

const HostSchema = z
  .string()
  .trim()
  .min(1)
  .max(255)
  .describe(
    'Host name (IDN allowed, stored as ASCII) or IP literal. Refused (422 with `reason`): ' +
      'non-public or metadata IP addresses, single-label names, internal suffixes, the gateway ' +
      'itself.',
  );

/** Postfix `match=` list: no spaces or `=`, so it can never inject another policy attribute. */
const VerifyNamesSchema = z
  .string()
  .regex(/^[A-Za-z0-9.:-]{1,512}$/, 'must be a `:`-separated list of names (A-Z a-z 0-9 . : -)')
  .describe(
    'Postfix `match=` list for tlsMode verify (`:`-separated; `nexthop`, `dot-nexthop`, names, ' +
      '`.suffix`). Omitted: `nexthop`.',
  );

const CustomServerSchema = z
  .strictObject({
    host: HostSchema,
    port: z
      .number()
      .int()
      .min(1)
      .max(65_535)
      .optional()
      .describe(
        'Default 25. Must be one of ROUTING_ALLOWED_DESTINATION_PORTS (default 25, 587, 2525); ' +
          'other ports are refused with 422 port_not_allowed',
      ),
    priority: z
      .number()
      .int()
      .min(0)
      .max(65_535)
      .optional()
      .describe('Lower is tried first; ties in list order. Default 10'),
    tlsMode: TlsModeSchema.optional().describe(
      'none | opportunistic (default) | required (encrypt, TLS ≥ 1.2) | verify (certificate ' +
        'verified against tlsVerifyNames)',
    ),
    tlsVerifyNames: VerifyNamesSchema.optional(),
  })
  .superRefine((server, ctx) => {
    if (server.tlsVerifyNames !== undefined && server.tlsMode !== 'verify') {
      ctx.addIssue({
        code: 'custom',
        path: ['tlsVerifyNames'],
        message: 'is only allowed with tlsMode verify',
      });
    }
  });
export type CustomServerInput = z.output<typeof CustomServerSchema>;

export const PutDestinationsSchema = z.discriminatedUnion('provider', [
  z
    .strictObject({
      provider: z.literal('microsoft_365'),
      host: HostSchema.describe(
        'The "points to address" of the domain’s MX in the Microsoft 365 admin center, e.g. ' +
          '`contoso-com.mail.protection.outlook.com`. Port 25 and verified TLS are forced.',
      ),
    })
    .describe('Microsoft 365 (Exchange Online): exactly one host of the preset’s patterns'),
  z
    .strictObject({ provider: z.literal('google_workspace') })
    .describe('Google Workspace: the preset’s servers (aspmx.l + alt1–4), verified TLS'),
  z
    .strictObject({
      provider: z.literal('custom'),
      servers: z
        .array(CustomServerSchema)
        .min(1)
        .max(MAX_CUSTOM_SERVERS)
        .describe('1..ROUTING_MAX_DESTINATIONS_PER_DOMAIN servers; host:port must be unique'),
    })
    .describe('Your own servers'),
]);
export type PutDestinationsInput = z.output<typeof PutDestinationsSchema>;

// ---- Responses ---------------------------------------------------------------------------

const IsoDate = z.iso.datetime();

export const DestinationServerSchema = z.object({
  id: z.uuid(),
  host: z.string(),
  port: z.number().int(),
  priority: z.number().int(),
  tlsMode: TlsModeSchema,
  tlsVerifyNames: z.string().nullable().describe('Postfix match= list; null = nexthop'),
  enabled: z.boolean(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type DestinationServerView = z.output<typeof DestinationServerSchema>;

export const DomainDestinationsSchema = z.object({
  provider: ProviderSchema.nullable().describe('null when the domain has no destination'),
  servers: z
    .array(DestinationServerSchema)
    .describe('In delivery order: (priority, insertion order); Postfix fails over in this order'),
});
export type DomainDestinationsView = z.output<typeof DomainDestinationsSchema>;

export const DestinationProviderSchema = z.object({
  provider: ProviderSchema,
  displayName: z.string(),
  hostHint: z.string().nullable(),
  hostPatterns: z.array(z.string()).describe('Anchored regular expressions (lower-case hosts)'),
  port: z.number().int(),
  tlsMode: TlsModeSchema,
  tlsVerifyNames: z.string(),
  maxServers: z.number().int(),
  defaultServers: z
    .array(z.object({ host: z.string(), priority: z.number().int() }))
    .nullable()
    .describe('Servers the preset provides; null = you supply the host'),
  documentationUrl: z.string().nullable(),
});
export type DestinationProviderView = z.output<typeof DestinationProviderSchema>;

export const DestinationProviderListSchema = z.object({ data: z.array(DestinationProviderSchema) });
export type DestinationProviderList = z.output<typeof DestinationProviderListSchema>;
