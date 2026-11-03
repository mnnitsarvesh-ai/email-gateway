import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';
import { normalizeFingerprint } from '../domain/credentials';
import {
  findInternalOverlap,
  MAX_NETWORKS_PER_CONNECTOR,
  NetworkError,
  parseNetwork,
} from '../domain/networks';

/** Request and response shapes of `/smtp-connectors` (§4.1 of docs/plan/steps/04-smtp-gateway.md). */

export const ConnectorIdParamSchema = z.uuid();

export const CONNECTOR_AUTH_TYPES = ['sasl', 'source_ip', 'client_certificate'] as const;
export const ConnectorAuthTypeSchema = z.enum(CONNECTOR_AUTH_TYPES);
export type ConnectorAuthType = z.infer<typeof ConnectorAuthTypeSchema>;
export const ConnectorStatusSchema = z.enum(['active', 'disabled']);

const NameSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[^\p{Cc}]+$/u, 'must not contain control characters');

/** One network: `address/prefix` or a bare address; canonicalized (host bits cleared). */
const NetworkInputSchema = z
  .string()
  .max(64)
  .transform((value, ctx) => {
    try {
      return parseNetwork(value).cidr;
    } catch (err) {
      if (!(err instanceof NetworkError)) throw err;
      ctx.addIssue({ code: 'custom', message: err.message });
      return z.NEVER;
    }
  });

/** Networks of one request must not overlap each other (runs only on valid entries). */
function refineNoInternalOverlap(cidrs: string[], ctx: z.RefinementCtx<string[]>): void {
  if (!cidrs.every((cidr) => typeof cidr === 'string')) return;
  let parsed;
  try {
    parsed = cidrs.map((cidr) => parseNetwork(cidr));
  } catch {
    return; // the entry already has its own issue
  }
  const overlap = findInternalOverlap(parsed);
  if (overlap) {
    ctx.addIssue({
      code: 'custom',
      path: [overlap[1]],
      message: `overlaps networks.${overlap[0]}`,
    });
  }
}

/** 1–20 networks that do not overlap each other. */
const NetworkListSchema = z
  .array(NetworkInputSchema)
  .min(1)
  .max(MAX_NETWORKS_PER_CONNECTOR)
  .superRefine(refineNoInternalOverlap)
  .describe(
    'IPv4/IPv6 CIDR networks (a bare address is a single host); IPv4 prefix ≥ /16, IPv6 ≥ /48; ' +
      'host bits are cleared. Must be publicly routable (non-public ranges are refused unless ' +
      'SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS) and must not overlap any network of any other ' +
      'connector.',
  );

const FingerprintSchema = z
  .string()
  .max(128)
  .transform((value, ctx) => {
    const normalized = normalizeFingerprint(value);
    if (normalized === null) {
      ctx.addIssue({
        code: 'custom',
        message: 'must be a SHA-256 fingerprint: 64 hex characters, with or without colons',
      });
      return z.NEVER;
    }
    return normalized;
  })
  .describe('SHA-256 fingerprint of the client certificate (hex, colons optional)');

const RequireTlsSchema = z
  .boolean()
  .describe(
    'Refuse sessions without STARTTLS (default true). Only source_ip connectors may set false.',
  );

export const CreateConnectorSchema = z
  .strictObject({
    name: NameSchema,
    authType: ConnectorAuthTypeSchema,
    networks: NetworkListSchema.optional(),
    certificateFingerprintSha256: FingerprintSchema.optional(),
    requireTls: RequireTlsSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.authType === 'source_ip' && value.networks === undefined) {
      ctx.addIssue({ code: 'custom', path: ['networks'], message: 'is required for source_ip' });
    }
    if (value.authType === 'sasl' && value.networks !== undefined) {
      ctx.addIssue({ code: 'custom', path: ['networks'], message: 'is not allowed for sasl' });
    }
    if (value.authType === 'client_certificate') {
      if (value.certificateFingerprintSha256 === undefined) {
        ctx.addIssue({
          code: 'custom',
          path: ['certificateFingerprintSha256'],
          message: 'is required for client_certificate',
        });
      }
    } else if (value.certificateFingerprintSha256 !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['certificateFingerprintSha256'],
        message: 'is only allowed for client_certificate',
      });
    }
    if (value.authType !== 'source_ip' && value.requireTls === false) {
      ctx.addIssue({
        code: 'custom',
        path: ['requireTls'],
        message: 'cannot be false: TLS is always required for sasl and client_certificate',
      });
    }
  });
export type CreateConnectorInput = z.output<typeof CreateConnectorSchema>;

export const UpdateConnectorSchema = z
  .strictObject({
    name: NameSchema.optional(),
    status: ConnectorStatusSchema.optional(),
    networks: z
      .array(NetworkInputSchema)
      .max(MAX_NETWORKS_PER_CONNECTOR)
      .superRefine(refineNoInternalOverlap)
      .optional()
      .describe(
        'Replaces every network atomically (same rules as on create). source_ip needs at least ' +
          'one; client_certificate may clear them with []; sasl connectors have none.',
      ),
    requireTls: RequireTlsSchema.optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'must change at least one field' });
export type UpdateConnectorInput = z.output<typeof UpdateConnectorSchema>;

export const ListConnectorsQuerySchema = PageQuerySchema.extend({
  status: ConnectorStatusSchema.optional(),
  authType: ConnectorAuthTypeSchema.optional(),
});
export type ListConnectorsQuery = z.output<typeof ListConnectorsQuerySchema>;

// ---- Responses ---------------------------------------------------------------------------

const IsoDate = z.iso.datetime();

export const ConnectorNetworkSchema = z.object({
  cidr: z.string().describe('Canonical CIDR'),
  ipVersion: z.union([z.literal(4), z.literal(6)]),
});

export const ConnectorSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  authType: ConnectorAuthTypeSchema,
  status: ConnectorStatusSchema,
  saslUsername: z.string().nullable().describe('sasl only'),
  certificateFingerprintSha256: z
    .string()
    .nullable()
    .describe('client_certificate only; lower-case hex'),
  networks: z.array(ConnectorNetworkSchema),
  requireTls: z.boolean(),
  secretSetAt: IsoDate.nullable().describe('sasl only: when the current password was issued'),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type ConnectorView = z.output<typeof ConnectorSchema>;

export const ConnectorCredentialsSchema = z
  .object({
    username: z.string(),
    password: z.string().describe('Shown once; store it now. Only a hash is kept.'),
  })
  .describe('SMTP AUTH credentials (PLAIN/LOGIN over STARTTLS on port 587)');
export type ConnectorCredentials = z.output<typeof ConnectorCredentialsSchema>;

export const CreatedConnectorSchema = ConnectorSchema.extend({
  credentials: ConnectorCredentialsSchema.optional().describe('sasl only, returned once'),
});
export type CreatedConnector = z.output<typeof CreatedConnectorSchema>;

export const RotatedSecretSchema = z.object({
  id: z.uuid(),
  credentials: ConnectorCredentialsSchema,
  secretSetAt: IsoDate,
});
export type RotatedSecret = z.output<typeof RotatedSecretSchema>;

export const ConnectorPageSchema = z.object({
  data: z.array(ConnectorSchema),
  nextCursor: z.string().nullable(),
});
