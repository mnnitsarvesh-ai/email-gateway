import { z } from 'zod';
import { intakeRecipientFieldSchema, storedAddressSchema } from '../documents/common';
import { PROVIDER_DKIM_RESULTS } from '../vocabulary';
import { INTAKE_NETWORKS_MAX, INTAKE_NETWORKS_MIN, parseCidr } from './networks';

/**
 * Documents of journal intake (step 8.6 §4.2), strict zod schemas with examples:
 *
 * - `journal-envelope/1` (`journal_intake_messages.envelope`): the journal envelope of one intake
 *   message (BCC included), with the field each recipient came from;
 * - `journal-intake-proof/1` (`journal_intake_messages.proof`): the codes of a passing sender
 *   proof (only passing proofs are stored);
 * - `intake-networks/1` (`journal_intake_sources.networks`).
 *
 * No document holds a secret: the address and header tokens are stored as SHA-256 only, in their
 * own columns.
 */

/** Recipient cap of the envelope (`JOURNAL_INTAKE_MAX_RECIPIENTS` default and schema bound). */
export const JOURNAL_ENVELOPE_MAX_RECIPIENTS = 10_000;

export const journalEnvelopeRecipientSchema = z.strictObject({
  /** `local@domain`, domain lower-cased. */
  address: storedAddressSchema.min(3),
  field: intakeRecipientFieldSchema,
  /** The distribution list this recipient was expanded from (`, Expanded: <dl>`). */
  expandedFrom: storedAddressSchema.min(3).optional(),
  /** The address that forwarded to this recipient (`, Forwarded: <addr>`). */
  forwardedFrom: storedAddressSchema.min(3).optional(),
});
export type JournalEnvelopeRecipient = z.infer<typeof journalEnvelopeRecipientSchema>;

export const journalEnvelopeSchema = z.strictObject({
  v: z.literal(1),
  /** `Sender:` of the report (copy kinds: null). */
  sender: storedAddressSchema.nullable(),
  /** `On-Behalf-Of:` of the report. */
  onBehalfOf: storedAddressSchema.nullable(),
  /** `Message-Id:` of the report, as written (angle brackets kept). */
  messageId: z.string().max(998).nullable(),
  recipients: z.array(journalEnvelopeRecipientSchema).max(JOURNAL_ENVELOPE_MAX_RECIPIENTS),
  /** Recipients were dropped beyond the cap. */
  truncated: z.boolean(),
  /** The envelope's Message-Id differs from the embedded message's (recorded, not refused). */
  envelopeMismatch: z.boolean(),
});
export type JournalEnvelope = z.infer<typeof journalEnvelopeSchema>;

export const JOURNAL_ENVELOPE_EXAMPLE: JournalEnvelope = {
  v: 1,
  sender: 'alice@example.com',
  onBehalfOf: null,
  messageId: '<example-1@example.com>',
  recipients: [
    { address: 'bob@example.org', field: 'to' },
    { address: 'carol@example.com', field: 'cc' },
    { address: 'dave@example.com', field: 'bcc' },
    { address: 'erin@example.com', field: 'to', expandedFrom: 'team@example.com' },
  ],
  truncated: false,
  envelopeMismatch: false,
};

export const JOURNAL_INTAKE_PROOF_NETWORKS = ['provider_egress', 'source_networks'] as const;

export const journalIntakeProofSchema = z.strictObject({
  v: z.literal(1),
  /** How the connecting client was authorized at RCPT. */
  network: z.enum(JOURNAL_INTAKE_PROOF_NETWORKS),
  /** The session used TLS. */
  tls: z.boolean(),
  clientCert: z.enum(['match', 'n/a']),
  /** Microsoft 365: every `X-MS-Exchange-CrossTenant-Id` equals the bound tenant. */
  tenantHeader: z.enum(['match', 'mismatch', 'absent', 'n/a']),
  /** Google Workspace: the `X-EG-Journal-Token` matched the current or the previous token. */
  headerToken: z.enum(['match', 'previous', 'mismatch', 'absent', 'n/a']),
  /** DKIM evidence (recorded, never required). */
  dkim: z.strictObject({
    result: z.enum([...PROVIDER_DKIM_RESULTS, 'n/a']),
    domains: z.array(z.string().min(1).max(253)).max(5),
  }),
  result: z.literal('pass'),
});
export type JournalIntakeProof = z.infer<typeof journalIntakeProofSchema>;

export const JOURNAL_INTAKE_PROOF_EXAMPLE: JournalIntakeProof = {
  v: 1,
  network: 'provider_egress',
  tls: true,
  clientCert: 'n/a',
  tenantHeader: 'match',
  headerToken: 'n/a',
  dkim: { result: 'aligned_pass', domains: ['example.com'] },
  result: 'pass',
};

/** A canonical network as `validateIntakeNetworks` writes it. */
const networkText = z
  .string()
  .min(2)
  .max(64)
  .refine((v) => {
    const parsed = parseCidr(v);
    return parsed !== null && !parsed.hostBitsSet && parsed.text === v;
  }, 'must be a canonical CIDR');

export const intakeNetworksSchema = z.strictObject({
  v: z.literal(1),
  cidrs: z
    .array(networkText)
    .min(INTAKE_NETWORKS_MIN)
    .max(INTAKE_NETWORKS_MAX)
    .refine((list) => new Set(list).size === list.length, {
      message: 'must not contain duplicates',
    }),
});
export type IntakeNetworks = z.infer<typeof intakeNetworksSchema>;

export const INTAKE_NETWORKS_EXAMPLE: IntakeNetworks = {
  v: 1,
  cidrs: ['198.51.100.0/24', '2001:db8:10::/48'],
};
