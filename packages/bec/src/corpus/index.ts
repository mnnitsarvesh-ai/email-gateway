import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { PACKAGE_DIR } from '../data';
import type { BecEvaluationInput, BecHistoryInput, BecTenantData } from '../rules/types';

/**
 * Fixture corpus (`fixtures/corpus/*.json`, §9): synthetic scenarios with expected verdicts and
 * required / forbidden codes. Used by the corpus test and as the templates of the seeded
 * training-set generator. Not part of the runtime API (not exported from the package index).
 */

export const CORPUS_DIR = join(PACKAGE_DIR, 'fixtures', 'corpus');

const date = z.string().datetime();
const authRow = z.strictObject({
  spf: z.string().nullable(),
  spfDomain: z.string().nullable(),
  dkim: z.string().nullable(),
  dkimSignatures: z.array(
    z.strictObject({
      domain: z.string(),
      result: z.string(),
      selector: z.string().nullable().optional(),
    }),
  ),
  dmarc: z.string().nullable(),
  dmarcPolicy: z.enum(['none', 'quarantine', 'reject']).nullable(),
  dmarcDomain: z.string().nullable(),
  arc: z.string().nullable(),
});
const historyRow = z.strictObject({
  messageCount: z.number().int().min(0),
  firstSeenAt: date,
  lastSeenAt: date,
  infra: z
    .array(z.strictObject({ fp: z.string(), count: z.number().int(), lastSeenAt: date }))
    .optional(),
});
const tenantSchema = z.strictObject({
  tenantDomains: z.array(z.string()),
  executives: z.array(
    z.strictObject({
      publicId: z.string(),
      name: z.string(),
      aliases: z.array(z.string()),
      knownAddresses: z.array(z.string()),
    }),
  ),
  vendors: z.array(
    z.strictObject({
      publicId: z.string(),
      name: z.string(),
      aliases: z.array(z.string()),
      domains: z.array(z.string()),
      knownSenders: z.array(z.string()),
      paymentChangeSensitive: z.boolean(),
    }),
  ),
  trustedSenders: z.array(
    z.strictObject({
      publicId: z.string(),
      kind: z.enum(['address', 'domain']),
      value: z.string(),
      expiresAt: date.nullable(),
    }),
  ),
  suppressions: z.array(
    z.strictObject({
      publicId: z.string(),
      reasonCode: z.string(),
      senderScope: z.enum(['address', 'domain']),
      senderValue: z.string(),
      expiresAt: date,
    }),
  ),
  freemailExtraDomains: z.array(z.string()),
  extraProtectedDomains: z.array(z.string()),
});
const historySchema = z.union([
  z.literal('disabled'),
  z.literal('error'),
  z.strictObject({
    sender: historyRow.nullable(),
    pairs: z.array(historyRow.nullable()),
    fingerprintHash: z.string().nullable(),
  }),
]);
const envelopeSchema = z.strictObject({
  direction: z.enum(['inbound', 'outbound', 'internal']),
  envelopeFrom: z.string().nullable(),
  recipients: z.array(z.string()),
  clientIp: z.string().nullable(),
  receivedAt: date,
});

const fixtureSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9-]+$/),
  description: z.string(),
  /** Training label (null: not used for training, e.g. missing-input cases). */
  label: z.enum(['bec', 'benign']).nullable(),
  input: z.strictObject({
    headers: z.record(z.string(), z.array(z.string())),
    envelope: envelopeSchema.partial(),
    auth: z.union([
      z.strictObject({ state: z.literal('available'), row: authRow }),
      z.strictObject({ state: z.enum(['failed', 'missing', 'not_in_round']) }),
    ]),
    url: z.union([
      z.strictObject({
        state: z.literal('available'),
        rows: z.array(
          z.strictObject({
            urlSeq: z.number().int(),
            verdict: z.enum(['clean', 'unknown', 'suspicious', 'malicious']),
            reasonCodes: z.array(z.string()),
            host: z.string().nullable().optional(),
            registrableDomain: z.string().nullable().optional(),
          }),
        ),
      }),
      z.strictObject({ state: z.enum(['failed', 'not_in_round']) }),
    ]),
    text: z.strictObject({
      subject: z.string().nullable(),
      text: z.string().nullable(),
      html: z.string().nullable(),
      parseIncomplete: z.boolean().optional(),
    }),
    tenant: tenantSchema.partial().optional(),
    history: historySchema.optional(),
  }),
  expected: z.strictObject({
    verdict: z.enum(['clean', 'suspicious', 'malicious', 'unknown', 'skipped']).optional(),
    verdictIn: z
      .array(z.enum(['clean', 'suspicious', 'malicious', 'unknown', 'skipped']))
      .optional(),
    requiredCodes: z.array(z.string()).optional(),
    requiredAnyCodes: z.array(z.string()).optional(),
    forbiddenCodes: z.array(z.string()).optional(),
  }),
});
export type CorpusFixture = z.infer<typeof fixtureSchema>;

const defaultsSchema = z.strictObject({
  description: z.string(),
  tenant: tenantSchema,
  envelope: envelopeSchema.omit({ envelopeFrom: true }),
  history: historySchema,
});

const toHistory = (value: z.infer<typeof historySchema>): BecHistoryInput => {
  if (typeof value === 'string') return value;
  const row = (r: z.infer<typeof historyRow> | null) =>
    r && {
      messageCount: r.messageCount,
      firstSeenAt: new Date(r.firstSeenAt),
      lastSeenAt: new Date(r.lastSeenAt),
      infra: r.infra ?? [],
    };
  return {
    sender: row(value.sender),
    pairs: value.pairs.map(row),
    fingerprintHash: value.fingerprintHash,
  };
};

const toTenant = (value: z.infer<typeof tenantSchema>): BecTenantData => ({
  ...value,
  trustedSenders: value.trustedSenders.map((t) => ({
    ...t,
    expiresAt: t.expiresAt ? new Date(t.expiresAt) : null,
  })),
  suppressions: value.suppressions.map((s) => ({ ...s, expiresAt: new Date(s.expiresAt) })),
});

export interface LoadedFixture {
  fixture: CorpusFixture;
  input: BecEvaluationInput;
}

export function toEvaluationInput(
  fixture: CorpusFixture,
  defaults: z.infer<typeof defaultsSchema>,
): BecEvaluationInput {
  const i = fixture.input;
  const envelope = { ...defaults.envelope, envelopeFrom: null, ...i.envelope };
  return {
    headers: i.headers,
    envelope: { ...envelope, receivedAt: new Date(envelope.receivedAt) },
    auth: i.auth as BecEvaluationInput['auth'],
    url: i.url,
    text: {
      subject: i.text.subject,
      textBody: i.text.text === null ? null : { content: i.text.text, truncated: false },
      htmlBody: i.text.html === null ? null : { content: i.text.html, truncated: false },
      parseIncomplete: i.text.parseIncomplete ?? false,
    },
    tenant: toTenant({ ...defaults.tenant, ...(i.tenant ?? {}) }),
    history: toHistory(i.history ?? defaults.history),
  };
}

/** All fixtures, sorted by id. */
export function loadCorpus(dir: string = CORPUS_DIR): LoadedFixture[] {
  const defaults = defaultsSchema.parse(
    JSON.parse(readFileSync(join(dir, '_defaults.json'), 'utf8')),
  );
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json') && !f.startsWith('_'))
    .sort()
    .map((file) => {
      const fixture = fixtureSchema.parse(JSON.parse(readFileSync(join(dir, file), 'utf8')));
      if (`${fixture.id}.json` !== file) throw new Error(`corpus ${file}: id mismatch`);
      return { fixture, input: toEvaluationInput(fixture, defaults) };
    });
}
