import {
  RISK_ACTIONS,
  RISK_HARD_BLOCK_IDS,
  RISK_LEVELS,
  RISK_VERDICTS,
  SANDBOX_INPUT_OUTCOMES,
} from '@email-gateway/risk-scoring';
import {
  ATTACHMENT_VERDICTS,
  AUTH_OUTCOMES,
  BEC_VERDICTS,
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_COVERAGES,
  DLP_SEVERITIES,
  DLP_VERDICTS,
  DMARC_POLICIES,
  ENGINE_NAMES,
  FILE_TYPE_FAMILIES,
  reasonCodeSchema,
  REWRITE_SKIP_REASONS,
  SCAN_VERDICTS,
  URL_VERDICTS,
} from '@email-gateway/security-contracts';
import { getDomain } from 'tldts';
import { z } from 'zod';
import {
  directoryIdSchema,
  ENGINE_FINAL_STATES,
  extensionOf,
  PolicyInputError,
  policyInputSchema,
  RISK_FAILURE_STATUSES,
  riskRowLevelOnly,
  SCAN_ENGINE_OUTCOMES,
  sortStrings,
  toAddr,
  TRUSTED_CODES,
  type PolicyInput,
} from './input';
import { formatIp, normalizeAddress, normalizeDomain, parseIp } from './matchers';
import { POLICY_INPUT_VERSION, POLICY_MESSAGE_DIRECTIONS, POLICY_TRIGGERS } from './vocabulary';

/**
 * Synthetic facts for policy testing (step 5.2 P23): a strict, friendly document where every
 * field is optional with a documented default. `buildSyntheticInput` turns it into a normal
 * `PolicyInput`; the evaluator is the same. Nothing is written; the synthetic risk row is
 * trusted only for the test.
 */

const codes = z.array(reasonCodeSchema).max(32);
const optionalNullable = <T extends z.ZodType>(schema: T) => schema.nullable().optional();

const syntheticRiskSchema = z.strictObject({
  status: z.enum(['scored', 'error']).optional(),
  score: z.number().int().min(0).max(1000).optional(),
  level: z.enum(RISK_LEVELS).optional(),
  verdict: z.enum(RISK_VERDICTS).optional(),
  recommendedAction: z.enum(RISK_ACTIONS).optional(),
  hardBlocks: z
    .array(z.strictObject({ id: z.enum(RISK_HARD_BLOCK_IDS), action: z.enum(RISK_ACTIONS) }))
    .max(RISK_HARD_BLOCK_IDS.length)
    .optional(),
  reasonCodes: codes.optional(),
  failureStatuses: z.array(z.enum(RISK_FAILURE_STATUSES)).max(5).optional(),
  levelOnly: z.boolean().optional(),
  aiRaiseOnly: z.boolean().optional(),
  sandboxOutcome: optionalNullable(z.enum(SANDBOX_INPUT_OUTCOMES)),
});

const addressText = z.string().min(1).max(320);
const directoryMap = z.record(addressText, z.array(directoryIdSchema).max(1000));

export const syntheticFactsSchema = z.strictObject({
  /** Default `scanned`. */
  trigger: z.enum(POLICY_TRIGGERS).optional(),
  /** Default `inbound`. */
  direction: z.enum(POLICY_MESSAGE_DIRECTIONS).optional(),
  /** Default `2026-01-01T12:00:00.000Z` (the api passes the request time). */
  evaluationTime: z.iso.datetime({ offset: false, precision: 3 }).optional(),
  lifecycleRound: z.number().int().min(0).max(65_535).optional(),
  message: z.strictObject({ sizeBytes: z.number().int().min(0).optional() }).optional(),
  sender: z
    .strictObject({
      /** Default `sender@example.com`; null = null sender. */
      envelope: optionalNullable(addressText),
      /** Default: the envelope sender. */
      headerFrom: optionalNullable(addressText),
      /** Default false: the authenticated sender is header From (inbound) or envelope. */
      authenticated: z.boolean().optional(),
      /** Default: derived like the input builder (inbound only). */
      trusted: optionalNullable(z.boolean()),
    })
    .optional(),
  /** Default one recipient `recipient@example.net`. */
  recipients: z
    .array(z.strictObject({ address: addressText }))
    .max(100)
    .optional(),
  client: z
    .strictObject({
      ip: optionalNullable(z.string().max(64)),
      hostname: optionalNullable(z.string().max(253)),
    })
    .optional(),
  /** Default null (no authentication row). */
  auth: optionalNullable(
    z.strictObject({
      spf: optionalNullable(z.enum(AUTH_OUTCOMES)),
      dkim: optionalNullable(z.enum(AUTH_OUTCOMES)),
      dmarc: optionalNullable(z.enum(AUTH_OUTCOMES)),
      dmarcPolicy: optionalNullable(z.enum(DMARC_POLICIES)),
      arc: optionalNullable(z.enum(AUTH_OUTCOMES)),
    }),
  ),
  attachments: z
    .array(
      z.strictObject({
        filename: optionalNullable(z.string().min(1).max(255)),
        declaredType: optionalNullable(z.string().min(1).max(255)),
        detectedType: optionalNullable(z.string().min(1).max(32)),
        typeFamily: optionalNullable(z.enum(FILE_TYPE_FAMILIES)),
        sizeBytes: z.number().int().min(0).optional(),
        sha256: z
          .string()
          .regex(/^[0-9a-fA-F]{64}$/)
          .optional(),
        verdict: optionalNullable(z.enum(ATTACHMENT_VERDICTS)),
        reasonCodes: optionalNullable(codes),
        isArchive: z.boolean().optional(),
        encrypted: z.boolean().optional(),
        typeMismatch: optionalNullable(z.boolean()),
      }),
    )
    .max(50)
    .optional(),
  urls: z
    .array(
      z.strictObject({
        host: z.string().min(1).max(253),
        /** Default: the registrable domain of `host` (tldts); null for IP hosts. */
        domain: optionalNullable(z.string().min(1).max(253)),
        scheme: z.enum(['http', 'https']).optional(),
        verdict: optionalNullable(z.enum(URL_VERDICTS)),
        reasonCodes: optionalNullable(codes),
      }),
    )
    .max(100)
    .optional(),
  urlRewriteStatus: z.enum(['rewritten', 'skipped', 'none']).optional(),
  urlRewriteSkipReason: optionalNullable(z.enum(REWRITE_SKIP_REASONS)),
  /** Default: a clean revision 0 (`deliver`, level `none`); null = no risk row. */
  risk: optionalNullable(
    z.strictObject({
      rev0: optionalNullable(syntheticRiskSchema),
      rev1: optionalNullable(syntheticRiskSchema),
    }),
  ),
  /** Default null (no DLP row). */
  dlp: optionalNullable(
    z.strictObject({
      action: z.enum(DLP_ACTIONS),
      verdict: z.enum(DLP_VERDICTS).optional(),
      coverage: z.enum(DLP_COVERAGES).optional(),
      categories: z.array(z.enum(DLP_CATEGORIES)).max(DLP_CATEGORIES.length).optional(),
      maxSeverity: optionalNullable(z.enum(DLP_SEVERITIES)),
      detectorCodes: codes.optional(),
    }),
  ),
  /** Default `definite` with a DLP row, else `absent`. */
  dlpFinal: z.enum(ENGINE_FINAL_STATES).optional(),
  /** Default null (no BEC row). */
  bec: optionalNullable(
    z.strictObject({
      deterministicVerdict: z.enum(BEC_VERDICTS),
      verdict: z.enum(BEC_VERDICTS).optional(),
      aiRaised: z.boolean().optional(),
      ruleCodes: z.array(reasonCodeSchema).max(64).optional(),
      trustedCode: z.enum(TRUSTED_CODES).optional(),
    }),
  ),
  becFinal: z.enum(ENGINE_FINAL_STATES).optional(),
  scan: z
    .strictObject({
      verdict: optionalNullable(z.enum(SCAN_VERDICTS)),
      reasonCodes: codes.optional(),
      engines: z
        .array(
          z.strictObject({
            engine: z.enum(ENGINE_NAMES),
            required: z.boolean().optional(),
            outcome: z.enum(SCAN_ENGINE_OUTCOMES),
          }),
        )
        .max(ENGINE_NAMES.length)
        .optional(),
    })
    .optional(),
  /** Memberships by address (the api may resolve them from the replica instead). */
  directory: z
    .strictObject({ departments: directoryMap.optional(), users: directoryMap.optional() })
    .optional(),
  /** Api flag: resolve the directory live from the replica (ignored by the builder). */
  resolveDirectory: z.boolean().optional(),
});
export type SyntheticFacts = z.infer<typeof syntheticFactsSchema>;

export const SYNTHETIC_DEFAULT_TIME = '2026-01-01T12:00:00.000Z';
const ZERO_SHA = '0'.repeat(64);

function normalizeMap(map: Readonly<Record<string, readonly string[]>> | undefined) {
  const out: Record<string, string[]> = {};
  for (const [address, ids] of Object.entries(map ?? {})) {
    const key = normalizeAddress(address).address;
    out[key] = sortStrings([...(out[key] ?? []), ...ids]);
  }
  return out;
}

function riskOf(r: z.infer<typeof syntheticRiskSchema>, revision: 0 | 1) {
  const status = r.status ?? 'scored';
  const hardBlocks = [...(r.hardBlocks ?? [])].sort((a, b) => (a.id < b.id ? -1 : 1));
  const reasonCodes = sortStrings(r.reasonCodes ?? []);
  const failureStatuses = sortStrings(
    r.failureStatuses ?? [],
  ) as (typeof RISK_FAILURE_STATUSES)[number][];
  const derived = riskRowLevelOnly({
    status,
    hardBlocks,
    failures: failureStatuses,
    engines: [],
    reasonCodes,
  });
  return {
    status,
    score: r.score ?? 0,
    level: r.level ?? 'none',
    verdict: r.verdict ?? 'clean',
    recommendedAction: r.recommendedAction ?? 'deliver',
    hardBlocks,
    reasonCodes,
    failureStatuses,
    levelOnly: r.levelOnly ?? derived,
    aiRaiseOnly: r.aiRaiseOnly ?? false,
    sandboxOutcome: revision === 1 ? (r.sandboxOutcome ?? null) : null,
  };
}

/** Synthetic facts → `PolicyInput` (P23). Throws `PolicyInputError` on invalid facts. */
export function buildSyntheticInput(raw: SyntheticFacts): PolicyInput {
  const parsed = syntheticFactsSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new PolicyInputError(
      `Invalid synthetic facts at ${first?.path.map(String).join('.') ?? ''}: ${first?.message ?? 'invalid'}`,
    );
  }
  const f = parsed.data;
  const trigger = f.trigger ?? 'scanned';
  const direction = f.direction ?? 'inbound';
  const departments = normalizeMap(f.directory?.departments);
  const users = normalizeMap(f.directory?.users);
  const envelopeText = f.sender?.envelope === undefined ? 'sender@example.com' : f.sender.envelope;
  const envelope = toAddr(envelopeText);
  const headerFrom = toAddr(
    f.sender?.headerFrom === undefined ? envelopeText : f.sender.headerFrom,
  );
  const authenticated = f.sender?.authenticated
    ? direction === 'inbound'
      ? headerFrom
      : envelope
    : null;
  const auth = f.auth
    ? {
        spf: f.auth.spf ?? null,
        dkim: f.auth.dkim ?? null,
        dmarc: f.auth.dmarc ?? null,
        dmarcPolicy: f.auth.dmarcPolicy ?? null,
        arc: f.auth.arc ?? null,
      }
    : null;
  const bec = f.bec
    ? {
        deterministicVerdict: f.bec.deterministicVerdict,
        verdict: f.bec.verdict ?? f.bec.deterministicVerdict,
        aiRaised: f.bec.aiRaised ?? false,
        ruleCodes: sortStrings(f.bec.ruleCodes ?? []),
        trustedCode: f.bec.trustedCode ?? 'none',
      }
    : null;
  const trusted =
    f.sender?.trusted !== undefined
      ? f.sender.trusted
      : direction !== 'inbound'
        ? false
        : bec === null || auth === null
          ? null
          : bec.trustedCode === 'authenticated' && auth.dmarc === 'pass' && authenticated !== null;
  const senderKey = direction === 'inbound' ? null : (authenticated?.address ?? null);
  const recipients = (f.recipients ?? [{ address: 'recipient@example.net' }]).map((r, i) => {
    const n = normalizeAddress(r.address);
    return {
      rcptSeq: i,
      address: n.address,
      domain: n.domain,
      localPart: n.localPart,
      departments: departments[n.address] ?? [],
      users: users[n.address] ?? [],
    };
  });
  const attachments = (f.attachments ?? []).map((a, i) => ({
    partIndex: i,
    extension: extensionOf(a.filename ?? null),
    filename: a.filename ?? null,
    declaredType: a.declaredType?.toLowerCase() ?? null,
    detectedType: a.detectedType ?? null,
    typeFamily: a.typeFamily ?? null,
    sizeBytes: a.sizeBytes ?? 0,
    sha256: (a.sha256 ?? ZERO_SHA).toLowerCase(),
    verdict: a.verdict ?? null,
    reasonCodes:
      a.reasonCodes === undefined || a.reasonCodes === null ? null : sortStrings(a.reasonCodes),
    isArchive: a.isArchive ?? a.typeFamily === 'archive',
    encrypted: a.encrypted ?? false,
    typeMismatch: a.typeMismatch ?? null,
  }));
  const urls = (f.urls ?? []).map((u, i) => {
    const ip = parseIp(u.host.replace(/^\[|\]$/g, ''));
    const host = ip ? formatIp(ip) : normalizeDomain(u.host);
    if (host === null) throw new PolicyInputError(`Invalid synthetic url host at urls.${i}.host`);
    const domain =
      u.domain !== undefined
        ? u.domain === null
          ? null
          : normalizeDomain(u.domain)
        : ip
          ? null
          : normalizeDomain(getDomain(host, { allowPrivateDomains: true }) ?? host);
    return {
      urlSeq: i,
      host,
      domain,
      scheme: u.scheme ?? 'https',
      hostKind: ip ? (ip.family === 4 ? 'ipv4' : 'ipv6') : 'domain',
      verdict: u.verdict ?? null,
      reasonCodes:
        u.reasonCodes === undefined || u.reasonCodes === null ? null : sortStrings(u.reasonCodes),
    };
  });
  const clientIp = f.client?.ip ? parseIp(f.client.ip) : null;
  const risk =
    f.risk === null
      ? { rev0: null, rev1: null }
      : {
          rev0:
            f.risk?.rev0 === undefined
              ? riskOf({}, 0)
              : f.risk.rev0 === null
                ? null
                : riskOf(f.risk.rev0, 0),
          rev1: f.risk?.rev1 ? riskOf(f.risk.rev1, 1) : null,
        };
  const dlp = f.dlp
    ? {
        action: f.dlp.action,
        verdict: f.dlp.verdict ?? (f.dlp.action === 'allow' ? 'clean' : 'suspicious'),
        coverage: f.dlp.coverage ?? 'complete',
        categories: sortStrings(f.dlp.categories ?? []),
        maxSeverity: f.dlp.maxSeverity ?? null,
        detectorCodes: sortStrings(f.dlp.detectorCodes ?? []),
      }
    : null;
  const notScanned = trigger === 'parse_failed';
  const input = {
    version: POLICY_INPUT_VERSION,
    trigger,
    evaluationTime: f.evaluationTime ?? SYNTHETIC_DEFAULT_TIME,
    direction,
    round: {
      lifecycleRound: f.lifecycleRound ?? 0,
      scanId: notScanned ? null : '0',
      scanKind: notScanned ? null : 'initial',
    },
    message: {
      sizeBytes: f.message?.sizeBytes ?? 0,
      recipientCount: recipients.length,
      attachmentCount: attachments.length,
    },
    sender: {
      envelope,
      headerFrom,
      authenticated,
      trusted,
      departments: senderKey ? (departments[senderKey] ?? []) : [],
      users: senderKey ? (users[senderKey] ?? []) : [],
    },
    recipients,
    recipientsTruncated: false,
    client: {
      ip: clientIp ? formatIp(clientIp) : null,
      hostname: f.client?.hostname ? normalizeDomain(f.client.hostname) : null,
    },
    auth,
    attachments: {
      count: attachments.length,
      totalBytes: attachments.reduce((s, a) => s + a.sizeBytes, 0),
      truncated: false,
      items: attachments,
    },
    urls: {
      count: urls.length,
      truncated: false,
      rewriteStatus: f.urlRewriteStatus ?? 'none',
      rewriteSkipReason: f.urlRewriteSkipReason ?? null,
      items: urls,
    },
    scan: {
      outcome: notScanned ? 'not_scanned' : trigger,
      verdict: notScanned ? null : (f.scan?.verdict ?? null),
      reasonCodes: notScanned ? [] : sortStrings(f.scan?.reasonCodes ?? []),
      engines: notScanned
        ? []
        : [...(f.scan?.engines ?? [])]
            .map((e) => ({ engine: e.engine, required: e.required ?? true, outcome: e.outcome }))
            .sort((a, b) => (a.engine < b.engine ? -1 : 1)),
    },
    risk: notScanned ? { rev0: null, rev1: null } : risk,
    dlp,
    dlpFinal: f.dlpFinal ?? (dlp ? 'definite' : 'absent'),
    bec,
    becFinal: f.becFinal ?? (bec ? 'definite' : 'absent'),
  };
  const result = policyInputSchema.safeParse(input);
  if (!result.success) {
    const first = result.error.issues[0];
    throw new PolicyInputError(
      `Invalid synthetic facts at ${first?.path.map(String).join('.') ?? ''}: ${first?.message ?? 'invalid'}`,
    );
  }
  return result.data;
}
