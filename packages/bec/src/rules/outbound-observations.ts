import { analyzeText, type AnalyzeOptions, type TextInput } from '../text/analyze';
import type { Lexicon, LexiconCategory } from '../text/lexicon';
import type { BecUrlInput, BecUrlRow } from './types';

/**
 * Outbound observations of the BEC engine (step 8.4 D6, extends ADR-0033 B1 additively; the "one
 * outbound mode" of the ATP gap analysis §3.11, extended later by ATP-7).
 *
 * For outbound and internal mail the BEC verdict stays `skipped` (`bec.not_inbound`); this pure
 * function only **observes** the stored subject and text/HTML bodies with the engine's existing
 * lexicon, pattern detectors and bounds, and the round's URL results, so account takeover
 * detection can see an authenticated account sending payment, bank-change, gift-card or
 * credential-request language or phishing links. The result holds counts and booleans only: no
 * spans, no text, no lexicon ids. It never changes a verdict, reason code, signal or score.
 */

export const OUTBOUND_OBSERVATIONS_VERSION = 'bec-outbound-obs/1';

/** Lexicon categories observed outbound (the intent categories; `authority` is inbound-only). */
export const OUTBOUND_OBSERVATION_CATEGORIES = [
  'payment_request',
  'bank_change',
  'gift_card',
  'wire_transfer',
  'invoice_change',
  'payroll_change',
  'urgency',
  'secrecy',
  'credential_request',
] as const satisfies readonly LexiconCategory[];
export type OutboundObservationCategory = (typeof OUTBOUND_OBSERVATION_CATEGORIES)[number];

export const OUTBOUND_OBSERVATION_STATUSES = ['complete', 'incomplete', 'unavailable'] as const;
export type OutboundObservationStatus = (typeof OUTBOUND_OBSERVATION_STATUSES)[number];

/**
 * Why observations are incomplete or unavailable (bounded codes): the text was cut by a parse,
 * part, HTML-node or character limit; the round's URL results are missing or failed; the stored
 * parts could not be read; the text budget ran out; an unexpected error.
 */
export const OUTBOUND_OBSERVATION_REASONS = [
  'text_parse_limits',
  'text_part_truncated',
  'text_html_nodes',
  'text_max_chars',
  'url_unavailable',
  'parse_row_missing',
  'part_unavailable',
  'read_failed',
  'timeout',
  'error',
] as const;
export type OutboundObservationReason = (typeof OUTBOUND_OBSERVATION_REASONS)[number];

export interface OutboundObservations {
  version: typeof OUTBOUND_OBSERVATIONS_VERSION;
  status: OutboundObservationStatus;
  reason: OutboundObservationReason | null;
  categories: Record<OutboundObservationCategory, number>;
  financialIdentifiers: { iban: number; swift: number; ifsc_account: number; amount: number };
  links: {
    /** A URL with a phishing verdict code, or a credential form on a lookalike (inbound K1). */
    credentialHarvesting: boolean;
    /** A URL with a credential form (inbound K2). */
    credentialForm: boolean;
    /** A lookalike or mixed-script URL (inbound K3). */
    lookalike: boolean;
    /** A URL with a malicious verdict (inbound K4). */
    malicious: boolean;
  };
}

export interface OutboundObservationInput {
  text: TextInput;
  url: BecUrlInput;
}

const zeroCategories = (): Record<OutboundObservationCategory, number> =>
  Object.fromEntries(OUTBOUND_OBSERVATION_CATEGORIES.map((c) => [c, 0])) as Record<
    OutboundObservationCategory,
    number
  >;

const noLinks = (): OutboundObservations['links'] => ({
  credentialHarvesting: false,
  credentialForm: false,
  lookalike: false,
  malicious: false,
});

const isLookalikeCode = (code: string): boolean =>
  code.startsWith('url.lookalike_') || code === 'url.mixed_script';
const isCredentialCode = (code: string): boolean =>
  code === 'url.credential_form' || code === 'url.credential_form_cross_origin';

/** The link flags of the round's URL results (the same code tests as inbound K1–K4). */
export function outboundLinkFlags(rows: readonly BecUrlRow[]): OutboundObservations['links'] {
  const links = noLinks();
  for (const row of rows) {
    const credential = row.reasonCodes.some(isCredentialCode);
    const lookalike = row.reasonCodes.some(isLookalikeCode);
    if (
      row.reasonCodes.includes('url.phishing_high_confidence') ||
      row.reasonCodes.includes('url.dynamic_phishing') ||
      (credential && lookalike)
    ) {
      links.credentialHarvesting = true;
    }
    if (credential) links.credentialForm = true;
    if (lookalike) links.lookalike = true;
    if (row.verdict === 'malicious') links.malicious = true;
  }
  return links;
}

/** Observations that could not be computed (a read or budget failure; never an attempt failure). */
export function unavailableOutboundObservations(
  reason: OutboundObservationReason,
): OutboundObservations {
  return {
    version: OUTBOUND_OBSERVATIONS_VERSION,
    status: 'unavailable',
    reason,
    categories: zeroCategories(),
    financialIdentifiers: { iban: 0, swift: 0, ifsc_account: 0, amount: 0 },
    links: noLinks(),
  };
}

/**
 * Observes one outbound or internal message. Deterministic for a given lexicon and input; throws
 * `BecTextTimeoutError` when the deadline of `options` passes (the caller records `timeout`).
 * Status `incomplete` when the analysed text was cut by a limit or the round has no usable URL
 * results (the first reason in a fixed order is reported).
 */
export function evaluateOutboundObservations(
  input: OutboundObservationInput,
  lexicon: Lexicon,
  options: AnalyzeOptions,
): OutboundObservations {
  const analysis = analyzeText(input.text, lexicon, options);
  const categories = zeroCategories();
  for (const category of OUTBOUND_OBSERVATION_CATEGORIES) {
    categories[category] = analysis.categories[category].count;
  }
  const reasons: OutboundObservationReason[] = analysis.incompleteReasons.map(
    (reason) => `text_${reason}` as OutboundObservationReason,
  );
  if (input.url.state !== 'available') reasons.push('url_unavailable');
  return {
    version: OUTBOUND_OBSERVATIONS_VERSION,
    status: reasons.length > 0 ? 'incomplete' : 'complete',
    reason: reasons[0] ?? null,
    categories,
    financialIdentifiers: {
      iban: analysis.patterns.iban,
      swift: analysis.patterns.swift,
      ifsc_account: analysis.patterns.ifscAccount,
      amount: analysis.patterns.amount,
    },
    links: input.url.state === 'available' ? outboundLinkFlags(input.url.rows) : noLinks(),
  };
}
