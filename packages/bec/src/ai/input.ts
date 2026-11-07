import { normalizeExtraDomains } from '../identity/freemail';
import type { BecRulesResult, BecTenantData } from '../rules/types';
import { buildExcerpt } from '../text/excerpt';
import type { AiIdentityFacts, AiInput } from './types';

/**
 * Builds the AI input of one evaluated message (B9/B10): the feature vector, the categorical
 * identity facts, the lexicon spans (local model) and, when `maxExcerptChars` is given (LLM),
 * the redacted excerpt with the tenant's executive/vendor names and domain labels as redaction
 * context. Addresses, display names, domains and identifiers are never part of the input.
 */
export function buildAiInput(
  result: BecRulesResult,
  tenant: Pick<BecTenantData, 'executives' | 'vendors' | 'tenantDomains'>,
  options: { maxExcerptChars?: number } = {},
): AiInput {
  const active = result.firedRules.filter((r) => r.suppressed === null);
  const has = (...ids: string[]): boolean => active.some((r) => ids.includes(r.id));
  const facts: AiIdentityFacts = {
    fromDomainKind: result.identity.from?.kind ?? 'external',
    replyToKind: result.identity.replyTo[0]?.kind ?? 'none',
    displayNameMatch: has('X1', 'X2', 'X3')
      ? 'executive'
      : has('V1')
        ? 'vendor'
        : has('D2')
          ? 'brand'
          : 'none',
    authenticatedAsFrom: result.authenticatedAsFrom,
  };
  const lexiconSpans: AiInput['lexiconSpans'] = {};
  if (result.text) {
    for (const [category, summary] of Object.entries(result.text.categories)) {
      if (summary.spans.length > 0) lexiconSpans[category] = summary.spans;
    }
  }
  const excerpt =
    options.maxExcerptChars !== undefined && result.text
      ? buildExcerpt(
          result.text,
          {
            executiveNames: tenant.executives.flatMap((e) => [e.name, ...e.aliases]),
            vendorNames: tenant.vendors.flatMap((v) => [v.name, ...v.aliases]),
            tenantLabels: [...normalizeExtraDomains(tenant.tenantDomains)].map(
              (d) => d.split('.')[0]!,
            ),
          },
          options.maxExcerptChars,
        )
      : null;
  return { features: { ...result.features }, excerpt, facts, lexiconSpans };
}
