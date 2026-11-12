import type { ExplanationLine } from './result';
import { POLICY_LIMITS } from './vocabulary';

/**
 * Fixed English templates of the evaluation explanation (step 5.2 P10). Parameters are ids,
 * rule refs, enum values, codes and integers only: the text never contains an address, domain,
 * URL, file name or other message content (unit and property tested).
 */
const TEMPLATES: Readonly<Record<ExplanationLine['code'], (p: Record<string, string>) => string>> =
  {
    summary: (p) => `Policy decision: ${p.disposition} (decided by ${p.source}).`,
    decisive_rule: (p) => `Decisive rule ${p.ref} (${p.disposition}).`,
    platform_default: (p) =>
      `Platform default ${p.platformDefault}: ${p.disposition}${p.tag === 'yes' ? ' with tag' : ''} from risk action ${p.riskAction} (${p.reason}).`,
    floor: (p) => `Floor ${p.reason} requires at least ${p.disposition}.`,
    override: (p) => `Override by rule ${p.ref}: ${p.to} instead of the recommended ${p.from}.`,
    clamp: (p) => `Rule ${p.ref} asked for ${p.from}; kept ${p.to} (${p.reason}).`,
    exception: (p) => `Rule ${p.ref} excepted by ${p.at}.`,
    action: (p) => `Action ${p.type} (${p.origin}).`,
    not_applicable: (p) => `Action ${p.type} not applicable to ${p.disposition}.`,
    split: (p) =>
      `Per-recipient decisions: ${p.allowed} allowed, ${p.held} quarantined, ${p.review} for review, ${p.rejected} rejected.`,
    snapshot: (p) =>
      `Snapshot generation ${p.generation}: ${p.policies} active policies, ${p.invalid} invalid.`,
  };

export function renderLine(line: ExplanationLine): string {
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(line.params)) params[k] = String(v);
  return TEMPLATES[line.code](params);
}

/** Renders the lines (at most 24), one per line, cut to 2 048 characters. */
export function renderExplanation(lines: readonly ExplanationLine[]): string {
  const text = lines.slice(0, POLICY_LIMITS.explanationLines).map(renderLine).join('\n');
  return text.length > POLICY_LIMITS.explanationText
    ? text.slice(0, POLICY_LIMITS.explanationText)
    : text;
}
