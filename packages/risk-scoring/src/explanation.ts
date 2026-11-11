import { MAX_EXPLANATION_TEXT, type ExplanationLine } from './result';

/**
 * Explanation templates (step 5.1 R11): fixed English sentences keyed by line code, filled with
 * integers and bounded vocabulary tokens (levels, actions, engines, signal ids, group ids,
 * statuses, profile ids). Never message content. The rendered text is at most 2048 characters;
 * lines that no longer fit are dropped whole and the text ends with "(more omitted)".
 */

const p = (line: ExplanationLine, key: string): string => {
  const value = line.params[key];
  return value === undefined ? '' : String(value);
};

const TRUST_DENIED_TEXT: Readonly<Record<string, string>> = {
  denied_unauthenticated: 'the sender did not authenticate (no DMARC pass)',
  denied_auth_failure: 'an authentication failure was reported',
};

const FLOOR_TEXT: Readonly<Record<string, string>> = {
  engine_malicious: 'an engine classified the message as malicious',
  bec_suspicious: 'the BEC rules classified the message as suspicious',
  engine_failure: 'a required engine failed or an input is missing',
  engine_unknown: 'a required engine returned no definite result',
  hard_block: 'a hard-block indicator fired',
};

export function renderLine(line: ExplanationLine): string {
  switch (line.code) {
    case 'summary':
      return `Risk ${p(line, 'score')}/1000 (${p(line, 'level')}): recommended ${p(line, 'action')}.`;
    case 'hard_block':
      return `Hard block ${p(line, 'indicator')}: verdict ${p(line, 'verdict')}, action ${p(line, 'action')}.`;
    case 'engine_failure':
      return `Engine ${p(line, 'engine')} ${p(line, 'status')}: ${p(line, 'points')} failure points; never treated as clean.`;
    case 'engine_unknown':
      return `Engine ${p(line, 'engine')} returned no definite result: ${p(line, 'points')} points; never treated as clean.`;
    case 'input_missing':
      return `Expected ${p(line, 'input')} result row is missing; treated as an engine failure.`;
    case 'top_signal':
      return `Signal ${p(line, 'signal')} (${p(line, 'group')}): ${p(line, 'points')} points, reported by ${p(line, 'engines')}.`;
    case 'unmapped_codes':
      return `${p(line, 'count')} reason codes are not in the signal map and contributed nothing.`;
    case 'arc_trusted':
      return 'ARC chain of a trusted sealer vouched for a DMARC failure.';
    case 'trust_applied':
      return `Trusted sender (authenticated): content signals reduced to ${p(line, 'factor')} permille, ${p(line, 'removed')} points removed.`;
    case 'trust_denied':
      return `Trusted sender not applied: ${TRUST_DENIED_TEXT[p(line, 'status')] ?? 'conditions not met'}.`;
    case 'floor':
      return `Level at least ${p(line, 'level')}: ${FLOOR_TEXT[p(line, 'source')] ?? 'floor'}.`;
    case 'ai_raise_only':
      return p(line, 'tagged') === 'yes'
        ? 'Only the AI layer raised the BEC verdict: tagged at most, never held for it.'
        : 'Only the AI layer raised the BEC verdict: no action taken for it.';
    case 'sandbox':
      return `Sandbox result included: ${p(line, 'outcome')}.`;
    case 'profile':
      return p(line, 'source') === 'tenant'
        ? `Profile: tenant version ${p(line, 'versionNo')} (${p(line, 'base')} base).`
        : p(line, 'fallback')
          ? `Profile: platform default ${p(line, 'base')} (tenant profile not used: ${p(line, 'fallback')}).`
          : `Profile: platform default ${p(line, 'base')}.`;
    case 'scoring_error':
      return 'Scoring failed; treated as high risk (fail-safe).';
  }
}

const OMITTED = ' (more omitted)';

/** Renders explanation lines to text (≤ 2048 characters, whole lines only). */
export function renderExplanation(lines: readonly ExplanationLine[]): string {
  let text = '';
  for (const line of lines) {
    const sentence = renderLine(line);
    const next = text === '' ? sentence : `${text} ${sentence}`;
    if (next.length > MAX_EXPLANATION_TEXT - OMITTED.length) return `${text}${OMITTED}`;
    text = next;
  }
  return text;
}
