/** Reputation provider contract (docs/plan/steps/11-url-protection.md U6). */

export const REPUTATION_KINDS = ['url', 'domain', 'ip'] as const;
export type ReputationKind = (typeof REPUTATION_KINDS)[number];

export const ANSWER_STATUSES = ['listed', 'clear', 'error'] as const;
export type AnswerStatus = (typeof ANSWER_STATUSES)[number];

export const THREAT_CATEGORIES = ['phishing', 'malware', 'spam', 'scam', 'c2', 'other'] as const;
export type ThreatCategory = (typeof THREAT_CATEGORIES)[number];

export const THREAT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type ThreatSeverity = (typeof THREAT_SEVERITIES)[number];

/** Bounded detail tokens. */
export const DETAIL_PATTERN = /^[a-z0-9][a-z0-9_.:-]{0,63}$/;

/** One item to look up: url (identity form), domain (ASCII host), ip (canonical text). */
export interface ReputationItem {
  kind: ReputationKind;
  value: string;
}

export interface ProviderAnswer {
  kind: ReputationKind;
  value: string;
  status: AnswerStatus;
  category: ThreatCategory | null;
  severity: ThreatSeverity | null;
  /** Bounded token (DETAIL_PATTERN) or null. */
  detail: string | null;
}

export interface ReputationProvider {
  readonly id: string;
  readonly version: string;
  readonly kinds: readonly ReputationKind[];
  /** Answers may be cached in Redis (the local feed is authoritative and never cached). */
  readonly cacheable: boolean;
  /**
   * One answer per item, in order. Never throws for one item; a whole-provider failure returns
   * `error` for every item.
   */
  lookup(items: readonly ReputationItem[], signal: AbortSignal): Promise<ProviderAnswer[]>;
}

export const errorAnswer = (
  item: ReputationItem,
  detail: string | null = null,
): ProviderAnswer => ({
  kind: item.kind,
  value: item.value,
  status: 'error',
  category: null,
  severity: null,
  detail,
});

export const clearAnswer = (
  item: ReputationItem,
  detail: string | null = null,
): ProviderAnswer => ({
  kind: item.kind,
  value: item.value,
  status: 'clear',
  category: null,
  severity: null,
  detail,
});

const CATEGORY_RANK: Readonly<Record<ThreatCategory, number>> = {
  c2: 6,
  malware: 5,
  phishing: 4,
  scam: 3,
  spam: 2,
  other: 1,
};
const SEVERITY_RANK: Readonly<Record<ThreatSeverity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Combines answers for one item: any listed → the most severe listed; else any error → error. */
export function combineAnswers(
  item: ReputationItem,
  answers: readonly ProviderAnswer[],
): ProviderAnswer {
  const listed = answers.filter((a) => a.status === 'listed');
  if (listed.length > 0) {
    return [...listed].sort(
      (a, b) =>
        (SEVERITY_RANK[b.severity ?? 'low'] ?? 0) - (SEVERITY_RANK[a.severity ?? 'low'] ?? 0) ||
        (CATEGORY_RANK[b.category ?? 'other'] ?? 0) - (CATEGORY_RANK[a.category ?? 'other'] ?? 0),
    )[0] as ProviderAnswer;
  }
  const error = answers.find((a) => a.status === 'error');
  if (error) return { ...error, kind: item.kind, value: item.value };
  return answers[0] ? { ...answers[0], kind: item.kind, value: item.value } : clearAnswer(item);
}
