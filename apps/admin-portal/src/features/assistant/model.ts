import { humanize } from '@/lib/format';
import type { AssistantUnavailableReason, ExecutionDecision } from './types';

/** Why the assistant cannot be used (`GET /assistant/status.reason`, contracts §35). */
export interface UnavailableExplanation {
  readonly title: string;
  readonly description: string;
  /** Configurers can act on it in Settings → AI assistant. */
  readonly settingsLink: boolean;
}

export const SETTINGS_HREF = '/settings?tab=assistant';

export function unavailableExplanation(
  reason: AssistantUnavailableReason | undefined,
): UnavailableExplanation {
  switch (reason) {
    case 'platform_disabled':
      return {
        title: 'The AI assistant is not enabled on this platform',
        description:
          'The platform operator has not enabled the AI assistant. Contact your platform operator.',
        settingsLink: false,
      };
    case 'feature_disabled':
      return {
        title: 'The AI assistant is not part of your plan',
        description:
          'The platform operator has not enabled the AI assistant feature for this organization.',
        settingsLink: false,
      };
    case 'tenant_disabled':
      return {
        title: 'The AI assistant is turned off for your organization',
        description:
          'An administrator can turn it on in Settings → AI assistant after acknowledging that conversation text is processed by an external AI provider.',
        settingsLink: true,
      };
    case 'provider_unavailable':
      return {
        title: 'The AI provider is temporarily unavailable',
        description:
          'The assistant pauses while its AI provider fails. Try again in a few minutes.',
        settingsLink: false,
      };
    case 'budget_exhausted':
      return {
        title: 'The daily AI budget is used up',
        description:
          'This organization used its token budget for today (UTC). It resets at midnight UTC; an administrator can raise it in Settings → AI assistant.',
        settingsLink: true,
      };
    default:
      return {
        title: 'The AI assistant is not available',
        description: 'Try again later.',
        settingsLink: false,
      };
  }
}

/** Plain-language execution decisions (contracts §35 "Executor decisions"). */
export function decisionLabel(decision: ExecutionDecision): string {
  switch (decision) {
    case 'allowed':
      return 'Allowed';
    case 'denied_permission':
      return 'You do not have the permission this needs';
    case 'denied_not_applicable':
      return 'Not available in chat; use the portal page';
    case 'denied_disabled':
      return 'Not available in chat yet';
    case 'denied_unknown_tool':
      return 'Unknown action';
    case 'denied_schema':
      return 'The request was not valid';
    case 'denied_ref':
      return 'Refers to a result that is not in this conversation';
    case 'denied_budget':
      return 'Too many actions in one answer';
    case 'denied_guard':
      return 'Not allowed in chat';
    default:
      return humanize(decision);
  }
}

/** Plain-language turn failure and refusal codes (stream `turn.failed`, api errors). */
export function turnErrorText(code: string, fallback?: string): string {
  switch (code) {
    case 'assistant_session_expired':
      return 'Your session expired while the assistant was working. Sign in again and retry.';
    case 'assistant_turn_limit':
      return 'The answer needed more steps or time than one turn allows. Ask a narrower question.';
    case 'assistant_refused':
      return 'The AI provider declined to answer this request.';
    case 'assistant_turn_abandoned':
      return 'The answer was interrupted. Retry the question.';
    case 'assistant_provider_error':
    case 'assistant_provider_unavailable':
      return 'The AI provider failed. Try again in a few minutes.';
    case 'assistant_budget_exhausted':
      return 'The daily AI budget is used up. It resets at midnight UTC.';
    case 'assistant_busy':
      return 'The assistant is busy. Try again in a moment.';
    case 'assistant_disabled':
    case 'assistant_not_enabled':
    case 'assistant_tenant_disabled':
      return 'The AI assistant is not available for your organization.';
    case 'assistant_turn_in_progress':
      return 'An answer is still running in this conversation. Wait for it or cancel it.';
    case 'rate_limited':
      return 'You asked too many questions in a short time. Wait a minute and retry.';
    case 'payload_too_large':
      return 'The question is too long.';
    case 'event_too_large':
    case 'stream_ended':
    case 'invalid_response':
      return 'The answer could not be received completely. Retry the question.';
    case 'network_error':
      return 'The portal could not be reached; check your connection and retry.';
    default:
      return fallback ?? 'The assistant could not answer.';
  }
}

/** Modules of `GET /assistant/tools` with a suggested question each (AI-1: reads only). */
const MODULE_PROMPTS: ReadonlyArray<{ module: string; label: string; prompt: string }> = [
  { module: 'policies', label: 'Policies', prompt: 'Which policies are active right now?' },
  {
    module: 'quarantine',
    label: 'Quarantine',
    prompt: 'Show the quarantined messages of the last 24 hours.',
  },
  { module: 'incidents', label: 'Incidents', prompt: 'List the open security incidents.' },
  {
    module: 'reports',
    label: 'Reports',
    prompt: 'Summarize mail traffic and threats of the last 7 days.',
  },
  {
    module: 'journaling',
    label: 'Journaling',
    prompt: 'Is journaling configured, and are the intake sources healthy?',
  },
  { module: 'domains', label: 'Domains', prompt: 'Which domains are not fully verified?' },
  { module: 'ato', label: 'Account takeover', prompt: 'Which accounts are at risk of takeover?' },
  { module: 'archive', label: 'Archive', prompt: 'What are the archive retention rules?' },
  { module: 'users', label: 'Users', prompt: 'Which users were added in the last 30 days?' },
  { module: 'audit', label: 'Audit', prompt: 'What changed in the audit log today?' },
];

export interface SuggestedPrompt {
  readonly module: string;
  readonly label: string;
  readonly prompt: string;
}

/** Up to `limit` suggestions for the modules the user's tool catalogue contains. */
export function suggestedPrompts(modules: Iterable<string>, limit = 4): readonly SuggestedPrompt[] {
  const available = new Set(modules);
  return MODULE_PROMPTS.filter((entry) => available.has(entry.module)).slice(0, limit);
}

/** The browser's IANA time zone (sent with each turn for relative dates). */
export function browserTimeZone(): string | undefined {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return zone && zone.length <= 64 ? zone : undefined;
  } catch {
    return undefined;
  }
}

/** A conversation's display title. */
export function conversationTitle(title: string | null | undefined): string {
  return title && title.trim() ? title : 'Untitled conversation';
}
