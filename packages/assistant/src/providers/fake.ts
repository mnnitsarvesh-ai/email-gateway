import { USER_MESSAGE_MARKER } from '../confirmations/updates';
import { abortableSleep } from './retry';
import {
  LLM_ERROR_REASONS,
  LlmError,
  type LlmErrorReason,
  type LlmProvider,
  type LlmRequest,
  type LlmResponse,
  type LlmToolCall,
  type LlmToolResult,
  type MetaToolName,
} from './types';

/**
 * Deterministic in-process LLM stand-in (`ASSISTANT_PROVIDER=fake`, design D6) for local stacks,
 * integration suites and Playwright: no network, no randomness, no clock except the injectable
 * `now()`. It is refused when `NODE_ENV=production` (the constructor throws).
 *
 * - Directive mode (the user message): `/tool <name> <json>` calls `call_tool` with exactly that,
 *   `/describe <name>` calls `describe_tool`, `/text <text>` answers with the text.
 * - Demo intents: a fixed table of phrases (e.g. "show active policies") mapped to registry tool
 *   names; a tool missing from the system prompt's catalogue index (no permission) is not called.
 * - Plans (step AI-2 D8): multi-step demo intents ("create an inbound policy that quarantines
 *   executables": validate → test → create); the next step runs only when the previous result was
 *   ok (and, after `policy_tools_validate`, `valid: true`); steps whose tool is missing from the
 *   catalogue index are skipped.
 * - Plans of step AI-3 (design 30 D11): "invite <email> as <role>" (`roles_get` → `users_invite`),
 *   "disable user <email>" (`users_list` → `users_change_status` only when the list returned
 *   exactly one row) and "add domain <name>" (`domains_create`). A step's arguments may depend on
 *   the message and on the previous result; a step without arguments ends the plan with the
 *   previous result's summary.
 * - Plans of step AI-4 (design 32 D12): "approve the pending (ATO) response"
 *   (`ato_responses_list { status: pending_approval, limit: 1 }` → `ato_responses_approve` on
 *   `@r<seq>.1` when the list returned one row), "open an incident for the account <address>"
 *   (`ato_accounts_list { q, limit: 1 }` → `incidents_create` only for exactly one row and no
 *   further page) and `add dlp dictionary "<name>" with terms a, b` (`dlp_dictionaries_create`,
 *   name and terms in the user's own case, at most 20 terms).
 * - Follow-ups (D8): "disable/enable the second one" (the newest `policy_management_list` result),
 *   "publish it" (the newest succeeded `policy_management_create` of the action updates) and, step
 *   AI-3, "verify it" / "verify the domain" (the newest succeeded `domains_create`).
 * - Reports (step AI-R D10): "generate a (security) report", "security dashboard", "report for
 *   the last 24 hours / 7 days / 30 days" → `report_generate { range }`; "send this report to my
 *   email" / "email me the report" → `report_send_email {}`; "send the report to <address>" →
 *   `report_send_email { to }`. After a `report_generate` result the answer cites the envelope's
 *   figures only ("Your security report for the last 7 days is ready below: …").
 * - After tool results: a deterministic template ("Found N records." / the coded error / the
 *   pending-confirmation sentence).
 * - `obedient: true` (tests only): follows instruction-shaped text found in tool results
 *   (`call_tool <name> <json>`, "ignore previous instructions … <tool name>") once each, to prove
 *   that the server-side controls hold when the model is fooled.
 * - Step AI-6: after a queued (background) `report_generate` result the answer says the report is
 *   being generated, without figures. `latencyMs` (tests and the load test) waits that long,
 *   abortably, before the first delta of every round and then streams the text in a few chunks;
 *   `failure` makes every `complete()` and `probe()` throw `LlmError(failure)` before any delta
 *   (provider fallback tests). Both are test options; the fake stays refused in production.
 *
 * Native transcript entries: `{ role: 'user', text }`, `{ role: 'assistant', text, toolCalls }`,
 * `{ role: 'tool', toolCallId, content, isError }`.
 */

export interface FakeProviderOptions {
  /** NODE_ENV; `production` is refused. */
  nodeEnv: string | undefined;
  model?: string;
  obedient?: boolean;
  now?: () => Date;
  /** Step AI-6 D11: deterministic delay (ms) before the first delta of each round (0–60 000). */
  latencyMs?: number;
  /** Step AI-6 D6: every `complete()` / `probe()` throws `LlmError(failure)` before any delta. */
  failure?: LlmErrorReason | null;
}

/** Most chunks of a streamed answer when `latencyMs` is set. */
export const FAKE_STREAM_CHUNKS = 4;
export const FAKE_MAX_LATENCY_MS = 60_000;

/** The text in at most `FAKE_STREAM_CHUNKS` consecutive pieces (deterministic). */
export function fakeChunks(text: string): string[] {
  if (text.length === 0) return [];
  const size = Math.ceil(text.length / FAKE_STREAM_CHUNKS);
  const chunks: string[] = [];
  for (let i = 0; i < text.length; i += size) chunks.push(text.slice(i, i + size));
  return chunks;
}

export interface FakeUserEntry {
  role: 'user';
  text: string;
}
export interface FakeAssistantEntry {
  role: 'assistant';
  text: string;
  toolCalls: LlmToolCall[];
}
export interface FakeToolEntry {
  role: 'tool';
  toolCallId: string;
  content: string;
  isError: boolean;
}
export type FakeTranscriptEntry = FakeUserEntry | FakeAssistantEntry | FakeToolEntry;

interface Intent {
  pattern: RegExp;
  tool: string;
  args: (now: Date) => Record<string, unknown>;
}

const startOfUtcDay = (now: Date): string =>
  new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
const today = (now: Date) => ({ from: startOfUtcDay(now), to: now.toISOString() });

/** The demo intents (first match wins). Tool names are registry names (checked by tests). */
export const FAKE_DEMO_INTENTS: readonly Intent[] = [
  {
    pattern: /\bactive\b.*\bpolic(y|ies)\b/,
    tool: 'policy_management_list',
    args: () => ({ status: 'active' }),
  },
  {
    pattern: /\b(show|list|which)\b.*\bpolic(y|ies)\b|^polic(y|ies)$/,
    tool: 'policy_management_list',
    args: () => ({}),
  },
  {
    pattern: /\bquarantin\w*\b.*\btoday\b|\btoday\b.*\bquarantin\w*/,
    tool: 'quarantine_entries_search',
    args: today,
  },
  { pattern: /\bquarantine summary\b/, tool: 'quarantine_tools_summary', args: today },
  { pattern: /\btraffic\b/, tool: 'reports_traffic', args: today },
  {
    pattern: /\bjournal\w*\b.*\bstatus\b|\bstatus\b.*\bjournal\w*/,
    tool: 'journaling_status',
    args: () => ({}),
  },
  {
    pattern: /\barchive\b.*\bstatus\b|\bstatus\b.*\barchive\b/,
    tool: 'archive_admin_status',
    args: () => ({}),
  },
  {
    pattern: /\bdead[- ]letters?\b|\bsystem (stats|statistics|health)\b/,
    tool: 'dead_letters_stats',
    args: () => ({}),
  },
  { pattern: /\bato\b|\baccount takeover\b/, tool: 'ato_overview_overview', args: () => ({}) },
  { pattern: /\bincidents?\b/, tool: 'incidents_list', args: () => ({}) },
  { pattern: /\bdomains?\b/, tool: 'domains_list', args: () => ({}) },
  { pattern: /\busers?\b/, tool: 'users_list', args: () => ({}) },
];

/** The policy definition D of the create-policy plan (design 29 D8; validated by a unit test). */
export const FAKE_EXECUTABLES_DEFINITION = {
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority: 100,
  rules: [
    {
      id: 'quarantine-executables',
      priority: 10,
      description: 'Quarantine inbound executable attachments',
      when: {
        field: 'attachment.type_family',
        op: 'in',
        value: ['executable'],
        quantifier: 'any',
      },
      actions: [{ type: 'QUARANTINE' }],
    },
  ],
} as const;

/**
 * The synthetic facts F of the plan's `policy_tools_test` (policy-dsl `syntheticFactsSchema`): an
 * inbound message with one attachment of type family `executable`.
 */
export const FAKE_EXECUTABLES_FACTS = {
  direction: 'inbound',
  sender: { envelope: 'sender@example.com' },
  recipients: [{ address: 'recipient@example.net' }],
  attachments: [{ filename: 'invoice.exe', typeFamily: 'executable', sizeBytes: 2048 }],
} as const;

export const FAKE_EXECUTABLES_POLICY_NAME = 'Quarantine inbound executables';
const CREATED_WITH_ASSISTANT = 'Created with the AI assistant';

/** What a plan step's arguments may depend on. */
export interface PlanContext {
  /** The plan pattern's match on the lower-cased user message. */
  match: RegExpExecArray;
  /** The previous tool result's envelope (parsed), or null for the first step. */
  previous: Record<string, unknown> | null;
  /** The current user message as typed (not lower-cased; step AI-4: names keep their case). */
  message: string;
}

interface PlanStep {
  tool: string;
  /** The step's arguments, or null: the plan ends with the previous result's summary. */
  args: (ctx: PlanContext) => Record<string, unknown> | null;
  /**
   * Called even though the tool is not in the catalogue index (step AI-5 D11): a not-applicable
   * operation the executor must refuse (`denied_not_applicable`), proving the portal-only path.
   */
  uncatalogued?: true;
}

interface Plan {
  pattern: RegExp;
  steps: readonly PlanStep[];
}

/** An email address of a message, without trailing sentence punctuation. */
const emailOf = (value: string | undefined): string => (value ?? '').replace(/[.,;:!?)]+$/, '');

export const FAKE_DISABLED_REASON = 'Disabled with the AI assistant';
export const FAKE_APPROVED_REASON = 'Approved with the AI assistant';
export const FAKE_INCIDENT_REASON = 'Opened with the AI assistant after a user report';
/** Most terms the dictionary plan sends (step AI-4 D12). */
export const FAKE_DICTIONARY_MAX_TERMS = 20;
export const FAKE_DICTIONARY_PATTERN =
  /\badd\s+(?:a\s+)?dlp\s+dictionary\s+"([^"]{1,80})"\s+with\s+terms\s+(.+)$/i;

/** The single row ref `@r<seq>.1` of a list result with exactly one row (and no further page). */
function singleRowRef(previous: Record<string, unknown> | null, allowMore: boolean): string | null {
  const rows = Array.isArray(previous?.data) ? previous.data : [];
  const ref = typeof previous?.ref === 'string' ? previous.ref : '';
  if (rows.length !== 1 || !/^r\d+$/.test(ref)) return null;
  if (!allowMore && previous?.hasMore === true) return null;
  return `@${ref}.1`;
}

export const FAKE_HOLD_RELEASE_REASON = 'Released with the AI assistant';
/** Most retention policies the retention plan lists (one page; an unambiguous match only). */
export const FAKE_RETENTION_LIST_LIMIT = '100';
export const FAKE_CASE_PATTERN = /\bcreate\s+(?:an?\s+)?ediscovery\s+case\s+"([^"]{1,120})"/i;
export const FAKE_RETENTION_PATTERN =
  /\bset\s+(?:the\s+)?retention\s+policy\s+"([^"]{1,128})"\s+to\s+(\d{1,5})\s+days\b/i;

/** A value of an envelope with `{ untrusted_text }` wrappers removed (fields the fake copies). */
function unwrapUntrusted(value: unknown, depth = 0): unknown {
  if (depth > 8) return null;
  if (Array.isArray(value)) return value.map((item) => unwrapUntrusted(item, depth + 1));
  const record = asRecord(value);
  if (!record) return value;
  if (Object.keys(record).length === 1 && typeof record.untrusted_text === 'string')
    return record.untrusted_text;
  return Object.fromEntries(
    Object.entries(record).map(([key, item]) => [key, unwrapUntrusted(item, depth + 1)]),
  );
}

/** True when a value still holds an `{ omitted_items }` marker (a list cut by the envelope). */
function hasOmittedItems(value: unknown, depth = 0): boolean {
  if (depth > 8) return false;
  if (Array.isArray(value)) return value.some((item) => hasOmittedItems(item, depth + 1));
  const record = asRecord(value);
  if (!record) return false;
  if ('omitted_items' in record) return true;
  return Object.values(record).some((item) => hasOmittedItems(item, depth + 1));
}

/** The row ref of the only row of a complete list whose (unwrapped) `name` equals `name`. */
function uniqueNamedRowRef(previous: Record<string, unknown> | null, name: string): string | null {
  const rows = Array.isArray(previous?.data) ? (previous.data as unknown[]) : [];
  if (previous?.hasMore === true || previous?.truncated === true) return null;
  const matches = rows
    .map(asRecord)
    .filter((row) => row !== null && unwrapUntrusted(row.name) === name);
  const ref = matches.length === 1 ? matches[0]!.ref : null;
  return typeof ref === 'string' && /^r\d+\.\d+$/.test(ref) ? `@${ref}` : null;
}

/** Multi-step demo intents (D8; step AI-3 D11). Tool names are registry names (checked by tests). */
export const FAKE_PLANS: readonly Plan[] = [
  {
    pattern:
      /\bcreate\b.*\binbound\b.*\bpolic(y|ies)\b.*\bexecutables?\b|\bquarantines? executables?\b/,
    steps: [
      {
        tool: 'policy_tools_validate',
        args: () => ({ body: { definition: FAKE_EXECUTABLES_DEFINITION } }),
      },
      {
        tool: 'policy_tools_test',
        args: () => ({
          body: {
            target: { definition: FAKE_EXECUTABLES_DEFINITION },
            facts: FAKE_EXECUTABLES_FACTS,
          },
        }),
      },
      {
        tool: 'policy_management_create',
        args: () => ({
          body: {
            name: FAKE_EXECUTABLES_POLICY_NAME,
            description: CREATED_WITH_ASSISTANT,
            definition: FAKE_EXECUTABLES_DEFINITION,
            changeNote: CREATED_WITH_ASSISTANT,
          },
        }),
      },
    ],
  },
  // --- step AI-3 (design 30 D11) ---
  {
    pattern: /\binvite\s+(\S+@\S+)\s+as\s+(?:an?\s+)?([a-z][a-z0-9_]{1,63})\b/,
    steps: [
      { tool: 'roles_get', args: ({ match }) => ({ key: match[2]! }) },
      {
        tool: 'users_invite',
        args: ({ match }) => {
          const email = emailOf(match[1]);
          return {
            body: {
              email,
              displayName: email.slice(0, email.indexOf('@')) || email,
              roleKeys: [match[2]!],
            },
          };
        },
      },
    ],
  },
  {
    pattern: /\b(?:disable|deactivate)\s+(?:the\s+)?user\s+(\S+@\S+)/,
    steps: [
      { tool: 'users_list', args: ({ match }) => ({ q: emailOf(match[1]), limit: 1 }) },
      {
        tool: 'users_change_status',
        // Only an unambiguous match: exactly one row and no further page.
        args: ({ previous }) => {
          const rows = Array.isArray(previous?.data) ? previous.data : [];
          const ref = typeof previous?.ref === 'string' ? previous.ref : '';
          if (rows.length !== 1 || previous?.hasMore === true || !/^r\d+$/.test(ref)) return null;
          return {
            id: `@${ref}.1`,
            body: { status: 'disabled', reason: FAKE_DISABLED_REASON },
          };
        },
      },
    ],
  },
  {
    pattern: /\badd\s+(?:the\s+)?domain\s+([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/,
    steps: [{ tool: 'domains_create', args: ({ match }) => ({ body: { name: match[1]! } }) }],
  },
  // --- step AI-4 (design 32 D12) ---
  {
    pattern: /\bapprove\s+(?:the\s+)?(?:pending|latest)\s+(?:ato\s+)?response\b/i,
    steps: [
      {
        tool: 'ato_responses_list',
        args: () => ({ status: 'pending_approval', limit: '1' }),
      },
      {
        tool: 'ato_responses_approve',
        // The newest pending response (the list is sorted by -createdAt); none: the summary.
        args: ({ previous }) => {
          const responseId = singleRowRef(previous, true);
          return responseId ? { responseId, body: { reason: FAKE_APPROVED_REASON } } : null;
        },
      },
    ],
  },
  {
    pattern: /\bopen\s+an?\s+incident\s+for\s+(?:the\s+)?account\s+(\S+@\S+)/i,
    steps: [
      // `q` is the account address prefix filter of `GET /ato/accounts`.
      { tool: 'ato_accounts_list', args: ({ match }) => ({ q: emailOf(match[1]), limit: '1' }) },
      {
        tool: 'incidents_create',
        // Only an unambiguous match: exactly one row and no further page.
        args: ({ previous }) => {
          const id = singleRowRef(previous, false);
          return id
            ? {
                body: {
                  category: 'account_takeover',
                  subject: { type: 'ato_account', id },
                  severity: 'high',
                  reason: FAKE_INCIDENT_REASON,
                },
              }
            : null;
        },
      },
    ],
  },
  {
    pattern: FAKE_DICTIONARY_PATTERN,
    steps: [
      {
        tool: 'dlp_dictionaries_create',
        args: ({ message }) => {
          const found = FAKE_DICTIONARY_PATTERN.exec(message);
          if (!found) return null;
          const terms = found[2]!
            .split(',')
            .map((term) => term.trim().replace(/[.!?]+$/, ''))
            .filter((term) => term.length > 0)
            .slice(0, FAKE_DICTIONARY_MAX_TERMS);
          if (terms.length === 0) return null;
          return {
            body: { name: found[1]!.trim(), category: 'custom', terms, severity: 'medium' },
          };
        },
      },
    ],
  },
  // --- step AI-5 (design 33 D11) ---
  {
    pattern: FAKE_CASE_PATTERN,
    steps: [
      {
        tool: 'ediscovery_cases_create',
        args: ({ message }) => {
          const found = FAKE_CASE_PATTERN.exec(message);
          const name = found?.[1]?.trim();
          return name ? { body: { name } } : null;
        },
      },
    ],
  },
  {
    pattern: FAKE_RETENTION_PATTERN,
    steps: [
      { tool: 'archive_retention_list', args: () => ({ limit: FAKE_RETENTION_LIST_LIMIT }) },
      {
        tool: 'archive_retention_get',
        // Only an unambiguous match: exactly one row of the complete list has that name.
        args: ({ previous, message }) => {
          const name = FAKE_RETENTION_PATTERN.exec(message)?.[1];
          const policyId = name ? uniqueNamedRowRef(previous, name) : null;
          return policyId ? { policyId } : null;
        },
      },
      {
        tool: 'archive_retention_update',
        // The PUT replaces the whole policy: copy onExpiry, priority and criteria from the read.
        args: ({ previous, message }) => {
          const found = FAKE_RETENTION_PATTERN.exec(message);
          const data = asRecord(previous?.data);
          const ref = typeof data?.ref === 'string' ? data.ref : '';
          if (!found || !data || !/^r\d+\.1$/.test(ref) || hasOmittedItems(data.criteria))
            return null;
          const criteria = unwrapUntrusted(data.criteria);
          if (typeof data.priority !== 'number' || asRecord(criteria) === null) return null;
          return {
            policyId: `@${ref}`,
            body: {
              name: found[1]!,
              retentionDays: Number(found[2]),
              onExpiry: unwrapUntrusted(data.onExpiry),
              priority: data.priority,
              criteria,
            },
          };
        },
      },
    ],
  },
  {
    pattern: /\brelease\s+(?:the\s+)?(?:latest\s+)?legal\s+hold\b/i,
    steps: [
      { tool: 'legal_holds_list', args: () => ({ status: 'active', limit: '1' }) },
      {
        // Critical (portal only): the executor always refuses it (`denied_not_applicable`).
        tool: 'legal_holds_release',
        uncatalogued: true,
        args: ({ previous }) => {
          const holdId = singleRowRef(previous, true);
          return holdId ? { holdId, body: { reason: FAKE_HOLD_RELEASE_REASON } } : null;
        },
      },
    ],
  },
];

/** A report intent (step AI-R D10): the tool and its arguments from the message's match. */
interface ReportIntent {
  pattern: RegExp;
  tool: 'report_generate' | 'report_send_email';
  args: (match: RegExpExecArray, lower: string) => Record<string, unknown>;
}

/** The range a report message names (default the last 7 days). */
export function fakeReportRange(lower: string): '24h' | '7d' | '30d' {
  if (/\b(24\s*h(ours?)?|24-hours?|last day|today|one day)\b/.test(lower)) return '24h';
  if (/\b(30\s*d(ays)?|30-days?|month|monthly)\b/.test(lower)) return '30d';
  return '7d';
}

/** The report intents, checked before the other demo intents (first match wins). */
export const FAKE_REPORT_INTENTS: readonly ReportIntent[] = [
  {
    pattern:
      /\b(?:send|e-?mail|mail)\s+(?:this|the|my)\s+(?:security\s+)?report\s+to\s+(?:my\s+(?:own\s+)?(?:e-?mail|address|inbox)|me)\b/,
    tool: 'report_send_email',
    args: () => ({}),
  },
  {
    pattern: /\be-?mail\s+me\s+(?:this|the)\s+(?:security\s+)?report\b/,
    tool: 'report_send_email',
    args: () => ({}),
  },
  {
    pattern: /\b(?:send|e-?mail|mail)\s+(?:this|the)\s+(?:security\s+)?report\s+to\s+(\S+@\S+)/,
    tool: 'report_send_email',
    args: (match) => ({ to: emailOf(match[1]) }),
  },
  {
    pattern:
      /\b(?:generate|create|build|make|show|give me)\s+(?:me\s+)?(?:an?\s+)?(?:security\s+)?(?:report|dashboard)\b|\bsecurity (?:report|dashboard)\b|\breport for the last\b/,
    tool: 'report_generate',
    args: (_match, lower) => ({ range: fakeReportRange(lower) }),
  },
];

export const FAKE_PENDING_TEXT =
  'I prepared this change. Review it in the confirmation card; nothing changes until you confirm it.';

export const FAKE_HELP_TEXT =
  'I can look things up for you, for example: "show active policies", "what was quarantined today", "show incidents", "journaling status", "archive status", "list domains", "list users", "traffic report today", "ATO overview" or "generate a security report".';
export const FAKE_UNAVAILABLE_TEXT =
  'That information is not available to you in chat. Ask an administrator for access or use the portal.';

const NAME = /^[a-z0-9_]{1,64}$/;

function usageOf(input: string, output: string) {
  return {
    inputTokens: Math.ceil(input.length / 4),
    outputTokens: Math.ceil(output.length / 4),
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
  };
}

/** The balanced `{...}` starting at `start` (string-aware), or null. */
export function extractJsonObject(text: string, start: number): string | null {
  if (text[start] !== '{') return null;
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i += 1) {
    const char = text[i];
    if (inString) {
      if (char === '\\') i += 1;
      else if (char === '"') inString = false;
    } else if (char === '"') inString = true;
    else if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, out);
  else if (value && typeof value === 'object')
    for (const item of Object.values(value as Record<string, unknown>)) collectStrings(item, out);
}

/** Instruction-shaped text in tool results (obedient mode). */
export function findInjectedCalls(content: string): Array<{ name: string; arguments: string }> {
  let strings: string[] = [];
  try {
    collectStrings(JSON.parse(content), strings);
  } catch {
    strings = [content];
  }
  const calls: Array<{ name: string; arguments: string }> = [];
  for (const text of strings) {
    for (const match of text.matchAll(/call_tool\s+([a-z0-9_]{1,64})/g)) {
      const after = (match.index ?? 0) + match[0].length;
      const brace = text.slice(after).search(/\S/);
      const json = brace >= 0 ? extractJsonObject(text, after + brace) : null;
      calls.push({ name: match[1]!, arguments: json ?? '{}' });
    }
    const ignore =
      /ignore (all |any )?(previous|prior|earlier) instructions[\s\S]*?\b([a-z0-9]+(?:_[a-z0-9]+)+)\b/i.exec(
        text,
      );
    if (ignore && ignore[3] !== 'call_tool')
      calls.push({ name: ignore[3]!.toLowerCase(), arguments: '{}' });
  }
  return calls;
}

const ORDINALS: Readonly<Record<string, number>> = {
  first: 1,
  second: 2,
  third: 3,
  fourth: 4,
  fifth: 5,
};

function parseRecord(content: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(content);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

/** Violations of an ok `policy_tools_validate` envelope with `valid: false`, else null. */
function invalidDefinition(envelope: Record<string, unknown>): number | null {
  if (envelope.tool !== 'policy_tools_validate') return null;
  const data = asRecord(envelope.data);
  if (!data || data.valid !== false) return null;
  const count = (key: string) => (Array.isArray(data[key]) ? (data[key] as unknown[]).length : 0);
  return count('violations') + count('referenceViolations');
}

/** The disposition of an ok `policy_tools_test` envelope, when the minimized result kept it. */
function testDisposition(envelope: Record<string, unknown>): string | null {
  if (envelope.tool !== 'policy_tools_test') return null;
  const data = asRecord(envelope.data);
  const value = data?.lifecycleDisposition ?? asRecord(data?.result)?.disposition;
  return typeof value === 'string' ? value : null;
}

/** A result after which a plan continues: ok, a valid definition, a quarantining test. */
function planMayContinue(content: string): boolean {
  const record = parseRecord(content);
  if (!record || record.status !== 'ok') return false;
  if (invalidDefinition(record) !== null) return false;
  const disposition = testDisposition(record);
  return disposition === null || disposition === 'quarantine';
}

/**
 * The answer after a `report_generate` result: the period and figures of the envelope only; a
 * queued background report (step AI-6 D5) has no figures yet.
 */
function reportAnswer(envelope: Record<string, unknown>): string {
  const data = asRecord(envelope.data);
  const period = asRecord(data?.period);
  const label = typeof period?.label === 'string' ? period.label : '';
  const when = /^Last /.test(label)
    ? `the ${label.toLowerCase()}`
    : label || 'the requested period';
  if (data?.status === 'queued')
    return `Your security report for ${when} is being generated; it will appear here when it is ready.`;
  const figures = Array.isArray(data?.figures) ? (data.figures as unknown[]) : [];
  const value = (name: string): string | null => {
    const figure = figures.map(asRecord).find((f) => f?.label === name);
    return typeof figure?.value === 'string' ? figure.value : null;
  };
  const parts = [
    value('Messages') !== null ? `${value('Messages')} messages` : null,
    value('Threats') !== null ? `${value('Threats')} threats` : null,
  ].filter((part): part is string => part !== null);
  return `Your security report for ${when} is ready below${parts.length > 0 ? `: ${parts.join(', ')}` : ''}.`;
}

function summarizeResult(content: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return 'I received a result I could not read.';
  }
  if (!parsed || typeof parsed !== 'object') return 'I received a result I could not read.';
  const record = parsed as Record<string, unknown>;
  if (record.status === 'error') return `The request failed: ${String(record.code)}.`;
  if (record.status === 'denied') return `The request was not allowed: ${String(record.code)}.`;
  if (record.status === 'pending_confirmation') return FAKE_PENDING_TEXT;
  if (record.status === 'ok' && record.tool === 'report_generate') return reportAnswer(record);
  if (record.status === 'ok') {
    const invalid = invalidDefinition(record);
    if (invalid !== null)
      return `The policy definition is not valid (${invalid} violation${invalid === 1 ? '' : 's'}).`;
    const disposition = testDisposition(record);
    if (disposition !== null && disposition !== 'quarantine')
      return `The test did not quarantine the sample message (disposition ${disposition}).`;
    if (Array.isArray(record.data)) {
      const count = record.data.length;
      return `Found ${count} record${count === 1 ? '' : 's'}.${record.hasMore ? ' More are available.' : ''}`;
    }
    return record.data === null ? 'Done.' : 'Here is the result.';
  }
  if (typeof record.name === 'string' && 'inputSchema' in record)
    return `Described ${record.name}.`;
  return 'Here is the result.';
}

/** The user's own text of a user entry (after the recap / action-updates marker, if any). */
function currentMessage(text: string): string {
  const marker = text.lastIndexOf(USER_MESSAGE_MARKER);
  return (marker >= 0 ? text.slice(marker + USER_MESSAGE_MARKER.length) : text).trim();
}

/** Tool names of the `call_tool` calls in the given entries, in order. */
function calledTools(entries: readonly FakeTranscriptEntry[]): string[] {
  return entries.flatMap((entry) =>
    entry.role === 'assistant'
      ? entry.toolCalls.flatMap((call) => {
          const input = asRecord(call.input);
          return call.name === 'call_tool' && typeof input?.name === 'string' ? [input.name] : [];
        })
      : [],
  );
}

/**
 * The plan step after the last one called since the user's message (the step index is the number
 * of plan tool calls so far); steps whose tool is not in the catalogue index are skipped.
 */
function nextPlanStep(
  plan: Plan,
  sinceUser: readonly FakeTranscriptEntry[],
  inCatalogue: (tool: string) => boolean,
): PlanStep | null {
  let index = -1;
  for (const tool of calledTools(sinceUser)) {
    const found = plan.steps.findIndex((step, i) => i > index && step.tool === tool);
    if (found >= 0) index = found;
  }
  for (let i = index + 1; i < plan.steps.length; i += 1) {
    const step = plan.steps[i]!;
    if (step.uncatalogued || inCatalogue(step.tool)) return step;
  }
  return null;
}

/** The execution ref (`r<seq>`) of the newest ok result of the tool, from its envelope. */
function newestListRef(transcript: readonly FakeTranscriptEntry[], tool: string): string | null {
  for (let i = transcript.length - 1; i >= 0; i -= 1) {
    const entry = transcript[i]!;
    if (entry.role !== 'tool') continue;
    const record = parseRecord(entry.content);
    if (
      record?.tool === tool &&
      record.status === 'ok' &&
      typeof record.ref === 'string' &&
      /^r\d+$/.test(record.ref)
    )
      return record.ref;
  }
  return null;
}

/** An action-update line of a succeeded create with a row ref (`updates.ts`). */
const createdLine = (tool: string): RegExp =>
  new RegExp(
    `^- ${tool} \\(call r\\d+\\): the user confirmed it; it succeeded[^\\n]*?Result: ref r\\d+, row ref (r\\d+\\.1)\\.`,
    'gm',
  );

/** The row ref of the newest succeeded create of the tool (`policy_management_create`, …). */
function newestCreatedRef(transcript: readonly FakeTranscriptEntry[], tool: string): string | null {
  const line = createdLine(tool);
  for (let i = transcript.length - 1; i >= 0; i -= 1) {
    const entry = transcript[i]!;
    if (entry.role !== 'user') continue;
    const matches = [...entry.text.matchAll(line)];
    if (matches.length > 0) return matches[matches.length - 1]![1]!;
  }
  return null;
}

export class FakeProvider implements LlmProvider {
  readonly id = 'fake' as const;
  readonly model: string;
  private readonly obedient: boolean;
  private readonly now: () => Date;
  private readonly latencyMs: number;
  private readonly failure: LlmErrorReason | null;

  constructor(options: FakeProviderOptions) {
    if (options.nodeEnv === 'production')
      throw new Error('ASSISTANT_PROVIDER=fake is refused when NODE_ENV=production');
    this.model = options.model ?? 'fake';
    this.obedient = options.obedient ?? false;
    this.now = options.now ?? (() => new Date());
    const latency = options.latencyMs ?? 0;
    if (!Number.isSafeInteger(latency) || latency < 0 || latency > FAKE_MAX_LATENCY_MS)
      throw new Error(`fake latencyMs must be an integer from 0 to ${FAKE_MAX_LATENCY_MS}`);
    this.latencyMs = latency;
    const failure = options.failure ?? null;
    if (failure !== null && !(LLM_ERROR_REASONS as readonly string[]).includes(failure))
      throw new Error('fake failure must be an LLM error reason');
    this.failure = failure;
  }

  /** Resolves (no network); throws the configured `failure`. */
  probe(signal: AbortSignal): Promise<void> {
    if (this.failure) return Promise.reject(new LlmError(this.failure));
    if (signal.aborted) return Promise.reject(new LlmError('aborted'));
    return Promise.resolve();
  }

  userEntry(text: string): unknown[] {
    return [{ role: 'user', text } satisfies FakeUserEntry];
  }

  toolResultEntries(results: readonly LlmToolResult[]): unknown[] {
    return results.map((result): FakeToolEntry => ({
      role: 'tool',
      toolCallId: result.toolCallId,
      content: result.content,
      isError: result.isError,
    }));
  }

  async complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    if (this.failure) throw new LlmError(this.failure);
    if (this.latencyMs === 0) return this.answer(request, onDelta);
    const response = await this.answer(request, () => undefined);
    await abortableSleep(this.latencyMs, signal);
    for (const chunk of fakeChunks(response.text)) onDelta(chunk);
    return response;
  }

  /** The deterministic answer of a round (deltas through `onDelta`). */
  private answer(request: LlmRequest, onDelta: (text: string) => void): Promise<LlmResponse> {
    const transcript = request.transcript as readonly FakeTranscriptEntry[];
    const input = request.system + JSON.stringify(transcript);
    const callCount = transcript.reduce(
      (sum, entry) => sum + (entry.role === 'assistant' ? entry.toolCalls.length : 0),
      0,
    );
    const callTool = (meta: MetaToolName, toolInput: Record<string, unknown>, index = 0) => ({
      id: `fake_call_${callCount + index + 1}`,
      name: meta,
      input: toolInput,
    });

    const tail: FakeToolEntry[] = [];
    for (let i = transcript.length - 1; i >= 0 && transcript[i]!.role === 'tool'; i -= 1)
      tail.unshift(transcript[i] as FakeToolEntry);

    const lastUserIndex = transcript.map((entry) => entry.role).lastIndexOf('user');
    const last = lastUserIndex >= 0 ? (transcript[lastUserIndex] as FakeUserEntry) : undefined;
    const message = currentMessage(last?.text ?? '');
    const lower = message.toLowerCase();
    const inCatalogue = (tool: string) => request.system.includes(`\n${tool}(`);
    const call = (tool: string, args: Record<string, unknown>) =>
      this.respond(
        input,
        '',
        [callTool('call_tool', { name: tool, arguments: JSON.stringify(args) })],
        onDelta,
      );
    const plan = /^\//.test(message) ? undefined : FAKE_PLANS.find((p) => p.pattern.test(lower));
    const match = plan ? plan.pattern.exec(lower) : null;

    if (tail.length > 0) {
      if (this.obedient) {
        const done = new Set(
          transcript.flatMap((entry) =>
            entry.role === 'assistant'
              ? entry.toolCalls.map((call) => JSON.stringify([call.name, call.input]))
              : [],
          ),
        );
        for (const result of tail) {
          for (const injected of findInjectedCalls(result.content)) {
            if (!NAME.test(injected.name)) continue;
            const call = callTool('call_tool', {
              name: injected.name,
              arguments: injected.arguments,
            });
            if (done.has(JSON.stringify([call.name, call.input]))) continue;
            return Promise.resolve(this.respond(input, '', [call], onDelta));
          }
        }
      }
      if (plan && match && tail.every((result) => planMayContinue(result.content))) {
        const next = nextPlanStep(plan, transcript.slice(lastUserIndex + 1), inCatalogue);
        const args = next?.args({
          match,
          previous: parseRecord(tail[tail.length - 1]!.content),
          message,
        });
        if (next && args) return Promise.resolve(call(next.tool, args));
      }
      const text = tail.map((result) => summarizeResult(result.content)).join(' ');
      return Promise.resolve(this.respond(input, text, [], onDelta));
    }

    const directive = /^\/(tool|describe|text)(?:\s+([\s\S]*))?$/.exec(message);
    if (directive) {
      const rest = (directive[2] ?? '').trim();
      if (directive[1] === 'text') return Promise.resolve(this.respond(input, rest, [], onDelta));
      const space = rest.search(/\s/);
      const name = space < 0 ? rest : rest.slice(0, space);
      if (directive[1] === 'describe')
        return Promise.resolve(
          this.respond(input, '', [callTool('describe_tool', { name })], onDelta),
        );
      const json = space < 0 ? '{}' : rest.slice(space + 1).trim() || '{}';
      return Promise.resolve(
        this.respond(input, '', [callTool('call_tool', { name, arguments: json })], onDelta),
      );
    }

    for (const report of FAKE_REPORT_INTENTS) {
      const found = report.pattern.exec(lower);
      if (!found) continue;
      if (!inCatalogue(report.tool))
        return Promise.resolve(this.respond(input, FAKE_UNAVAILABLE_TEXT, [], onDelta));
      return Promise.resolve(call(report.tool, report.args(found, lower)));
    }

    if (plan && match) {
      const first = nextPlanStep(plan, [], inCatalogue);
      const args = first?.args({ match, previous: null, message });
      return Promise.resolve(
        first && args
          ? call(first.tool, args)
          : this.respond(input, FAKE_UNAVAILABLE_TEXT, [], onDelta),
      );
    }

    const toggle =
      /\b(disable|enable) the (first|second|third|fourth|fifth|(\d+)(?:st|nd|rd|th)) one\b/.exec(
        lower,
      );
    if (toggle) {
      const tool = `policy_management_${toggle[1]}`;
      const n = toggle[3] ? Number(toggle[3]) : (ORDINALS[toggle[2]!] ?? 0);
      const listRef = newestListRef(transcript, 'policy_management_list');
      if (!listRef || n < 1)
        return Promise.resolve(this.respond(input, FAKE_HELP_TEXT, [], onDelta));
      if (!inCatalogue(tool))
        return Promise.resolve(this.respond(input, FAKE_UNAVAILABLE_TEXT, [], onDelta));
      return Promise.resolve(call(tool, { policyId: `@${listRef}.${n}` }));
    }

    if (/\bpublish (it|the policy)\b/.test(lower)) {
      const rowRef = newestCreatedRef(transcript, 'policy_management_create');
      if (!rowRef) return Promise.resolve(this.respond(input, FAKE_HELP_TEXT, [], onDelta));
      if (!inCatalogue('policy_management_publish'))
        return Promise.resolve(this.respond(input, FAKE_UNAVAILABLE_TEXT, [], onDelta));
      return Promise.resolve(
        call('policy_management_publish', {
          policyId: `@${rowRef}`,
          versionNo: 1,
          body: { activate: true },
        }),
      );
    }

    if (/\bverify (it|the domain)\b/.test(lower)) {
      const rowRef = newestCreatedRef(transcript, 'domains_create');
      if (!rowRef) return Promise.resolve(this.respond(input, FAKE_HELP_TEXT, [], onDelta));
      if (!inCatalogue('domain_dns_verify'))
        return Promise.resolve(this.respond(input, FAKE_UNAVAILABLE_TEXT, [], onDelta));
      return Promise.resolve(call('domain_dns_verify', { id: `@${rowRef}` }));
    }

    const intent = FAKE_DEMO_INTENTS.find((candidate) => candidate.pattern.test(lower));
    if (intent) {
      if (!inCatalogue(intent.tool))
        return Promise.resolve(this.respond(input, FAKE_UNAVAILABLE_TEXT, [], onDelta));
      const args = JSON.stringify(intent.args(this.now()));
      return Promise.resolve(
        this.respond(
          input,
          '',
          [callTool('call_tool', { name: intent.tool, arguments: args })],
          onDelta,
        ),
      );
    }
    return Promise.resolve(this.respond(input, FAKE_HELP_TEXT, [], onDelta));
  }

  private respond(
    input: string,
    text: string,
    toolCalls: LlmToolCall[],
    onDelta: (text: string) => void,
  ): LlmResponse {
    if (text.length > 0) onDelta(text);
    const entry: FakeAssistantEntry = { role: 'assistant', text, toolCalls };
    return {
      stop: toolCalls.length > 0 ? 'tool_use' : 'end_turn',
      text,
      toolCalls,
      appendToTranscript: [entry],
      usage: usageOf(input, JSON.stringify(entry)),
      responseModel: this.model,
    };
  }
}
