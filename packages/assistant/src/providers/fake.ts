import { USER_MESSAGE_MARKER } from '../confirmations/updates';
import type {
  LlmProvider,
  LlmRequest,
  LlmResponse,
  LlmToolCall,
  LlmToolResult,
  MetaToolName,
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
 * - Follow-ups (D8): "disable/enable the second one" (the newest `policy_management_list` result)
 *   and "publish it" (the newest succeeded `policy_management_create` of the action updates).
 * - After tool results: a deterministic template ("Found N records." / the coded error / the
 *   pending-confirmation sentence).
 * - `obedient: true` (tests only): follows instruction-shaped text found in tool results
 *   (`call_tool <name> <json>`, "ignore previous instructions … <tool name>") once each, to prove
 *   that the server-side controls hold when the model is fooled.
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

interface PlanStep {
  tool: string;
  args: () => Record<string, unknown>;
}

interface Plan {
  pattern: RegExp;
  steps: readonly PlanStep[];
}

/** Multi-step demo intents (D8). Tool names are registry names (checked by tests). */
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
];

export const FAKE_PENDING_TEXT =
  'I prepared this change. Review it in the confirmation card; nothing changes until you confirm it.';

export const FAKE_HELP_TEXT =
  'I can look things up for you, for example: "show active policies", "what was quarantined today", "show incidents", "journaling status", "archive status", "list domains", "list users", "traffic report today" or "ATO overview".';
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
  for (let i = index + 1; i < plan.steps.length; i += 1)
    if (inCatalogue(plan.steps[i]!.tool)) return plan.steps[i]!;
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

const CREATED_POLICY_LINE =
  /^- policy_management_create \(call r\d+\): the user confirmed it; it succeeded[^\n]*?Result: ref r\d+, row ref (r\d+\.1)\./gm;

/** The row ref of the newest succeeded `policy_management_create` in the action updates. */
function newestCreatedPolicyRef(transcript: readonly FakeTranscriptEntry[]): string | null {
  for (let i = transcript.length - 1; i >= 0; i -= 1) {
    const entry = transcript[i]!;
    if (entry.role !== 'user') continue;
    const matches = [...entry.text.matchAll(CREATED_POLICY_LINE)];
    if (matches.length > 0) return matches[matches.length - 1]![1]!;
  }
  return null;
}

export class FakeProvider implements LlmProvider {
  readonly id = 'fake' as const;
  readonly model: string;
  private readonly obedient: boolean;
  private readonly now: () => Date;

  constructor(options: FakeProviderOptions) {
    if (options.nodeEnv === 'production')
      throw new Error('ASSISTANT_PROVIDER=fake is refused when NODE_ENV=production');
    this.model = options.model ?? 'fake';
    this.obedient = options.obedient ?? false;
    this.now = options.now ?? (() => new Date());
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

  complete(
    request: LlmRequest,
    _signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
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
      if (plan && tail.every((result) => planMayContinue(result.content))) {
        const next = nextPlanStep(plan, transcript.slice(lastUserIndex + 1), inCatalogue);
        if (next) return Promise.resolve(call(next.tool, next.args()));
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

    if (plan) {
      const first = nextPlanStep(plan, [], inCatalogue);
      return Promise.resolve(
        first
          ? call(first.tool, first.args())
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
      const rowRef = newestCreatedPolicyRef(transcript);
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
