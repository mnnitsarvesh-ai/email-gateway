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
 * - After tool results: a deterministic template ("Found N records." / the coded error).
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
  if (record.status === 'ok') {
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
      const text = tail.map((result) => summarizeResult(result.content)).join(' ');
      return Promise.resolve(this.respond(input, text, [], onDelta));
    }

    const last = [...transcript]
      .reverse()
      .find((entry): entry is FakeUserEntry => entry.role === 'user');
    let message = (last?.text ?? '').trim();
    const marker = message.lastIndexOf('Current user message:\n');
    if (marker >= 0) message = message.slice(marker + 'Current user message:\n'.length).trim();

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

    const lower = message.toLowerCase();
    const intent = FAKE_DEMO_INTENTS.find((candidate) => candidate.pattern.test(lower));
    if (intent) {
      if (!request.system.includes(`\n${intent.tool}(`))
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
