/**
 * Builds the step AI-1 assistant services by hand for unit tests: the real services over the
 * in-memory `AssistantWorld`, an in-memory key-value store, the fake loopback dispatcher and a
 * test LLM provider (the package's deterministic `FakeProvider` by default, or a scripted one).
 * No database, Redis, LLM or network.
 */
import {
  type AssistantStreamEvent,
  FakeProvider,
  type LlmProvider,
  type LlmRequest,
  type LlmResponse,
  type LlmToolResult,
} from '@email-gateway/assistant';
import { MetricsService } from '@email-gateway/common';
import type { UserPrincipal } from '../../src/auth-contracts/principal';
import { scopeFromPrincipal, type TenantScope } from '../../src/auth-contracts/tenant-scope';
import { type ApiConfig, loadApiConfig } from '../../src/config';
import { CursorCodec } from '../../src/http/cursor/cursor-codec';
import type { AssistantConfig } from '../../src/modules/assistant/assistant.constants';
import { AssistantAvailabilityService } from '../../src/modules/assistant/services/assistant-availability.service';
import { AssistantLimitsService } from '../../src/modules/assistant/services/assistant-limits.service';
import { AssistantMetrics } from '../../src/modules/assistant/services/assistant-metrics';
import { AssistantProviderService } from '../../src/modules/assistant/services/assistant-provider.service';
import type { ConversationsRepository } from '../../src/modules/assistant/repositories/conversations.repository';
import { AssistantRetentionService } from '../../src/modules/assistant/services/assistant-retention.service';
import { AssistantSettingsService } from '../../src/modules/assistant/services/assistant-settings.service';
import { AssistantUsageService } from '../../src/modules/assistant/services/assistant-usage.service';
import { ConversationService } from '../../src/modules/assistant/services/conversation.service';
import { ExecutionsService } from '../../src/modules/assistant/services/executions.service';
import type { TurnSink } from '../../src/modules/assistant/services/sse-writer';
import { ToolExecutorService } from '../../src/modules/assistant/services/tool-executor.service';
import {
  type PreparedTurn,
  type ReplayedTurn,
  TurnEngineService,
} from '../../src/modules/assistant/services/turn-engine.service';
import { stubbedApiEnv } from './api-test-app';
import {
  AssistantWorld,
  FakeLoopback,
  immediateAssistantRunner,
  RecordingAssistantAudit,
  testUser,
} from './assistant-fixtures';
import { InMemoryKeyValueStore } from './in-memory-key-value-store';

/** A provider whose answers are scripted per call (rounds, refusals, waits, usage). */
export class ScriptedProvider implements LlmProvider {
  readonly id = 'fake' as const;
  readonly model = 'fake';
  readonly requests: LlmRequest[] = [];
  constructor(
    readonly script: Array<
      (
        request: LlmRequest,
        signal: AbortSignal,
        onDelta: (text: string) => void,
      ) => Promise<LlmResponse> | LlmResponse
    >,
    private readonly fallback?: (request: LlmRequest) => LlmResponse,
  ) {}

  userEntry(text: string): unknown[] {
    return [{ role: 'user', text }];
  }

  toolResultEntries(results: readonly LlmToolResult[]): unknown[] {
    return results.map((r) => ({
      role: 'tool',
      toolCallId: r.toolCallId,
      content: r.content,
      isError: r.isError,
    }));
  }

  async complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    this.requests.push(structuredClone({ ...request, tools: [] }));
    const step = this.script[this.requests.length - 1];
    if (step) return step(request, signal, onDelta);
    if (this.fallback) return this.fallback(request);
    throw new Error('ScriptedProvider: script exhausted');
  }
}

/** A scripted response helper. */
export function reply(
  partial: Partial<LlmResponse> & { text?: string },
  onDelta?: (text: string) => void,
): LlmResponse {
  const text = partial.text ?? '';
  if (text && onDelta) onDelta(text);
  const toolCalls = partial.toolCalls ?? [];
  return {
    stop: partial.stop ?? (toolCalls.length > 0 ? 'tool_use' : 'end_turn'),
    text,
    toolCalls,
    appendToTranscript: partial.appendToTranscript ?? [{ role: 'assistant', text, toolCalls }],
    usage: partial.usage ?? {
      inputTokens: 100,
      outputTokens: 10,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    },
    responseModel: partial.responseModel ?? 'fake',
    ...(partial.refusalCategory !== undefined && { refusalCategory: partial.refusalCategory }),
  };
}

/** A `call_tool` of a scripted response. */
export const callTool = (id: string, name: string, args: unknown = {}) => ({
  id,
  name: 'call_tool',
  input: { name, arguments: JSON.stringify(args) },
});

export class CollectingSink implements TurnSink {
  readonly events: AssistantStreamEvent[] = [];
  emit(event: AssistantStreamEvent): void {
    this.events.push(structuredClone(event));
  }
  get types(): string[] {
    return this.events.map((e) => e.type);
  }
}

export interface AssistantHarness {
  config: Readonly<ApiConfig>;
  world: AssistantWorld;
  kv: InMemoryKeyValueStore;
  loopback: FakeLoopback;
  audit: RecordingAssistantAudit;
  metrics: AssistantMetrics;
  provider: AssistantProviderService;
  limits: AssistantLimitsService;
  availability: AssistantAvailabilityService;
  settings: AssistantSettingsService;
  usage: AssistantUsageService;
  conversations: ConversationService;
  executor: ToolExecutorService;
  engine: TurnEngineService;
  executions: ExecutionsService;
  retention: AssistantRetentionService;
  /** The conversations repository double (tests may wrap a method). */
  conversationsRepo: ConversationsRepository;
  user: UserPrincipal;
  scope: TenantScope;
  /** Prepares and runs a turn; returns the events and the prepared/replayed handle. */
  ask(
    conversationPublicId: string,
    message: string,
    options?: { clientTurnId?: string; principal?: UserPrincipal },
  ): Promise<{ sink: CollectingSink; prepared: PreparedTurn | ReplayedTurn }>;
}

export function createAssistantHarness(
  env: Record<string, string> = {},
  llm?: LlmProvider,
  principal: UserPrincipal = testUser(),
): AssistantHarness {
  const config = loadApiConfig(
    stubbedApiEnv({ ASSISTANT_ENABLED: 'true', ASSISTANT_PROVIDER: 'fake', ...env }),
  );
  const c = config as AssistantConfig;
  const world = new AssistantWorld();
  const kv = new InMemoryKeyValueStore();
  const loopback = new FakeLoopback();
  const audit = new RecordingAssistantAudit();
  const metrics = new AssistantMetrics(new MetricsService({ service: 'api-test' }));
  const settingsRepo = world.settingsDouble();
  const conversationsRepo = world.conversationsDouble();
  const executionsRepo = world.executionsDouble();
  const usageRepo = world.usageDouble();
  const features = world.featuresDouble();
  const runner = immediateAssistantRunner;
  const provider = new AssistantProviderService(
    c,
    () => llm ?? new FakeProvider({ nodeEnv: 'test', model: 'fake' }),
    kv,
    metrics,
  );
  const limits = new AssistantLimitsService(c, kv, usageRepo, metrics);
  const availability = new AssistantAvailabilityService(
    c,
    settingsRepo,
    features,
    provider,
    limits,
    metrics,
  );
  const settings = new AssistantSettingsService(
    c,
    settingsRepo,
    features,
    limits,
    runner,
    audit,
    conversationsRepo,
  );
  const usage = new AssistantUsageService(usageRepo, provider);
  const codec = new CursorCodec(config);
  const conversations = new ConversationService(
    c,
    conversationsRepo,
    executionsRepo,
    settingsRepo,
    availability,
    codec,
    runner,
    audit,
  );
  const executor = new ToolExecutorService(c, executionsRepo, loopback, runner, audit, metrics);
  const engine = new TurnEngineService(
    c,
    conversationsRepo,
    executionsRepo,
    usageRepo,
    conversations,
    availability,
    limits,
    provider,
    executor,
    loopback,
    runner,
    metrics,
  );
  const executions = new ExecutionsService(executionsRepo, executor, availability, limits);
  const retention = new AssistantRetentionService(
    c,
    kv,
    conversationsRepo,
    executionsRepo,
    usageRepo,
    runner,
    metrics,
  );
  const scope = scopeFromPrincipal(principal);
  let counter = 0;
  return {
    config,
    world,
    kv,
    loopback,
    audit,
    metrics,
    provider,
    limits,
    availability,
    settings,
    usage,
    conversations,
    executor,
    engine,
    executions,
    retention,
    conversationsRepo,
    user: principal,
    scope,
    async ask(conversationPublicId, message, options = {}) {
      counter += 1;
      const who = options.principal ?? principal;
      const sink = new CollectingSink();
      const prepared = await engine.prepare(
        who,
        scopeFromPrincipal(who),
        conversationPublicId,
        {
          clientTurnId:
            options.clientTurnId ?? `0193d000-0000-7000-8000-${String(counter).padStart(12, '0')}`,
          message,
        },
        { authorization: 'Bearer it-access-token', clientIp: '198.51.100.7' },
      );
      if (prepared.kind === 'run') await engine.run(prepared, sink);
      else engine.replayEvents(prepared.result, sink);
      return { sink, prepared };
    },
  };
}
