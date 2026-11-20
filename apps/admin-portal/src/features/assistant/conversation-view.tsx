'use client';

import {
  AlertTriangleIcon,
  BotIcon,
  CheckCircle2Icon,
  CircleSlashIcon,
  Loader2Icon,
  RotateCcwIcon,
  SparklesIcon,
  XCircleIcon,
} from 'lucide-react';
import { useEffect, useMemo, useRef } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useAssistant } from './assistant-context';
import { useAssistantTools, useConversationMessages } from './hooks';
import { AssistantMarkdown } from './markdown';
import { suggestedPrompts, turnErrorText } from './model';
import { DeniedCard, ResultCard } from './result-card';
import { cardSchema } from './stream';
import type { ToolChipState, ToolEntry } from './turn-state';
import type { AssistantCard, StoredMessage } from './types';

/**
 * The messages of the open conversation (step AI-1 D14): stored messages with their tool
 * executions (chips and result cards) and the running turn, whose streamed text sits in a polite
 * live region (busy while it streams, so screen readers read the finished answer once). An empty
 * conversation shows suggested questions from the user's own tool catalogue.
 */

type StoredExecution = StoredMessage['executions'][number];

const CHIP: Record<ToolChipState, { label: string; icon: typeof CheckCircle2Icon; tone: string }> =
  {
    running: {
      label: 'running',
      icon: Loader2Icon,
      tone: 'bg-tone-info text-tone-info-foreground',
    },
    succeeded: {
      label: 'succeeded',
      icon: CheckCircle2Icon,
      tone: 'bg-tone-success text-tone-success-foreground',
    },
    denied: {
      label: 'denied',
      icon: CircleSlashIcon,
      tone: 'bg-tone-warning text-tone-warning-foreground',
    },
    failed: {
      label: 'failed',
      icon: XCircleIcon,
      tone: 'bg-tone-danger text-tone-danger-foreground',
    },
  };

function chipStateOf(execution: StoredExecution): ToolChipState {
  if (execution.decision !== 'allowed' || execution.status === 'refused') return 'denied';
  return execution.status === 'succeeded' ? 'succeeded' : 'failed';
}

function parseCard(value: unknown): AssistantCard | null {
  const parsed = cardSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function toEntry(execution: StoredExecution): ToolEntry {
  const card = execution.card ? parseCard(execution.card) : null;
  return {
    executionId: execution.id,
    tool: execution.tool,
    title: card?.title ?? execution.tool,
    state: chipStateOf(execution),
    decision: execution.decision,
    card,
    message: card?.message ?? card?.error?.message ?? execution.errorCode,
  };
}

export function ToolChips({ tools }: { tools: readonly ToolEntry[] }) {
  if (tools.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-1.5" aria-label="Tools the assistant used">
      {tools.map((tool) => {
        const chip = CHIP[tool.state];
        const Icon = chip.icon;
        return (
          <li
            key={tool.executionId}
            className={cn(
              'inline-flex max-w-full items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
              chip.tone,
            )}
          >
            <Icon
              className={cn('size-3.5 shrink-0', tool.state === 'running' && 'animate-spin')}
              aria-hidden
            />
            <span className="truncate">{tool.title}</span>
            <span className="sr-only">: {chip.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

function ToolResults({
  tools,
  hasMore,
  onNavigate,
}: {
  tools: readonly ToolEntry[];
  hasMore?: ReadonlyMap<string, boolean>;
  onNavigate?: () => void;
}) {
  const shown = tools.filter((tool) => tool.card || tool.state === 'denied');
  if (shown.length === 0) return null;
  return (
    <div className="grid gap-2">
      {shown.map((tool) =>
        tool.state === 'denied' && tool.decision && tool.decision !== 'allowed' ? (
          <DeniedCard
            key={tool.executionId}
            title={tool.title}
            decision={tool.decision}
            message={tool.message ?? 'The assistant could not use this tool.'}
          />
        ) : tool.card ? (
          <ResultCard
            key={tool.executionId}
            card={tool.card}
            hasMore={hasMore?.get(tool.executionId)}
            onNavigate={onNavigate}
          />
        ) : null,
      )}
    </div>
  );
}

function UserBubble({ text }: { text: string }) {
  return (
    <div className="flex justify-end">
      <div className="max-w-[85%] rounded-lg bg-primary px-3 py-2 text-sm whitespace-pre-wrap text-primary-foreground">
        <span className="sr-only">You: </span>
        {text}
      </div>
    </div>
  );
}

function AssistantBlock({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <span
        className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground"
        aria-hidden
      >
        <BotIcon className="size-3.5" />
      </span>
      <div className="grid min-w-0 flex-1 gap-2">
        <span className="sr-only">Assistant:</span>
        {children}
      </div>
    </div>
  );
}

function FailedNote({
  message,
  requestId,
  onRetry,
  disabled,
}: {
  message: string;
  requestId?: string | null;
  onRetry?: () => void;
  disabled?: boolean;
}) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-start gap-2 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground"
    >
      <AlertTriangleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid min-w-0 flex-1 gap-1">
        <p>{message}</p>
        {requestId ? (
          <p className="text-xs">
            Request ID: <span className="font-mono">{requestId}</span>
          </p>
        ) : null}
      </div>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry} disabled={disabled}>
          <RotateCcwIcon aria-hidden />
          Retry
        </Button>
      ) : null}
    </div>
  );
}

interface Exchange {
  readonly key: string;
  readonly turnId: string;
  readonly user: string | null;
  readonly assistant: string | null;
  readonly status: StoredMessage['turn']['status'];
  readonly errorCode: string | null;
  readonly tools: ToolEntry[];
  readonly hasMore: Map<string, boolean>;
}

/** Groups stored messages by turn (user question, tools, answer); executions deduplicated. */
export function exchangesOf(messages: readonly StoredMessage[]): Exchange[] {
  const byTurn = new Map<string, Exchange>();
  const seen = new Set<string>();
  for (const message of messages) {
    let exchange = byTurn.get(message.turnId);
    if (!exchange) {
      exchange = {
        key: message.turnId,
        turnId: message.turnId,
        user: null,
        assistant: null,
        status: message.turn.status,
        errorCode: message.turn.errorCode,
        tools: [],
        hasMore: new Map(),
      };
      byTurn.set(message.turnId, exchange);
    }
    const target: Exchange = exchange;
    const text = message.content;
    const next: Exchange = {
      ...target,
      user: message.role === 'user' ? text : target.user,
      assistant: message.role === 'assistant' ? text : target.assistant,
      tools: [...target.tools],
      hasMore: target.hasMore,
    };
    for (const execution of message.executions) {
      // "More" pages are follow-ups of a card already shown; never a separate result.
      if (seen.has(execution.id) || execution.parentExecutionId) continue;
      seen.add(execution.id);
      next.tools.push(toEntry(execution));
      next.hasMore.set(execution.id, execution.hasMore);
    }
    byTurn.set(message.turnId, next);
  }
  return [...byTurn.values()];
}

function SuggestedPrompts({
  onPick,
  disabled,
}: {
  onPick: (prompt: string) => void;
  disabled: boolean;
}) {
  const tools = useAssistantTools(true);
  const prompts = useMemo(
    () => suggestedPrompts((tools.data?.tools ?? []).map((tool) => tool.module)),
    [tools.data],
  );
  return (
    <div className="grid place-items-center gap-3 px-2 py-8 text-center">
      <span className="flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <SparklesIcon className="size-5" aria-hidden />
      </span>
      <div className="grid gap-1">
        <p className="text-base font-semibold">Ask about your email security</p>
        <p className="max-w-md text-sm text-muted-foreground">
          The assistant reads data with your own permissions and links to the portal pages. It
          cannot change settings yet.
        </p>
      </div>
      {tools.isLoading ? (
        <LoadingState label="Loading suggestions" rows={2} className="w-full max-w-sm" />
      ) : prompts.length > 0 ? (
        <ul className="grid w-full max-w-md gap-2" aria-label="Suggested questions">
          {prompts.map((prompt) => (
            <li key={prompt.module}>
              <Button
                variant="outline"
                className="h-auto w-full justify-start py-2 text-left whitespace-normal"
                onClick={() => onPick(prompt.prompt)}
                disabled={disabled}
              >
                <span className="grid gap-0.5">
                  <span className="text-xs text-muted-foreground">{prompt.label}</span>
                  <span>{prompt.prompt}</span>
                </span>
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function ConversationView({
  onNavigate,
  className,
}: {
  /** Called when a portal link is followed (the panel closes). */
  onNavigate?: () => void;
  className?: string;
}) {
  const { conversationId, pending, running, send, retry } = useAssistant();
  const messages = useConversationMessages(conversationId);
  const endRef = useRef<HTMLDivElement>(null);

  const exchanges = useMemo(
    () =>
      exchangesOf(messages.data?.messages ?? []).filter(
        (exchange) => !pending || exchange.turnId !== pending.turnId,
      ),
    [messages.data, pending],
  );
  const showPending = pending && (pending.conversationId === conversationId || !conversationId);
  const lastExchange = exchanges[exchanges.length - 1];

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' });
  }, [exchanges.length, pending?.text, pending?.tools.length, pending?.status]);

  // The running turn stays visible while the stored messages (re)load.
  if (conversationId && messages.isLoading && !showPending)
    return <LoadingState label="Loading the conversation" rows={4} className={className} />;
  if (conversationId && messages.error && !messages.data && !showPending)
    return (
      <ErrorState
        error={messages.error}
        onRetry={() => void messages.refetch()}
        className={className}
      />
    );

  const empty = exchanges.length === 0 && !showPending;
  return (
    <div className={cn('grid content-start gap-4', className)}>
      {empty ? (
        <SuggestedPrompts onPick={(prompt) => void send(prompt)} disabled={running} />
      ) : null}
      {messages.data && !messages.data.complete ? (
        <p className="text-center text-xs text-muted-foreground">
          Only the first {messages.data.messages.length} messages of this long conversation are
          shown. Start a new conversation for new questions.
        </p>
      ) : null}
      {exchanges.map((exchange) => {
        const failed = exchange.status === 'failed';
        const isLast = exchange === lastExchange && !showPending;
        return (
          <article key={exchange.key} className="grid gap-2" aria-label="Question and answer">
            {exchange.user !== null ? <UserBubble text={exchange.user} /> : null}
            {exchange.tools.length > 0 ||
            exchange.assistant ||
            failed ||
            exchange.status === 'cancelled' ? (
              <AssistantBlock>
                <ToolChips tools={exchange.tools} />
                <ToolResults
                  tools={exchange.tools}
                  hasMore={exchange.hasMore}
                  onNavigate={onNavigate}
                />
                {exchange.assistant ? (
                  <AssistantMarkdown source={exchange.assistant} onNavigate={onNavigate} />
                ) : null}
                {exchange.status === 'cancelled' ? (
                  <p className="text-xs text-muted-foreground">Stopped.</p>
                ) : null}
                {failed ? (
                  <FailedNote
                    message={turnErrorText(exchange.errorCode ?? 'assistant_provider_error')}
                    onRetry={
                      isLast && exchange.user ? () => void retry(exchange.user ?? '') : undefined
                    }
                    disabled={running}
                  />
                ) : null}
              </AssistantBlock>
            ) : null}
          </article>
        );
      })}
      {showPending && pending ? (
        <article className="grid gap-2" aria-label="Current question and answer">
          <UserBubble text={pending.message} />
          <AssistantBlock>
            <ToolChips tools={pending.tools} />
            <ToolResults tools={pending.tools} onNavigate={onNavigate} />
            <div aria-live="polite" aria-busy={pending.status === 'running'}>
              {pending.text ? (
                <AssistantMarkdown source={pending.text} onNavigate={onNavigate} />
              ) : pending.status === 'running' ? (
                <p className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2Icon className="size-4 animate-spin" aria-hidden />
                  {pending.tools.some((tool) => tool.state === 'running')
                    ? 'Looking up data …'
                    : 'Thinking …'}
                </p>
              ) : null}
            </div>
            {pending.status === 'cancelled' ? (
              <p className="text-xs text-muted-foreground">Stopped.</p>
            ) : null}
            {pending.status === 'failed' && pending.error ? (
              <FailedNote
                message={pending.error.message}
                requestId={pending.error.requestId}
                onRetry={() => void retry(pending.message)}
              />
            ) : null}
          </AssistantBlock>
        </article>
      ) : null}
      <div ref={endRef} />
    </div>
  );
}
