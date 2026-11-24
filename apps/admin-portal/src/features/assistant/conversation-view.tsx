'use client';

import {
  AlertTriangleIcon,
  BotIcon,
  CheckCircle2Icon,
  CircleSlashIcon,
  ClockIcon,
  HourglassIcon,
  Loader2Icon,
  RotateCcwIcon,
  SparklesIcon,
  XCircleIcon,
} from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api/errors';
import { cn } from '@/lib/utils';
import { useAssistant } from './assistant-context';
import { ConfirmationCard } from './confirmation-card';
import { useAssistantTools, useConversationMessages } from './hooks';
import { AssistantMarkdown } from './markdown';
import { suggestedPrompts, turnErrorText } from './model';
import { DeniedCard, ResultCard } from './result-card';
import { cardSchema, parseConfirmationView } from './stream';
import {
  chipState,
  confirmationChipState,
  withLiveConfirmations,
  type ToolChipState,
  type ToolEntry,
} from './turn-state';
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
    pending: {
      label: 'awaiting your confirmation',
      icon: HourglassIcon,
      tone: 'bg-tone-warning text-tone-warning-foreground',
    },
    cancelled: {
      label: 'cancelled',
      icon: CircleSlashIcon,
      tone: 'bg-tone-neutral text-tone-neutral-foreground',
    },
    expired: {
      label: 'expired',
      icon: ClockIcon,
      tone: 'bg-tone-neutral text-tone-neutral-foreground',
    },
  };

/** The nearest ancestor that scrolls vertically, never the document itself. */
export function scrollContainerOf(element: HTMLElement): HTMLElement | null {
  for (let node = element.parentElement; node; node = node.parentElement) {
    if (node === document.body || node === document.documentElement) return null;
    const { overflowY } = window.getComputedStyle(node);
    if (overflowY === 'auto' || overflowY === 'scroll') return node;
  }
  return null;
}

function parseCard(value: unknown): AssistantCard | null {
  const parsed = cardSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function toEntry(execution: StoredExecution): ToolEntry {
  const card = execution.card ? parseCard(execution.card) : null;
  const confirmation =
    execution.status === 'pending_confirmation' && execution.confirmation
      ? parseConfirmationView(execution.confirmation)
      : null;
  return {
    executionId: execution.id,
    tool: execution.tool,
    title: confirmation?.summary?.title ?? card?.title ?? execution.title,
    state: confirmation
      ? confirmationChipState(confirmation.status)
      : chipState(execution.status, execution.decision),
    decision: execution.decision,
    card,
    // A refused call has no card: its message is the api's fixed text (for `denied_guard` the
    // guard's own message, design 30 D12), as the live `tool.denied` event carried it.
    message: card?.message ?? card?.error?.message ?? execution.message ?? execution.errorCode,
    confirmation,
    resultCard: null,
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

/** A proposal's confirmation card wired to the tab's confirmation store (step AI-2 D10). */
function ConfirmationSlot({
  tool,
  onNavigate,
  onAnnounce,
}: {
  tool: ToolEntry;
  onNavigate?: () => void;
  onAnnounce?: (text: string) => void;
}) {
  const { confirmations, updateConfirmation, running, pending } = useAssistant();
  const queryClient = useQueryClient();
  const view = tool.confirmation;
  const live = confirmations.get(tool.executionId);
  const isPending = view?.status === 'pending';
  const hasToken = Boolean(live?.token);
  // A view from elsewhere (history) says it is decided: the token is useless.
  useEffect(() => {
    if (!isPending && hasToken)
      updateConfirmation({ type: 'drop_token', executionId: tool.executionId });
  }, [hasToken, isPending, tool.executionId, updateConfirmation]);
  const conversationId = view?.conversationId;
  const onChanged = useCallback(() => {
    void queryClient.invalidateQueries({
      queryKey: ['AssistantMessagesController_list_v1', conversationId],
    });
    // Step AI-R: a confirmed report email adds a delivery; the report cards show it.
    if (view?.tool === 'report_send_email')
      void queryClient.invalidateQueries({ queryKey: ['AssistantReportsController_get_v1'] });
  }, [conversationId, queryClient, view?.tool]);
  if (!view) return null;
  return (
    <ConfirmationCard
      view={view}
      token={isPending ? (live?.token ?? null) : null}
      phase={live?.phase ?? (isPending ? 'idle' : 'decided')}
      resultCard={tool.resultCard}
      focusPending={live?.focusPending ?? false}
      streaming={running && pending?.conversationId === view.conversationId}
      dispatch={updateConfirmation}
      onChanged={onChanged}
      onAnnounce={onAnnounce}
      onNavigate={onNavigate}
    />
  );
}

function ToolResults({
  tools,
  hasMore,
  onNavigate,
  onAnnounce,
}: {
  tools: readonly ToolEntry[];
  hasMore?: ReadonlyMap<string, boolean>;
  onNavigate?: () => void;
  onAnnounce?: (text: string) => void;
}) {
  const shown = tools.filter((tool) => tool.card || tool.confirmation || tool.state === 'denied');
  if (shown.length === 0) return null;
  return (
    <div className="grid gap-2">
      {shown.map((tool) =>
        tool.confirmation ? (
          <ConfirmationSlot
            key={tool.executionId}
            tool={tool}
            onNavigate={onNavigate}
            onAnnounce={onAnnounce}
          />
        ) : tool.state === 'denied' && tool.decision && tool.decision !== 'allowed' ? (
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

/**
 * One question and its answer. Stored and running turns render through this one component so
 * the tool chips and cards sit at the same place in the tree for both.
 */
function ExchangeArticle({
  label,
  user,
  tools,
  hasMore,
  showAssistant,
  onNavigate,
  onAnnounce,
  children,
}: {
  label: string;
  user: string | null;
  tools: readonly ToolEntry[];
  hasMore?: ReadonlyMap<string, boolean>;
  showAssistant: boolean;
  onNavigate?: () => void;
  onAnnounce?: (text: string) => void;
  children?: React.ReactNode;
}) {
  return (
    <article className="grid gap-2" aria-label={label}>
      {user !== null ? <UserBubble text={user} /> : null}
      {showAssistant ? (
        <AssistantBlock>
          <ToolChips tools={tools} />
          <ToolResults
            tools={tools}
            hasMore={hasMore}
            onNavigate={onNavigate}
            onAnnounce={onAnnounce}
          />
          {children}
        </AssistantBlock>
      ) : null}
    </article>
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

/**
 * Groups stored messages by turn (user question, tools, answer); executions deduplicated. A
 * confirmed write's execution (child of its proposal) supplies the proposal's result card.
 */
export function exchangesOf(messages: readonly StoredMessage[]): Exchange[] {
  const byTurn = new Map<string, Exchange>();
  const seen = new Set<string>();
  const children = new Map<string, StoredExecution>();
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
      // "More" pages and confirmed writes are follow-ups of a card already shown.
      if (execution.parentExecutionId) children.set(execution.id, execution);
      if (seen.has(execution.id) || execution.parentExecutionId) continue;
      seen.add(execution.id);
      next.tools.push(toEntry(execution));
      next.hasMore.set(execution.id, execution.hasMore);
    }
    byTurn.set(message.turnId, next);
  }
  return [...byTurn.values()].map((exchange) => ({
    ...exchange,
    tools: exchange.tools.map((tool) => {
      const resultId = tool.confirmation?.resultExecutionId;
      const result = resultId ? children.get(resultId) : undefined;
      return result?.card ? { ...tool, resultCard: parseCard(result.card) } : tool;
    }),
  }));
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
          The assistant reads data with your own permissions and links to the portal pages. Changes
          it proposes run only after you review and confirm them.
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
  const { conversationId, pending, running, send, retry, confirmations, selectConversation } =
    useAssistant();
  const messages = useConversationMessages(conversationId);

  // A remembered conversation that no longer exists (deleted, purged by retention, or another
  // user's): start a new chat instead of showing an error.
  const missing = messages.error instanceof ApiError && messages.error.status === 404;
  useEffect(() => {
    if (missing && !running) selectConversation(null);
  }, [missing, running, selectConversation]);
  const endRef = useRef<HTMLDivElement>(null);
  // Confirmation status changes (D10): one polite status region for the conversation.
  const [announcement, setAnnouncement] = useState('');
  const announce = useCallback((text: string) => setAnnouncement(text), []);

  const exchanges = useMemo(
    () =>
      exchangesOf(messages.data?.messages ?? [])
        .filter((exchange) => !pending || exchange.turnId !== pending.turnId)
        .map((exchange) => ({
          ...exchange,
          tools: withLiveConfirmations(exchange.tools, confirmations),
        })),
    [confirmations, messages.data, pending],
  );
  const pendingTools = useMemo(
    () => (pending ? withLiveConfirmations(pending.tools, confirmations) : []),
    [confirmations, pending],
  );
  const showPending = pending && (pending.conversationId === conversationId || !conversationId);
  const lastExchange = exchanges[exchanges.length - 1];

  useEffect(() => {
    // Scroll only the conversation's own scroll container: `scrollIntoView` would also scroll
    // the window (and every other scrollable ancestor), dragging the whole console page.
    const end = endRef.current;
    const container = end ? scrollContainerOf(end) : null;
    if (container) container.scrollTop = container.scrollHeight;
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
      <p className="sr-only" role="status" aria-live="polite">
        {announcement}
      </p>
      {messages.data && !messages.data.complete ? (
        <p className="text-center text-xs text-muted-foreground">
          Only the first {messages.data.messages.length} messages of this long conversation are
          shown. Start a new conversation for new questions.
        </p>
      ) : null}
      {[
        ...exchanges.map((exchange) => {
          const failed = exchange.status === 'failed';
          const isLast = exchange === lastExchange && !showPending;
          return (
            <ExchangeArticle
              key={exchange.key}
              label="Question and answer"
              user={exchange.user}
              tools={exchange.tools}
              hasMore={exchange.hasMore}
              showAssistant={
                exchange.tools.length > 0 ||
                Boolean(exchange.assistant) ||
                failed ||
                exchange.status === 'cancelled'
              }
              onNavigate={onNavigate}
              onAnnounce={announce}
            >
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
            </ExchangeArticle>
          );
        }),
        // The running turn shares the stored turn's key (its turn id) and element structure, so
        // when the stored messages replace it the same card instances stay mounted: a focused
        // confirmation card keeps the focus instead of being remounted (step AI-2 D10).
        showPending && pending ? (
          <ExchangeArticle
            key={pending.turnId ?? pending.clientTurnId}
            label="Current question and answer"
            user={pending.message}
            tools={pendingTools}
            showAssistant
            onNavigate={onNavigate}
            onAnnounce={announce}
          >
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
          </ExchangeArticle>
        ) : null,
      ]}
      <div ref={endRef} />
    </div>
  );
}
