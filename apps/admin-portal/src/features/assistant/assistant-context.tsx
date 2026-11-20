'use client';

import { useQueryClient } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { isAbortError } from '@/lib/api/stream';
import { browserTimeZone, turnErrorText } from './model';
import { StreamProtocolError, runTurn } from './stream';
import { endTurn, newPendingTurn, reduceTurn, type PendingTurn } from './turn-state';

/**
 * Shell-wide assistant state (step AI-1 D14): which conversation is open, whether the panel is
 * open, and the one running turn. It lives above the panel and the `/assistant` page so a running
 * turn keeps streaming when the panel closes or the user follows a link to a portal page.
 */
export interface AssistantContextValue {
  readonly panelOpen: boolean;
  readonly setPanelOpen: (open: boolean) => void;
  readonly conversationId: string | null;
  readonly selectConversation: (conversationId: string | null) => void;
  readonly pending: PendingTurn | null;
  readonly running: boolean;
  /** Sends a message (creates the conversation first when none is open). */
  readonly send: (message: string) => Promise<void>;
  /** Asks the same question again with a new `clientTurnId` (a failed turn). */
  readonly retry: (message: string) => Promise<void>;
  /** Cancels the running turn (`POST /assistant/turns/{id}/cancel` and abort of the stream). */
  readonly cancel: () => Promise<void>;
}

const AssistantContext = createContext<AssistantContextValue | null>(null);

export const MESSAGES_PAGE_LIMIT = 100;
const TITLE_MAX = 80;

function titleFrom(message: string): string {
  const line = message.replace(/\s+/g, ' ').trim();
  return line.length > TITLE_MAX ? `${line.slice(0, TITLE_MAX - 1)}…` : line;
}

function errorOf(error: unknown): { code: string; message: string; requestId: string | null } {
  if (error instanceof ApiError) {
    const retry =
      error.status === 429 && error.retryAfterSeconds
        ? ` Try again in ${error.retryAfterSeconds} s.`
        : '';
    return {
      code: error.code,
      message: `${turnErrorText(error.code, error.message)}${retry}`,
      requestId: error.requestId,
    };
  }
  if (error instanceof StreamProtocolError) {
    return { code: error.code, message: turnErrorText(error.code), requestId: null };
  }
  return { code: 'client_error', message: turnErrorText('client_error'), requestId: null };
}

export function AssistantProvider({
  children,
  initialConversationId = null,
}: {
  children: ReactNode;
  initialConversationId?: string | null;
}) {
  const queryClient = useQueryClient();
  const [panelOpen, setPanelOpen] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(initialConversationId);
  const [pending, setPending] = useState<PendingTurn | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const pendingRef = useRef<PendingTurn | null>(null);
  pendingRef.current = pending;

  useEffect(() => () => controllerRef.current?.abort(), []);

  const update = useCallback(
    (clientTurnId: string, next: (turn: PendingTurn) => PendingTurn | null) =>
      setPending((current) =>
        current && current.clientTurnId === clientTurnId ? next(current) : current,
      ),
    [],
  );

  const refreshAfterTurn = useCallback(
    async (forConversation: string) => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ['AssistantMessagesController_list_v1', forConversation],
        }),
        queryClient.invalidateQueries({ queryKey: ['AssistantConversationsController_list_v1'] }),
        queryClient.invalidateQueries({ queryKey: ['AssistantStatusController_get_v1'] }),
      ]);
    },
    [queryClient],
  );

  const ask = useCallback(
    async (message: string) => {
      const text = message.trim();
      if (!text || pendingRef.current?.status === 'running') return;
      let target = conversationId;
      const clientTurnId = crypto.randomUUID();
      const placeholder = newPendingTurn({
        clientTurnId,
        conversationId: target ?? '',
        message: text,
      });
      setPending(placeholder);
      pendingRef.current = placeholder;
      try {
        if (!target) {
          const created = await callOperation('AssistantConversationsController_create_v1', {
            body: { title: titleFrom(text) },
          });
          target = created.id;
          // A new conversation has no stored messages: no request until the turn ends.
          queryClient.setQueryData(['AssistantMessagesController_list_v1', created.id], {
            messages: [],
            complete: true,
          });
          setConversationId(created.id);
          update(clientTurnId, (turn) => ({ ...turn, conversationId: created.id }));
          void queryClient.invalidateQueries({
            queryKey: ['AssistantConversationsController_list_v1'],
          });
        }
      } catch (error) {
        const info = errorOf(error);
        update(clientTurnId, (turn) => endTurn(turn, 'failed', info));
        return;
      }
      const controller = new AbortController();
      controllerRef.current = controller;
      const conversation = target;
      try {
        const outcome = await runTurn(
          {
            conversationId: conversation,
            clientTurnId,
            message: text,
            timeZone: browserTimeZone(),
          },
          {
            signal: controller.signal,
            onEvent: (event) => update(clientTurnId, (turn) => reduceTurn(turn, event)),
          },
        );
        if (outcome.kind === 'failed') {
          update(clientTurnId, (turn) =>
            turn.status === 'failed'
              ? {
                  ...turn,
                  error: {
                    code: outcome.code,
                    message: turnErrorText(outcome.code, outcome.message),
                  },
                }
              : endTurn(turn, 'failed', {
                  code: outcome.code,
                  message: turnErrorText(outcome.code, outcome.message),
                }),
          );
          void refreshAfterTurn(conversation);
          return;
        }
        // Completed or cancelled: the stored turn replaces the streamed one once refetched.
        await refreshAfterTurn(conversation);
        update(clientTurnId, () => null);
      } catch (error) {
        if (controller.signal.aborted || isAbortError(error)) {
          update(clientTurnId, (turn) => endTurn(turn, 'cancelled'));
          await refreshAfterTurn(conversation);
          update(clientTurnId, () => null);
          return;
        }
        update(clientTurnId, (turn) => endTurn(turn, 'failed', errorOf(error)));
        if (error instanceof ApiError) {
          // The api refused the turn before storing anything (budget, rate limit, switches).
          void queryClient.invalidateQueries({ queryKey: ['AssistantStatusController_get_v1'] });
        } else {
          void refreshAfterTurn(conversation);
        }
      } finally {
        if (controllerRef.current === controller) controllerRef.current = null;
      }
    },
    [conversationId, queryClient, refreshAfterTurn, update],
  );

  const cancel = useCallback(async () => {
    const turn = pendingRef.current;
    if (!turn || turn.status !== 'running') return;
    if (turn.turnId) {
      try {
        await callOperation('AssistantTurnsController_cancel_v1', {
          path: { turnId: turn.turnId },
        });
      } catch {
        // The abort below ends the stream either way; the api cancels on disconnect too.
      }
    }
    controllerRef.current?.abort();
  }, []);

  const selectConversation = useCallback((id: string | null) => {
    if (pendingRef.current?.status === 'running') return;
    setPending(null);
    setConversationId(id);
  }, []);

  const value = useMemo<AssistantContextValue>(
    () => ({
      panelOpen,
      setPanelOpen,
      conversationId,
      selectConversation,
      pending,
      running: pending?.status === 'running',
      send: ask,
      retry: ask,
      cancel,
    }),
    [ask, cancel, conversationId, panelOpen, pending, selectConversation],
  );
  return <AssistantContext.Provider value={value}>{children}</AssistantContext.Provider>;
}

export function useAssistant(): AssistantContextValue {
  const context = useContext(AssistantContext);
  if (!context) throw new Error('useAssistant needs <AssistantProvider>');
  return context;
}
