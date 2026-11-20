'use client';

import { useQuery } from '@tanstack/react-query';
import { callOperation } from '@/lib/api/call';
import type { ApiError } from '@/lib/api/errors';
import { shouldRetry, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { MESSAGES_PAGE_LIMIT } from './assistant-context';
import type { AssistantStatus, StoredMessage } from './types';

/**
 * Who sees the assistant (step AI-1 D14): the entry points need `AssistantConversationsController_list_v1`
 * (`assistant:use`) and `GET /assistant/status.available`; when it is not available only users
 * holding `assistant:configure` (gate `AssistantSettingsController_get_v1`) see the reason.
 */
export interface AssistantAccess {
  readonly canUse: boolean;
  readonly canConfigure: boolean;
  readonly status: AssistantStatus | undefined;
  readonly statusError: ApiError | null;
  readonly loading: boolean;
  readonly available: boolean;
  /** The header button is shown (available, or unavailable with a reason for a configurer). */
  readonly showEntry: boolean;
}

export function useAssistantStatus(enabled: boolean) {
  return useApiQuery('AssistantStatusController_get_v1', undefined, {
    enabled,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

export function useAssistantAccess(): AssistantAccess {
  const canUse = useCan('AssistantConversationsController_list_v1');
  const canConfigure = useCan('AssistantSettingsController_get_v1');
  const status = useAssistantStatus(canUse);
  const available = canUse && status.data?.available === true;
  return {
    canUse,
    canConfigure,
    status: status.data,
    statusError: status.error,
    loading: canUse && status.isLoading,
    available,
    showEntry: available || (canUse && canConfigure && status.data !== undefined),
  };
}

/** Upper bound of stored messages loaded for one conversation (pages of 100, oldest first). */
export const MAX_MESSAGE_PAGES = 10;

/** Every stored message of a conversation, oldest → newest (cursor v1 pages). */
export function useConversationMessages(conversationId: string | null) {
  return useQuery<{ messages: StoredMessage[]; complete: boolean }, ApiError>({
    queryKey: ['AssistantMessagesController_list_v1', conversationId],
    enabled: Boolean(conversationId),
    retry: shouldRetry,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
    queryFn: async ({ signal }) => {
      const messages: StoredMessage[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < MAX_MESSAGE_PAGES; page += 1) {
        const body: Awaited<
          ReturnType<typeof callOperation<'AssistantMessagesController_list_v1'>>
        > = await callOperation(
          'AssistantMessagesController_list_v1',
          {
            path: { conversationId: conversationId ?? '' },
            query: { limit: String(MESSAGES_PAGE_LIMIT), ...(cursor ? { cursor } : {}) },
          },
          { signal },
        );
        messages.push(...body.data);
        cursor = body.nextCursor;
        if (!cursor) return { messages, complete: true };
      }
      return { messages, complete: false };
    },
  });
}

/** The caller's tool catalogue (suggested prompts). */
export function useAssistantTools(enabled: boolean) {
  return useApiQuery('AssistantToolsController_list_v1', undefined, {
    enabled,
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
}
