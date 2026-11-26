'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useRef } from 'react';
import { PageHeader } from '@/components/page-header';
import { LoadingState } from '@/components/states/loading-state';
import { RouteGate } from '@/lib/auth/route-gate';
import { navGate } from '@/features/reports/nav-gate';
import { useAssistant } from './assistant-context';
import { UnavailableReason } from './assistant-panel';
import { Composer, DEFAULT_MESSAGE_MAX_CHARS } from './composer';
import { ConversationList } from './conversation-list';
import { ConversationView } from './conversation-view';
import { useAssistantAccess } from './hooks';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * `/assistant` (step AI-1 D14): the full-screen chat with the conversation history beside it
 * (stacked below `md`). The open conversation is kept in `?conversation=<id>` so the page can be
 * reloaded or shared with oneself; another user's id simply answers 404.
 */
export function AssistantPage() {
  return (
    <RouteGate gate={navGate('assistant')}>
      <AssistantWorkspace />
    </RouteGate>
  );
}

function AssistantWorkspace() {
  const access = useAssistantAccess();
  const { conversationId, selectConversation, running, send, cancel } = useAssistant();
  const searchParams = useSearchParams();
  const router = useRouter();
  const requested = searchParams.get('conversation');
  const composerRef = useRef<HTMLTextAreaElement>(null);
  /** The conversation the URL reflects (`undefined` before the first sync). */
  const synced = useRef<string | null | undefined>(undefined);

  // URL → state once on arrival (a conversation the panel had open wins without a parameter),
  // then state → URL on every change of the open conversation.
  useEffect(() => {
    const replace = (id: string | null) =>
      router.replace(id ? `/assistant?conversation=${encodeURIComponent(id)}` : '/assistant', {
        scroll: false,
      });
    if (synced.current === undefined) {
      if (requested && UUID.test(requested)) {
        synced.current = requested;
        if (requested !== conversationId) selectConversation(requested);
      } else {
        synced.current = conversationId;
        if (conversationId) replace(conversationId);
      }
      return;
    }
    if (conversationId === synced.current) return;
    synced.current = conversationId;
    replace(conversationId);
  }, [conversationId, requested, router, selectConversation]);

  return (
    // On md+ the page fills the viewport below the top bar (h-14) and the main padding (py-5),
    // so only the conversation scrolls, never the whole page.
    <div className="flex flex-col gap-4 md:h-[calc(100dvh-6rem)]">
      <PageHeader
        title="AI assistant"
        description="Ask questions about your organization's email security in plain language. The assistant uses your own permissions and links to the pages it used. It changes nothing until you confirm the action in its card."
      />
      {access.loading ? (
        <LoadingState label="Checking the AI assistant" rows={4} />
      ) : !access.available ? (
        <UnavailableReason access={access} />
      ) : (
        <div className="grid gap-4 md:min-h-0 md:flex-1 md:grid-cols-[16rem_minmax(0,1fr)] lg:grid-cols-[18rem_minmax(0,1fr)]">
          <aside
            aria-label="Conversation history"
            className="relative rounded-lg border bg-card p-3 md:min-h-0 md:overflow-hidden"
          >
            <ConversationList
              className="h-full max-h-80 md:max-h-none"
              onSelected={() => composerRef.current?.focus()}
            />
          </aside>
          <section
            aria-label="Conversation"
            className="flex min-h-[28rem] flex-col rounded-lg border bg-card md:min-h-0"
          >
            <div className="relative min-h-0 flex-1 overflow-y-auto p-4">
              <ConversationView />
            </div>
            <div className="border-t p-3">
              <Composer
                ref={composerRef}
                running={running}
                onSend={(message) => void send(message)}
                onCancel={() => void cancel()}
                maxLength={access.status?.limits.messageMaxChars ?? DEFAULT_MESSAGE_MAX_CHARS}
              />
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
