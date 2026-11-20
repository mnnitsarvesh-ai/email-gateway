'use client';

import {
  HistoryIcon,
  Maximize2Icon,
  MessageSquarePlusIcon,
  SparklesIcon,
  ZapOffIcon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { cn } from '@/lib/utils';
import { useAssistant } from './assistant-context';
import { Composer, DEFAULT_MESSAGE_MAX_CHARS } from './composer';
import { ConversationList } from './conversation-list';
import { ConversationView } from './conversation-view';
import { useAssistantAccess, type AssistantAccess } from './hooks';
import { SETTINGS_HREF, unavailableExplanation } from './model';

/**
 * The chat panel (step AI-1 D14): a right-side sheet (full screen below `md`) with the open
 * conversation, history, composer and a link to the full `/assistant` page. Radix traps focus in
 * the sheet and the shell returns focus to what opened it. `AssistantLauncher` is the persistent
 * "Ask AI" header button (Ctrl/Cmd+J toggles the panel).
 */

export function UnavailableReason({
  access,
  onNavigate,
  className,
}: {
  access: AssistantAccess;
  onNavigate?: () => void;
  className?: string;
}) {
  if (access.statusError)
    return <ErrorState error={access.statusError} compact className={className} />;
  const explanation = unavailableExplanation(access.status?.reason);
  return (
    <section
      aria-label="AI assistant unavailable"
      className={cn('grid gap-2 rounded-lg border border-dashed bg-card p-4 text-sm', className)}
    >
      <div className="flex items-center gap-2 font-semibold">
        <ZapOffIcon className="size-4 text-muted-foreground" aria-hidden />
        <h3>{explanation.title}</h3>
      </div>
      <p className="text-muted-foreground">{explanation.description}</p>
      {explanation.settingsLink && access.canConfigure ? (
        <Link
          href={SETTINGS_HREF}
          onClick={onNavigate}
          className="text-sm text-primary underline underline-offset-2"
        >
          Open Settings → AI assistant
        </Link>
      ) : null}
    </section>
  );
}

function PanelBody({ access, onNavigate }: { access: AssistantAccess; onNavigate: () => void }) {
  const { running, send, cancel, selectConversation } = useAssistant();
  const [history, setHistory] = useState(false);
  const composerRef = useRef<HTMLTextAreaElement>(null);
  if (access.loading)
    return <LoadingState label="Checking the AI assistant" rows={3} className="p-4" />;
  if (!access.available)
    return <UnavailableReason access={access} onNavigate={onNavigate} className="m-4" />;
  return (
    <>
      <div className="flex flex-wrap items-center gap-1 border-b px-3 py-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setHistory((value) => !value)}
          aria-expanded={history}
          aria-controls="assistant-panel-history"
        >
          <HistoryIcon aria-hidden />
          History
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            selectConversation(null);
            setHistory(false);
            composerRef.current?.focus();
          }}
          disabled={running}
        >
          <MessageSquarePlusIcon aria-hidden />
          New
        </Button>
        <Button variant="ghost" size="sm" asChild className="ml-auto">
          <Link href="/assistant" onClick={onNavigate}>
            <Maximize2Icon aria-hidden />
            Full page
          </Link>
        </Button>
      </div>
      {history ? (
        <div
          id="assistant-panel-history"
          className="max-h-[45%] min-h-0 overflow-hidden border-b p-3"
        >
          <ConversationList
            className="h-full"
            onSelected={() => {
              setHistory(false);
              composerRef.current?.focus();
            }}
          />
        </div>
      ) : null}
      <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
        <ConversationView onNavigate={onNavigate} />
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
    </>
  );
}

export function AssistantPanel({
  access,
  returnFocusTo,
}: {
  access: AssistantAccess;
  /** Element that gets focus back when the panel closes (the launcher or the shortcut origin). */
  returnFocusTo: React.RefObject<HTMLElement | null>;
}) {
  const { panelOpen, setPanelOpen } = useAssistant();
  const close = () => setPanelOpen(false);
  return (
    <Sheet open={panelOpen} onOpenChange={setPanelOpen}>
      <SheetContent
        side="right"
        className="w-full gap-0 p-0 sm:max-w-none md:w-[34rem] md:max-w-[34rem]"
        onCloseAutoFocus={(event) => {
          const target = returnFocusTo.current;
          if (target && target.isConnected) {
            event.preventDefault();
            target.focus();
          }
        }}
      >
        <div className="flex items-center gap-2 border-b px-4 py-3 pr-12">
          <SparklesIcon className="size-4 text-primary" aria-hidden />
          <SheetTitle className="text-base">AI assistant</SheetTitle>
        </div>
        <SheetDescription className="sr-only">
          Ask questions about your organization&apos;s email security. Answers use your own
          permissions.
        </SheetDescription>
        <div className="flex min-h-0 flex-1 flex-col">
          <PanelBody access={access} onNavigate={close} />
        </div>
      </SheetContent>
    </Sheet>
  );
}

/** Whether a keyboard event is the panel shortcut (Ctrl+J, or Cmd+J on macOS). */
export function isPanelShortcut(event: KeyboardEvent): boolean {
  return (
    (event.ctrlKey || event.metaKey) &&
    !event.altKey &&
    !event.shiftKey &&
    event.key.toLowerCase() === 'j'
  );
}

/**
 * "Ask AI" in the app-shell header: visible to `assistant:use` holders when the assistant is
 * available; when it is not, only to `assistant:configure` holders (who see the reason). Hidden
 * on the full `/assistant` page.
 */
export function AssistantLauncher() {
  const access = useAssistantAccess();
  const { panelOpen, setPanelOpen } = useAssistant();
  const pathname = usePathname();
  const buttonRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const onAssistantPage = pathname === '/assistant' || pathname.startsWith('/assistant/');
  const visible = access.showEntry && !onAssistantPage;

  useEffect(() => {
    if (!visible) return;
    const onKey = (event: KeyboardEvent) => {
      if (!isPanelShortcut(event)) return;
      event.preventDefault();
      if (!panelOpen) {
        const active = document.activeElement;
        returnFocus.current = active instanceof HTMLElement ? active : buttonRef.current;
      }
      setPanelOpen(!panelOpen);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [panelOpen, setPanelOpen, visible]);

  useEffect(() => {
    if (onAssistantPage && panelOpen) setPanelOpen(false);
  }, [onAssistantPage, panelOpen, setPanelOpen]);

  if (!visible) return null;
  const unavailable = !access.available;
  return (
    <>
      <Button
        ref={buttonRef}
        variant="outline"
        size="sm"
        onClick={() => {
          returnFocus.current = buttonRef.current;
          setPanelOpen(true);
        }}
        aria-haspopup="dialog"
        aria-expanded={panelOpen}
        aria-keyshortcuts="Control+J Meta+J"
        aria-label={unavailable ? 'Ask AI (unavailable)' : 'Ask AI'}
        title={
          unavailable
            ? unavailableExplanation(access.status?.reason).title
            : 'Ask the AI assistant (Ctrl+J)'
        }
      >
        <SparklesIcon aria-hidden />
        <span className="hidden sm:inline">Ask AI</span>
      </Button>
      <AssistantPanel access={access} returnFocusTo={returnFocus} />
    </>
  );
}
