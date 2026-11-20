'use client';

import { ArchiveIcon, MoreHorizontalIcon, PlusIcon, SearchIcon } from 'lucide-react';
import { useEffect, useId, useState, type FormEvent } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { cn } from '@/lib/utils';
import { useAssistant } from './assistant-context';
import { conversationTitle } from './model';
import type { Conversation } from './types';

/**
 * Conversation history (step AI-1 D14): search by title (`q`), active or archived, new
 * conversation, rename, archive/restore and delete ("Clear conversation": soft delete with
 * immediate content purge by the api). Only the user's own conversations exist here.
 */

export const CONVERSATION_LIST_LIMIT = 50;
const TITLE_MAX = 200;

function RenameDialog({
  conversation,
  onOpenChange,
}: {
  conversation: Conversation | null;
  onOpenChange: (open: boolean) => void;
}) {
  const [title, setTitle] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const mutation = useApiMutation('AssistantConversationsController_update_v1', {
    successMessage: 'Conversation renamed.',
    invalidates: ['AssistantConversationsController_list_v1'],
  });
  useEffect(() => {
    setTitle(conversation?.title ?? '');
    setError(null);
  }, [conversation]);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!conversation) return;
    const value = title.trim();
    if (!value) {
      setError('Enter a title.');
      return;
    }
    const outcome = await mutation.submit({
      path: { conversationId: conversation.id },
      body: { title: value },
    });
    if (outcome.ok) onOpenChange(false);
    else setError(outcome.error.messages.join(' '));
  };
  return (
    <Dialog open={conversation !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={(event) => void submit(event)} className="grid gap-4" noValidate>
          <DialogHeader>
            <DialogTitle>Rename conversation</DialogTitle>
            <DialogDescription>Only you see your conversations.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor={inputId}>Title</Label>
            <Input
              id={inputId}
              value={title}
              maxLength={TITLE_MAX}
              onChange={(event) => setTitle(event.target.value)}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? `${inputId}-error` : undefined}
              autoComplete="off"
            />
            {error ? (
              <p id={`${inputId}-error`} className="text-sm text-destructive">
                {error}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? 'Saving …' : 'Save'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function ConversationList({
  onSelected,
  className,
}: {
  /** Called after a conversation was chosen or a new one started (the panel shows it). */
  onSelected?: () => void;
  className?: string;
}) {
  const { conversationId, selectConversation, running } = useAssistant();
  const [search, setSearch] = useState('');
  const [archived, setArchived] = useState(false);
  const q = useDebouncedValue(search.trim(), 300);
  const [renaming, setRenaming] = useState<Conversation | null>(null);
  const [deleting, setDeleting] = useState<Conversation | null>(null);
  const searchId = useId();
  const archivedId = useId();
  const list = useApiQuery('AssistantConversationsController_list_v1', {
    query: {
      limit: String(CONVERSATION_LIST_LIMIT),
      status: archived ? 'archived' : 'active',
      ...(q ? { q } : {}),
    },
  });
  const update = useApiMutation('AssistantConversationsController_update_v1', {
    invalidates: ['AssistantConversationsController_list_v1'],
  });
  const remove = useApiMutation('AssistantConversationsController_remove_v1', {
    successMessage: 'Conversation cleared.',
    invalidates: ['AssistantConversationsController_list_v1'],
  });

  const choose = (id: string | null) => {
    selectConversation(id);
    onSelected?.();
  };

  const setStatus = async (conversation: Conversation, status: 'active' | 'archived') => {
    const outcome = await update.submit({
      path: { conversationId: conversation.id },
      body: { status },
    });
    if (outcome.ok && status === 'archived' && conversation.id === conversationId)
      selectConversation(null);
  };

  const rows = list.data?.data ?? [];
  return (
    <div className={cn('flex min-h-0 flex-col gap-2', className)}>
      <Button onClick={() => choose(null)} disabled={running} className="justify-start">
        <PlusIcon aria-hidden />
        New conversation
      </Button>
      <div className="relative">
        <SearchIcon
          className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <label htmlFor={searchId} className="sr-only">
          Search conversations by title
        </label>
        <Input
          id={searchId}
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search by title"
          className="h-8 pl-8"
        />
      </div>
      <div className="flex items-center gap-2 text-xs">
        <Switch id={archivedId} checked={archived} onCheckedChange={setArchived} />
        <Label htmlFor={archivedId} className="text-xs font-normal">
          Show archived
        </Label>
      </div>
      {list.isLoading ? (
        <LoadingState label="Loading conversations" rows={4} />
      ) : list.error ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : rows.length === 0 ? (
        <p className="px-1 py-4 text-sm text-muted-foreground">
          {q
            ? 'No conversation title matches this search.'
            : archived
              ? 'No archived conversations.'
              : 'No conversations yet.'}
        </p>
      ) : (
        <ul className="grid min-h-0 gap-1 overflow-y-auto" aria-label="Conversations">
          {rows.map((conversation) => {
            const current = conversation.id === conversationId;
            const title = conversationTitle(conversation.title);
            return (
              <li
                key={conversation.id}
                className={cn(
                  'group flex items-center gap-1 rounded-md pr-1 hover:bg-accent',
                  current && 'bg-accent',
                )}
              >
                <button
                  type="button"
                  onClick={() => choose(conversation.id)}
                  disabled={running && !current}
                  aria-current={current ? 'true' : undefined}
                  className="grid min-w-0 flex-1 gap-0.5 rounded-md px-2 py-1.5 text-left text-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-60"
                >
                  <span className="truncate font-medium">
                    {conversation.contentPurged ? 'Content removed after retention' : title}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {conversation.lastTurnAt ? (
                      <DateTime value={conversation.lastTurnAt} />
                    ) : (
                      'No questions yet'
                    )}
                    {conversation.status === 'archived' ? (
                      <span className="ml-1 inline-flex items-center gap-0.5">
                        <ArchiveIcon className="size-3" aria-hidden /> Archived
                      </span>
                    ) : null}
                  </span>
                </button>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label={`Actions for ${title}`}
                      className="size-7"
                    >
                      <MoreHorizontalIcon aria-hidden />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onSelect={() => setRenaming(conversation)}>
                      Rename
                    </DropdownMenuItem>
                    {conversation.status === 'archived' ? (
                      <DropdownMenuItem onSelect={() => void setStatus(conversation, 'active')}>
                        Restore
                      </DropdownMenuItem>
                    ) : (
                      <DropdownMenuItem
                        onSelect={() => void setStatus(conversation, 'archived')}
                        disabled={running && current}
                      >
                        Archive
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={() => setDeleting(conversation)}
                      disabled={running && current}
                    >
                      Clear conversation
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </li>
            );
          })}
        </ul>
      )}
      {list.data?.nextCursor ? (
        <p className="px-1 text-xs text-muted-foreground">
          The {CONVERSATION_LIST_LIMIT} most recent conversations are shown; search by title to find
          older ones.
        </p>
      ) : null}
      <RenameDialog
        conversation={renaming}
        onOpenChange={(open) => {
          if (!open) setRenaming(null);
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) setDeleting(null);
        }}
        title="Clear conversation"
        description={
          <p>
            “{conversationTitle(deleting?.title)}” and its messages and results are deleted now. The
            record that tools were used stays in the audit log. This cannot be undone.
          </p>
        }
        confirmLabel="Clear conversation"
        destructive
        error={
          remove.error ? (
            <ErrorState error={remove.error} compact showRequirement={false} />
          ) : undefined
        }
        onConfirm={async () => {
          if (!deleting) return false;
          const outcome = await remove.submit({ path: { conversationId: deleting.id } });
          if (!outcome.ok) return false;
          if (deleting.id === conversationId) selectConversation(null);
          return true;
        }}
      />
    </div>
  );
}
