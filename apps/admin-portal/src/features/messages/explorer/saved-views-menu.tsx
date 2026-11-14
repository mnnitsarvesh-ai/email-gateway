'use client';

import { BookmarkIcon, ChevronDownIcon } from 'lucide-react';
import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { FormErrorSummary, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
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
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useMe } from '@/lib/auth/me';
import {
  SAVED_VIEWS_PAGE_SIZE,
  SAVED_VIEW_KIND,
  createViewBody,
  definitionKey,
  updateViewBody,
  viewNameFormSchema,
  type SavedView,
  type SavedViewDefinition,
} from './saved-view-definition';

/** Saved views are cached for 5 minutes (§2 E10: rate-limit friendly). */
export const SAVED_VIEWS_STALE_MS = 5 * 60_000;
const LIST = 'SavedViewsController_list_v1';

const MEMBER_ONLY_TEXT =
  'Saved views belong to the members of an organization. While you act in another organization through a platform override, you cannot list or save views.';

/** The views list query (shared by the menu and the page, which resolves `?view=`). */
export function useSavedViews(enabled: boolean) {
  return useApiQuery(
    LIST,
    { query: { kind: SAVED_VIEW_KIND, limit: SAVED_VIEWS_PAGE_SIZE } },
    { staleTime: SAVED_VIEWS_STALE_MS, refetchOnWindowFocus: false, enabled },
  );
}

/** Whether saved views are unavailable to this session (platform override). */
export function useSavedViewsMemberOnly(): boolean {
  const me = useMe();
  return Boolean(me.data?.override);
}

type Dialogs =
  | { kind: 'save-as' }
  | { kind: 'rename'; view: SavedView }
  | { kind: 'delete'; view: SavedView }
  | null;

/**
 * The explorer's "Views" menu (step 7.2 §2 E4, E10): apply, save as, save changes, rename and
 * delete (with confirmation) the caller's own views. The api keeps them per user and
 * organization; a platform override session gets `403 saved_views_member_only`, so the menu is
 * replaced by an explanation.
 */
export function SavedViewsMenu({
  viewId,
  definition,
  onApply,
  onSaved,
  onDeleted,
}: {
  /** The applied view (`?view=`). */
  viewId: string | undefined;
  /** The definition of the current explorer state and column set. */
  definition: SavedViewDefinition;
  onApply: (view: SavedView) => void;
  /** A view was created or its changes were saved: it becomes the applied view. */
  onSaved: (view: SavedView) => void;
  onDeleted: (viewId: string) => void;
}) {
  const memberOnly = useSavedViewsMemberOnly();
  const list = useSavedViews(!memberOnly);
  const [dialog, setDialog] = useState<Dialogs>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const save = useApiMutation('SavedViewsController_update_v1', {
    invalidates: [LIST],
    successMessage: 'View saved.',
  });
  const remove = useApiMutation('SavedViewsController_remove_v1', {
    invalidates: [LIST],
    successMessage: 'View deleted.',
  });

  const forbidden =
    memberOnly ||
    (list.error instanceof ApiError &&
      list.error.status === 403 &&
      list.error.code === 'saved_views_member_only');
  if (forbidden) {
    return (
      <p className="max-w-md text-xs text-muted-foreground" data-testid="saved-views-member-only">
        {MEMBER_ONLY_TEXT}
      </p>
    );
  }

  const views = list.data?.data ?? [];
  const current = views.find((view) => view.id === viewId) ?? null;
  const modified = current
    ? definitionKey(current.definition) !== definitionKey(definition)
    : false;

  const saveChanges = async () => {
    if (!current) return;
    setNotice(null);
    const outcome = await save.submit({
      path: { viewId: current.id },
      body: updateViewBody(current, current.name, definition),
    });
    if (outcome.ok) {
      onSaved(outcome.data);
      return;
    }
    if (outcome.error.status === 409 && outcome.error.code === 'saved_view_conflict') {
      setNotice(
        'This view was changed elsewhere (another tab or device). The list was reloaded: apply the view again, then save your changes.',
      );
      void list.refetch();
      return;
    }
    setNotice(outcome.error.messages.join(' '));
  };

  return (
    <div className="grid min-w-0 gap-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="max-w-full justify-between">
            <BookmarkIcon aria-hidden />
            <span className="truncate">
              Views
              {current ? `: ${current.name}` : ''}
              {modified ? ' (modified)' : ''}
            </span>
            <ChevronDownIcon className="opacity-60" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="max-w-80">
          <DropdownMenuLabel>Your saved views</DropdownMenuLabel>
          {list.isLoading ? (
            <DropdownMenuItem disabled>Loading views …</DropdownMenuItem>
          ) : list.error ? (
            <DropdownMenuItem onSelect={() => void list.refetch()}>
              Views could not be loaded. Retry
            </DropdownMenuItem>
          ) : views.length === 0 ? (
            <DropdownMenuItem disabled>No saved views yet</DropdownMenuItem>
          ) : (
            <DropdownMenuRadioGroup value={current?.id ?? ''}>
              {views.map((view) => (
                <DropdownMenuRadioItem
                  key={view.id}
                  value={view.id}
                  onSelect={() => {
                    setNotice(null);
                    onApply(view);
                  }}
                >
                  <span className="truncate">{view.name}</span>
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setDialog({ kind: 'save-as' })}>
            Save as new view …
          </DropdownMenuItem>
          {current ? (
            <>
              <DropdownMenuItem
                disabled={!modified || save.isPending}
                onSelect={() => void saveChanges()}
              >
                Save changes to “{current.name}”
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setDialog({ kind: 'rename', view: current })}>
                Rename “{current.name}” …
              </DropdownMenuItem>
              <DropdownMenuItem
                variant="destructive"
                onSelect={() => setDialog({ kind: 'delete', view: current })}
              >
                Delete “{current.name}” …
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      {notice ? (
        <p role="alert" className="max-w-md text-xs font-medium text-destructive">
          {notice}
        </p>
      ) : null}
      {dialog?.kind === 'save-as' ? (
        <SaveAsDialog
          definition={definition}
          onClose={() => setDialog(null)}
          onCreated={(view) => {
            setDialog(null);
            onSaved(view);
          }}
        />
      ) : null}
      {dialog?.kind === 'rename' ? (
        <RenameDialog
          view={dialog.view}
          onClose={() => setDialog(null)}
          onConflict={() => void list.refetch()}
        />
      ) : null}
      <ConfirmDialog
        open={dialog?.kind === 'delete'}
        onOpenChange={(open) => {
          if (!open) {
            remove.reset();
            setDialog(null);
          }
        }}
        title="Delete saved view"
        description={
          dialog?.kind === 'delete' ? (
            <p>
              Delete the view “{dialog.view.name}”? Its filters and columns are removed for you on
              every device. Messages are not affected.
            </p>
          ) : null
        }
        confirmLabel="Delete view"
        destructive
        pending={remove.isPending}
        error={remove.error ? <ErrorState error={remove.error} compact /> : null}
        onConfirm={async () => {
          if (dialog?.kind !== 'delete') return false;
          const outcome = await remove.submit({ path: { viewId: dialog.view.id } });
          if (!outcome.ok && outcome.error.status !== 404) return false;
          onDeleted(dialog.view.id);
          return true;
        }}
      />
    </div>
  );
}

function NameDialog({
  title,
  description,
  initialName,
  submitLabel,
  pending,
  messages,
  requestId,
  onSubmit,
  onClose,
  fieldError,
}: {
  title: string;
  description: string;
  initialName: string;
  submitLabel: string;
  pending: boolean;
  messages: string[];
  requestId: string | null | undefined;
  onSubmit: (name: string) => Promise<void>;
  onClose: () => void;
  /** A name error from the api (`409 saved_view_name_taken`). */
  fieldError: string | null;
}) {
  const form = useZodForm(viewNameFormSchema, { defaultValues: { name: initialName } });
  const submit = form.handleSubmit(async (values) => onSubmit(values.name));
  const nameError = fieldError;
  return (
    <Dialog open onOpenChange={(open) => (!open && !pending ? onClose() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form className="grid gap-4" noValidate onSubmit={(event) => void submit(event)}>
            <FormErrorSummary messages={messages} requestId={requestId} />
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name (required)</FormLabel>
                  <FormControl>
                    <Input autoComplete="off" maxLength={80} {...field} />
                  </FormControl>
                  <FormDescription>Up to 80 characters; unique among your views.</FormDescription>
                  <FormMessage />
                  {nameError ? (
                    <p role="alert" className="text-xs font-medium text-destructive">
                      {nameError}
                    </p>
                  ) : null}
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={onClose} disabled={pending}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? 'Saving …' : submitLabel}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

/** Messages of the coded errors of the views api (§3.3). */
function viewErrorMessages(error: ApiError): { field: string | null; form: string[] } {
  if (error.status === 409 && error.code === 'saved_view_name_taken') {
    return { field: 'You already have a view with this name. Choose another name.', form: [] };
  }
  if (error.status === 409 && error.code === 'saved_view_limit_reached') {
    const limit = typeof error.details.limit === 'number' ? ` (${error.details.limit})` : '';
    return {
      field: null,
      form: [`You have reached the maximum number of saved views${limit}. Delete one first.`],
    };
  }
  if (error.status === 403 && error.code === 'saved_views_member_only') {
    return { field: null, form: [MEMBER_ONLY_TEXT] };
  }
  if (error.status === 403 && error.code === 'message_filter_forbidden') {
    const permission =
      typeof error.details.permission === 'string' ? ` (${error.details.permission})` : '';
    return {
      field: null,
      form: [`A filter of this view needs a permission you do not have${permission}.`],
    };
  }
  return { field: null, form: [] };
}

function SaveAsDialog({
  definition,
  onClose,
  onCreated,
}: {
  definition: SavedViewDefinition;
  onClose: () => void;
  onCreated: (view: SavedView) => void;
}) {
  const create = useApiMutation('SavedViewsController_create_v1', {
    invalidates: [LIST],
    successMessage: 'View saved.',
  });
  const [messages, setMessages] = useState<string[]>([]);
  const [fieldError, setFieldError] = useState<string | null>(null);
  return (
    <NameDialog
      title="Save as new view"
      description="Saves the current filters, time range, sort and visible columns for you. Searched values are kept with the view."
      initialName=""
      submitLabel="Save view"
      pending={create.isPending}
      messages={messages}
      requestId={create.error?.requestId}
      fieldError={fieldError}
      onClose={onClose}
      onSubmit={async (name) => {
        setMessages([]);
        setFieldError(null);
        const outcome = await create.submit({ body: createViewBody(name, definition) });
        if (outcome.ok) {
          onCreated(outcome.data);
          return;
        }
        const coded = viewErrorMessages(outcome.error);
        setFieldError(coded.field);
        setMessages(coded.field || coded.form.length > 0 ? coded.form : outcome.error.messages);
      }}
    />
  );
}

function RenameDialog({
  view,
  onClose,
  onConflict,
}: {
  view: SavedView;
  onClose: () => void;
  onConflict: () => void;
}) {
  const update = useApiMutation('SavedViewsController_update_v1', {
    invalidates: [LIST],
    successMessage: 'View renamed.',
  });
  const [messages, setMessages] = useState<string[]>([]);
  const [fieldError, setFieldError] = useState<string | null>(null);
  return (
    <NameDialog
      title="Rename view"
      description="Only the name changes; the filters and columns of the view stay as saved."
      initialName={view.name}
      submitLabel="Rename"
      pending={update.isPending}
      messages={messages}
      requestId={update.error?.requestId}
      fieldError={fieldError}
      onClose={onClose}
      onSubmit={async (name) => {
        setMessages([]);
        setFieldError(null);
        const outcome = await update.submit({
          path: { viewId: view.id },
          body: updateViewBody(view, name, view.definition),
        });
        if (outcome.ok) {
          onClose();
          return;
        }
        if (outcome.error.status === 409 && outcome.error.code === 'saved_view_conflict') {
          setMessages([
            'This view was changed elsewhere. The list was reloaded: close this dialog and rename the current version.',
          ]);
          onConflict();
          return;
        }
        const coded = viewErrorMessages(outcome.error);
        setFieldError(coded.field);
        setMessages(coded.field || coded.form.length > 0 ? coded.form : outcome.error.messages);
      }}
    />
  );
}
