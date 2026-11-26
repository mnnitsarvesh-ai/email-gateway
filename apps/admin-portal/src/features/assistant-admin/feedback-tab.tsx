'use client';

import { MessageSquareIcon, ThumbsDownIcon, ThumbsUpIcon } from 'lucide-react';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { FilterSelect } from '@/features/domains/kit';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { FEEDBACK_REASONS, FEEDBACK_REASON_LABEL, userLabel } from './model';
import { useAdminRange } from './range-control';
import { USER_URL_SHAPE, UserCell } from './usage-tab';

type FeedbackRow = ListItem<'AssistantAdminController_feedback_v1'>;

const URL_SHAPE = {
  ...USER_URL_SHAPE,
  rating: z.enum(['up', 'down']).optional().catch(undefined),
  reason: z.enum(FEEDBACK_REASONS).optional().catch(undefined),
};

export function RatingBadge({ rating }: { rating: 'up' | 'down' }) {
  const Icon = rating === 'up' ? ThumbsUpIcon : ThumbsDownIcon;
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      <Icon
        className={
          rating === 'up' ? 'size-4 text-tone-success-foreground' : 'size-4 text-destructive'
        }
        aria-hidden
      />
      {rating === 'up' ? 'Helpful' : 'Not helpful'}
    </span>
  );
}

/**
 * Feedback tab (D2): the ratings people gave to answers, with the optional reason and comment
 * they submitted under the notice "visible to your organization's AI administrators". The
 * conversation link opens the metadata-only audit view (never the conversation itself).
 */
export function FeedbackTab({ onOpenConversation }: { onOpenConversation?: (id: string) => void }) {
  const [range] = useAdminRange();
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canAudit = useCan('AssistantAdminAuditController_conversation_v1');
  const list = useCursorList('AssistantAdminController_feedback_v1', {
    from: range.from,
    to: range.to,
    ...(filters.rating ? { rating: filters.rating } : {}),
    ...(filters.reason ? { reason: filters.reason } : {}),
    ...(filters.user ? { userId: filters.user } : {}),
  });
  const columns = useMemo<DataTableColumn<FeedbackRow>[]>(
    () => [
      {
        id: 'created',
        header: 'Rated',
        meta: { label: 'Rated', hideable: false },
        cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
      },
      {
        id: 'user',
        header: 'Person',
        meta: { label: 'Person' },
        cell: ({ row }) => <UserCell user={row.original.user} />,
      },
      {
        id: 'rating',
        header: 'Rating',
        meta: { label: 'Rating' },
        cell: ({ row }) => <RatingBadge rating={row.original.rating} />,
      },
      {
        id: 'reason',
        header: 'Reason',
        meta: { label: 'Reason' },
        cell: ({ row }) =>
          row.original.reason ? (
            FEEDBACK_REASON_LABEL[row.original.reason]
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'comment',
        header: 'Comment',
        meta: { label: 'Comment' },
        cell: ({ row }) =>
          row.original.comment ? (
            <p className="max-w-md text-sm whitespace-pre-wrap break-words">
              {row.original.comment}
            </p>
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'turn',
        header: 'Answer by',
        meta: { label: 'Answer by' },
        cell: ({ row }) =>
          row.original.turn ? (
            <span className="grid gap-0.5 text-xs">
              <span className="font-mono">
                {row.original.turn.provider} / {row.original.turn.model}
              </span>
              <span className="text-muted-foreground">
                {row.original.turn.promptVersion} · {row.original.turn.dataSharing}
              </span>
            </span>
          ) : (
            <span className="text-muted-foreground">Unknown</span>
          ),
      },
      {
        id: 'tools',
        header: 'Tools used',
        meta: { label: 'Tools used' },
        cell: ({ row }) =>
          row.original.tools.length > 0 ? (
            <span className="font-mono text-xs break-all">{row.original.tools.join(', ')}</span>
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      ...(canAudit && onOpenConversation
        ? [
            {
              id: 'audit',
              header: 'Audit',
              meta: { label: 'Audit' },
              cell: ({ row }: { row: { original: FeedbackRow } }) => (
                <Button
                  variant="link"
                  className="h-auto p-0"
                  onClick={() => onOpenConversation(row.original.conversationId)}
                  aria-label={`Open audit of the conversation rated by ${userLabel(row.original.user)}`}
                >
                  Open audit
                </Button>
              ),
            } satisfies DataTableColumn<FeedbackRow>,
          ]
        : []),
    ],
    [canAudit, onOpenConversation],
  );
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <p className="text-sm text-muted-foreground">
        People see the notice “Your rating and comment are visible to your organization&apos;s AI
        administrators” when they rate an answer. Comments are deleted with the conversation
        content.
      </p>
      <DataTable<FeedbackRow>
        tableId="assistant-admin-feedback"
        caption={`Feedback on AI answers, ${range.fromDay} to ${range.toDay} (UTC)`}
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `Feedback of ${userLabel(row.user)}`}
        filters={
          <>
            <FilterSelect
              label="Rating"
              value={filters.rating}
              onChange={(rating) => setFilters({ rating: rating as 'up' | 'down' | undefined })}
              options={[
                { value: 'up', label: 'Helpful' },
                { value: 'down', label: 'Not helpful' },
              ]}
            />
            <FilterSelect
              label="Reason"
              value={filters.reason}
              onChange={(reason) =>
                setFilters({ reason: reason as (typeof FEEDBACK_REASONS)[number] | undefined })
              }
              options={FEEDBACK_REASONS.map((value) => ({
                value,
                label: FEEDBACK_REASON_LABEL[value],
              }))}
            />
          </>
        }
        isFiltered={Boolean(filters.rating || filters.reason || filters.user)}
        onClearFilters={() => setFilters({ rating: undefined, reason: undefined, user: undefined })}
        emptyState={
          <EmptyState
            icon={MessageSquareIcon}
            title="No feedback in this range"
            description="Ratings appear here when people rate answers of the AI assistant."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <UserCell user={row.user} />
            <span className="flex flex-wrap items-center gap-2">
              <RatingBadge rating={row.rating} />
              {row.reason ? <span>{FEEDBACK_REASON_LABEL[row.reason]}</span> : null}
            </span>
            {row.comment ? <p className="whitespace-pre-wrap break-words">{row.comment}</p> : null}
            <DateTime value={row.updatedAt} className="text-xs" />
          </div>
        )}
      />
    </div>
  );
}
