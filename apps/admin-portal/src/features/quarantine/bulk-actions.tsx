'use client';

import { XIcon } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { useApiMutation } from '@/lib/api/hooks';
import { formatNumber, humanize } from '@/lib/format';
import { EnumBadge } from '@/features/messages/controls';
import { bulkBody } from './forms';
import { ReasonConfirm } from './reason-confirm';
import { BULK_STATUS_TONE } from './semantic';
import type { BulkAction, BulkResult, Catalog } from './types';

const LABEL: Record<BulkAction, string> = {
  release: 'Release',
  reject: 'Reject',
  delete: 'Delete',
  approve: 'Approve',
  deny: 'Deny',
};

const BULK_INVALIDATES = [
  'QuarantineEntriesController_search_v1',
  'QuarantineToolsController_summary_v1',
  'QuarantineApprovalsController_list_v1',
  'QuarantineEntriesController_detail_v1',
  'QuarantineApprovalsController_get_v1',
] as const;

/**
 * Bulk actions over the selected rows (`POST /quarantine/bulk`, Idempotency-Key required). Only
 * actions the catalog offers and the user's permissions allow are passed in; the item limit is
 * the catalog's `bulkMaxItems`. Each item runs through the single-item rules in the api.
 */
export function BulkActionBar({
  ids,
  actions,
  catalog,
  onDone,
}: {
  ids: readonly string[];
  actions: readonly BulkAction[];
  catalog: Catalog | undefined;
  onDone: (result: BulkResult) => void;
}) {
  const [action, setAction] = useState<BulkAction | null>(null);
  const [notify, setNotify] = useState(false);
  const mutation = useApiMutation('QuarantineToolsController_bulk_v1', {
    invalidates: BULK_INVALIDATES,
    successMessage: null,
    onSuccess: (data) => onDone(data),
  });
  const maxItems = catalog?.limits.bulkMaxItems;
  const tooMany = maxItems !== undefined && ids.length > maxItems;
  return (
    <>
      {actions.map((name) => (
        <Button
          key={name}
          size="sm"
          variant={
            name === 'delete' || name === 'reject' || name === 'deny' ? 'outline' : 'secondary'
          }
          disabled={tooMany || mutation.retryAfterSeconds > 0}
          onClick={() => setAction(name)}
        >
          {LABEL[name]} selected
        </Button>
      ))}
      {tooMany ? <span className="text-xs">At most {maxItems} items per bulk action.</span> : null}
      <ReasonConfirm
        open={action !== null}
        onOpenChange={(open) => {
          if (!open) setAction(null);
        }}
        title={action ? `${LABEL[action]} ${ids.length} selected?` : ''}
        description={
          <p>
            Each item is processed with the same checks as a single action (re-validation,
            separation of duties); items that are not allowed are reported as refused.
          </p>
        }
        confirmLabel={action ? `${LABEL[action]} ${ids.length}` : 'Confirm'}
        destructive={action === 'delete' || action === 'reject' || action === 'deny'}
        maxChars={catalog?.limits.reasonMaxChars}
        pending={mutation.isPending}
        extra={
          action === 'reject' ? (
            <div className="flex items-center gap-2">
              <Checkbox
                id="bulk-notify"
                checked={notify}
                onCheckedChange={(value) => setNotify(value === true)}
              />
              <Label htmlFor="bulk-notify">Notify senders of outbound and internal mail</Label>
            </div>
          ) : null
        }
        onSubmit={(reason) =>
          action
            ? mutation.submit({ body: bulkBody(action, ids, reason, notify) })
            : Promise.resolve({ ok: false })
        }
        onRetry={() => mutation.retry()}
      />
    </>
  );
}

export function BulkResultNotice({
  result,
  onDismiss,
}: {
  result: BulkResult;
  onDismiss: () => void;
}) {
  const refused = result.results.filter(
    (item) => item.status === 'refused' || item.status === 'not_found',
  );
  return (
    <div className="grid gap-2 rounded-md border bg-card p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <strong>Bulk {humanize(result.action)}:</strong>
        {Object.entries(result.counts).map(([status, count]) => (
          <span key={status} className="flex items-center gap-1">
            <EnumBadge value={status} tones={BULK_STATUS_TONE} /> {formatNumber(count)}
          </span>
        ))}
        <Button
          variant="ghost"
          size="icon"
          className="ml-auto size-7"
          aria-label="Dismiss the bulk result"
          onClick={onDismiss}
        >
          <XIcon aria-hidden />
        </Button>
      </div>
      {refused.length > 0 ? (
        <ul className="grid gap-1 text-xs" aria-label="Items not processed">
          {refused.map((item) => (
            <li key={item.id} className="font-mono">
              {item.id}: {item.status}
              {item.code ? ` (${item.code})` : ''}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
