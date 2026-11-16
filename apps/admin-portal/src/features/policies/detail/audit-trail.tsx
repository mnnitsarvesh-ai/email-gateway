'use client';

import { useInfiniteQuery, type InfiniteData } from '@tanstack/react-query';
import { useId, useMemo, useState } from 'react';
import { CopyableId, DateTime } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { callOperation } from '@/lib/api/call';
import type { ApiError } from '@/lib/api/errors';
import { shouldRetry } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import type { DirectoryNames } from '../builder';

type AuditRow = ListItem<'AuditLogsController_search_v1'>;
type AuditPage = SuccessBody<'AuditLogsController_search_v1'>;

/** Days of history the tab reads (`API_AUDIT_MAX_RANGE_DAYS`, design B11). */
export const POLICY_AUDIT_DAYS = 90;
const PAGE_SIZE = 50;
const MINUTE = 60_000;

/** The resource types of a policy's audit rows (both carry the policy public id, B11). */
export const POLICY_AUDIT_RESOURCES = ['email_policy', 'policy_version'] as const;

function useAuditStream(resourceType: string, resourceId: string, from: string, to: string) {
  return useInfiniteQuery<
    AuditPage,
    ApiError,
    InfiniteData<AuditPage, string | null>,
    unknown[],
    string | null
  >({
    queryKey: [
      'AuditLogsController_search_v1',
      { resourceType, resourceId, from, to, merged: true },
    ],
    queryFn: ({ pageParam, signal }) =>
      callOperation(
        'AuditLogsController_search_v1',
        {
          query: {
            resourceType,
            resourceId,
            from,
            to,
            limit: PAGE_SIZE,
            ...(pageParam ? { cursor: pageParam } : {}),
          },
        },
        { signal },
      ),
    initialPageParam: null,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    retry: shouldRetry,
  });
}

/**
 * Merges keyset streams newest first. A stream with more pages hides everything older than its
 * last loaded row (those rows may interleave with its next page), so the merged list never skips.
 */
export function mergeAuditStreams(
  streams: ReadonlyArray<{ rows: readonly AuditRow[]; hasMore: boolean }>,
): AuditRow[] {
  let frontier = Number.NEGATIVE_INFINITY;
  for (const stream of streams) {
    const last = stream.rows[stream.rows.length - 1];
    if (stream.hasMore && last) frontier = Math.max(frontier, Date.parse(last.createdAt));
  }
  return streams
    .flatMap((stream) => stream.rows)
    .filter((row) => Date.parse(row.createdAt) >= frontier)
    .sort(
      (a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt) || b.id.localeCompare(a.id, 'en'),
    );
}

const METADATA_LABELS: Readonly<Record<string, string>> = {
  policyId: 'Policy',
  versionNo: 'Version',
  previousVersionNo: 'Previous version',
  previousStatus: 'Previous status',
  generation: 'Generation',
  rowVersion: 'Row version',
  ruleCount: 'Rules',
  wasActive: 'Was active',
  changedPaths: 'Changed',
  overrideRuleIds: 'Override rules',
  definitionSha256: 'Definition hash',
  definitionSha256Before: 'Hash before',
};

function metadataValue(value: unknown): string {
  if (value === null || value === undefined) return 'none';
  if (Array.isArray(value)) return value.map((v) => metadataValue(v)).join(', ');
  if (typeof value === 'string') {
    return /^[0-9a-f]{64}$/.test(value) ? `${value.slice(0, 12)}…` : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value) ?? '';
}

/** Ids, numbers and hashes of the row's metadata (text only; never rendered as HTML). */
function Metadata({ metadata }: { metadata: AuditRow['metadata'] }) {
  if (!metadata) return <span className="text-muted-foreground">None</span>;
  const entries = Object.entries(metadata).filter(([key]) => key !== 'policyId');
  if (entries.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-xs">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-muted-foreground">{METADATA_LABELS[key] ?? key}</dt>
          <dd className="min-w-0 font-mono break-all">{metadataValue(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Actor({ actor, names }: { actor: AuditRow['actor']; names: DirectoryNames }) {
  if (actor.type === 'system') return <span>System</span>;
  if (!actor.id) return <span>{humanize(actor.type)}</span>;
  const name = actor.type === 'user' ? names.users?.get(actor.id) : undefined;
  return (
    <span className="grid gap-0.5">
      <span className="text-xs text-muted-foreground">{humanize(actor.type)}</span>
      {name ? <span>{name}</span> : <CopyableId value={actor.id} label="actor ID" max={14} />}
    </span>
  );
}

/**
 * The audit tab of a policy (design B11): `GET /audit/logs` read twice (`resourceType` =
 * `email_policy` and `policy_version`, `resourceId` = the policy id) over the last 90 days,
 * merged by time; action, actor, time and the metadata numbers.
 */
export function PolicyAuditTrail({ policyId, names }: { policyId: string; names: DirectoryNames }) {
  const captionId = useId();
  const [window] = useState(() => {
    const to = Math.ceil(Date.now() / MINUTE) * MINUTE;
    return {
      from: new Date(to - POLICY_AUDIT_DAYS * 86_400_000).toISOString(),
      to: new Date(to).toISOString(),
    };
  });
  const policyRows = useAuditStream('email_policy', policyId, window.from, window.to);
  const versionRows = useAuditStream('policy_version', policyId, window.from, window.to);
  const streams = [policyRows, versionRows];
  const rows = useMemo(
    () =>
      mergeAuditStreams(
        [policyRows, versionRows].map((stream) => ({
          rows: stream.data?.pages.flatMap((page) => page.data) ?? [],
          hasMore: stream.hasNextPage,
        })),
      ),
    [policyRows, versionRows],
  );
  const loading = streams.some((s) => s.isLoading);
  const error = streams.find((s) => s.error)?.error ?? null;
  const hasMore = streams.some((s) => s.hasNextPage);
  const fetching = streams.some((s) => s.isFetchingNextPage);

  if (loading) return <LoadingState label="Loading the audit trail" rows={5} variant="table" />;
  if (error && rows.length === 0) {
    return (
      <ErrorState
        error={error}
        onRetry={() => {
          void policyRows.refetch();
          void versionRows.refetch();
        }}
      />
    );
  }
  return (
    <div className="grid min-w-0 gap-2">
      <p className="text-xs text-muted-foreground">
        {`Changes to this policy and its versions in the last ${POLICY_AUDIT_DAYS} days, newest first. Validation, tests and dry runs write nothing and are not audited.`}
      </p>
      {error ? <ErrorState error={error} compact /> : null}
      {rows.length === 0 ? (
        <EmptyState title="No audit entries in this period" />
      ) : (
        <div
          role="group"
          aria-labelledby={captionId}
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
          tabIndex={0}
          className="min-w-0 overflow-x-auto rounded-lg border bg-card"
        >
          <table className="w-full text-left text-sm">
            <caption id={captionId} className="sr-only">
              Audit trail of the policy
            </caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                {['Time', 'Action', 'Actor', 'Details'].map((h) => (
                  <th key={h} scope="col" className="px-3 py-2 font-semibold whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-t align-top">
                  <td className="px-3 py-2 whitespace-nowrap">
                    <DateTime value={row.createdAt} mode="absolute" />
                  </td>
                  <td className="px-3 py-2">
                    <span className="grid gap-0.5">
                      <span>{humanize(row.action.replace(/^policy\./, ''))}</span>
                      <span className="font-mono text-xs text-muted-foreground">{row.action}</span>
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <Actor actor={row.actor} names={names} />
                  </td>
                  <td className="px-3 py-2">
                    <Metadata metadata={row.metadata} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {hasMore ? (
        <Button
          variant="outline"
          size="sm"
          className="justify-self-start"
          disabled={fetching}
          onClick={() => {
            for (const stream of streams) if (stream.hasNextPage) void stream.fetchNextPage();
          }}
        >
          {fetching ? 'Loading …' : 'Load older entries'}
        </Button>
      ) : null}
    </div>
  );
}
