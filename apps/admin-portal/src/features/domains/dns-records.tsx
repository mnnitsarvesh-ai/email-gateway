'use client';

import { AlertTriangleIcon } from 'lucide-react';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { useApiQuery } from '@/lib/api/hooks';
import {
  PURPOSE_LABEL,
  REQUIREMENT_LABEL,
  RecordStatusBadge,
  zoneLine,
  type DnsRecord,
} from './model';

function RecordCard({ record }: { record: DnsRecord }) {
  const title = `${PURPOSE_LABEL[record.purpose]} record`;
  return (
    <li className="grid gap-3 rounded-md border bg-card p-3 text-sm" aria-label={title}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-semibold">{title}</h3>
          <span className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs">{record.type}</span>
          <span className="text-xs text-muted-foreground">
            {REQUIREMENT_LABEL[record.requirement]}
          </span>
        </div>
        <RecordStatusBadge status={record.status} />
      </div>
      <dl className="grid gap-2 sm:grid-cols-[7rem_1fr]">
        <dt className="text-xs font-medium text-muted-foreground">Host</dt>
        <dd className="flex min-w-0 items-center gap-1">
          <code className="min-w-0 font-mono text-xs break-all">{record.host}</code>
          <CopyButton value={record.host} label={`Copy ${title} host`} />
        </dd>
        <dt className="text-xs font-medium text-muted-foreground">Name (relative)</dt>
        <dd>
          <code className="font-mono text-xs break-all">{record.name}</code>
        </dd>
        {record.priority !== null && record.priority !== undefined ? (
          <>
            <dt className="text-xs font-medium text-muted-foreground">Priority</dt>
            <dd className="tabular-nums">{record.priority}</dd>
          </>
        ) : null}
        <dt className="text-xs font-medium text-muted-foreground">Value</dt>
        <dd className="flex min-w-0 items-start gap-1">
          <code className="min-w-0 rounded-sm bg-muted px-1.5 py-1 font-mono text-xs break-all">
            {record.value}
          </code>
          <CopyButton value={record.value} label={`Copy ${title} value`} />
        </dd>
        {record.observedValue ? (
          <>
            <dt className="text-xs font-medium text-muted-foreground">Found in DNS</dt>
            <dd>
              <UntrustedText value={record.observedValue} mono maxLength={300} />
            </dd>
          </>
        ) : null}
        <dt className="text-xs font-medium text-muted-foreground">Last checked</dt>
        <dd>
          <DateTime value={record.lastCheckedAt} emptyLabel="Not checked yet" />
          {record.lastOutcome === 'indeterminate' ? (
            <span className="ml-2 text-xs text-muted-foreground">
              (the DNS lookup gave no definitive answer; it is retried)
            </span>
          ) : null}
        </dd>
      </dl>
      {record.instructions ? (
        <p className="text-xs text-muted-foreground">{record.instructions}</p>
      ) : null}
      {record.warnings.length > 0 || record.lastError ? (
        <ul className="grid gap-1 text-xs text-tone-warning-foreground">
          {[...record.warnings, ...(record.lastError ? [record.lastError] : [])].map((w, i) => (
            <li key={i} className="flex items-start gap-1.5">
              <AlertTriangleIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              <UntrustedText value={w} maxLength={240} />
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/**
 * The DNS records to publish for a domain (`GET /domains/{id}/dns-records`), each with copy
 * buttons, plus "Copy all" as zone-file lines and the retired DKIM selectors to clean up.
 */
export function DnsRecordsPanel({ domainId }: { domainId: string }) {
  const records = useApiQuery('DomainDnsController_dnsRecords_v1', { path: { id: domainId } });
  if (records.isLoading) return <LoadingState label="Loading DNS records" rows={4} />;
  if (records.error)
    return <ErrorState error={records.error} onRetry={() => void records.refetch()} />;
  const data = records.data;
  if (!data || data.records.length === 0)
    return <EmptyState title="No DNS records" description="The api returned no records." />;
  const all = data.records.map(zoneLine).join('\n');
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Publish these records at your DNS provider. Changes can take from a few minutes up to the
          record&apos;s TTL to propagate.
        </p>
        <CopyButton value={all} label="Copy all records" size="sm" />
      </div>
      <ul className="grid min-w-0 gap-3 [&>*]:min-w-0" aria-label="DNS records">
        {data.records.map((record) => (
          <RecordCard key={record.key} record={record} />
        ))}
      </ul>
      {data.cleanup.length > 0 ? (
        <div className="grid gap-2 rounded-md border border-dashed p-3 text-sm">
          <h3 className="font-semibold">Records you can remove</h3>
          <ul className="grid gap-1">
            {data.cleanup.map((item) => (
              <li key={item.host} className="flex flex-wrap items-center gap-2 text-xs">
                <code className="font-mono break-all">{item.host}</code>
                <span className="text-muted-foreground">
                  {item.type}, retired DKIM selector since <DateTime value={item.retiredAt} />
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
