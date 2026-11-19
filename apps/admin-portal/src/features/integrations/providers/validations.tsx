'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { z } from 'zod';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { MutationError } from '@/features/domains/kit';
import { CONNECTION_QUERIES } from './mail-flow-dialog';
import {
  CheckStatusBadge,
  RunStatusBadge,
  errorHint,
  runInProgress,
  type Connection,
  type ValidationResult,
  type ValidationRun,
} from './model';

const AREA_LABEL: Record<string, string> = {
  credentials: 'Access',
  permissions: 'Access',
  tenant: 'Access',
  domains: 'Domains',
  dns: 'DNS',
  inbound: 'Inbound',
  outbound: 'Outbound',
  routing: 'Loops',
  lockdown: 'Lockdown',
};

/** Results grouped by area (the code's first segment), in the server's order. */
export function groupResults(results: readonly ValidationResult[]) {
  const groups = new Map<string, ValidationResult[]>();
  for (const result of results) {
    const area = AREA_LABEL[result.code.split('.')[0] ?? ''] ?? 'Other';
    groups.set(area, [...(groups.get(area) ?? []), result]);
  }
  return [...groups.entries()];
}

function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence ?? {});
  if (entries.length === 0) return null;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-xs text-muted-foreground">
      {entries.slice(0, 12).map(([key, value]) => (
        <div key={key} className="contents">
          <dt>{humanize(key)}</dt>
          <dd className="font-mono break-all">
            {typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
              ? String(value)
              : JSON.stringify(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** A check's remediation: an anchor of the setup guide (`#…`) or a documentation path. */
export function Remediation({
  connectionId,
  remediation,
}: {
  connectionId: string;
  remediation: string;
}) {
  if (remediation.startsWith('#')) {
    return (
      <Link
        className="text-xs underline"
        href={`/integrations/providers/${connectionId}?tab=guide${remediation}`}
      >
        How to fix this (setup guide)
      </Link>
    );
  }
  return <span className="text-xs text-muted-foreground">How to fix this: {remediation}</span>;
}

/** Check results of a run (the worker's results rendered as they are; never re-evaluated). */
export function RunResults({ run, connectionId }: { run: ValidationRun; connectionId: string }) {
  if (run.results.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {runInProgress(run.status) ? 'Checks are running …' : 'No check results.'}
      </p>
    );
  }
  return (
    <div className="grid gap-4">
      {groupResults(run.results).map(([area, results]) => (
        <section key={area} aria-label={area} className="grid gap-2">
          <h4 className="text-sm font-semibold">{area}</h4>
          <ul className="grid gap-2">
            {results.map((r) => (
              <li key={`${r.code}:${r.subject}`} className="grid gap-1 rounded-md border p-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <CheckStatusBadge status={r.status} />
                  <code className="font-mono text-xs">{r.code}</code>
                  {r.subject ? <span className="text-muted-foreground">{r.subject}</span> : null}
                </div>
                <Evidence evidence={r.evidence} />
                {r.remediation && (r.status === 'fail' || r.status === 'warn') ? (
                  <Remediation connectionId={connectionId} remediation={r.remediation} />
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ))}
      {run.probeObservations.length > 0 ? (
        <section aria-label="Probe messages" className="grid gap-2">
          <h4 className="text-sm font-semibold">Probe messages received</h4>
          <ul className="grid gap-2 text-sm">
            {run.probeObservations.map((o) => (
              <li key={`${o.receivedAt}:${o.clientIp}`} className="rounded-md border p-3">
                <DateTime value={o.receivedAt} /> from {o.clientIp} ({o.envelopeFromDomain}
                {o.tlsProtocol ? `, ${o.tlsProtocol}` : ''}): proof{' '}
                <strong>{humanize(o.proofResult)}</strong>, tenant header {humanize(o.tenantHeader)}
                , DKIM {humanize(o.dkim)}
                {o.failureCode ? ` (${humanize(o.failureCode)})` : ''}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function Countdown({ until }: { until: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const left = Math.max(0, Math.floor((new Date(until).getTime() - now) / 1000));
  const h = Math.floor(left / 3600);
  const m = Math.floor((left % 3600) / 60);
  return <span>{left === 0 ? 'expired' : `${h > 0 ? `${h} h ` : ''}${m} min left`}</span>;
}

/** One run, polled every 5 s while the worker has not finished it. */
export function RunView({
  connectionId,
  runId,
  probeAddress,
}: {
  connectionId: string;
  runId: string;
  probeAddress?: string | null;
}) {
  const run = useApiQuery(
    'ProviderValidationsController_get_v1',
    { path: { id: connectionId, runId } },
    {
      refetchInterval: (query) =>
        query.state.data && runInProgress(query.state.data.status) ? 5000 : false,
    },
  );
  if (run.isLoading) return <LoadingState label="Loading the validation run" rows={3} />;
  if (run.error) return <ErrorState error={run.error} onRetry={() => void run.refetch()} />;
  if (!run.data) return null;
  const data = run.data;
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <RunStatusBadge status={data.status} />
        <span>{humanize(data.kind)} validation</span>
        <span className="text-muted-foreground">
          started <DateTime value={data.startedAt ?? data.createdAt} />
        </span>
        <span className="text-muted-foreground">
          {data.summary
            ? `${data.summary.pass} passed · ${data.summary.warn} warnings · ${data.summary.fail} failed`
            : 'No results yet'}
        </span>
      </div>
      {data.status === 'awaiting_probe' ? (
        <div className="grid gap-2 rounded-md border border-dashed p-3 text-sm" role="status">
          {probeAddress ? (
            <>
              <p>
                Send a test message to this probe address through your provider: in the Exchange
                admin center use <strong>Connectors → the outbound connector → Validate</strong>; in
                Google Workspace send any message from a user of a linked domain.
              </p>
              <p className="inline-flex flex-wrap items-center gap-1 font-mono text-xs break-all">
                {probeAddress}
                <CopyButton value={probeAddress} label="Copy probe address" />
              </p>
            </>
          ) : (
            <p>
              Waiting for the probe message. The probe address was shown when the run started; start
              a new run if you no longer have it.
            </p>
          )}
          {data.probeExpiresAt ? (
            <p className="text-xs text-muted-foreground">
              The probe address expires: <Countdown until={data.probeExpiresAt} />. This page checks
              every 5 seconds.
            </p>
          ) : null}
        </div>
      ) : null}
      <RunResults run={data} connectionId={connectionId} />
    </div>
  );
}

/** Wizard step "Validate" (D10): start a full run; the probe address is shown once. */
export function ValidateStep({
  connection,
  latestRunId,
}: {
  connection: Connection;
  latestRunId: string | null;
}) {
  const canRun = useCan('ProviderValidationsController_create_v1');
  const [started, setStarted] = useState<{ id: string; probeAddress: string | null } | null>(null);
  const create = useApiMutation('ProviderValidationsController_create_v1', {
    invalidates: [...CONNECTION_QUERIES, 'ProviderValidationsController_list_v1'],
    successMessage: 'Validation started.',
  });
  const runId = started?.id ?? latestRunId;
  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">
        A full validation checks access, the tenant, domains and DNS, inbound delivery to your
        provider (an SMTP probe without sending any message), outbound proof through a probe
        message, and loops. It cannot see your provider’s own connector or lockdown settings: those
        are your statements.
      </p>
      {canRun && connection.status !== 'disabled' ? (
        <Button
          className="justify-self-start"
          disabled={create.isPending}
          onClick={() =>
            void create
              .submit({ path: { id: connection.id }, body: { kind: 'full' } })
              .then((outcome) => {
                if (outcome.ok) {
                  setStarted({ id: outcome.data.id, probeAddress: outcome.data.probeAddress });
                  create.reset();
                }
              })
          }
        >
          {create.isPending ? 'Starting …' : 'Run full validation'}
        </Button>
      ) : null}
      {create.error ? (
        <div className="grid gap-1">
          <MutationError error={create.error} />
          {errorHint(create.error.code) ? (
            <p className="text-xs text-muted-foreground">{errorHint(create.error.code)}</p>
          ) : null}
        </div>
      ) : null}
      {runId ? (
        <RunView
          connectionId={connection.id}
          runId={runId}
          probeAddress={started?.id === runId ? started.probeAddress : null}
        />
      ) : (
        <p className="text-sm text-muted-foreground">No validation has run yet.</p>
      )}
    </div>
  );
}

const RUN_URL = { run: z.string().uuid().optional().catch(undefined) };

/** Tab "Validations": run history and the details of one run (`?run=`). */
export function ValidationsTab({ connection }: { connection: Connection }) {
  const [{ run }, setUrl] = useUrlState(RUN_URL);
  const list = useCursorList('ProviderValidationsController_list_v1', undefined, {
    path: { id: connection.id },
    limit: 25,
  });
  const rows = list.rows;
  const selected = run ?? rows[0]?.id ?? null;
  const runs = useMemo(() => rows, [rows]);
  if (list.query.isLoading) return <LoadingState label="Loading validation runs" rows={4} />;
  if (list.query.error)
    return <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} />;
  if (runs.length === 0) {
    return <p className="text-sm text-muted-foreground">No validation has run yet.</p>;
  }
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(14rem,20rem)_1fr]">
      <nav aria-label="Validation runs">
        <ul className="grid gap-1">
          {runs.map((r) => (
            <li key={r.id}>
              <button
                type="button"
                aria-current={r.id === selected ? 'true' : undefined}
                onClick={() => setUrl({ run: r.id }, { push: true })}
                className="flex w-full flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-left text-sm hover:bg-muted aria-[current=true]:border-primary aria-[current=true]:bg-accent"
              >
                <RunStatusBadge status={r.status} />
                <span>{humanize(r.kind)}</span>
                <span className="text-xs text-muted-foreground">
                  <DateTime value={r.createdAt} />
                </span>
              </button>
            </li>
          ))}
        </ul>
        {list.hasNext || list.hasPrevious ? (
          <div className="mt-2 flex gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!list.hasPrevious}
              onClick={list.previous}
            >
              Newer
            </Button>
            <Button size="sm" variant="outline" disabled={!list.hasNext} onClick={list.next}>
              Older
            </Button>
          </div>
        ) : null}
      </nav>
      {selected ? <RunView connectionId={connection.id} runId={selected} /> : null}
    </div>
  );
}
