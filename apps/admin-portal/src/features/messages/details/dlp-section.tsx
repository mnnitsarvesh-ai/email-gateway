'use client';

import { useQueryClient } from '@tanstack/react-query';
import { EyeIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { DateTime, UntrustedText } from '@/components/domain';
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
import { ApiError } from '@/lib/api/errors';
import { queryKeyFor, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { emitSessionEvent } from '@/lib/session/events';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '../controls';
import { SCAN_VERDICT_TONE } from '../semantic';
import { Block, DataGrid, NoData } from './parts';
import { RoundPanel, engineOf, type Engine, type ScanRound } from './rounds';
import { EngineFacts } from './scan-sections';

type Dlp = NonNullable<Engine['dlp']>;

const SEVERITY_TONE = {
  info: 'neutral',
  low: 'info',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
} as const;

const ACTION_TONE = {
  allow: 'success',
  alert: 'info',
  require_approval: 'purple',
  quarantine: 'warning',
  block: 'danger',
} as const;

function sourceLabel(source: { kind: string; partIndex?: number; path?: string }): string {
  return `${humanize(source.kind)}${source.partIndex !== undefined ? ` part ${source.partIndex}` : ''}${source.path ? ` (${source.path})` : ''}`;
}

/** Section 9: DLP results (masked findings of the `dlp` engine; `dlp:read`). */
export function DlpSection({ messageId }: { messageId: string }) {
  return (
    <Section
      title="DLP results"
      description="Masked findings of the data loss prevention engine for the selected round. Matched values are never shown here; the audited evidence view opens them on request."
    >
      <RoundPanel>{(round) => <DlpRound round={round} messageId={messageId} />}</RoundPanel>
    </Section>
  );
}

function DlpRound({ round, messageId }: { round: ScanRound; messageId: string }) {
  const engine = engineOf(round, 'dlp');
  if (!engine) return <NoData>No DLP engine result in round {round.round}.</NoData>;
  const dlp = engine.dlp;
  return (
    <div className="grid gap-4">
      <EngineFacts engine={engine} />
      {dlp ? (
        <DlpResult dlp={dlp} round={round} messageId={messageId} />
      ) : (
        <NoData>
          No masked DLP result for this round: the engine has no final result yet, failed or was
          skipped.
        </NoData>
      )}
    </div>
  );
}

function DlpResult({ dlp, round, messageId }: { dlp: Dlp; round: ScanRound; messageId: string }) {
  const canEvidence = useCan('DlpMessageEvidenceController_read_v1');
  const [open, setOpen] = useState(false);
  const evidenceReadable = dlp.evidence.status === 'stored' && !dlp.evidence.purged;
  return (
    <>
      <DetailList
        items={[
          {
            label: 'Verdict',
            value: <EnumBadge value={dlp.verdict} tones={SCAN_VERDICT_TONE} />,
          },
          {
            label: 'Action',
            value: (
              <span className="flex flex-wrap items-center gap-2">
                <EnumBadge value={dlp.action} tones={ACTION_TONE} />
                <span className="text-xs text-muted-foreground">
                  from {humanize(dlp.actionSource)}
                </span>
              </span>
            ),
          },
          { label: 'Coverage', value: humanize(dlp.coverage) },
          { label: 'Aadhaar detection', value: humanize(dlp.aadhaar) },
          {
            label: 'Policy',
            value: dlp.policy.winner ? (
              <span className="font-mono text-xs">
                {dlp.policy.winner.policyId} · rule {dlp.policy.winner.ruleId}
              </span>
            ) : (
              <span className="text-muted-foreground">No rule decided</span>
            ),
          },
          {
            label: 'Exceptions applied',
            value: <CodeList codes={dlp.policy.exceptionsApplied} />,
          },
          {
            label: 'Versions',
            value: (
              <span className="font-mono text-xs">
                engine {dlp.engineVersion} · rules {dlp.rulesVersion} · policy {dlp.policyVersion}
              </span>
            ),
          },
        ]}
      />
      {dlp.categories.length > 0 ? (
        <DataGrid
          caption="Categories"
          captionVisible
          rows={dlp.categories}
          rowKey={(row) => row.category}
          columns={[
            { header: 'Category', rowHeader: true, cell: (row) => humanize(row.category) },
            {
              header: 'Findings',
              cell: (row) => formatNumber(row.count),
              className: 'tabular-nums',
            },
            {
              header: 'Highest severity',
              cell: (row) => <EnumBadge value={row.maxSeverity} tones={SEVERITY_TONE} />,
            },
            {
              header: 'Highest confidence',
              cell: (row) => `${Math.round(row.maxConfidence * 100)} %`,
              className: 'tabular-nums',
            },
          ]}
        />
      ) : null}
      {dlp.findings.length === 0 ? (
        <NoData>No sensitive data was found in the scanned parts.</NoData>
      ) : (
        <DataGrid
          caption="Findings (masked samples)"
          captionVisible
          rows={dlp.findings}
          rowKey={(row, index) => `${row.detector}-${row.code}-${index}`}
          columns={[
            {
              header: 'Detector',
              rowHeader: true,
              cell: (row) => (
                <span className="grid text-xs">
                  <span className="font-mono">{row.detector}</span>
                  <span className="font-mono text-muted-foreground">{row.code}</span>
                </span>
              ),
            },
            { header: 'Category', cell: (row) => humanize(row.category), className: 'text-xs' },
            {
              header: 'Severity',
              cell: (row) => <EnumBadge value={row.severity} tones={SEVERITY_TONE} />,
            },
            {
              header: 'Count',
              cell: (row) => `${formatNumber(row.count)}${row.capped ? '+' : ''}`,
              className: 'tabular-nums text-xs',
            },
            {
              header: 'Where',
              className: 'text-xs',
              cell: (row) => row.sources.map(sourceLabel).join(', ') || 'Unknown',
            },
            {
              header: 'Masked samples',
              cell: (row) =>
                row.masked.length === 0 ? (
                  <span className="text-muted-foreground">None</span>
                ) : (
                  <ul className="grid gap-0.5">
                    {row.masked.map((sample, index) => (
                      <li key={index}>
                        <UntrustedText value={sample} mono maxLength={60} />
                      </li>
                    ))}
                  </ul>
                ),
            },
          ]}
        />
      )}
      {dlp.coverageDetail.length > 0 ? (
        <details className="rounded-md border p-3 text-sm">
          <summary className="cursor-pointer font-medium">
            Coverage per part ({dlp.coverageDetail.length})
          </summary>
          <ul className="mt-2 grid gap-1 text-xs">
            {dlp.coverageDetail.map((part, index) => (
              <li key={index} className="flex flex-wrap items-center gap-2">
                <span>
                  {sourceLabel({ kind: part.source, partIndex: part.partIndex, path: part.path })}
                </span>
                <span className="text-muted-foreground">
                  {part.format} · {humanize(part.status)} · {formatNumber(part.chars)} characters
                  {part.truncated ? ', truncated' : ''}
                </span>
                <CodeList codes={part.reasons} emptyLabel="" />
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      <Block
        title="Evidence"
        description="Matched values are stored encrypted and opened only through the audited evidence view (an MFA session and dlp:evidence_read are required)."
        actions={
          canEvidence && evidenceReadable ? (
            <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
              <EyeIcon aria-hidden />
              Show matched values
            </Button>
          ) : null
        }
      >
        <DetailList
          items={[
            { label: 'Status', value: humanize(dlp.evidence.status) },
            {
              label: 'Expires',
              value: (
                <DateTime value={dlp.evidence.expiresAt} mode="absolute" emptyLabel="Not stored" />
              ),
            },
            { label: 'Purged', value: dlp.evidence.purged ? 'Yes (crypto-shredded)' : 'No' },
          ]}
        />
        {!canEvidence && evidenceReadable ? (
          <p className="text-xs text-muted-foreground">
            Opening the evidence needs the dlp:evidence_read permission.
          </p>
        ) : null}
      </Block>
      {open ? (
        <EvidenceDialog
          messageId={messageId}
          scanId={round.scanId}
          onClose={() => setOpen(false)}
        />
      ) : null}
    </>
  );
}

/**
 * The decrypted evidence, shown once (7.1 secret pattern): fetched only after the click, never
 * cached (`gcTime: 0`, removed on close), never refetched; `403 mfa_required` opens the 7.1 MFA
 * dialog. Every read is audited by the api (`dlp_evidence.read`) before decryption.
 */
function EvidenceDialog({
  messageId,
  scanId,
  onClose,
}: {
  messageId: string;
  scanId: string;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const input = { path: { messageId, scanId } };
  const query = useApiQuery('DlpMessageEvidenceController_read_v1', input, {
    gcTime: 0,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    refetchOnReconnect: false,
    retry: false,
  });
  const mfa = query.error instanceof ApiError && query.error.code === 'mfa_required';
  useEffect(() => {
    if (mfa) emitSessionEvent({ type: 'mfa-required' });
  }, [mfa]);
  const close = () => {
    queryClient.removeQueries({
      queryKey: queryKeyFor('DlpMessageEvidenceController_read_v1', input),
    });
    onClose();
  };
  const evidence = query.data;
  return (
    <Dialog open onOpenChange={(next) => (!next ? close() : undefined)}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Matched values</DialogTitle>
          <DialogDescription>
            Shown once: closing this dialog removes the values from the page. This view is recorded
            in the audit log. Do not copy values into tickets or chats.
          </DialogDescription>
        </DialogHeader>
        {query.isLoading ? (
          <LoadingState label="Opening the evidence" rows={4} />
        ) : mfa ? (
          <p role="alert" className="text-sm">
            The evidence needs a session signed in with MFA. Sign in again with your authenticator
            code to open it.
          </p>
        ) : query.error ? (
          <ErrorState error={query.error} compact />
        ) : evidence ? (
          <div className="grid gap-3">
            <p className="text-xs text-muted-foreground">
              {formatNumber(evidence.matchCount)} match{evidence.matchCount === 1 ? '' : 'es'}
              {evidence.evidence.dropped > 0
                ? `, ${formatNumber(evidence.evidence.dropped)} not stored (limit)`
                : ''}{' '}
              · evidence expires <DateTime value={evidence.expiresAt} mode="absolute" />
            </p>
            {evidence.evidence.matches.length === 0 ? (
              <NoData>The evidence holds no match.</NoData>
            ) : (
              <DataGrid
                caption="Matched values"
                rows={evidence.evidence.matches}
                rowKey={(row, index) => `${row.detector}-${row.start}-${index}`}
                columns={[
                  {
                    header: 'Detector',
                    rowHeader: true,
                    cell: (row) => <span className="font-mono text-xs">{row.detector}</span>,
                  },
                  {
                    header: 'Where',
                    className: 'text-xs',
                    cell: (row) =>
                      `${sourceLabel(row.source)} · characters ${row.start}–${row.end}`,
                  },
                  {
                    header: 'Value',
                    cell: (row) => <UntrustedText value={row.value} mono maxLength={80} />,
                  },
                  {
                    header: 'Context',
                    className: 'max-w-80',
                    cell: (row) => (
                      <UntrustedText
                        value={`${row.context.before}[…]${row.context.after}`}
                        mono
                        maxLength={120}
                      />
                    ),
                  },
                ]}
              />
            )}
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={close}>Close and forget the values</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
