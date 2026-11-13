'use client';

import Link from 'next/link';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId, DateTime, RiskScore, UntrustedText } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, formatDuration, formatNumber, humanize } from '@/lib/format';
import { CodeList, CursorPager, DetailList, EnumBadge, Section, YesNo } from './controls';
import { attachmentSearchHref, messageHref } from './links';
import {
  AUTH_RESULT_TONE,
  DISPOSITION_TONE,
  FINAL_ACTION_TONE,
  RISK_LEVEL_TONE,
  SCAN_STATUS_TONE,
  SCAN_VERDICT_TONE,
} from './semantic';

type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type Engine = ScanRound['engines'][number];
type RiskRevision = ScanRound['risk'][number];
type Evaluation = SuccessBody<'PolicyMessagesController_evaluations_v1'>['data'][number];
type AttachmentRow = ListItem<'AttachmentsController_ofMessage_v1'>;
type UrlRow = ListItem<'UrlProtectionController_ofMessage_v1'>;

const SCAN_TABS = ['rounds', 'attachments', 'urls', 'policy'] as const;
const SCAN_URL_SHAPE = { tab: z.enum(SCAN_TABS).default('rounds').catch('rounds') };
const TAB_LABEL: Record<(typeof SCAN_TABS)[number], string> = {
  rounds: 'Scan rounds',
  attachments: 'Attachments',
  urls: 'URLs',
  policy: 'Policy evaluations',
};

/** Security scan details (`/messages/[messageId]/scans`, §1.3 row 11). */
export function ScanDetails({ messageId }: { messageId: string }) {
  return (
    <RouteGate gate={['MessageScansController_scansOf_v1']}>
      <ScanDetailsContent messageId={messageId} />
    </RouteGate>
  );
}

function ScanDetailsContent({ messageId }: { messageId: string }) {
  const [state, setState] = useUrlState(SCAN_URL_SHAPE);
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Security scan details"
        breadcrumbs={[
          { label: 'Email explorer', href: '/messages' },
          { label: 'Message', href: messageHref(messageId) },
          { label: 'Security scans' },
        ]}
        description="Scan rounds, per-engine results, attachments, URLs and policy evaluations of one message. Symbol options, filenames and URLs come from the message and are shown as text only."
      />
      <Tabs value={state.tab} onValueChange={(tab) => setState({ tab: tab as typeof state.tab })}>
        <TabsList aria-label="Scan detail views">
          {SCAN_TABS.map((tab) => (
            <TabsTrigger key={tab} value={tab}>
              {TAB_LABEL[tab]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="rounds">
          <ScanRounds messageId={messageId} />
        </TabsContent>
        <TabsContent value="attachments">
          <AttachmentsTable messageId={messageId} />
        </TabsContent>
        <TabsContent value="urls">
          <UrlsTable messageId={messageId} />
        </TabsContent>
        <TabsContent value="policy">
          <PolicyEvaluations messageId={messageId} />
        </TabsContent>
      </Tabs>
      <UnavailableState
        step="7.2"
        title="DLP evidence"
        description="Masked DLP findings and the audited evidence view are available in step 7.2; they are not shown here."
      />
    </div>
  );
}

function ScanRounds({ messageId }: { messageId: string }) {
  const list = useCursorList('MessageScansController_scansOf_v1', undefined, {
    path: { messageId },
    limit: 10,
  });
  const { isLoading, error, isFetching } = list.query;
  if (isLoading) return <LoadingState label="Loading scan rounds" rows={6} />;
  if (error && list.rows.length === 0) {
    return <ErrorState error={error} onRetry={() => void list.query.refetch()} />;
  }
  if (list.rows.length === 0) {
    return (
      <EmptyState
        title="No scan rounds yet"
        description="The message has not been scanned yet, or its scan is still being recorded."
      />
    );
  }
  return (
    <div className="grid gap-4">
      {list.rows.map((round) => (
        <RoundCard key={round.scanId} round={round} />
      ))}
      <CursorPager
        label="Scan rounds"
        state={{
          page: list.page,
          hasNext: list.hasNext,
          hasPrevious: list.hasPrevious,
          isShortPage: list.isShortPage,
          next: list.next,
          previous: list.previous,
          rowCount: list.rows.length,
          isFetching,
        }}
      />
    </div>
  );
}

function durationOf(start: string | null, end: string | null): string {
  if (!start || !end) return '';
  const ms = Date.parse(end) - Date.parse(start);
  return Number.isFinite(ms) && ms >= 0 ? formatDuration(ms) : '';
}

function RoundCard({ round }: { round: ScanRound }) {
  const risk = round.risk.length > 0 ? round.risk[round.risk.length - 1] : undefined;
  return (
    <Section
      title={`Round ${round.round} · ${humanize(round.scanKind)}`}
      description={`Scan ${round.scanId}`}
      actions={
        <>
          <EnumBadge value={round.status} tones={SCAN_STATUS_TONE} />
          <EnumBadge value={round.verdict} tones={SCAN_VERDICT_TONE} emptyLabel="No verdict yet" />
        </>
      }
    >
      <DetailList
        items={[
          {
            label: 'Started',
            value: <DateTime value={round.startedAt} mode="absolute" emptyLabel="Not started" />,
          },
          {
            label: 'Completed',
            value: (
              <span>
                <DateTime value={round.completedAt} mode="absolute" emptyLabel="Not completed" />
                {durationOf(round.startedAt, round.completedAt) ? (
                  <span className="text-xs text-muted-foreground">
                    {' '}
                    ({durationOf(round.startedAt, round.completedAt)})
                  </span>
                ) : null}
              </span>
            ),
          },
          {
            label: 'Deadline',
            value: <DateTime value={round.deadlineAt} mode="absolute" emptyLabel="None" />,
          },
          { label: 'Required engines', value: <CodeList codes={round.requiredEngines} /> },
          { label: 'Reason codes', value: <CodeList codes={round.reasonCodes} /> },
        ]}
      />
      {round.auth ? <AuthResults auth={round.auth} /> : null}
      <EnginesTable engines={round.engines} round={round.round} />
      {risk ? <RiskSummary risk={risk} /> : null}
      {round.policy ? (
        <div className="grid gap-2 rounded-md border p-3">
          <h3 className="text-sm font-semibold">Policy decision of this round</h3>
          <EvaluationSummary evaluation={round.policy} />
        </div>
      ) : null}
    </Section>
  );
}

function AuthResults({ auth }: { auth: NonNullable<ScanRound['auth']> }) {
  return (
    <div className="grid gap-2 rounded-md border p-3">
      <h3 className="text-sm font-semibold">Authentication results</h3>
      <DetailList
        items={[
          {
            label: 'SPF',
            value: (
              <span className="flex flex-wrap items-center gap-2">
                <EnumBadge value={auth.spf} tones={AUTH_RESULT_TONE} emptyLabel="Not checked" />
                {auth.spfDomain ? <UntrustedText value={auth.spfDomain} mono /> : null}
              </span>
            ),
          },
          {
            label: 'DKIM',
            value: (
              <div className="grid gap-1">
                <EnumBadge value={auth.dkim} tones={AUTH_RESULT_TONE} emptyLabel="Not checked" />
                {auth.dkimSignatures.length > 0 ? (
                  <ul className="grid gap-1 text-xs" aria-label="DKIM signatures">
                    {auth.dkimSignatures.map((signature, index) => (
                      <li key={index} className="flex flex-wrap items-center gap-2">
                        <EnumBadge value={signature.result} tones={AUTH_RESULT_TONE} />
                        <UntrustedText value={signature.domain} mono />
                        {signature.selector ? (
                          <span className="text-muted-foreground">
                            selector <UntrustedText value={signature.selector} mono />
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ),
          },
          {
            label: 'DMARC',
            value: (
              <span className="flex flex-wrap items-center gap-2">
                <EnumBadge value={auth.dmarc} tones={AUTH_RESULT_TONE} emptyLabel="Not checked" />
                {auth.dmarcPolicy ? (
                  <span className="text-xs text-muted-foreground">policy {auth.dmarcPolicy}</span>
                ) : null}
                {auth.dmarcDomain ? <UntrustedText value={auth.dmarcDomain} mono /> : null}
              </span>
            ),
          },
          {
            label: 'ARC',
            value: <EnumBadge value={auth.arc} tones={AUTH_RESULT_TONE} emptyLabel="Not checked" />,
          },
        ]}
      />
    </div>
  );
}

function EnginesTable({ engines, round }: { engines: readonly Engine[]; round: number }) {
  if (engines.length === 0) {
    return <p className="text-sm text-muted-foreground">No engine results recorded yet.</p>;
  }
  return (
    <div className="grid gap-2">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <caption className="sr-only">Engine results of round {round}</caption>
          <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2 font-semibold">
                Engine
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Outcome
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Score
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Reason codes
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Attempts
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Duration
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Version
              </th>
            </tr>
          </thead>
          <tbody>
            {engines.map((engine) => (
              <tr key={engine.engine} className="border-t align-top">
                <th scope="row" className="px-3 py-2 text-left font-medium">
                  {humanize(engine.engine)}
                  {!engine.final ? (
                    <span className="block text-xs font-normal text-muted-foreground">
                      No final result yet
                    </span>
                  ) : null}
                </th>
                <td className="px-3 py-2">
                  <EnumBadge
                    value={engine.outcome}
                    tones={SCAN_VERDICT_TONE}
                    emptyLabel="Pending"
                  />
                  {engine.action ? (
                    <span className="block text-xs text-muted-foreground">
                      action {engine.action}
                    </span>
                  ) : null}
                </td>
                <td className="px-3 py-2 font-mono text-xs tabular-nums">
                  {engine.score === null ? (
                    <span className="text-muted-foreground">None</span>
                  ) : (
                    <>
                      {formatNumber(engine.score)}
                      {engine.requiredScore !== null
                        ? ` / ${formatNumber(engine.requiredScore)}`
                        : ''}
                    </>
                  )}
                </td>
                <td className="px-3 py-2">
                  <CodeList codes={engine.reasonCodes} />
                </td>
                <td className="px-3 py-2 text-xs">
                  {engine.attempts.length}
                  {engine.attempts.some((a) => a.errorCode) ? (
                    <span className="block text-muted-foreground">
                      last error{' '}
                      <span className="font-mono">
                        {engine.attempts.filter((a) => a.errorCode).at(-1)?.errorCode}
                      </span>
                    </span>
                  ) : null}
                </td>
                <td className="px-3 py-2 text-xs whitespace-nowrap">
                  {engine.durationMs === null ? (
                    <span className="text-muted-foreground">Not reported</span>
                  ) : (
                    formatDuration(engine.durationMs)
                  )}
                </td>
                <td className="px-3 py-2 font-mono text-xs">
                  {engine.engineVersion ?? <span className="text-muted-foreground">Unknown</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {engines
        .filter((engine) => engine.symbols.length > 0)
        .map((engine) => (
          <details key={engine.engine} className="rounded-md border p-3 text-sm">
            <summary className="cursor-pointer font-medium">
              {humanize(engine.engine)} symbols ({engine.symbols.length})
            </summary>
            <p className="mt-2 text-xs text-muted-foreground">
              Symbol options can contain addresses or URLs of the message; they are shown as text.
            </p>
            <ul className="mt-2 grid gap-1" aria-label={`${humanize(engine.engine)} symbols`}>
              {engine.symbols.map((symbol, index) => (
                <li key={`${symbol.name}-${index}`} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs">{symbol.name}</span>
                  <span className="font-mono text-xs text-muted-foreground tabular-nums">
                    {formatNumber(symbol.score)}
                  </span>
                  {symbol.options.map((option, optionIndex) => (
                    <UntrustedText key={optionIndex} value={option} mono maxLength={80} />
                  ))}
                </li>
              ))}
            </ul>
          </details>
        ))}
      {engines.some((engine) => engine.engine === 'dlp') ? (
        <p className="text-xs text-muted-foreground">
          DLP findings are not shown here (available in step 7.2).
        </p>
      ) : null}
    </div>
  );
}

function RiskSummary({ risk }: { risk: RiskRevision }) {
  return (
    <div className="grid gap-2 rounded-md border p-3">
      <h3 className="text-sm font-semibold">
        Risk score (revision {risk.revision}
        {risk.revision === 1 ? ', with the late sandbox result' : ''})
      </h3>
      <DetailList
        items={[
          {
            label: 'Score',
            value:
              risk.status === 'scored' ? (
                <RiskScore score={risk.score} level={risk.level} />
              ) : (
                <EnumBadge value="error" tones={SCAN_VERDICT_TONE} />
              ),
          },
          { label: 'Level', value: <EnumBadge value={risk.level} tones={RISK_LEVEL_TONE} /> },
          {
            label: 'Recommended action',
            value: <EnumBadge value={risk.recommendedAction} tones={FINAL_ACTION_TONE} />,
          },
          {
            label: 'Hard blocks',
            value: <CodeList codes={risk.hardBlocks.map((block) => block.id)} />,
          },
          { label: 'Reason codes', value: <CodeList codes={risk.reasonCodes} /> },
          {
            label: 'Explanation',
            value: <p className="text-sm whitespace-pre-wrap">{risk.explanation.text}</p>,
          },
          {
            label: 'Profile',
            value: (
              <span className="font-mono text-xs">
                {risk.versions.profile.id} ({risk.versions.profile.source})
              </span>
            ),
          },
        ]}
      />
      <p className="text-xs text-muted-foreground">
        A recommendation, not a decision: the policy decides. Signal contributions arrive with the
        risk breakdown in step 7.2.
      </p>
    </div>
  );
}

function EvaluationSummary({ evaluation }: { evaluation: Evaluation }) {
  return (
    <DetailList
      items={[
        {
          label: 'Disposition',
          value: <EnumBadge value={evaluation.disposition} tones={DISPOSITION_TONE} />,
        },
        {
          label: 'Final action',
          value: <EnumBadge value={evaluation.finalAction} tones={FINAL_ACTION_TONE} />,
        },
        {
          label: 'Decided by',
          value: (
            <span className="flex flex-wrap items-center gap-2 text-xs">
              <span>{humanize(evaluation.decisive.source)}</span>
              {evaluation.decisive.policyPublicId ? (
                <span className="font-mono">
                  {evaluation.decisive.policyPublicId}
                  {evaluation.decisive.versionNo ? ` v${evaluation.decisive.versionNo}` : ''}
                </span>
              ) : null}
              {evaluation.decisive.ruleId ? (
                <span className="font-mono">rule {evaluation.decisive.ruleId}</span>
              ) : null}
              <span className="font-mono text-muted-foreground">{evaluation.decisive.reason}</span>
            </span>
          ),
        },
        {
          label: 'Actions',
          value: (
            <ul className="flex flex-wrap gap-1" aria-label="Policy actions">
              {evaluation.actions.map((action, index) => (
                <li key={index} className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {action.type}
                  {evaluation.actionStatuses[index] ? ` · ${evaluation.actionStatuses[index]}` : ''}
                </li>
              ))}
            </ul>
          ),
        },
        { label: 'Reason codes', value: <CodeList codes={evaluation.reasonCodes} /> },
        {
          label: 'Explanation',
          value: <p className="text-sm whitespace-pre-wrap">{evaluation.explanation.text}</p>,
        },
        {
          label: 'Override',
          value: evaluation.override ? (
            <span className="text-xs">
              {evaluation.override.from} → {evaluation.override.to} by{' '}
              <span className="font-mono">{evaluation.override.ref}</span>
            </span>
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
        },
        { label: 'Per-recipient', value: <YesNo value={evaluation.recipientSplit} /> },
        {
          label: 'Evaluated',
          value: (
            <span>
              <DateTime value={evaluation.evaluatedAt} mode="absolute" />{' '}
              <span className="text-xs text-muted-foreground">
                in {formatDuration(evaluation.durationUs / 1000)}
              </span>
            </span>
          ),
        },
      ]}
    />
  );
}

function PolicyEvaluations({ messageId }: { messageId: string }) {
  const query = useApiQuery('PolicyMessagesController_evaluations_v1', { path: { messageId } });
  if (query.isLoading) return <LoadingState label="Loading policy evaluations" rows={5} />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const rows = query.data?.data ?? [];
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No policy evaluations"
        description="The message has not been evaluated by the policy engine yet."
      />
    );
  }
  return (
    <div className="grid gap-4">
      {rows.map((evaluation) => (
        <Section
          key={`${evaluation.lifecycleRound}-${evaluation.evaluatedAt}`}
          title={`Round ${evaluation.lifecycleRound} · ${humanize(evaluation.trigger)}`}
          description={`Direction ${evaluation.direction} · final verdict ${humanize(evaluation.finalVerdict)}${
            evaluation.riskScore !== null ? ` · risk ${evaluation.riskScore}` : ''
          }`}
          headingLevel={2}
        >
          <EvaluationSummary evaluation={evaluation} />
          {evaluation.matchedRules.length > 0 ? (
            <div className="grid gap-1">
              <h3 className="text-xs font-medium text-muted-foreground">Matched rules</h3>
              <CodeList
                codes={evaluation.matchedRules.map(
                  (rule) => `${rule.policyPublicId} v${rule.versionNo} ${rule.ruleId}`,
                )}
                label="Matched rules"
              />
            </div>
          ) : null}
        </Section>
      ))}
    </div>
  );
}

const ATTACHMENT_COLUMNS: DataTableColumn<AttachmentRow>[] = [
  {
    id: 'part',
    header: 'Part',
    meta: { label: 'Part', className: 'tabular-nums' },
    cell: ({ row }) => row.original.partIndex,
  },
  {
    id: 'filename',
    header: 'Filename',
    meta: { label: 'Filename', className: 'max-w-64' },
    cell: ({ row }) => (
      <UntrustedText value={row.original.filename} maxLength={60} emptyLabel="(no filename)" />
    ),
  },
  {
    id: 'type',
    header: 'Type',
    meta: { label: 'Type' },
    cell: ({ row }) => {
      const scan = row.original.latestScan;
      return (
        <div className="grid text-xs">
          <span>
            Declared:{' '}
            <UntrustedText value={row.original.declaredContentType} mono emptyLabel="none" />
          </span>
          <span>
            Detected:{' '}
            <span className="font-mono">
              {scan?.detectedType ?? row.original.detectedContentType ?? 'unknown'}
            </span>
            {scan ? ` (${humanize(scan.typeFamily)})` : ''}
          </span>
          {scan?.typeMismatch ? (
            <span className="font-medium text-tone-orange-foreground">Type mismatch</span>
          ) : null}
        </div>
      );
    },
  },
  {
    id: 'size',
    header: 'Size',
    meta: { label: 'Size', className: 'whitespace-nowrap tabular-nums' },
    cell: ({ row }) => formatBytes(row.original.sizeBytes),
  },
  {
    id: 'sha256',
    header: 'SHA-256',
    meta: { label: 'SHA-256' },
    cell: ({ row }) => (
      <div className="grid gap-0.5">
        <CopyableId value={row.original.sha256} label="SHA-256" />
        <Link
          href={attachmentSearchHref(row.original.sha256)}
          className="text-xs text-primary underline-offset-2 hover:underline"
        >
          Other messages with this file
        </Link>
      </div>
    ),
  },
  {
    id: 'verdict',
    header: 'Verdict',
    meta: { label: 'Verdict' },
    cell: ({ row }) => (
      <EnumBadge value={row.original.verdict} tones={SCAN_VERDICT_TONE} emptyLabel="Not scanned" />
    ),
  },
  {
    id: 'findings',
    header: 'Findings',
    meta: { label: 'Findings', className: 'max-w-80' },
    cell: ({ row }) => {
      const scan = row.original.latestScan;
      if (!scan) return <span className="text-muted-foreground">None</span>;
      return (
        <div className="grid gap-1 text-xs">
          <CodeList codes={scan.reasonCodes} />
          {scan.clamav?.signature ? (
            <span>
              ClamAV: <span className="font-mono">{scan.clamav.signature}</span>
            </span>
          ) : null}
          {scan.yara && scan.yara.matches.length > 0 ? (
            <span>
              YARA:{' '}
              <span className="font-mono">
                {scan.yara.matches.map((m) => `${m.rule} (${m.severity})`).join(', ')}
              </span>
            </span>
          ) : null}
          {scan.knownHash ? <span>Known hash: {scan.knownHash.severity}</span> : null}
          {scan.archive ? (
            <span>
              Archive {scan.archive.format}: {scan.archive.entries} entries
              {scan.archive.encrypted ? ', encrypted' : ''}
            </span>
          ) : null}
        </div>
      );
    },
  },
];

function AttachmentsTable({ messageId }: { messageId: string }) {
  const list = useCursorList('AttachmentsController_ofMessage_v1', undefined, {
    path: { messageId },
    limit: 50,
  });
  return (
    <div className="grid gap-2">
      <p className="text-xs text-muted-foreground">
        Filenames are sanitized display names chosen by the sender. Attachments cannot be downloaded
        here; quarantined messages offer a controlled download from their quarantine entry.
      </p>
      <DataTable
        tableId="message-attachments"
        caption="Attachments"
        columns={ATTACHMENT_COLUMNS}
        list={list}
        getRowId={(row) => String(row.partIndex)}
        getRowLabel={(row) => `attachment part ${row.partIndex}`}
        emptyState={
          <EmptyState title="No attachments" description="This message has no attachments." />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <UntrustedText value={row.filename} maxLength={50} emptyLabel="(no filename)" />
            <span className="text-xs text-muted-foreground">{formatBytes(row.sizeBytes)}</span>
            <EnumBadge value={row.verdict} tones={SCAN_VERDICT_TONE} emptyLabel="Not scanned" />
          </div>
        )}
      />
    </div>
  );
}

const URL_COLUMNS: DataTableColumn<UrlRow>[] = [
  {
    id: 'seq',
    header: '#',
    meta: { label: 'Sequence', className: 'tabular-nums' },
    cell: ({ row }) => row.original.urlSeq,
  },
  {
    id: 'url',
    header: 'URL',
    meta: { label: 'URL', className: 'max-w-96' },
    cell: ({ row }) => (
      <div className="grid gap-0.5">
        <UntrustedText value={row.original.url} mono maxLength={80} copy copyLabel="Copy URL" />
        <span className="text-xs text-muted-foreground">
          Host{' '}
          <UntrustedText
            value={row.original.unicodeHost ?? row.original.host}
            mono
            maxLength={60}
          />{' '}
          ({row.original.hostKind})
        </span>
      </div>
    ),
  },
  {
    id: 'verdict',
    header: 'Verdict',
    meta: { label: 'Verdict' },
    cell: ({ row }) => (
      <div className="grid gap-1">
        <EnumBadge
          value={row.original.latest?.verdict}
          tones={SCAN_VERDICT_TONE}
          emptyLabel="Not scanned"
        />
        <CodeList codes={row.original.latest?.reasonCodes} emptyLabel="" />
      </div>
    ),
  },
  {
    id: 'flags',
    header: 'Flags',
    meta: { label: 'Flags', className: 'max-w-72' },
    cell: ({ row }) => <CodeList codes={row.original.flags} />,
  },
  {
    id: 'rewrite',
    header: 'Rewrite',
    meta: { label: 'Rewrite' },
    cell: ({ row }) => {
      const rewrite = row.original.rewrite;
      if (!rewrite) return <span className="text-muted-foreground">Not recorded</span>;
      return (
        <span className="text-xs">
          {humanize(rewrite.status)}
          {rewrite.skipReason ? ` (${humanize(rewrite.skipReason)})` : ''}
        </span>
      );
    },
  },
  {
    id: 'clicks',
    header: 'Clicks',
    meta: { label: 'Clicks' },
    cell: ({ row }) => {
      const clicks = row.original.clicks;
      const decisions = Object.entries(clicks.byDecision);
      return (
        <span className="text-xs tabular-nums">
          {formatNumber(clicks.total)}
          {decisions.length > 0
            ? ` (${decisions.map(([decision, count]) => `${humanize(decision)} ${count}`).join(', ')})`
            : ''}
        </span>
      );
    },
  },
];

function UrlsTable({ messageId }: { messageId: string }) {
  const list = useCursorList('UrlProtectionController_ofMessage_v1', undefined, {
    path: { messageId },
    limit: 50,
  });
  return (
    <div className="grid gap-2">
      <p className="text-xs text-muted-foreground">
        URLs are shown as text and are never clickable. Use the copy button to inspect one in an
        isolated environment.
      </p>
      <DataTable
        tableId="message-urls"
        caption="URLs"
        columns={URL_COLUMNS}
        list={list}
        getRowId={(row) => String(row.urlSeq)}
        getRowLabel={(row) => `URL ${row.urlSeq}`}
        emptyState={<EmptyState title="No URLs" description="No URL was found in this message." />}
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <UntrustedText value={row.url} mono maxLength={60} copy copyLabel="Copy URL" />
            <EnumBadge
              value={row.latest?.verdict}
              tones={SCAN_VERDICT_TONE}
              emptyLabel="Not scanned"
            />
          </div>
        )}
      />
    </div>
  );
}
