'use client';

import { DataTable } from '@/components/data-table';
import { CopyableId, DateTime, UntrustedText } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { useCursorList } from '@/lib/api/hooks';
import { formatBytes, formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section, YesNo } from '../controls';
import { ATTACHMENT_COLUMNS, URL_COLUMNS } from '../scan-details';
import { SCAN_VERDICT_TONE } from '../semantic';
import { Block, DataGrid, NoData } from './parts';
import { RoundPanel, engineOf, type Engine, type ScanRound } from './rounds';
import { EngineFacts } from './scan-sections';

type Submission = NonNullable<Engine['submissions']>[number];
type AttachmentResult = NonNullable<Engine['attachments']>[number];

/** Section 7: URL analysis (`UrlProtectionController_ofMessage` v1 + the round's rewrite). */
export function UrlsSection({ messageId }: { messageId: string }) {
  const list = useCursorList('UrlProtectionController_ofMessage_v1', undefined, {
    path: { messageId },
    limit: 50,
  });
  return (
    <div className="grid gap-4">
      <Section
        title="URL analysis"
        description="URLs found in the message with their latest verdict, flags, rewrite and clicks. URLs are shown as text and are never clickable; copy one to inspect it in an isolated environment."
      >
        <DataTable
          tableId="message-details-urls"
          caption="URLs"
          columns={URL_COLUMNS}
          list={list}
          getRowId={(row) => String(row.urlSeq)}
          getRowLabel={(row) => `URL ${row.urlSeq}`}
          emptyState={
            <EmptyState title="No URLs" description="No URL was found in this message." />
          }
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
      </Section>
      <Section
        title="URL engine of the round"
        headingLevel={3}
        description="The url engine's result and link rewrite for the selected scan round."
      >
        <RoundPanel>{(round) => <UrlRound round={round} />}</RoundPanel>
      </Section>
    </div>
  );
}

function UrlRound({ round }: { round: ScanRound }) {
  const engine = engineOf(round, 'url');
  if (!engine) return <NoData>No URL engine result in round {round.round}.</NoData>;
  const rewrite = engine.rewrite;
  return (
    <div className="grid gap-3">
      <EngineFacts engine={engine} />
      <Block title="Link rewrite">
        {rewrite ? (
          <DetailList
            items={[
              {
                label: 'Status',
                value: (
                  <span>
                    {humanize(rewrite.status)}
                    {rewrite.skipReason ? ` (${humanize(rewrite.skipReason)})` : ''}
                  </span>
                ),
              },
              { label: 'Links rewritten', value: formatNumber(rewrite.linksRewritten) },
              { label: 'Parts rewritten', value: formatNumber(rewrite.partsRewritten) },
              { label: 'DKIM signed after rewrite', value: <YesNo value={rewrite.dkimSigned} /> },
              {
                label: 'Rewritten links expire',
                value: <DateTime value={rewrite.expiresAt} mode="absolute" emptyLabel="Never" />,
              },
            ]}
          />
        ) : (
          <NoData>No rewrite recorded for this round.</NoData>
        )}
      </Block>
      {engine.urls && engine.urls.length > 0 ? (
        <DataGrid
          caption={`URL results of round ${round.round}`}
          captionVisible
          rows={engine.urls}
          rowKey={(url) => String(url.urlSeq)}
          columns={[
            {
              header: 'URL',
              rowHeader: true,
              className: 'max-w-80',
              cell: (url) => (
                <span className="grid gap-0.5">
                  <span className="text-xs text-muted-foreground">#{url.urlSeq}</span>
                  <UntrustedText
                    value={url.url}
                    mono
                    maxLength={80}
                    copy
                    copyLabel={`Copy URL ${url.urlSeq}`}
                  />
                </span>
              ),
            },
            {
              header: 'Verdict',
              cell: (url) => <EnumBadge value={url.verdict} tones={SCAN_VERDICT_TONE} />,
            },
            { header: 'Reason codes', cell: (url) => <CodeList codes={url.reasonCodes} /> },
            {
              header: 'Redirects',
              className: 'text-xs',
              cell: (url) =>
                url.fetch ? (
                  <span>
                    {humanize(url.fetch.status)}, {url.fetch.hops} hop
                    {url.fetch.hops === 1 ? '' : 's'}
                    {url.fetch.finalStatus !== null ? ` · HTTP ${url.fetch.finalStatus}` : ''}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Not fetched</span>
                ),
            },
            {
              header: 'Rewritten',
              cell: (url) => <YesNo value={url.rewritten} />,
              className: 'text-xs',
            },
          ]}
        />
      ) : (
        <NoData>No per-URL results in this round.</NoData>
      )}
    </div>
  );
}

/** Section 8: attachment analysis (`AttachmentsController_ofMessage` v1 + attachment and sandbox engines). */
export function AttachmentsSection({ messageId }: { messageId: string }) {
  const list = useCursorList('AttachmentsController_ofMessage_v1', undefined, {
    path: { messageId },
    limit: 50,
  });
  return (
    <div className="grid gap-4">
      <Section
        title="Attachment analysis"
        description="Attachment metadata and scan results; the content stays in object storage. Filenames are display names chosen by the sender. Nothing can be downloaded here: a quarantined copy offers a controlled download from its quarantine entry (Quarantine actions)."
      >
        <DataTable
          tableId="message-details-attachments"
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
      </Section>
      <Section
        title="Attachment and sandbox engines of the round"
        headingLevel={3}
        description="Per-attachment results and sandbox submissions of the selected scan round. The sandbox result can arrive after the round and never changes its verdict."
      >
        <RoundPanel>{(round) => <AttachmentRound round={round} />}</RoundPanel>
      </Section>
    </div>
  );
}

function AttachmentRound({ round }: { round: ScanRound }) {
  const attachment = engineOf(round, 'attachment');
  const sandbox = engineOf(round, 'sandbox');
  return (
    <div className="grid gap-3">
      {attachment ? (
        <Block title="Attachment engine">
          <EngineFacts engine={attachment} />
          {attachment.attachments && attachment.attachments.length > 0 ? (
            <AttachmentResults rows={attachment.attachments} round={round.round} />
          ) : (
            <NoData>No per-attachment results (no attachments, or no final result yet).</NoData>
          )}
        </Block>
      ) : (
        <NoData>No attachment engine result in round {round.round}.</NoData>
      )}
      {sandbox ? (
        <Block title="Sandbox">
          <EngineFacts engine={sandbox} />
          {sandbox.submissions && sandbox.submissions.length > 0 ? (
            <ul className="grid gap-2" aria-label="Sandbox submissions">
              {sandbox.submissions.map((submission) => (
                <SubmissionItem key={submission.submissionId} submission={submission} />
              ))}
            </ul>
          ) : (
            <NoData>No sandbox submission in this round.</NoData>
          )}
        </Block>
      ) : (
        <NoData>
          No sandbox result in round {round.round} (no submission, or the asynchronous result has
          not arrived).
        </NoData>
      )}
    </div>
  );
}

function AttachmentResults({ rows, round }: { rows: readonly AttachmentResult[]; round: number }) {
  return (
    <DataGrid
      caption={`Per-attachment results of round ${round}`}
      captionVisible
      rows={rows}
      rowKey={(row) => String(row.partIndex)}
      columns={[
        {
          header: 'Part',
          rowHeader: true,
          className: 'max-w-64',
          cell: (row) => (
            <span className="grid gap-0.5">
              <span className="text-xs text-muted-foreground">part {row.partIndex}</span>
              <UntrustedText value={row.filename} maxLength={60} emptyLabel="(no filename)" />
            </span>
          ),
        },
        {
          header: 'Type',
          className: 'text-xs',
          cell: (row) => (
            <span className="grid">
              <span className="font-mono">{row.detectedType}</span>
              <span className="text-muted-foreground">{humanize(row.typeFamily)}</span>
              {row.typeMismatch ? (
                <span className="font-medium text-tone-orange-foreground">Type mismatch</span>
              ) : null}
            </span>
          ),
        },
        {
          header: 'Verdict',
          cell: (row) => <EnumBadge value={row.verdict} tones={SCAN_VERDICT_TONE} />,
        },
        {
          header: 'Findings',
          className: 'max-w-80 text-xs',
          cell: (row) => (
            <span className="grid gap-1">
              <CodeList codes={row.reasonCodes} />
              {row.clamav?.signature ? (
                <span>
                  ClamAV <span className="font-mono">{row.clamav.signature}</span>
                </span>
              ) : null}
              {row.yara && row.yara.matches.length > 0 ? (
                <span>
                  YARA{' '}
                  <span className="font-mono">
                    {row.yara.matches.map((m) => `${m.rule} (${m.severity})`).join(', ')}
                  </span>
                </span>
              ) : null}
              {row.knownHash ? <span>Known hash ({row.knownHash.severity})</span> : null}
              {row.archive ? (
                <span>
                  Archive {row.archive.format}: {row.archive.entries} entries
                  {row.archive.encrypted ? ', encrypted' : ''}
                </span>
              ) : null}
            </span>
          ),
        },
        {
          header: 'Sandbox',
          className: 'text-xs',
          cell: (row) =>
            row.sandbox ? (
              <span className="grid">
                <span>
                  {humanize(row.sandbox.status)}
                  {row.sandbox.skipReason ? ` (${humanize(row.sandbox.skipReason)})` : ''}
                </span>
                {row.sandbox.verdict ? (
                  <EnumBadge value={row.sandbox.verdict} tones={SCAN_VERDICT_TONE} />
                ) : null}
              </span>
            ) : (
              <span className="text-muted-foreground">Not submitted</span>
            ),
        },
        {
          header: 'SHA-256',
          cell: (row) => (
            <CopyableId value={row.sha256} label={`SHA-256 of part ${row.partIndex}`} />
          ),
        },
      ]}
    />
  );
}

function SubmissionItem({ submission }: { submission: Submission }) {
  return (
    <li className="grid gap-2 rounded-md border p-2 text-xs">
      <span className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Part {submission.partIndex}</span>
        <span>
          {humanize(submission.status)}
          {submission.skipReason ? ` (${humanize(submission.skipReason)})` : ''}
        </span>
        <EnumBadge value={submission.verdict} tones={SCAN_VERDICT_TONE} emptyLabel="No verdict" />
        <span className="text-muted-foreground">
          executed: {submission.executed === null ? 'unknown' : submission.executed ? 'yes' : 'no'}
          {submission.isolation ? ` · isolation ${submission.isolation}` : ''}
          {submission.backend ? ` · backend ${submission.backend}` : ''}
        </span>
      </span>
      <CodeList codes={submission.reasonCodes} />
      {submission.findings.length > 0 ? (
        <ul
          className="flex flex-wrap gap-1"
          aria-label={`Sandbox findings of part ${submission.partIndex}`}
        >
          {submission.findings.map((finding) => (
            <li key={finding.code} className="rounded-sm bg-muted px-1.5 py-0.5 font-mono">
              {finding.code} · {finding.severity} × {finding.count}
            </li>
          ))}
        </ul>
      ) : null}
      {submission.indicators.dns.length + submission.indicators.httpHosts.length > 0 ? (
        <span className="flex flex-wrap items-center gap-1">
          <span className="text-muted-foreground">Contacted hosts:</span>
          {[...submission.indicators.dns, ...submission.indicators.httpHosts]
            .slice(0, 10)
            .map((host, index) => (
              <UntrustedText key={`${host}-${index}`} value={host} mono maxLength={60} />
            ))}
        </span>
      ) : null}
      {submission.droppedFiles.length > 0 || submission.artifacts.length > 0 ? (
        <span className="text-muted-foreground">
          {submission.droppedFiles.length} dropped file
          {submission.droppedFiles.length === 1 ? '' : 's'}, {submission.artifacts.length} artifact
          {submission.artifacts.length === 1 ? '' : 's'} (metadata only; no artifact download
          exists)
        </span>
      ) : null}
      <DateTime value={submission.completedAt} mode="absolute" emptyLabel="Not completed" />
    </li>
  );
}
