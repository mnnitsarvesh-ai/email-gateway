'use client';

import {
  DownloadIcon,
  EyeIcon,
  EyeOffIcon,
  FileSearchIcon,
  ShieldAlertIcon,
  Trash2Icon,
} from 'lucide-react';
import Link from 'next/link';
import { useState, type ReactNode } from 'react';
import {
  CopyableId,
  DateTime,
  DirectionBadge,
  RiskScore,
  SensitiveValue,
  UntrustedText,
  VerdictBadge,
} from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section, YesNo } from '@/features/messages/controls';
import { RoundCard } from '@/features/messages/scan-details';
import { FINAL_ACTION_TONE } from '@/features/messages/semantic';
import { PreviewContent } from '@/features/quarantine/preview-panel';
import { isUuid } from '@/features/domains/kit';
import { ArchiveQueryError, Notice, RateLimited, ReasonDialog, ArchiveSubject } from './components';
import { GrantDownloadDialog } from './download-dialog';
import { useArchiveReveal, useCountdown, type RevealedArchiveValues } from './hooks';
import {
  CATEGORY_TONE,
  LOCK_TONE,
  RECORD_STATUS_TONE,
  contentBlocker,
  explainArchiveError,
  legalHoldHref,
  retentionHref,
  useArchiveAccess,
  type ArchiveAccess,
  type ArchiveDetail,
} from './model';

type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;

/** Archived message details (`/archive/[messageId]`, step 8.1 A19, A28). */
export function ArchiveDetails({ messageId }: { messageId: string }) {
  return (
    <RouteGate gate={['ArchiveMessagesController_detail_v1']}>
      {isUuid(messageId) ? <ArchiveDetailsContent messageId={messageId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function ArchiveDetailsContent({ messageId }: { messageId: string }) {
  const access = useArchiveAccess();
  const detail = useApiQuery(
    'ArchiveMessagesController_detail_v1',
    { path: { messageId } },
    { refetchOnWindowFocus: false },
  );
  const reveal = useArchiveReveal(messageId);
  const revealed = reveal.values.get(messageId);
  const [downloadOpen, setDownloadOpen] = useState(false);
  const [disposeOpen, setDisposeOpen] = useState(false);

  if (detail.isLoading) return <LoadingState label="Loading the archived message" rows={8} />;
  if (detail.error || !detail.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Archived message" breadcrumbs={crumbs()} />
        <ArchiveQueryError error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }
  const record = detail.data;
  const canDispose = access.manage && record.status === 'expiry_review';
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Archived message"
        breadcrumbs={crumbs()}
        description={
          <>
            Received <DateTime value={record.receivedAt} mode="absolute" /> · captured{' '}
            <DateTime value={record.capturedAt} mode="absolute" emptyLabel="not yet" />. Opening
            this page, the journal and the security sections is recorded in the audit log.
          </>
        }
        actions={
          <>
            {access.reveal ? (
              revealed ? (
                <Button variant="outline" size="sm" onClick={reveal.hide}>
                  <EyeOffIcon aria-hidden />
                  Hide again
                </Button>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={reveal.pending || reveal.retryAfterSeconds > 0}
                  onClick={() =>
                    void reveal.reveal([messageId], ['subject', 'recipients', 'headers'])
                  }
                >
                  <EyeIcon aria-hidden />
                  {reveal.pending ? 'Revealing …' : 'Reveal'}
                </Button>
              )
            ) : null}
            {canDispose ? (
              <Button variant="destructive" size="sm" onClick={() => setDisposeOpen(true)}>
                <Trash2Icon aria-hidden />
                Dispose
              </Button>
            ) : null}
          </>
        }
      />
      <p className="sr-only" aria-live="polite">
        {reveal.announcement}
      </p>
      {revealed ? (
        <Notice>
          <span>
            Revealed values are shown for this page view only (revealed{' '}
            <DateTime value={revealed.revealedAt} />
            ). The reveal is recorded in the audit log; “Hide again” or leaving the page hides them.
          </span>
        </Notice>
      ) : null}
      {reveal.error ? (
        reveal.error.status === 429 ? (
          <RateLimited seconds={reveal.retryAfterSeconds} what="reveals" />
        ) : (
          <div className="grid gap-1">
            <p className="text-sm">{explainArchiveError(reveal.error).join(' ')}</p>
            <ErrorState error={reveal.error} compact />
          </div>
        )
      ) : null}
      {record.status === 'disposing' ? (
        <Notice tone="danger" icon={Trash2Icon}>
          <span>
            This record is being disposed: its content is already unreadable (crypto-shredded) and
            the remaining copies are being deleted.
          </span>
        </Notice>
      ) : null}
      <SummarySection record={record} revealed={revealed} />
      <PartiesSection record={record} revealed={revealed} />
      <RetentionSection record={record} access={access} />
      <IntegritySection record={record} />
      <JournalSection
        messageId={messageId}
        revealed={revealed}
        disposed={record.status === 'disposing'}
      />
      <SecuritySection messageId={messageId} disposed={record.status === 'disposing'} />
      {access.retrieve ? (
        <>
          <PreviewSection messageId={messageId} access={access} record={record} />
          <DownloadSection
            record={record}
            access={access}
            onDownload={() => setDownloadOpen(true)}
          />
          <GrantDownloadDialog
            target={{ kind: 'message', messageId }}
            open={downloadOpen}
            onOpenChange={setDownloadOpen}
            title="Download the archived original"
            description="Confirm your identity to create a single-use download link valid for a short time. The original message (.eml) is saved, never opened in the portal; the download is recorded in the audit log."
          />
        </>
      ) : null}
      {canDispose ? (
        <DisposeDialog messageId={messageId} open={disposeOpen} onOpenChange={setDisposeOpen} />
      ) : null}
    </div>
  );
}

function crumbs() {
  return [{ label: 'Archive', href: '/archive' }, { label: 'Archived message' }];
}

function SummarySection({
  record,
  revealed,
}: {
  record: ArchiveDetail;
  revealed?: RevealedArchiveValues;
}) {
  return (
    <Section title="Summary" description="Metadata of the archived record (no content).">
      <DetailList
        items={[
          { label: 'Message', value: <CopyableId value={record.messageId} /> },
          { label: 'Subject', value: <ArchiveSubject row={record} revealed={revealed} /> },
          { label: 'Direction', value: <DirectionBadge direction={record.direction} /> },
          {
            label: 'Category',
            value: <EnumBadge value={record.category} tones={CATEGORY_TONE} />,
          },
          {
            label: 'Captured by',
            value: <CodeList codes={record.sources.map(humanize)} />,
          },
          {
            label: 'Record status',
            value: <EnumBadge value={record.status} tones={RECORD_STATUS_TONE} />,
          },
          {
            label: 'Message-ID',
            value: (
              <UntrustedText
                value={record.internetMessageId}
                mono
                emptyLabel="None"
                maxLength={120}
              />
            ),
          },
          {
            label: 'Verdict',
            value: (
              <span className="flex flex-wrap items-center gap-1">
                <VerdictBadge verdict={record.verdict} />
                {record.malicious ? (
                  <EnumBadge value="malicious" tones={{ malicious: 'danger' }} />
                ) : null}
              </span>
            ),
          },
          {
            label: 'Final action',
            value: <EnumBadge value={record.finalAction} tones={FINAL_ACTION_TONE} />,
          },
          { label: 'Risk score', value: <RiskScore score={record.riskScore} /> },
          { label: 'Size', value: formatBytes(record.sizeBytes) },
          {
            label: 'Attachments',
            value:
              record.attachmentCount === 0 ? (
                'None'
              ) : (
                <span>
                  {record.attachmentCount}
                  {record.attachmentNames.length > 0 ? (
                    <>
                      {': '}
                      <UntrustedText value={record.attachmentNames.join(', ')} maxLength={200} />
                    </>
                  ) : null}
                </span>
              ),
          },
          {
            label: 'Capture',
            value: (
              <span className="text-xs">
                <DateTime value={record.capture.capturedAt} mode="absolute" /> · state at capture{' '}
                {humanize(record.capture.messageState)}
                {record.capture.messageStateReason
                  ? ` (${humanize(record.capture.messageStateReason)})`
                  : ''}
                {record.capture.sources.policyRuleRef ? (
                  <>
                    {' '}
                    · policy rule{' '}
                    <span className="font-mono">{record.capture.sources.policyRuleRef}</span>
                  </>
                ) : null}
                {record.capture.outcomeRefreshedAt ? (
                  <>
                    {' '}
                    · outcome refreshed{' '}
                    <DateTime value={record.capture.outcomeRefreshedAt} mode="absolute" />
                  </>
                ) : null}
              </span>
            ),
          },
          {
            label: 'Scan rounds',
            value:
              record.rounds.length === 0 ? (
                'None linked'
              ) : (
                <ul className="grid gap-0.5 text-xs">
                  {record.rounds.map((r) => (
                    <li key={`${r.round}-${r.revision}`}>
                      Round {r.round}, revision {r.revision} · frozen{' '}
                      <DateTime value={r.frozenAt} mode="absolute" />
                    </li>
                  ))}
                </ul>
              ),
          },
        ]}
      />
    </Section>
  );
}

function PartiesSection({
  record,
  revealed,
}: {
  record: ArchiveDetail;
  revealed?: RevealedArchiveValues;
}) {
  const parties = record.parties;
  return (
    <Section
      title="Parties"
      description="The sender side is in clear; recipient addresses are masked for everyone (reveal is audited)."
    >
      <DetailList
        items={[
          {
            label: 'Envelope sender',
            value: <UntrustedText value={parties.envelopeFrom} emptyLabel="(null sender)" />,
          },
          {
            label: 'Header From',
            value: <UntrustedText value={parties.headerFrom} emptyLabel="None" />,
          },
          { label: 'Recipients', value: String(parties.recipientCount) },
        ]}
      />
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <caption className="sr-only">Envelope recipients</caption>
          <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2">
                #
              </th>
              <th scope="col" className="px-3 py-2">
                Address
              </th>
              <th scope="col" className="px-3 py-2">
                Direction
              </th>
              <th scope="col" className="px-3 py-2">
                Status
              </th>
              <th scope="col" className="px-3 py-2">
                Final action
              </th>
            </tr>
          </thead>
          <tbody>
            {parties.recipients.map((recipient) => {
              const clear = revealed?.recipients.get(recipient.seq);
              return (
                <tr key={recipient.seq} className="border-t">
                  <td className="px-3 py-2 font-mono text-xs">{recipient.seq}</td>
                  <td className="px-3 py-2">
                    <SensitiveValue
                      value={clear ?? recipient.address}
                      masked
                      revealed={clear !== undefined}
                      kind="address"
                      maxLength={80}
                    />
                  </td>
                  <td className="px-3 py-2">
                    <DirectionBadge direction={recipient.direction} />
                  </td>
                  <td className="px-3 py-2">{humanize(recipient.status)}</td>
                  <td className="px-3 py-2">
                    <EnumBadge value={recipient.finalAction} tones={FINAL_ACTION_TONE} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {parties.recipientsTruncated ? (
        <p className="text-xs text-muted-foreground">
          Only the first {parties.recipients.length} recipients are listed.
        </p>
      ) : null}
    </Section>
  );
}

function RetentionSection({ record, access }: { record: ArchiveDetail; access: ArchiveAccess }) {
  const retention = record.retention;
  const holdsVisible = (access.legalHold || access.ediscovery) && record.holds !== null;
  const holds = record.holds ?? [];
  return (
    <Section
      title="Retention and holds"
      description="Retention only grows: the effective date is the later of the stored date and the policy’s current length."
    >
      <DetailList
        items={[
          {
            label: 'Retention policy',
            value: retention.policyName ? (
              access.read ? (
                <Link
                  href={retentionHref('policies')}
                  className="text-primary underline underline-offset-2"
                >
                  <UntrustedText value={retention.policyName} />
                </Link>
              ) : (
                <UntrustedText value={retention.policyName} />
              )
            ) : (
              <span className="text-muted-foreground">Policy deleted</span>
            ),
          },
          {
            label: 'Retain until (stored)',
            value: <DateTime value={retention.retainUntil} mode="absolute" />,
          },
          {
            label: 'Effective retain until',
            value: <DateTime value={retention.effectiveRetainUntil} mode="absolute" />,
          },
          { label: 'At expiry', value: humanize(retention.expiryAction) },
          {
            label: 'Held past an expiry',
            value: <YesNo value={record.legalHold} />,
          },
          {
            label: 'Legal holds now',
            hidden: !holdsVisible,
            value:
              holds.length === 0 ? (
                <span className="text-muted-foreground">No active hold covers this message</span>
              ) : (
                <ul className="grid gap-0.5">
                  {holds.map((hold) => (
                    <li key={hold.id}>
                      <Link
                        href={legalHoldHref(hold.id)}
                        className="text-primary underline underline-offset-2"
                      >
                        <UntrustedText value={hold.name} />
                      </Link>
                    </li>
                  ))}
                </ul>
              ),
          },
        ]}
      />
      {!holdsVisible ? (
        <p className="text-xs text-muted-foreground">
          Which holds cover a message is confidential (archive:legal_hold or ediscovery:manage).
        </p>
      ) : null}
    </Section>
  );
}

function IntegritySection({ record }: { record: ArchiveDetail }) {
  return (
    <Section
      title="Immutability and integrity"
      description="Archive objects are write-once and encrypted per record under your organization’s key."
    >
      <DetailList
        items={[
          {
            label: 'Object Lock',
            value: <EnumBadge value={record.immutability.lockMode} tones={LOCK_TONE} />,
          },
          {
            label: 'Locked until',
            value: (
              <DateTime
                value={record.immutability.lockUntil}
                mode="absolute"
                emptyLabel="Not locked"
              />
            ),
          },
          {
            label: 'Original SHA-256',
            value: <span className="font-mono text-xs break-all">{record.integrity.sha256}</span>,
          },
          { label: 'Original size', value: formatBytes(record.integrity.sizeBytes) },
          { label: 'Stored (encrypted)', value: formatBytes(record.integrity.storedBytes) },
          {
            label: 'Encryption',
            value: (
              <span className="font-mono text-xs">
                {record.integrity.encryptionFormat} · key version {record.integrity.keyVersion}
              </span>
            ),
          },
        ]}
      />
    </Section>
  );
}

/** A section whose content is loaded only on request (each load is audited). */
function OnDemand({
  label,
  disabled,
  children,
}: {
  label: string;
  disabled?: string | null;
  children: () => ReactNode;
}) {
  const [requested, setRequested] = useState(false);
  if (disabled) return <p className="text-sm text-muted-foreground">{disabled}</p>;
  if (!requested) {
    return (
      <Button
        variant="outline"
        size="sm"
        className="justify-self-start"
        onClick={() => setRequested(true)}
      >
        <FileSearchIcon aria-hidden />
        {label}
      </Button>
    );
  }
  return <>{children()}</>;
}

function JournalSection({
  messageId,
  revealed,
  disposed,
}: {
  messageId: string;
  revealed?: RevealedArchiveValues;
  disposed: boolean;
}) {
  return (
    <Section
      title="Journal"
      description="The journal record written at capture: envelope, a safe subset of headers, attachments and deliveries. Loading it decrypts the record and is audited."
    >
      <OnDemand
        label="Load the journal"
        disabled={disposed ? 'Not available: the record is being disposed.' : null}
      >
        {() => <JournalContent messageId={messageId} revealed={revealed} />}
      </OnDemand>
    </Section>
  );
}

function JournalContent({
  messageId,
  revealed,
}: {
  messageId: string;
  revealed?: RevealedArchiveValues;
}) {
  const journal = useApiQuery(
    'ArchiveMessagesController_journal_v1',
    { path: { messageId } },
    { staleTime: Infinity, gcTime: 0, refetchOnWindowFocus: false, refetchOnMount: false },
  );
  if (journal.isLoading) return <LoadingState label="Decrypting the journal" rows={5} />;
  if (journal.error || !journal.data) {
    return <ArchiveQueryError error={journal.error} onRetry={() => void journal.refetch()} />;
  }
  const j = journal.data;
  return (
    <div className="grid gap-4">
      <DetailList
        items={[
          { label: 'Capture', value: <CopyableId value={j.captureId} /> },
          {
            label: 'Message-ID',
            value: <UntrustedText value={j.message.internetMessageId} mono emptyLabel="None" />,
          },
          {
            label: 'Envelope sender',
            value: <UntrustedText value={j.message.envelopeFrom} emptyLabel="(null sender)" />,
          },
          {
            label: 'Client',
            value: (
              <span className="font-mono text-xs">
                {j.message.clientIp ?? 'Unknown'} · {j.message.clientHelo ?? 'no HELO'}
              </span>
            ),
          },
          {
            label: 'EML SHA-256',
            value: <span className="font-mono text-xs break-all">{j.message.emlSha256}</span>,
          },
          {
            label: 'Parse',
            value: (
              <span className="flex flex-wrap items-center gap-2">
                {j.parse.status ? humanize(j.parse.status) : 'Not parsed'}
                <CodeList codes={j.parse.codes} emptyLabel="" />
              </span>
            ),
          },
          {
            label: 'Body',
            value: j.body.unavailableReason
              ? humanize(j.body.unavailableReason)
              : `${j.body.textAvailable ? 'Text' : ''}${j.body.textAvailable && j.body.htmlAvailable ? ' and ' : ''}${j.body.htmlAvailable ? 'HTML' : ''} part${j.body.truncated ? ' (truncated)' : ''} — shown only through the sanitized preview`,
          },
        ]}
      />
      <div className="grid gap-1">
        <h3 className="text-sm font-semibold">Envelope recipients</h3>
        <ul className="grid gap-1 text-sm">
          {j.envelope.recipients.map((r) => {
            const clear = revealed?.recipients.get(r.seq);
            return (
              <li key={r.seq} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">#{r.seq}</span>
                <SensitiveValue
                  value={clear ?? r.address}
                  masked
                  revealed={clear !== undefined}
                  kind="address"
                />
                <DirectionBadge direction={r.direction} />
                <span className="text-xs text-muted-foreground">{humanize(r.status)}</span>
              </li>
            );
          })}
        </ul>
      </div>
      <div className="grid gap-1">
        <h3 className="text-sm font-semibold">Headers ({j.headers.length})</h3>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]">
          {j.headers.map((header, index) => (
            <div key={`${header.name}-${index}`} className="contents">
              <dt className="font-mono text-xs text-muted-foreground">
                <UntrustedText value={header.name} mono maxLength={64} />
              </dt>
              <dd className="min-w-0">
                <SensitiveValue value={header.value} masked={header.masked} mono maxLength={300} />
              </dd>
            </div>
          ))}
        </dl>
        {revealed && revealed.headers.length > 0 ? (
          <div className="grid gap-1 rounded-md border border-dashed p-2">
            <h4 className="text-xs font-semibold">Revealed To, Cc and Subject values</h4>
            <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]">
              {revealed.headers.map((header, index) => (
                <div key={`${header.name}-${index}`} className="contents">
                  <dt className="font-mono text-xs text-muted-foreground">{header.name}</dt>
                  <dd className="min-w-0">
                    <SensitiveValue value={header.value} masked revealed mono maxLength={300} />
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        ) : null}
      </div>
      <div className="grid gap-1">
        <h3 className="text-sm font-semibold">Attachments ({j.attachments.length})</h3>
        {j.attachments.length === 0 ? (
          <p className="text-sm text-muted-foreground">None</p>
        ) : (
          <ul className="grid gap-1 text-sm">
            {j.attachments.map((a) => (
              <li key={a.partIndex} className="grid gap-0.5 rounded-md border p-2">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-muted-foreground">
                    part {a.partIndex}
                  </span>
                  <UntrustedText value={a.fileName} maxLength={80} emptyLabel="(no filename)" />
                  <span className="text-xs text-muted-foreground">
                    {a.detectedType ?? a.contentType ?? 'unknown type'} · {formatBytes(a.sizeBytes)}
                  </span>
                </span>
                {a.sha256 ? (
                  <span className="font-mono text-xs break-all text-muted-foreground">
                    {a.sha256}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="grid gap-1">
        <h3 className="text-sm font-semibold">Deliveries at capture</h3>
        {j.deliveries.length === 0 ? (
          <p className="text-sm text-muted-foreground">None recorded</p>
        ) : (
          <ul className="grid gap-1 text-sm">
            {j.deliveries.map((d) => (
              <li key={d.seq} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">#{d.seq}</span>
                {humanize(d.status)}
                <DateTime value={d.finalAt} mode="absolute" emptyLabel="not final" />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function SecuritySection({ messageId, disposed }: { messageId: string; disposed: boolean }) {
  return (
    <Section
      title="Security"
      description="The scan results frozen at capture (and later revisions within the outcome window), shown like the live scan details. Nothing is rescanned."
    >
      <OnDemand
        label="Load the security results"
        disabled={disposed ? 'Not available: the record is being disposed.' : null}
      >
        {() => <SecurityContent messageId={messageId} />}
      </OnDemand>
    </Section>
  );
}

function SecurityContent({ messageId }: { messageId: string }) {
  const security = useApiQuery(
    'ArchiveMessagesController_security_v1',
    { path: { messageId } },
    { staleTime: Infinity, gcTime: 0, refetchOnWindowFocus: false, refetchOnMount: false },
  );
  if (security.isLoading) return <LoadingState label="Decrypting the scan snapshots" rows={5} />;
  if (security.error || !security.data) {
    return <ArchiveQueryError error={security.error} onRetry={() => void security.refetch()} />;
  }
  return (
    <div className="grid gap-3">
      {security.data.rounds.length === 0 ? (
        <p className="text-sm text-muted-foreground">No scan round was linked at capture.</p>
      ) : (
        security.data.rounds.map((r) => (
          <div key={`${r.round}-${r.revision}`} className="grid gap-1">
            <p className="text-xs text-muted-foreground">
              Snapshot of round {r.round}, revision {r.revision}, frozen{' '}
              <DateTime value={r.frozenAt} mode="absolute" />
            </p>
            <RoundCard
              round={r.scan as unknown as ScanRound}
              messageId={messageId}
              showLinks={false}
            />
          </div>
        ))
      )}
      <p className="text-xs text-muted-foreground">
        DLP evidence has its own retention and is not archived; masked DLP findings are listed with
        the engines.
      </p>
    </div>
  );
}

function PreviewSection({
  messageId,
  access,
  record,
}: {
  messageId: string;
  access: ArchiveAccess;
  record: ArchiveDetail;
}) {
  const blocker =
    record.status === 'disposing'
      ? 'Not available: the record is being disposed.'
      : contentBlocker(access);
  return (
    <Section
      title="Sanitized preview"
      description="Text only, produced and sanitized by the platform from the archived original. Opening it is audited and rate limited."
    >
      <OnDemand label="Show sanitized preview" disabled={blocker}>
        {() => <PreviewLoaded messageId={messageId} />}
      </OnDemand>
    </Section>
  );
}

function PreviewLoaded({ messageId }: { messageId: string }) {
  const preview = useApiQuery(
    'ArchiveMessagesController_preview_v1',
    { path: { messageId } },
    {
      staleTime: Infinity,
      gcTime: 0,
      refetchOnWindowFocus: false,
      refetchOnMount: false,
      refetchOnReconnect: false,
    },
  );
  const error = preview.error;
  const seconds = useCountdown(
    error instanceof ApiError && error.status === 429 ? (error.retryAfterSeconds ?? 60) : 0,
    error,
  );
  if (preview.isLoading) return <LoadingState label="Loading the preview" rows={6} />;
  if (error instanceof ApiError && error.status === 429) {
    return <RateLimited seconds={seconds} what="previews" />;
  }
  if (error || !preview.data) {
    return <ArchiveQueryError error={error} onRetry={() => void preview.refetch()} />;
  }
  return <PreviewContent preview={preview.data} />;
}

function DownloadSection({
  record,
  access,
  onDownload,
}: {
  record: ArchiveDetail;
  access: ArchiveAccess;
  onDownload: () => void;
}) {
  const settings = useApiQuery('ArchiveAdminController_get_v1', undefined, {
    enabled: access.read,
  });
  const disabledBySettings = settings.data ? !settings.data.settings.access.downloadEnabled : false;
  const blocker =
    record.status === 'disposing'
      ? 'Not available: the record is being disposed.'
      : record.malicious
        ? 'This message was classified as malicious: it cannot be downloaded interactively. An eDiscovery export includes it under malicious/ with a warning, after an explicit acknowledgement.'
        : disabledBySettings
          ? 'Downloads of archived originals are turned off in your organization’s archive settings.'
          : contentBlocker(access);
  return (
    <Section
      title="Original message"
      description="The original (.eml) as received, decrypted and verified against its SHA-256 while it streams."
    >
      {blocker ? (
        <p className="flex items-start gap-2 text-sm text-muted-foreground">
          <ShieldAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          {blocker}
        </p>
      ) : (
        <Button variant="outline" size="sm" className="justify-self-start" onClick={onDownload}>
          <DownloadIcon aria-hidden />
          Download original
        </Button>
      )}
    </Section>
  );
}

function DisposeDialog({
  messageId,
  open,
  onOpenChange,
}: {
  messageId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const dispose = useApiMutation('ArchiveMessagesController_dispose_v1', {
    successMessage: 'Disposal requested',
    invalidates: ['ArchiveMessagesController_detail_v1', 'ArchiveMessagesController_list_v1'],
  });
  return (
    <ReasonDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Dispose this archived message?"
      description={
        <p>
          The record’s retention has ended and it was kept for review. Disposal crypto-shreds it at
          once (no copy can be decrypted any more), then deletes every object version, replica copy,
          index document and the row. Legal holds are checked again first. This cannot be undone; it
          needs a session signed in with MFA.
        </p>
      }
      confirmLabel="Dispose"
      destructive
      maxChars={4096}
      pending={dispose.isPending}
      onSubmit={(reason) => dispose.submit({ path: { messageId }, body: { reason } })}
      onRetry={() => dispose.retry()}
    />
  );
}
