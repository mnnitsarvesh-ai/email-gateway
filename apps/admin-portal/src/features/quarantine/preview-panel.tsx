'use client';

import { EyeIcon, ShieldIcon } from 'lucide-react';
import { useState } from 'react';
import { UntrustedText } from '@/components/domain';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { formatBytes, formatNumber, humanize } from '@/lib/format';
import { CodeList, Section } from '@/features/messages/controls';
import { explainQuarantineError } from './reason-confirm';
import type { PreviewBody } from './types';

const UNAVAILABLE: Record<string, string> = {
  not_parsed: 'The message could not be parsed, so no body text is available.',
  too_large: 'The body is too large for a preview.',
  no_text_part: 'The message has no text or HTML part.',
  purged: 'The message content has been deleted.',
};

/**
 * The only message text the portal shows (design P12): the 5.3 sanitized preview, rendered as
 * React text in a pre-wrap block. Never HTML, never an iframe, never a blob or data URL.
 */
export function PreviewText({ text }: { text: string }) {
  return (
    <pre
      className="rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap"
      data-testid="preview-text"
      aria-label="Sanitized message text"
    >
      {text}
    </pre>
  );
}

export function PreviewContent({ preview }: { preview: PreviewBody }) {
  return (
    <div className="grid gap-4">
      <p className="flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
        <ShieldIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          Sanitized by the platform ({preview.version}): HTML is converted to text; scripts, styles,
          forms and media are removed; links are defanged and listed separately, never clickable;
          control and bidirectional characters are removed
          {preview.dlp.masked > 0
            ? `; ${formatNumber(preview.dlp.masked)} sensitive value${preview.dlp.masked === 1 ? '' : 's'} masked (${preview.dlp.categories.map(humanize).join(', ')})`
            : '; no sensitive values needed masking'}
          . Viewing the preview is recorded in the audit log.
        </span>
      </p>
      <div className="grid gap-1">
        <h3 className="text-xs font-medium text-muted-foreground">Subject</h3>
        <UntrustedText value={preview.subject} maxLength={1024} emptyLabel="(no subject)" />
      </div>
      {preview.headers.length > 0 ? (
        <details className="rounded-md border p-3 text-sm">
          <summary className="cursor-pointer font-medium">
            Headers ({preview.headers.length})
          </summary>
          <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[minmax(8rem,auto)_1fr]">
            {preview.headers.map((header, index) => (
              <div key={`${header.name}-${index}`} className="contents">
                <dt className="font-mono text-xs text-muted-foreground">{header.name}</dt>
                <dd className="min-w-0">
                  <UntrustedText value={header.value} mono maxLength={300} />
                </dd>
              </div>
            ))}
          </dl>
        </details>
      ) : null}
      <div className="grid gap-1">
        <h3 className="text-xs font-medium text-muted-foreground">
          Body text{preview.body.source ? ` (from the ${preview.body.source} part)` : ''}
        </h3>
        {preview.body.unavailableReason ? (
          <p className="text-sm text-muted-foreground">
            {UNAVAILABLE[preview.body.unavailableReason] ??
              humanize(preview.body.unavailableReason)}
          </p>
        ) : (
          <PreviewText text={preview.body.text} />
        )}
        {preview.body.truncated ? (
          <p className="text-xs text-muted-foreground">The text was truncated for the preview.</p>
        ) : null}
      </div>
      {preview.links.length > 0 ? (
        <div className="grid gap-1">
          <h3 className="text-xs font-medium text-muted-foreground">
            Links (defanged, not clickable)
            {preview.linksTruncated ? ' — list truncated' : ''}
          </h3>
          <ol className="grid gap-1 text-sm">
            {preview.links.map((link) => (
              <li key={link.n} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">[link {link.n}]</span>
                <UntrustedText
                  value={link.displayUrl}
                  mono
                  maxLength={120}
                  copy
                  copyLabel={`Copy link ${link.n}`}
                />
                {link.verdict ? <span className="text-xs">{humanize(link.verdict)}</span> : null}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      {preview.attachments.length > 0 ? (
        <div className="grid gap-1">
          <h3 className="text-xs font-medium text-muted-foreground">
            Attachments (listed, never opened)
          </h3>
          <ul className="grid gap-2 text-sm">
            {preview.attachments.map((attachment) => (
              <li key={attachment.partIndex} className="grid gap-0.5 rounded-md border p-2">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-muted-foreground">
                    part {attachment.partIndex}
                  </span>
                  <UntrustedText
                    value={attachment.filename}
                    maxLength={80}
                    emptyLabel="(no filename)"
                  />
                  <span className="text-xs text-muted-foreground">
                    {formatBytes(attachment.sizeBytes)}
                  </span>
                  {attachment.verdict ? (
                    <span className="text-xs">{humanize(attachment.verdict)}</span>
                  ) : null}
                  <span className="text-xs text-muted-foreground">
                    {attachment.downloadable ? 'Downloadable' : 'Not downloadable'}
                  </span>
                </span>
                <CodeList codes={attachment.reasonCodes} emptyLabel="" />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

/** The preview section: loaded on demand (each preview is audited and rate limited). */
export function PreviewSection({ entryId, self = false }: { entryId: string; self?: boolean }) {
  const [requested, setRequested] = useState(false);
  const operator = useApiQuery(
    'QuarantineEntriesController_preview_v1',
    { path: { entryId } },
    { enabled: requested && !self, staleTime: Infinity, refetchOnWindowFocus: false },
  );
  const own = useApiQuery(
    'QuarantineSelfController_preview_v1',
    { path: { entryId } },
    { enabled: requested && self, staleTime: Infinity, refetchOnWindowFocus: false },
  );
  const query = self ? own : operator;
  return (
    <Section
      title="Sanitized preview"
      description="Text only, produced and sanitized by the platform. Opening it is audited."
    >
      {!requested ? (
        <Button
          variant="outline"
          size="sm"
          className="justify-self-start"
          onClick={() => setRequested(true)}
        >
          <EyeIcon aria-hidden />
          Show sanitized preview
        </Button>
      ) : query.isLoading ? (
        <LoadingState label="Loading the preview" rows={6} />
      ) : query.error ? (
        <div className="grid gap-2">
          {query.error instanceof ApiError && query.error.status !== 404 ? (
            <p className="text-sm">{explainQuarantineError(query.error).join(' ')}</p>
          ) : null}
          <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
        </div>
      ) : query.data ? (
        <PreviewContent preview={query.data} />
      ) : null}
    </Section>
  );
}
