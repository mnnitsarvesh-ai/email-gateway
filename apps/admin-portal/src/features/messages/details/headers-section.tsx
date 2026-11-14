'use client';

import { SensitiveValue, UntrustedText } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { Section } from '../controls';
import { DataGrid, QueryBoundary } from './parts';
import { useRevealed } from './use-message-reveal';

export type HeadersBody = SuccessBody<'MessageHeadersController_headers_v1'>;
type HeaderRow = HeadersBody['headers'][number];

const AVAILABILITY_TEXT: Record<Exclude<HeadersBody['availability'], 'available'>, string> = {
  not_parsed:
    'No headers are available: the message has not been parsed yet, or its MIME parse failed, so no header rows were stored.',
  none_stored:
    'The message was parsed, but none of the stored headers (the allow-list below) is present in it.',
  retention_expired:
    'Stored headers are kept for 3 months; the headers of this message have been removed by retention.',
};

export const FULL_HEADER_STATEMENT =
  'Only an allow-list of headers is stored (decoded, at most 2 048 characters each). The full header block stays in the stored message in object storage and is never fetched or shown here.';

/** `GET /messages/{id}/headers` (shared by the headers and authentication sections). */
export function useMessageHeaders(messageId: string) {
  return useApiQuery('MessageHeadersController_headers_v1', { path: { messageId } });
}

/** A header value: safe subset in clear, To/Cc/Subject masked unless revealed (by `seq`). */
export function HeaderValue({ header }: { header: HeaderRow }) {
  const { values } = useRevealed();
  const revealed = header.masked ? values?.headers.get(header.seq) : undefined;
  if (!header.masked) {
    return <UntrustedText value={header.value} mono maxLength={300} emptyLabel="(empty)" />;
  }
  return (
    <SensitiveValue
      value={revealed ? revealed.value : null}
      masked
      revealed={Boolean(revealed)}
      mono
      maxLength={300}
      emptyLabel="(empty)"
    />
  );
}

/** Section 3: email headers (`MessageHeadersController_headers`, ADR-0062 safe subset). */
export function HeadersSection({ messageId }: { messageId: string }) {
  const query = useMessageHeaders(messageId);
  const canReveal = useCan('MessageRevealController_reveal_v1');
  return (
    <Section
      title="Email headers"
      description="Header values are text written by the sender; they are shown as text only."
    >
      <p className="text-xs text-muted-foreground">{FULL_HEADER_STATEMENT}</p>
      <QueryBoundary query={query} label="Loading headers" rows={6}>
        {() => {
          const body = query.data;
          if (!body) return null;
          const maskedCount = body.headers.filter((h) => h.masked).length;
          return (
            <div className="grid gap-3">
              {body.availability === 'available' ? (
                body.headers.length === 0 ? (
                  <EmptyState
                    title="No header rows"
                    description="No stored header row was returned."
                  />
                ) : (
                  <>
                    {maskedCount > 0 ? (
                      <p className="text-xs text-muted-foreground">
                        {maskedCount} value{maskedCount === 1 ? ' is' : 's are'} masked (To, Cc,
                        Subject and any header outside the safe subset).{' '}
                        {canReveal
                          ? 'Reveal at the top of the page shows To, Cc and Subject; the reveal is recorded in the audit log.'
                          : 'Revealing them needs the message:reveal permission.'}
                      </p>
                    ) : null}
                    <DataGrid
                      caption="Stored headers"
                      rows={body.headers}
                      rowKey={(row) => String(row.seq)}
                      columns={[
                        {
                          header: '#',
                          cell: (row) => row.seq,
                          className: 'tabular-nums text-xs',
                        },
                        {
                          header: 'Name',
                          cell: (row) => <span className="font-mono text-xs">{row.name}</span>,
                          rowHeader: true,
                        },
                        {
                          header: 'Value',
                          cell: (row) => <HeaderValue header={row} />,
                          className: 'max-w-[36rem]',
                        },
                      ]}
                    />
                  </>
                )
              ) : (
                <p role="status" className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
                  {AVAILABILITY_TEXT[body.availability]}
                </p>
              )}
              <dl className="grid gap-1 text-xs text-muted-foreground sm:grid-cols-[minmax(10rem,auto)_1fr]">
                <dt>Stored headers (allow-list)</dt>
                <dd className="font-mono">{body.storedHeaderNames.join(', ') || 'None'}</dd>
                <dt>Shown in clear (safe subset)</dt>
                <dd className="font-mono">{body.safeHeaderNames.join(', ') || 'None'}</dd>
              </dl>
            </div>
          );
        }}
      </QueryBoundary>
    </Section>
  );
}
