'use client';

import { DownloadIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { Button } from '@/components/ui/button';
import { api, unwrap } from '@/lib/api/client';
import type { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { MutationError, QueryView, Section } from '@/features/domains/kit';
import { PROVIDER_LABEL, type Connection, type SetupGuide } from './model';

type GuideStep = SetupGuide['sections'][number]['steps'][number];

/** `setup-<provider>-<slug>.md`, the api's download name (D14) when no header names one. */
export function guideFileName(connection: Pick<Connection, 'provider' | 'displayName'>): string {
  const slug =
    connection.displayName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'connection';
  return `setup-${connection.provider.replace('_', '-')}-${slug}.md`;
}

function fileNameFrom(disposition: string | null): string | null {
  const match = disposition?.match(/filename="?([A-Za-z0-9._-]+)"?/);
  return match?.[1] ?? null;
}

/** GET …/setup-guide?format=markdown through the BFF, saved as a file (never stored). */
export async function downloadGuideMarkdown(connection: Connection): Promise<void> {
  let disposition: string | null = null;
  const text = await unwrap(
    api
      .GET('/api/v1/provider-connections/{id}/setup-guide', {
        params: { path: { id: connection.id }, query: { format: 'markdown' } },
        parseAs: 'text',
      })
      .then((result) => {
        disposition = result.response.headers.get('content-disposition');
        return result;
      }),
    'ProviderGuideController_get_v1',
  );
  const blob = new Blob([String(text)], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileNameFrom(disposition) ?? guideFileName(connection);
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function Step({ step }: { step: GuideStep }) {
  return (
    <li id={step.id} className="grid scroll-mt-20 gap-2 rounded-md border p-3">
      <h4 className="font-medium">{step.title}</h4>
      {step.paragraphs.map((p) => (
        <p key={p} className="text-sm">
          {p}
        </p>
      ))}
      {step.values?.length ? (
        <dl className="grid gap-1 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]">
          {step.values.map((v) => (
            <div key={`${v.label}:${v.value}`} className="contents">
              <dt className="text-xs font-medium text-muted-foreground sm:pt-1">{v.label}</dt>
              <dd className="inline-flex min-w-0 items-center gap-1 font-mono text-xs break-all">
                {v.value}
                <CopyButton value={v.value} label={`Copy ${v.label}`} />
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
      {step.commands?.map((c) => (
        <div key={c.code} className="relative min-w-0">
          {/* Focusable: long commands scroll horizontally and must be reachable by keyboard
              (axe scrollable-region-focusable, WCAG 2.1.1). */}
          <pre
            // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scrollable region
            tabIndex={0}
            className="overflow-x-auto rounded-md bg-muted p-3 pr-10 font-mono text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            aria-label={`${c.language} commands`}
          >
            <code>{c.code}</code>
          </pre>
          <CopyButton
            value={c.code}
            label={`Copy the ${c.language === 'powershell' ? 'PowerShell' : c.language} commands of “${step.title}”`}
            className="absolute top-1 right-1"
          />
        </div>
      ))}
      {step.warning ? (
        <p className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground">
          {step.warning}
        </p>
      ) : null}
      {step.attestation ? (
        <p className="flex flex-wrap items-center gap-2 text-xs">
          {step.attestation.attested ? (
            <>
              <ToneBadge tone="success">Stated</ToneBadge>
              <span>
                {step.attestation.statement} (your statement, not a gateway check,{' '}
                <DateTime value={step.attestation.attestedAt} />)
              </span>
            </>
          ) : (
            <>
              <ToneBadge tone="neutral">Not stated yet</ToneBadge>
              <span>{step.attestation.statement} Confirm it in the Setup tab when done.</span>
            </>
          )}
        </p>
      ) : null}
    </li>
  );
}

function GuideView({ connection, guide }: { connection: Connection; guide: SetupGuide }) {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  useEffect(() => {
    // Remediation links land on `?tab=guide#anchor`: scroll once the guide is rendered.
    const id = window.location.hash.slice(1);
    if (id) document.getElementById(id)?.scrollIntoView?.({ block: 'start' });
  }, []);
  return (
    <Section
      title={`Setup guide for ${PROVIDER_LABEL[guide.provider]}`}
      description={
        <span>
          Written for this connection and its domains; generated{' '}
          <DateTime value={guide.generatedAt} />.
        </span>
      }
      actions={
        <Button
          variant="outline"
          size="sm"
          disabled={downloading}
          onClick={() => {
            setDownloading(true);
            setError(null);
            downloadGuideMarkdown(connection)
              .catch((e: unknown) => setError(e as ApiError))
              .finally(() => setDownloading(false));
          }}
        >
          <DownloadIcon aria-hidden />
          Download Markdown
        </Button>
      }
    >
      <MutationError error={error} />
      <p className="text-sm">{guide.notice}</p>
      <nav aria-label="Guide sections">
        <ol className="grid list-decimal gap-1 pl-5 text-sm">
          {guide.sections.map((s) => (
            <li key={s.id}>
              <a href={`#${s.id}`} className="underline-offset-4 hover:underline">
                {s.title}
              </a>
            </li>
          ))}
        </ol>
      </nav>
      {guide.sections.map((section) => (
        <section
          key={section.id}
          id={section.id}
          aria-labelledby={`${section.id}-title`}
          className="grid scroll-mt-20 gap-3"
        >
          <h3 id={`${section.id}-title`} className="text-base font-semibold">
            {section.number}. {section.title}
          </h3>
          {section.paragraphs.map((p) => (
            <p key={p} className="text-sm">
              {p}
            </p>
          ))}
          {section.steps.length > 0 ? (
            <ol className="grid gap-3">
              {section.steps.map((step) => (
                <Step key={step.id} step={step} />
              ))}
            </ol>
          ) : null}
        </section>
      ))}
    </Section>
  );
}

/** Tab "Setup guide" (D14): the customer-specific guide with copyable values and commands. */
export function GuideTab({ connection }: { connection: Connection }) {
  const guide = useApiQuery('ProviderGuideController_get_v1', {
    path: { id: connection.id },
    query: { format: 'json' },
  });
  return (
    <QueryView query={guide} label="setup guide" notFound="inline">
      {(data) => <GuideView connection={connection} guide={data} />}
    </QueryView>
  );
}
