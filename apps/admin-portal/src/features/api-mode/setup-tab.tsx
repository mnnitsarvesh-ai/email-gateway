'use client';

import { DownloadIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useState } from 'react';
import { z } from 'zod';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useUrlState } from '@/hooks/use-url-state';
import { api, unwrap } from '@/lib/api/client';
import type { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { MutationError, QueryView, Section } from '@/features/domains/kit';
import { GuideStepView } from '@/features/integrations/providers/guide-tab';
import { PROVIDER_LABEL } from '@/features/integrations/providers/model';
import { grantHref } from './coverage-tab';
import {
  ApiModeHealthBadge,
  ApiModeWizardBadge,
  WIZARD_STEP_LABEL,
  checkTitle,
  wizardCodeText,
  type ApiModeConnection,
  type ApiModeConnectionDetail,
  type ApiModeGuide,
} from './model';

const URL_SHAPE = { connection: z.string().uuid().optional().catch(undefined) };

const CHECK_TONE = { pass: 'success', warn: 'warning', fail: 'danger' } as const;

/** `api-mode-<provider>-<slug>.md` when the response names no file. */
export function apiModeGuideFileName(
  connection: Pick<ApiModeConnection, 'provider' | 'displayName'>,
): string {
  const slug =
    connection.displayName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'connection';
  return `api-mode-${connection.provider.replace('_', '-')}-${slug}.md`;
}

/** GET …/setup-guide?format=markdown through the BFF, saved as a file (never stored). */
export async function downloadApiModeGuide(connection: ApiModeConnection): Promise<void> {
  let disposition: string | null = null;
  const text = await unwrap(
    api
      .GET('/api/v1/api-mode/connections/{connectionId}/setup-guide', {
        params: { path: { connectionId: connection.id }, query: { format: 'markdown' } },
        parseAs: 'text',
      })
      .then((result) => {
        disposition = result.response.headers.get('content-disposition');
        return result;
      }),
    'ApiModeController_setupGuide_v1',
  );
  const blob = new Blob([String(text)], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  const match = (disposition as string | null)?.match(/filename="?([A-Za-z0-9._-]+)"?/);
  link.download = match?.[1] ?? apiModeGuideFileName(connection);
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function WizardSection({
  connection,
  detail,
}: {
  connection: ApiModeConnection;
  detail: ApiModeConnectionDetail;
}) {
  const next = detail.wizard.nextAction;
  return (
    <Section
      title="Setup steps"
      description={
        next
          ? `Next: ${WIZARD_STEP_LABEL[next.step]} — ${wizardCodeText(next.action)}`
          : 'Every step is done.'
      }
    >
      <ol className="grid gap-2" aria-label="API-mode setup steps">
        {detail.wizard.steps.map((step) => (
          <li
            key={step.step}
            className="grid gap-1 rounded-md border p-3 text-sm sm:grid-cols-[minmax(14rem,auto)_auto_1fr] sm:items-start sm:gap-3"
          >
            <span className="font-medium">{WIZARD_STEP_LABEL[step.step]}</span>
            <ApiModeWizardBadge status={step.status} />
            <span className="text-muted-foreground">
              {step.blockers.map(wizardCodeText).join(' · ')}
            </span>
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-3 text-sm">
        <Link
          href={`/integrations/providers/${connection.id}`}
          className="text-primary underline underline-offset-2"
        >
          Open the provider connection
        </Link>
        <Link href={grantHref(connection.id)} className="text-primary underline underline-offset-2">
          Mailbox access grant
        </Link>
        <Link href="/settings?tab=journaling" className="text-primary underline underline-offset-2">
          Journal intake sources
        </Link>
      </div>
    </Section>
  );
}

function HealthSection({ detail }: { detail: ApiModeConnectionDetail }) {
  return (
    <Section
      title="Health checks"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <ApiModeHealthBadge health={detail.health.status} />
          {detail.health.changedAt ? (
            <span>
              since <DateTime value={detail.health.changedAt} />
            </span>
          ) : null}
        </span>
      }
    >
      {detail.healthChecks.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          The checks run every minute once the connection is used for API mode.
        </p>
      ) : (
        <ul className="grid gap-2">
          {detail.healthChecks.map((check) => (
            <li
              key={check.code}
              className="grid gap-1 rounded-md border p-3 text-sm sm:grid-cols-[minmax(14rem,auto)_auto_1fr] sm:items-start sm:gap-3"
            >
              <span className="font-medium">{checkTitle(check.code)}</span>
              <ToneBadge tone={CHECK_TONE[check.status]}>{check.status}</ToneBadge>
              <span className="text-muted-foreground">{check.evidence ?? ''}</span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function GuideSection({
  connection,
  guide,
}: {
  connection: ApiModeConnection;
  guide: ApiModeGuide;
}) {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <Section
      title={`Setup guide for ${PROVIDER_LABEL[guide.provider]}`}
      description={
        <span>
          Written for this connection; generated <DateTime value={guide.generatedAt} />.
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
            downloadApiModeGuide(connection)
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
      {guide.permissions.length > 0 ? (
        <div className="grid gap-1 text-sm">
          <p className="text-xs font-medium text-muted-foreground">Permissions of mailbox access</p>
          <ul className="list-disc pl-5 font-mono text-xs break-all">
            {guide.permissions.map((permission) => (
              <li key={permission}>{permission}</li>
            ))}
          </ul>
        </div>
      ) : null}
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
                <GuideStepView key={step.id} step={step} />
              ))}
            </ol>
          ) : null}
        </section>
      ))}
    </Section>
  );
}

function ConnectionSetup({ connection }: { connection: ApiModeConnection }) {
  const detail = useApiQuery('ApiModeController_getConnection_v1', {
    path: { connectionId: connection.id },
  });
  const guide = useApiQuery('ApiModeController_setupGuide_v1', {
    path: { connectionId: connection.id },
    query: { format: 'json' },
  });
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <QueryView query={detail} label="setup steps" notFound="inline">
        {(data) => (
          <>
            <WizardSection connection={connection} detail={data} />
            <HealthSection detail={data} />
          </>
        )}
      </QueryView>
      <QueryView query={guide} label="setup guide" notFound="inline">
        {(data) => <GuideSection connection={connection} guide={data} />}
      </QueryView>
    </div>
  );
}

/** Tab "Setup" (D14): per-connection wizard steps, health checks and the generated guide. */
export function SetupTab() {
  const selectId = useId();
  const [state, setState] = useUrlState(URL_SHAPE);
  const connections = useApiQuery('ApiModeController_listConnections_v1');
  return (
    <QueryView query={connections} label="connections" notFound="inline">
      {(data) => {
        if (data.data.length === 0) {
          return (
            <EmptyState
              title="No provider connection"
              description="API mode uses a Microsoft 365 or Google Workspace connection: connect one under Integrations first."
              action={
                <Button asChild size="sm" variant="outline">
                  <Link href="/integrations">Open integrations</Link>
                </Button>
              }
            />
          );
        }
        const selected = data.data.find((c) => c.id === state.connection) ?? data.data[0]!;
        return (
          <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
            <div className="grid max-w-sm gap-2">
              <Label htmlFor={selectId}>Connection</Label>
              <Select value={selected.id} onValueChange={(connection) => setState({ connection })}>
                <SelectTrigger id={selectId} className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {data.data.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.displayName} ({PROVIDER_LABEL[c.provider]})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <ConnectionSetup key={selected.id} connection={selected} />
          </div>
        );
      }}
    </QueryView>
  );
}
