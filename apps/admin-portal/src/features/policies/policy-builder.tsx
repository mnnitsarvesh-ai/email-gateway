'use client';

import { SearchIcon } from 'lucide-react';
import { useId, useMemo } from 'react';
import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, FilterSelect, Section, YesNo } from '@/features/messages/controls';

type Catalog = SuccessBody<'PolicyToolsController_catalog_v1'>;
type Field = Catalog['fields'][number];

const SCOPES = ['message', 'recipients', 'attachments', 'urls'] as const;
const URL_SHAPE = {
  q: z.string().max(100).optional().catch(undefined),
  scope: z.enum(SCOPES).optional().catch(undefined),
};

export function filterFields(
  fields: readonly Field[],
  q: string | undefined,
  scope: string | undefined,
): Field[] {
  const needle = q?.trim().toLowerCase();
  return fields.filter(
    (field) =>
      (!scope || field.scope === scope) &&
      (!needle ||
        field.name.toLowerCase().includes(needle) ||
        field.description.toLowerCase().includes(needle) ||
        field.type.includes(needle) ||
        field.ops.some((op) => op.includes(needle))),
  );
}

/** Policy builder (`/policies/builder`, §1.3 row 14): the DSL catalogue as a searchable reference. */
export function PolicyBuilder() {
  return (
    <RouteGate gate={['PolicyToolsController_catalog_v1']}>
      <PolicyBuilderContent />
    </RouteGate>
  );
}

function PolicyBuilderContent() {
  const catalog = useApiQuery('PolicyToolsController_catalog_v1', undefined, {
    staleTime: 300_000,
  });
  const [state, setState] = useUrlState(URL_SHAPE);
  const searchId = useId();
  const fields = useMemo(
    () => filterFields(catalog.data?.fields ?? [], state.q, state.scope),
    [catalog.data, state.q, state.scope],
  );
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Policy builder"
        breadcrumbs={[
          { label: 'Policy management', href: '/policies' },
          { label: 'Policy builder' },
        ]}
        description="The policy DSL catalogue of this deployment: fields, operators, actions and limits."
      />
      <UnavailableState
        step="7.3"
        title="Visual policy builder"
        description="The visual policy builder, test and dry-run arrive in step 7.3. Until then this page is a read-only reference of the DSL."
      />
      {catalog.isLoading ? (
        <LoadingState label="Loading the DSL catalogue" rows={10} />
      ) : catalog.error || !catalog.data ? (
        <ErrorState error={catalog.error} onRetry={() => void catalog.refetch()} />
      ) : (
        <>
          <Section title="Versions">
            <DetailList
              items={[
                {
                  label: 'DSL',
                  value: <span className="font-mono text-xs">{catalog.data.versions.dsl}</span>,
                },
                {
                  label: 'Input',
                  value: <span className="font-mono text-xs">{catalog.data.versions.input}</span>,
                },
                {
                  label: 'Evaluator',
                  value: (
                    <span className="font-mono text-xs">{catalog.data.versions.evaluator}</span>
                  ),
                },
                {
                  label: 'Platform default',
                  value: (
                    <span>
                      <span className="font-mono text-xs">{catalog.data.platformDefault.id}</span> —{' '}
                      {catalog.data.platformDefault.description}
                    </span>
                  ),
                },
                { label: 'Enforcement', value: catalog.data.enforcement },
              ]}
            />
          </Section>
          <Section
            title={`Fields (${formatNumber(fields.length)} of ${formatNumber(catalog.data.fields.length)})`}
            description="What a rule condition can test. Quantified fields are evaluated for each recipient, attachment or URL."
          >
            <div className="flex flex-wrap items-end gap-2">
              <div className="grid gap-1">
                <Label htmlFor={searchId} className="text-xs text-muted-foreground">
                  Search fields
                </Label>
                <div className="relative">
                  <SearchIcon
                    className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
                    aria-hidden
                  />
                  <Input
                    id={searchId}
                    type="search"
                    className="h-8 min-w-64 pl-8"
                    value={state.q ?? ''}
                    onChange={(event) => setState({ q: event.target.value || undefined })}
                    placeholder="Name, description, type or operator"
                  />
                </div>
              </div>
              <FilterSelect
                label="Scope"
                value={state.scope}
                options={SCOPES.map((scope) => ({ value: scope, label: humanize(scope) }))}
                onChange={(scope) => setState({ scope: scope as typeof state.scope })}
              />
            </div>
            {fields.length === 0 ? (
              <EmptyState
                icon={SearchIcon}
                title="No field matches"
                description="Try another word or scope."
              />
            ) : (
              <ul className="grid gap-2" aria-label="DSL fields">
                {fields.map((field) => (
                  <li key={field.name} className="grid gap-1 rounded-md border p-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold">{field.name}</span>
                      <span className="rounded-sm bg-muted px-1.5 py-0.5 text-xs">
                        {field.type}
                      </span>
                      <span className="text-xs text-muted-foreground">{humanize(field.scope)}</span>
                      {field.aiDerived ? (
                        <span className="text-xs text-muted-foreground">AI-derived</span>
                      ) : null}
                      {field.senderIdentity ? (
                        <span className="text-xs text-muted-foreground">
                          sender identity: {field.senderIdentity}
                        </span>
                      ) : null}
                    </div>
                    <p>{field.description}</p>
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-muted-foreground">Operators</span>
                      <CodeList codes={field.ops} />
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      <span>Directions: {field.directions.map(humanize).join(', ')}</span>
                      {field.min !== null || field.max !== null ? (
                        <span>
                          Range: {field.min ?? '…'} to {field.max ?? '…'}
                        </span>
                      ) : null}
                      <span>
                        Quantified: <YesNo value={field.quantified} />
                      </span>
                    </div>
                    {field.values && field.values.length > 0 ? (
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="text-muted-foreground">
                          Values{field.ordered ? ' (ordered)' : ''}
                        </span>
                        <CodeList codes={field.values} />
                      </div>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section
            title="Operators"
            description="The catalogue does not describe operators; the field types that use each one are listed."
          >
            <ul className="grid gap-1 text-sm sm:grid-cols-2" aria-label="DSL operators">
              {catalog.data.operators.map((op) => {
                const types = [
                  ...new Set(
                    catalog.data.fields.filter((f) => f.ops.includes(op)).map((f) => f.type),
                  ),
                ];
                return (
                  <li key={op} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-semibold">{op}</span>
                    <span className="text-xs text-muted-foreground">
                      {types.length > 0 ? `on ${types.join(', ')}` : 'not used by any field'}
                    </span>
                  </li>
                );
              })}
            </ul>
          </Section>
          <Section title="Actions and dispositions">
            <DetailList
              items={[
                {
                  label: 'Actions',
                  value: (
                    <ul className="grid gap-1" aria-label="DSL actions">
                      {catalog.data.actions.map((action) => (
                        <li key={action} className="flex flex-wrap items-center gap-2 text-sm">
                          <span className="font-mono text-xs font-semibold">{action}</span>
                          <span className="text-xs text-muted-foreground">
                            {catalog.data.nonTerminalActions.includes(action as never)
                              ? 'Non-terminal (combines with a decision)'
                              : 'Terminal (decides the disposition)'}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ),
                },
                { label: 'Dispositions', value: <CodeList codes={catalog.data.dispositions} /> },
                {
                  label: 'Limits',
                  value: (
                    <ul className="grid gap-0.5 text-xs" aria-label="DSL limits">
                      {Object.entries(catalog.data.limits).map(([name, value]) => (
                        <li key={name}>
                          <span className="font-mono">{name}</span>: {formatNumber(value)}
                        </li>
                      ))}
                    </ul>
                  ),
                },
                {
                  label: 'Settings defaults',
                  value: (
                    <span className="text-xs">
                      overrides{' '}
                      {catalog.data.settingsDefaults.allowRecommendationOverrides
                        ? 'allowed'
                        : 'not allowed'}
                      , alerts {catalog.data.settingsDefaults.alerts.enabled ? 'on' : 'off'}, sender
                      notices{' '}
                      {catalog.data.settingsDefaults.notices.senderNonDelivery ? 'on' : 'off'}
                    </span>
                  ),
                },
              ]}
            />
          </Section>
        </>
      )}
    </div>
  );
}
