'use client';

import {
  BookOpenIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  FlaskConicalIcon,
  HistoryIcon,
  PlusIcon,
  SearchIcon,
} from 'lucide-react';
import Link from 'next/link';
import { useId, useMemo, useState } from 'react';
import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useUrlState } from '@/hooks/use-url-state';
import type { SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, FilterSelect, Section, YesNo } from '@/features/messages/controls';
import type { BuilderCatalog } from './builder';
import { CatalogGate } from './catalog-state';
import { NEW_POLICY_HREF } from './links';
import { PolicyDryRunPanel, useDryRunPanelState } from './panels/dry-run-panel';
import { PolicyTestPanel, useTestPanelState } from './panels/test-panel';
import { ACTIVE_TARGET, PLATFORM_TARGET } from './panels/targets';
import { useBuilderCatalog } from './use-builder-catalog';

type Catalog = SuccessBody<'PolicyToolsController_catalog_v1'>;
type Field = Catalog['fields'][number];

const SCOPES = ['message', 'recipients', 'attachments', 'urls'] as const;
const URL_SHAPE = {
  q: z.string().max(100).optional().catch(undefined),
  scope: z.enum(SCOPES).optional().catch(undefined),
};

/** Catalogue fields matching a search text (name, label, description, type, operator) and scope. */
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
        field.label.toLowerCase().includes(needle) ||
        field.description.toLowerCase().includes(needle) ||
        field.type.includes(needle) ||
        field.ops.some((op) => op.includes(needle))),
  );
}

const ACTIVE_TARGETS = [ACTIVE_TARGET, PLATFORM_TARGET];

/**
 * Policy builder (`/policies/builder`, page 14; step 7.3 design B17): start a new policy, test or
 * dry-run the organization's active policies on the server, and the DSL catalogue reference.
 */
export function PolicyBuilder() {
  return (
    <RouteGate gate={['PolicyToolsController_catalog_v1']}>
      <PolicyBuilderContent />
    </RouteGate>
  );
}

function PolicyBuilderContent() {
  const catalog = useBuilderCatalog();
  const canCreate = useCan('PolicyManagementController_create_v1');
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Policy builder"
        breadcrumbs={[
          { label: 'Policy management', href: '/policies' },
          { label: 'Policy builder' },
        ]}
        description="Build email policies from the DSL catalogue of this deployment, test and dry-run them on the server, and look up fields, operators and actions."
        actions={
          canCreate ? (
            <Button asChild size="sm">
              <Link href={NEW_POLICY_HREF}>
                <PlusIcon aria-hidden />
                New policy
              </Link>
            </Button>
          ) : null
        }
      />
      <CatalogGate state={catalog}>
        {(builderCatalog) =>
          catalog.query.data ? (
            <>
              <ActiveSetTools catalog={builderCatalog} />
              <CatalogReference raw={catalog.query.data} />
            </>
          ) : null
        }
      </CatalogGate>
    </div>
  );
}

/** Test and dry-run of the active set (targets: active policies, platform default only). */
function ActiveSetTools({ catalog }: { catalog: BuilderCatalog }) {
  const canTest = useCan('PolicyToolsController_test_v1');
  const canSample = useCan('PolicyToolsController_sampleDryRun_v1');
  const canMessage = useCan('PolicyMessagesController_dryRun_v1');
  const [panel, setPanel] = useState<'test' | 'dry-run' | null>(null);
  const [testState, setTestState] = useTestPanelState('active');
  const [dryRunState, setDryRunState] = useDryRunPanelState('active');
  if (!canTest && !canSample && !canMessage) return null;
  return (
    <Section
      title="Test the active policies"
      description="Evaluate synthetic facts or re-evaluate stored messages against the policies that are active now, or against the platform default alone. The server evaluates; nothing is stored."
    >
      <div className="flex flex-wrap gap-2">
        {canTest ? (
          <Button variant="outline" onClick={() => setPanel('test')}>
            <FlaskConicalIcon aria-hidden />
            Test with synthetic facts
          </Button>
        ) : null}
        {canSample || canMessage ? (
          <Button variant="outline" onClick={() => setPanel('dry-run')}>
            <HistoryIcon aria-hidden />
            Dry run on stored messages
          </Button>
        ) : null}
      </div>
      <PolicyTestPanel
        open={panel === 'test'}
        onOpenChange={(open) => setPanel(open ? 'test' : null)}
        catalog={catalog}
        targets={ACTIVE_TARGETS}
        state={testState}
        onStateChange={setTestState}
      />
      <PolicyDryRunPanel
        open={panel === 'dry-run'}
        onOpenChange={(open) => setPanel(open ? 'dry-run' : null)}
        catalog={catalog}
        targets={ACTIVE_TARGETS}
        state={dryRunState}
        onStateChange={setDryRunState}
      />
    </Section>
  );
}

function CatalogReference({ raw }: { raw: Catalog }) {
  const [open, setOpen] = useState(true);
  const [state, setState] = useUrlState(URL_SHAPE);
  const searchId = useId();
  const fields = useMemo(
    () => filterFields(raw.fields, state.q, state.scope),
    [raw.fields, state.q, state.scope],
  );
  const groups = useMemo(() => {
    const byId = new Map(raw.fieldGroups.map((g) => [g.id, { ...g, fields: [] as Field[] }]));
    const other = { id: '__other', label: 'Other fields', fields: [] as Field[] };
    for (const field of fields) (byId.get(field.group) ?? other).fields.push(field);
    return [...byId.values(), other].filter((g) => g.fields.length > 0);
  }, [fields, raw.fieldGroups]);
  const opLabel = useMemo(
    () => new Map(raw.operatorDefinitions.map((o) => [o.op, o.label])),
    [raw.operatorDefinitions],
  );
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="grid min-w-0 gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <BookOpenIcon className="size-5" aria-hidden />
          DSL catalogue reference
        </h2>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm">
            {open ? <ChevronUpIcon aria-hidden /> : <ChevronDownIcon aria-hidden />}
            {open ? 'Hide the reference' : 'Show the reference'}
          </Button>
        </CollapsibleTrigger>
      </div>
      <CollapsibleContent className="grid min-w-0 gap-4">
        <Section title="Versions">
          <DetailList
            items={[
              {
                label: 'DSL',
                value: <span className="font-mono text-xs">{raw.versions.dsl}</span>,
              },
              {
                label: 'Evaluator',
                value: <span className="font-mono text-xs">{raw.versions.evaluator}</span>,
              },
              {
                label: 'Platform default',
                value: (
                  <span>
                    <span className="font-mono text-xs">{raw.platformDefault.id}</span> —{' '}
                    {raw.platformDefault.description}
                  </span>
                ),
              },
              { label: 'Enforcement', value: raw.enforcement },
            ]}
          />
        </Section>
        <Section
          title={`Fields (${formatNumber(fields.length)} of ${formatNumber(raw.fields.length)})`}
          description="What a rule condition can test. Fields of a list (recipients, attachments, links) are checked for any or every item."
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
                  className="h-8 w-full pl-8 sm:min-w-64"
                  value={state.q ?? ''}
                  onChange={(event) => setState({ q: event.target.value || undefined })}
                  placeholder="Label, name, type or operator"
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
            groups.map((group) => (
              <section key={group.id} aria-label={group.label} className="grid min-w-0 gap-2">
                <h3 className="text-sm font-semibold">{group.label}</h3>
                <ul className="grid gap-2" aria-label={`${group.label} fields`}>
                  {group.fields.map((field) => (
                    <FieldEntry key={field.name} field={field} opLabel={opLabel} />
                  ))}
                </ul>
              </section>
            ))
          )}
        </Section>
        <Section title="Operators" description="How a condition compares a field with its values.">
          <ul className="grid gap-2 text-sm sm:grid-cols-2" aria-label="DSL operators">
            {raw.operatorDefinitions.map((op) => (
              <li key={op.op} className="grid gap-0.5 rounded-md border p-2">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{op.label}</span>
                  <span className="font-mono text-xs text-muted-foreground">{op.op}</span>
                </span>
                <span className="text-xs text-muted-foreground">{op.description}</span>
                <span className="text-xs">
                  {`Value: ${humanize(op.valueShape)}${op.itemKind ? ` of ${humanize(op.itemKind)}` : ''}${op.maxItems !== null ? `, at most ${op.maxItems}` : ''}${op.allowedInException ? '' : '; not in exceptions'}`}
                </span>
              </li>
            ))}
          </ul>
        </Section>
        <Section title="Actions">
          <ul className="grid gap-2 text-sm" aria-label="DSL actions">
            {raw.actionDefinitions.map((action) => (
              <li key={action.type} className="grid gap-1 rounded-md border p-2">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{action.label}</span>
                  <span className="font-mono text-xs text-muted-foreground">{action.type}</span>
                  <span className="text-xs text-muted-foreground">
                    {action.kind === 'disposition'
                      ? `Decision (${humanize(action.disposition ?? '')})`
                      : 'Additional action'}
                  </span>
                </span>
                <span className="text-xs text-muted-foreground">{action.description}</span>
                {action.params.length > 0 ? (
                  <ul className="grid gap-0.5 text-xs" aria-label={`Parameters of ${action.label}`}>
                    {action.params.map((param) => (
                      <li key={param.name}>
                        <span className="font-medium">{param.label}</span>
                        {` (${param.required ? 'required' : 'optional'}${param.values ? `: ${param.values.join(', ')}` : ''}): ${param.description}`}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </li>
            ))}
          </ul>
        </Section>
        <Section title="Limits">
          <ul className="grid gap-0.5 text-xs sm:grid-cols-2" aria-label="DSL limits">
            {Object.entries(raw.limits).map(([name, value]) => (
              <li key={name}>
                <span className="font-mono">{name}</span>: {formatNumber(value)}
              </li>
            ))}
          </ul>
        </Section>
      </CollapsibleContent>
    </Collapsible>
  );
}

function FieldEntry({ field, opLabel }: { field: Field; opLabel: ReadonlyMap<string, string> }) {
  return (
    <li className="grid min-w-0 gap-1 rounded-md border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">{field.label}</span>
        <span className="font-mono text-xs break-all text-muted-foreground">{field.name}</span>
        <span className="rounded-sm bg-muted px-1.5 py-0.5 text-xs">{field.type}</span>
        {field.aiDerived ? <span className="text-xs text-muted-foreground">AI-derived</span> : null}
      </div>
      <p>{field.description}</p>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">Operators</span>
        <CodeList codes={field.ops.map((op) => opLabel.get(op) ?? op)} />
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>Directions: {field.directions.map(humanize).join(', ')}</span>
        {field.min !== null || field.max !== null ? (
          <span>
            Range: {field.min ?? '…'} to {field.max ?? '…'}
            {field.unit ? ` ${field.unit}` : ''}
          </span>
        ) : null}
        <span>
          For each item: <YesNo value={field.quantified} />
        </span>
        <span>
          In exceptions: <YesNo value={field.contexts.exception} />
        </span>
      </div>
      {field.values && field.values.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted-foreground">Values{field.ordered ? ' (ordered)' : ''}</span>
          <CodeList codes={field.values} />
        </div>
      ) : null}
    </li>
  );
}
