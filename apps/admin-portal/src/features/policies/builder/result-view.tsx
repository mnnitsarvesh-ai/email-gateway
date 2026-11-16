'use client';

import { ListTreeIcon } from 'lucide-react';
import { useId, type ReactNode } from 'react';
import { ToneBadge } from '@/components/domain/tone-badge';
import { Button } from '@/components/ui/button';
import { CodeList, DetailList, YesNo } from '@/features/messages/controls';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';
import { actionOf, fieldOf, operatorOf, type BuilderCatalog } from './catalog';
import type { PolicyTestResponse } from './facts';

/**
 * The server's answer to a policy test (design B7): rendered as returned, never recomputed. The
 * trace's "Show in editor" hands the DSL path to the page, which highlights the node through the
 * editor's path index.
 */

type Result = PolicyTestResponse['result'];

const DISPOSITION_TONE: Readonly<Record<string, Tone>> = {
  allow: 'success',
  require_approval: 'warning',
  quarantine: 'orange',
  reject: 'danger',
};

function Disposition({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-muted-foreground">None</span>;
  return <ToneBadge tone={DISPOSITION_TONE[value] ?? 'neutral'}>{humanize(value)}</ToneBadge>;
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="grid min-w-0 gap-2">
      <h3 id={id} className="text-sm font-semibold">
        {title}
      </h3>
      {children}
    </section>
  );
}

/** A captioned table in a focusable, horizontally scrollable container (design system). */
function Table({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  const captionId = useId();
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">None.</p>;
  return (
    <div
      role="group"
      aria-labelledby={captionId}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region (design system: tables)
      tabIndex={0}
      className="relative min-w-0 overflow-x-auto rounded-md border"
    >
      <table className="w-full text-left text-sm">
        <caption id={captionId} className="sr-only">
          {caption}
        </caption>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cells, i) => (
            <tr key={i} className="border-t align-top">
              {cells.map((cell, j) => (
                <td key={j} className="px-2 py-1.5">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const paramsText = (params: Record<string, unknown>): string =>
  Object.entries(params)
    .map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(', ');

const Mono = ({ children }: { children: ReactNode }) => (
  <span className="font-mono text-xs break-all">{children}</span>
);

function Delivery({ delivery }: { delivery: Result['delivery'] }) {
  if (!delivery)
    return (
      <p className="text-sm text-muted-foreground">No delivery edits (nothing is delivered).</p>
    );
  return (
    <DetailList
      items={[
        {
          label: 'Header edits',
          value:
            delivery.headers.length === 0 ? (
              <span className="text-muted-foreground">None</span>
            ) : (
              <ul className="grid gap-0.5">
                {delivery.headers.map((h, i) => (
                  <li key={i}>
                    <Mono>{`${h.name}: ${h.value}`}</Mono>
                  </li>
                ))}
              </ul>
            ),
        },
        {
          label: 'Subject prefix',
          value: delivery.subjectPrefix ? <Mono>{delivery.subjectPrefix}</Mono> : 'None',
        },
        {
          label: 'Body banner',
          value: delivery.bodyBanner ? humanize(delivery.bodyBanner) : 'None',
        },
        {
          label: 'URL rewriting',
          value: delivery.urlRewrite.required
            ? `Required; ${delivery.urlRewrite.rewritten ? 'rewritten' : `not rewritten${delivery.urlRewrite.skipReason ? ` (${humanize(delivery.urlRewrite.skipReason)})` : ''}`}`
            : 'Not required',
        },
      ]}
    />
  );
}

export function EvaluationResultView({
  response,
  catalog,
  onShowPath,
  isEditorRef,
}: {
  response: PolicyTestResponse;
  catalog: BuilderCatalog;
  onShowPath?: (path: string) => void;
  /** Which trace refs belong to the edited version (others get no "Show in editor"). */
  isEditorRef?: (ref: string) => boolean;
}) {
  const result = response.result;
  const actionLabel = (type: string) => actionOf(catalog, type)?.label ?? type;
  const headingId = useId();
  return (
    <section
      aria-labelledby={headingId}
      className="grid min-w-0 gap-4 text-sm"
      data-builder="result"
    >
      <h2 id={headingId} className="text-base font-semibold">
        Test result (evaluated by the server)
      </h2>
      <DetailList
        items={[
          { label: 'Disposition', value: <Disposition value={result.disposition} /> },
          {
            label: 'Lifecycle disposition',
            value: <Disposition value={response.lifecycleDisposition} />,
          },
          { label: 'Final verdict', value: humanize(result.finalVerdict) },
          {
            label: 'Risk score',
            value: result.riskScore === null ? 'Not scored' : String(result.riskScore),
          },
          {
            label: 'Decided by',
            value: (
              <span className="grid gap-0.5">
                <span>{humanize(result.decisive.source)}</span>
                {result.decisive.policyPublicId ? (
                  <Mono>{`Policy ${result.decisive.policyPublicId}${result.decisive.versionNo !== null ? ` v${result.decisive.versionNo}` : ''}`}</Mono>
                ) : null}
                {result.decisive.ruleId ? <span>{`Rule ${result.decisive.ruleId}`}</span> : null}
                <Mono>{result.decisive.reason}</Mono>
              </span>
            ),
          },
          { label: 'Recipient split', value: <YesNo value={response.recipientSplit} /> },
        ]}
      />

      <Block title="Explanation">
        <p className="rounded-md border bg-muted/30 p-2 text-sm whitespace-pre-wrap">
          {result.explanation.text}
        </p>
      </Block>

      {response.recipientDecisions.length > 0 ? (
        <Block title="Recipient decisions">
          <Table
            caption="Recipient decisions"
            head={['Recipient', 'Disposition', 'Source', 'Decisive rule', 'Reason codes']}
            rows={response.recipientDecisions.map((d) => [
              `#${d.rcptSeq}`,
              <Disposition key="d" value={d.disposition} />,
              humanize(d.source),
              d.decisiveRuleRef ? <Mono key="r">{d.decisiveRuleRef}</Mono> : 'None',
              <CodeList key="c" codes={d.reasonCodes} />,
            ])}
          />
        </Block>
      ) : null}

      <Block title="Matched rules">
        <Table
          caption="Matched rules"
          head={['Rule', 'Policy version', 'Decision', 'Override', 'Actions']}
          rows={result.matchedRules.map((m) => [
            m.ruleId,
            <Mono key="p">{`${m.policyPublicId} v${m.versionNo}`}</Mono>,
            <Disposition key="d" value={m.disposition} />,
            m.override ? 'Yes' : 'No',
            m.actionTypes.map(actionLabel).join(', '),
          ])}
        />
      </Block>

      <Block title="Actions">
        <Table
          caption="Actions with their applicability"
          head={['Action', 'Origin', 'Applies', 'Rules', 'Parameters']}
          rows={result.actions.map((a) => [
            actionLabel(a.type),
            humanize(a.origin),
            a.applicability === 'applies' ? 'Yes' : 'No (not applicable)',
            a.ruleRefs.length > 0 ? <Mono key="r">{a.ruleRefs.join(', ')}</Mono> : 'None',
            Object.keys(a.params).length > 0 ? <Mono key="p">{paramsText(a.params)}</Mono> : 'None',
          ])}
        />
      </Block>

      <Block title="Delivery">
        <Delivery delivery={result.delivery} />
      </Block>

      <Block title="Platform floor and recommendation">
        <DetailList
          items={[
            { label: 'Floor', value: <Disposition value={result.floor.disposition} /> },
            { label: 'Floor reasons', value: <CodeList codes={result.floor.reasons} /> },
            { label: 'Mandatory floor tag', value: <YesNo value={result.floor.tag} /> },
            {
              label: 'Recommendation',
              value: <Disposition value={result.recommendation.disposition} />,
            },
            {
              label: 'Risk action',
              value: result.recommendation.riskAction
                ? humanize(result.recommendation.riskAction)
                : 'None',
            },
            { label: 'Level-only', value: <YesNo value={result.recommendation.levelOnly} /> },
            { label: 'Revisions', value: result.recommendation.revisions.join(', ') || 'None' },
            {
              label: 'Override',
              value: result.override ? (
                <span>
                  {`Applied: ${humanize(result.override.from)} → ${humanize(result.override.to)} `}
                  <Mono>{result.override.ref}</Mono>
                </span>
              ) : (
                'None'
              ),
            },
            {
              label: 'Clamps',
              value:
                result.clamps.length === 0 ? (
                  'None'
                ) : (
                  <ul className="grid gap-0.5">
                    {result.clamps.map((c, i) => (
                      <li key={i}>
                        {`${humanize(c.from)} → ${humanize(c.to)} (${humanize(c.reason)}) `}
                        <Mono>{c.ref}</Mono>
                      </li>
                    ))}
                  </ul>
                ),
            },
            { label: 'Reason codes', value: <CodeList codes={result.reasonCodes} /> },
          ]}
        />
      </Block>

      {response.invalidVersions.length > 0 ? (
        <Block title="Versions excluded as invalid">
          <ul className="grid gap-2">
            {response.invalidVersions.map((v) => (
              <li
                key={`${v.policyId}-${v.versionNo}`}
                className="grid gap-0.5 rounded-md border p-2"
              >
                <Mono>{`${v.policyId} v${v.versionNo}`}</Mono>
                <ul className="grid gap-0.5 text-xs">
                  {v.violations.map((violation, i) => (
                    <li key={i}>
                      <Mono>{violation.path}</Mono>
                      {`: ${violation.message} (${violation.code})`}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </Block>
      ) : null}

      <Block title={`Trace${result.traceTruncated ? ' (truncated)' : ''}`}>
        <Table
          caption="Evaluation trace"
          head={['Rule', 'Result', 'Where', 'Condition', 'Path', '']}
          rows={result.trace.map((t) => {
            const path = t.path;
            const showable = onShowPath && path !== null && (isEditorRef?.(t.ref) ?? true);
            return [
              <Mono key="r">{t.ref}</Mono>,
              humanize(t.result),
              t.at ?? 'None',
              t.field
                ? `${fieldOf(catalog, t.field)?.label ?? t.field} ${t.op ? (operatorOf(catalog, t.op)?.phrase ?? t.op) : ''}`.trim()
                : 'None',
              path ? <Mono key="p">{path}</Mono> : 'None',
              showable ? (
                <Button
                  key="s"
                  variant="outline"
                  size="sm"
                  onClick={() => onShowPath(path)}
                  aria-label={`Show in editor: ${path}`}
                >
                  <ListTreeIcon aria-hidden />
                  Show in editor
                </Button>
              ) : null,
            ];
          })}
        />
      </Block>

      <p className="text-xs text-muted-foreground">
        {`Evaluator ${result.versions.evaluator}, generation ${result.versions.generation}, time zone data ${result.versions.tzdata}. Nothing was stored.`}
      </p>
    </section>
  );
}
