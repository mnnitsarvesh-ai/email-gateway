'use client';

import { EmptyState } from '@/components/states/empty-state';
import { useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '../controls';
import { EvaluationSummary } from '../scan-details';
import { DISPOSITION_TONE } from '../semantic';
import { Block, DataGrid, NoData, QueryBoundary } from './parts';

type Evaluation = SuccessBody<'PolicyMessagesController_evaluations_v1'>['data'][number];

function EvaluationBlock({ evaluation }: { evaluation: Evaluation }) {
  return (
    <Section
      title={`Round ${evaluation.lifecycleRound} · ${humanize(evaluation.trigger)}`}
      description={`Direction ${evaluation.direction} · final verdict ${humanize(evaluation.finalVerdict)}${
        evaluation.riskScore !== null ? ` · risk ${evaluation.riskScore}` : ''
      } · delivered object ${humanize(evaluation.deliveredObject)}`}
      headingLevel={3}
    >
      <EvaluationSummary evaluation={evaluation} />
      {evaluation.matchedRules.length > 0 ? (
        <DataGrid
          caption="Matched rules"
          captionVisible
          rows={evaluation.matchedRules}
          rowKey={(rule) => rule.ref}
          columns={[
            {
              header: 'Rule',
              rowHeader: true,
              cell: (rule) => (
                <span className="font-mono text-xs">
                  {rule.policyPublicId} v{rule.versionNo} · {rule.ruleId}
                </span>
              ),
            },
            {
              header: 'Disposition',
              cell: (rule) => (
                <EnumBadge
                  value={rule.disposition}
                  tones={DISPOSITION_TONE}
                  emptyLabel="Actions only"
                />
              ),
            },
            { header: 'Actions', cell: (rule) => <CodeList codes={rule.actionTypes} /> },
            {
              header: 'Override',
              cell: (rule) => (rule.override ? 'Yes' : 'No'),
              className: 'text-xs',
            },
          ]}
        />
      ) : (
        <NoData>No tenant rule matched this round.</NoData>
      )}
      <Block title="Floor and recommendation">
        <DetailList
          items={[
            {
              label: 'Strictness floor',
              value: evaluation.floor.disposition ? (
                <span className="flex flex-wrap items-center gap-2">
                  <EnumBadge value={evaluation.floor.disposition} tones={DISPOSITION_TONE} />
                  <CodeList codes={evaluation.floor.reasons} />
                </span>
              ) : (
                <span className="text-muted-foreground">None</span>
              ),
            },
            {
              label: 'Risk recommendation',
              value: (
                <span className="flex flex-wrap items-center gap-2 text-xs">
                  <EnumBadge
                    value={evaluation.recommendation.disposition}
                    tones={DISPOSITION_TONE}
                  />
                  {evaluation.recommendation.riskAction
                    ? `risk action ${humanize(evaluation.recommendation.riskAction)}`
                    : ''}
                  {evaluation.recommendation.levelOnly ? ' (level only)' : ''}
                </span>
              ),
            },
            {
              label: 'Clamps',
              value:
                evaluation.clamps.length === 0 ? (
                  <span className="text-muted-foreground">None</span>
                ) : (
                  <span className="text-xs">
                    {evaluation.clamps
                      .map((clamp) => `${clamp.from} → ${clamp.to} (${humanize(clamp.reason)})`)
                      .join(', ')}
                  </span>
                ),
            },
            {
              label: 'Delivery changes',
              value: evaluation.delivery ? (
                <span className="grid gap-0.5 text-xs">
                  {evaluation.delivery.headers.map((header, index) => (
                    <span key={index} className="font-mono">
                      {header.name}
                    </span>
                  ))}
                  {evaluation.delivery.subjectPrefix !== null ? (
                    <span>Subject prefix added</span>
                  ) : null}
                  {evaluation.delivery.bodyBanner ? (
                    <span>Body banner {humanize(evaluation.delivery.bodyBanner)}</span>
                  ) : null}
                  <span>
                    URL rewrite{' '}
                    {evaluation.delivery.urlRewrite.required ? 'required' : 'not required'}
                    {evaluation.delivery.urlRewrite.rewritten ? ', rewritten' : ''}
                  </span>
                </span>
              ) : (
                <span className="text-muted-foreground">None</span>
              ),
            },
            {
              label: 'Versions',
              value: (
                <span className="font-mono text-xs">
                  {evaluation.versions.evaluator} · generation {evaluation.versions.generation} ·{' '}
                  {evaluation.versions.platformDefault}
                </span>
              ),
            },
          ]}
        />
      </Block>
      {evaluation.recipientDecisions && evaluation.recipientDecisions.length > 0 ? (
        <DataGrid
          caption="Per-recipient decisions"
          captionVisible
          rows={evaluation.recipientDecisions}
          rowKey={(row) => String(row.rcptSeq)}
          columns={[
            { header: 'Recipient', rowHeader: true, cell: (row) => `#${row.rcptSeq}` },
            {
              header: 'Disposition',
              cell: (row) => <EnumBadge value={row.disposition} tones={DISPOSITION_TONE} />,
            },
            { header: 'Source', cell: (row) => humanize(row.source), className: 'text-xs' },
            { header: 'Reason codes', cell: (row) => <CodeList codes={row.reasonCodes} /> },
          ]}
        />
      ) : null}
      {evaluation.trace.length > 0 ? (
        <details className="rounded-md border p-3 text-sm">
          <summary className="cursor-pointer font-medium">
            Evaluation trace ({evaluation.trace.length}
            {evaluation.traceTruncated ? ', truncated' : ''})
          </summary>
          <ul className="mt-2 grid gap-1 font-mono text-xs">
            {evaluation.trace.map((step, index) => (
              <li key={`${step.ref}-${index}`}>
                {step.ref} · {step.result}
                {step.field ? ` · ${step.field}` : ''}
                {step.op ? ` ${step.op}` : ''}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </Section>
  );
}

/** Section 11: policy decisions (`PolicyMessagesController_evaluations`, every round). */
export function PolicySection({ messageId }: { messageId: string }) {
  const query = useApiQuery('PolicyMessagesController_evaluations_v1', { path: { messageId } });
  return (
    <Section
      title="Policy decisions"
      description="Every stored policy evaluation of the message, newest round first. Testing a policy against this message (dry run) comes with the policy builder in step 7.3."
    >
      <QueryBoundary query={query} label="Loading policy evaluations" rows={5}>
        {() => {
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
              {[...rows]
                .sort((a, b) => b.lifecycleRound - a.lifecycleRound)
                .map((evaluation) => (
                  <EvaluationBlock
                    key={`${evaluation.lifecycleRound}-${evaluation.evaluatedAt}`}
                    evaluation={evaluation}
                  />
                ))}
            </div>
          );
        }}
      </QueryBoundary>
    </Section>
  );
}
