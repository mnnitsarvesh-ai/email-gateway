'use client';

import { DateTime, RiskScore } from '@/components/domain';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '../controls';
import { FINAL_ACTION_TONE, RISK_LEVEL_TONE, SCAN_VERDICT_TONE } from '../semantic';
import { Block, DataGrid, NoData } from './parts';
import { RoundPanel, type ScanRound } from './rounds';

type Revision = ScanRound['risk'][number];

const permille = (value: number | null) => (value === null ? '—' : `${(value / 10).toFixed(1)} %`);

function RevisionBlock({ revision }: { revision: Revision }) {
  return (
    <Block
      title={`Revision ${revision.revision}${revision.revision === 1 ? ' (with the late sandbox result)' : ''}`}
      description={
        <>
          Scored <DateTime value={revision.createdAt} mode="absolute" />
        </>
      }
    >
      <DetailList
        items={[
          {
            label: 'Score',
            value:
              revision.status === 'scored' ? (
                <RiskScore score={revision.score} level={revision.level} />
              ) : (
                <span className="text-sm">
                  Scoring failed (status error); the policy applied its floor.
                </span>
              ),
          },
          { label: 'Level', value: <EnumBadge value={revision.level} tones={RISK_LEVEL_TONE} /> },
          { label: 'Verdict', value: humanize(revision.verdict) },
          {
            label: 'Recommended action',
            value: <EnumBadge value={revision.recommendedAction} tones={FINAL_ACTION_TONE} />,
          },
          {
            label: 'Hard blocks',
            value: <CodeList codes={revision.hardBlocks.map((block) => block.id)} />,
          },
          { label: 'Reason codes', value: <CodeList codes={revision.reasonCodes} /> },
          {
            label: 'Trust',
            value: (
              <span className="text-xs">
                {humanize(revision.trust.status)}
                {revision.trust.pointsRemoved > 0
                  ? ` · ${formatNumber(revision.trust.pointsRemoved)} points removed`
                  : ''}
              </span>
            ),
          },
          {
            label: 'Floors',
            value:
              revision.floors.length === 0 ? (
                <span className="text-muted-foreground">None</span>
              ) : (
                <span className="text-xs">
                  {revision.floors
                    .map((floor) => `${humanize(floor.source)} → ${floor.level}`)
                    .join(', ')}
                </span>
              ),
          },
          {
            label: 'Explanation',
            value: <p className="text-sm whitespace-pre-wrap">{revision.explanation.text}</p>,
          },
          {
            label: 'Versions',
            value: (
              <span className="font-mono text-xs">
                {revision.versions.scorer} · {revision.versions.signalMap} · profile{' '}
                {revision.versions.profile.id} ({revision.versions.profile.source})
              </span>
            ),
          },
        ]}
      />
      {revision.contributions.length === 0 ? (
        <NoData>No signal contributed to this score.</NoData>
      ) : (
        <DataGrid
          caption="Signal contributions"
          captionVisible
          rows={revision.contributions}
          rowKey={(row, index) => `${row.signal}-${index}`}
          columns={[
            {
              header: 'Signal',
              rowHeader: true,
              cell: (row) => <span className="font-mono text-xs">{row.signal}</span>,
            },
            { header: 'Group', cell: (row) => humanize(row.group), className: 'text-xs' },
            {
              header: 'Weight',
              cell: (row) => row.weight,
              className: 'font-mono text-xs tabular-nums',
            },
            {
              header: 'Applied',
              cell: (row) => row.applied,
              className: 'font-mono text-xs tabular-nums',
            },
            { header: 'Codes', cell: (row) => <CodeList codes={row.codes} /> },
          ]}
        />
      )}
      {revision.groups.length > 0 ? (
        <DataGrid
          caption="Groups"
          captionVisible
          rows={revision.groups}
          rowKey={(row) => row.group}
          columns={[
            { header: 'Group', rowHeader: true, cell: (row) => humanize(row.group) },
            { header: 'Rule', cell: (row) => humanize(row.rule), className: 'text-xs' },
            { header: 'Raw', cell: (row) => row.raw, className: 'font-mono text-xs tabular-nums' },
            {
              header: 'Multiplier',
              cell: (row) => permille(row.multiplierPermille),
              className: 'font-mono text-xs tabular-nums',
            },
            {
              header: 'Trust factor',
              cell: (row) => permille(row.trustFactorPermille),
              className: 'font-mono text-xs tabular-nums',
            },
            {
              header: 'Cap',
              cell: (row) => (row.cap === null ? 'None' : row.cap),
              className: 'font-mono text-xs tabular-nums',
            },
            {
              header: 'Total',
              cell: (row) => row.total,
              className: 'font-mono text-xs tabular-nums',
            },
          ]}
        />
      ) : null}
      {revision.engines.length > 0 ? (
        <DataGrid
          caption="Engine inputs"
          captionVisible
          rows={revision.engines}
          rowKey={(row) => row.engine}
          columns={[
            { header: 'Engine', rowHeader: true, cell: (row) => humanize(row.engine) },
            {
              header: 'Required',
              cell: (row) => (row.required ? 'Yes' : 'No'),
              className: 'text-xs',
            },
            { header: 'Status', cell: (row) => humanize(row.status), className: 'text-xs' },
            {
              header: 'Outcome',
              cell: (row) => (
                <EnumBadge value={row.outcome} tones={SCAN_VERDICT_TONE} emptyLabel="None" />
              ),
            },
            {
              header: 'Error',
              cell: (row) =>
                row.errorCode ? (
                  <span className="font-mono text-xs">{row.errorCode}</span>
                ) : (
                  <span className="text-muted-foreground">None</span>
                ),
            },
          ]}
        />
      ) : null}
      {revision.failures.length > 0 ? (
        <p className="text-xs">
          Engine failures:{' '}
          {revision.failures
            .map(
              (failure) =>
                `${humanize(failure.engine)} ${humanize(failure.status)} (+${failure.weight})`,
            )
            .join(', ')}
        </p>
      ) : null}
    </Block>
  );
}

/** Section 10: risk score (the round's `risk` revisions; a recommendation, not a decision). */
export function RiskSection() {
  return (
    <Section
      title="Risk score"
      description="The stored risk scores of the selected round: a recommendation the policy decides on, never a decision itself. Every number is the api's."
    >
      <RoundPanel>
        {(round) =>
          round.risk.length === 0 ? (
            <NoData>
              No risk score for round {round.round}: the round is still running, or it ran before
              risk scoring existed (step 5.1).
            </NoData>
          ) : (
            <div className="grid gap-3">
              {round.risk.map((revision) => (
                <RevisionBlock key={revision.revision} revision={revision} />
              ))}
            </div>
          )
        }
      </RoundPanel>
    </Section>
  );
}
