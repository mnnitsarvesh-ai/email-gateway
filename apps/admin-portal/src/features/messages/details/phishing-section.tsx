'use client';

import type { ReactNode } from 'react';
import { DateTime, UntrustedText } from '@/components/domain';
import { formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '../controls';
import { AUTH_RESULT_TONE, SCAN_VERDICT_TONE } from '../semantic';
import { EngineFacts } from './scan-sections';
import { Block, DataGrid, NoData } from './parts';
import { RoundPanel, engineOf, type Engine, type ScanRound } from './rounds';

type Bec = NonNullable<Engine['bec']>;
type BecRule = Bec['rules'][number];
type Evidence = BecRule['evidence'][number];
type AiAssessment = Bec['aiShadow'][number] & { effect?: Bec['ai'][number]['effect'] };
type UrlResult = NonNullable<Engine['urls']>[number];

const SEVERITY_TONE = {
  info: 'neutral',
  low: 'info',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
} as const;

/** One structured BEC evidence item (ids, header names, sender-side addresses, spans by offset). */
function EvidenceItem({ evidence }: { evidence: Evidence }) {
  const parts: ReactNode[] = [];
  if (evidence.header) parts.push(<span key="h">header {evidence.header}</span>);
  if (evidence.address)
    parts.push(
      <span key="a" className="inline-flex items-center gap-1">
        address <UntrustedText value={evidence.address} mono maxLength={80} />
      </span>,
    );
  if (evidence.displayName)
    parts.push(
      <span key="d" className="inline-flex items-center gap-1">
        display name <UntrustedText value={evidence.displayName} maxLength={80} />
      </span>,
    );
  if (evidence.domain)
    parts.push(
      <span key="dm" className="inline-flex items-center gap-1">
        domain <UntrustedText value={evidence.domain} mono maxLength={80} />
      </span>,
    );
  if (evidence.profile)
    parts.push(
      <span key="p">
        {humanize(evidence.profile.kind)} profile{' '}
        <span className="font-mono">{evidence.profile.id}</span> ({humanize(evidence.profile.match)}
        )
      </span>,
    );
  if (evidence.lookalike)
    parts.push(
      <span key="l" className="inline-flex flex-wrap items-center gap-1">
        lookalike {evidence.lookalike.rule} of {humanize(evidence.lookalike.targetKind)}{' '}
        <UntrustedText value={evidence.lookalike.targetDomain} mono maxLength={60} /> (score{' '}
        {formatNumber(evidence.lookalike.score)})
      </span>,
    );
  if (evidence.auth)
    parts.push(
      <span key="au" className="inline-flex flex-wrap items-center gap-1">
        SPF <EnumBadge value={evidence.auth.spf} tones={AUTH_RESULT_TONE} emptyLabel="none" /> DKIM{' '}
        <EnumBadge value={evidence.auth.dkim} tones={AUTH_RESULT_TONE} emptyLabel="none" /> DMARC{' '}
        <EnumBadge value={evidence.auth.dmarc} tones={AUTH_RESULT_TONE} emptyLabel="none" />
        {evidence.auth.aligned.dkim || evidence.auth.aligned.spf
          ? ` aligned: ${[evidence.auth.aligned.dkim ? 'DKIM' : '', evidence.auth.aligned.spf ? 'SPF' : ''].filter(Boolean).join(', ')}`
          : ' not aligned'}
      </span>,
    );
  if (evidence.keywords)
    parts.push(
      <span key="k">
        keywords {humanize(evidence.keywords.category)} ({evidence.keywords.language}),{' '}
        {evidence.keywords.spans.length} span{evidence.keywords.spans.length === 1 ? '' : 's'} in{' '}
        {[...new Set(evidence.keywords.spans.map((span) => humanize(span.source)))].join(', ') ||
          'no part'}
      </span>,
    );
  if (evidence.urls && evidence.urls.length > 0)
    parts.push(<span key="u">URLs #{evidence.urls.join(', #')}</span>);
  if (evidence.history)
    parts.push(
      <span key="hi">
        {evidence.history.firstContact ? 'first contact' : 'known correspondent'}, prior messages{' '}
        {evidence.history.priorMessages}
      </span>,
    );
  if (evidence.trusted) parts.push(<span key="t">trusted sender {evidence.trusted.id}</span>);
  if (evidence.suppression)
    parts.push(<span key="s">feedback suppression {evidence.suppression.id}</span>);
  if (evidence.suppressedCodes && evidence.suppressedCodes.length > 0)
    parts.push(<span key="sc">suppressed {evidence.suppressedCodes.join(', ')}</span>);
  if (evidence.patterns)
    parts.push(
      <span key="pt">
        patterns IBAN {evidence.patterns.iban}, SWIFT {evidence.patterns.swift}, IFSC/account{' '}
        {evidence.patterns.ifsc_account}, amounts {evidence.patterns.amount}
      </span>,
    );
  if (parts.length === 0) return <span className="text-muted-foreground">No details</span>;
  return <span className="flex flex-wrap gap-x-3 gap-y-1 text-xs">{parts}</span>;
}

function AiList({ title, items }: { title: string; items: readonly AiAssessment[] }) {
  if (items.length === 0) return null;
  return (
    <DataGrid
      caption={title}
      captionVisible
      rows={items}
      rowKey={(item, index) => `${item.layer}-${item.modelId}-${index}`}
      columns={[
        {
          header: 'Model',
          rowHeader: true,
          cell: (item) => (
            <span className="grid text-xs">
              <span>
                {humanize(item.layer)} · {humanize(item.mode)}
              </span>
              <span className="font-mono text-muted-foreground">
                {item.provider} {item.modelId} {item.modelVersion}
              </span>
            </span>
          ),
        },
        { header: 'Status', cell: (item) => humanize(item.status), className: 'text-xs' },
        {
          header: 'Labels',
          cell: (item) =>
            item.labels.length === 0 ? (
              <span className="text-muted-foreground">None</span>
            ) : (
              <span className="text-xs">
                {item.labels
                  .map((label) => `${label.label} ${Math.round(label.confidence * 100)} %`)
                  .join(', ')}
              </span>
            ),
        },
        {
          header: 'Indicators',
          cell: (item) => <CodeList codes={item.indicators} />,
        },
        {
          header: 'Effect',
          cell: (item) =>
            item.effect ? (
              humanize(item.effect)
            ) : (
              <span className="text-muted-foreground">Shadow only</span>
            ),
          className: 'text-xs',
        },
      ]}
    />
  );
}

function BecBlock({ engine, bec }: { engine: Engine; bec: Bec }) {
  return (
    <Block
      title="Phishing and BEC analysis"
      description="Deterministic rules with structured evidence; AI assessments only raise, never lower, the verdict. Span offsets point into derived text, which is never shown."
    >
      <DetailList
        items={[
          {
            label: 'Verdict',
            value: (
              <span className="flex flex-wrap items-center gap-2">
                <EnumBadge value={bec.verdict} tones={SCAN_VERDICT_TONE} />
                <span className="text-xs text-muted-foreground">
                  deterministic{' '}
                  <EnumBadge value={bec.deterministicVerdict} tones={SCAN_VERDICT_TONE} />
                </span>
              </span>
            ),
          },
          {
            label: 'Score',
            value: (
              <span className="font-mono text-xs tabular-nums">
                {formatNumber(bec.score)} (deterministic {formatNumber(bec.deterministicScore)})
              </span>
            ),
          },
          {
            label: 'Thresholds',
            value: (
              <span className="text-xs">
                suspicious {bec.thresholds.suspicious ?? 'not recorded'}, malicious{' '}
                {bec.thresholds.malicious ?? 'not recorded'}
              </span>
            ),
          },
          {
            label: 'Inputs',
            value: bec.inputs ? (
              <span className="text-xs">
                auth {humanize(bec.inputs.auth)}, URLs {humanize(bec.inputs.url)}, text{' '}
                {humanize(bec.inputs.text)}, history {humanize(bec.inputs.history)}
              </span>
            ) : (
              <span className="text-muted-foreground">Not recorded</span>
            ),
          },
          {
            label: 'Versions',
            value: (
              <span className="font-mono text-xs">
                engine {bec.engineVersion} · rules {bec.rulesVersion} · lexicon {bec.lexiconVersion}
              </span>
            ),
          },
        ]}
      />
      <EngineFacts engine={engine} />
      {bec.rules.length === 0 ? (
        <NoData>No rule matched.</NoData>
      ) : (
        <DataGrid
          caption="Matched rules"
          captionVisible
          rows={bec.rules}
          rowKey={(rule, index) => `${rule.id}-${index}`}
          columns={[
            {
              header: 'Rule',
              rowHeader: true,
              cell: (rule) => (
                <span className="grid text-xs">
                  <span className="font-mono">{rule.id}</span>
                  <span className="font-mono text-muted-foreground">{rule.code}</span>
                </span>
              ),
            },
            { header: 'Category', cell: (rule) => humanize(rule.category), className: 'text-xs' },
            {
              header: 'Severity',
              cell: (rule) => <EnumBadge value={rule.severity} tones={SEVERITY_TONE} />,
            },
            {
              header: 'Weight',
              cell: (rule) => (
                <span className="font-mono text-xs tabular-nums">
                  {rule.weight}
                  {rule.suppressed ? ` (suppressed: ${rule.suppressed})` : ''}
                </span>
              ),
            },
            {
              header: 'Evidence',
              className: 'max-w-[32rem]',
              cell: (rule) =>
                rule.evidence.length === 0 ? (
                  <span className="text-muted-foreground">None</span>
                ) : (
                  <ul className="grid gap-1">
                    {rule.evidence.map((evidence, index) => (
                      <li key={index}>
                        <EvidenceItem evidence={evidence} />
                      </li>
                    ))}
                  </ul>
                ),
            },
          ]}
        />
      )}
      <AiList title="AI assessments" items={bec.ai} />
      <AiList
        title="AI assessments in shadow mode (no effect on the verdict)"
        items={bec.aiShadow}
      />
      <div className="grid gap-1">
        <h4 className="text-xs font-medium text-muted-foreground">Analyst feedback (read only)</h4>
        {bec.feedback.length === 0 ? (
          <NoData>No feedback recorded for this round.</NoData>
        ) : (
          <ul className="grid gap-1 text-xs" aria-label="Analyst feedback">
            {bec.feedback.map((feedback) => (
              <li key={feedback.id} className="flex flex-wrap items-center gap-2">
                <span>{humanize(feedback.kind)}</span>
                <span className="font-mono text-muted-foreground">{feedback.id}</span>
                <DateTime value={feedback.createdAt} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </Block>
  );
}

function UrlFindings({ urls }: { urls: readonly UrlResult[] }) {
  const flagged = urls.filter(
    (url) => url.lookalike.length > 0 || url.reputation.some((r) => r.status === 'listed'),
  );
  if (flagged.length === 0) {
    return <NoData>No lookalike or reputation finding for the URLs of this round.</NoData>;
  }
  return (
    <DataGrid
      caption="URL lookalike and reputation findings"
      captionVisible
      rows={flagged}
      rowKey={(url) => String(url.urlSeq)}
      columns={[
        {
          header: 'URL',
          rowHeader: true,
          className: 'max-w-80',
          cell: (url) => (
            <span className="grid gap-0.5">
              <span className="text-xs text-muted-foreground">#{url.urlSeq}</span>
              <UntrustedText
                value={url.url}
                mono
                maxLength={80}
                copy
                copyLabel={`Copy URL ${url.urlSeq}`}
              />
            </span>
          ),
        },
        {
          header: 'Verdict',
          cell: (url) => <EnumBadge value={url.verdict} tones={SCAN_VERDICT_TONE} />,
        },
        {
          header: 'Lookalike',
          cell: (url) =>
            url.lookalike.length === 0 ? (
              <span className="text-muted-foreground">None</span>
            ) : (
              <ul className="grid gap-0.5 text-xs">
                {url.lookalike.map((finding, index) => (
                  <li key={index} className="flex flex-wrap items-center gap-1">
                    {finding.rule} of {finding.targetKind ? humanize(finding.targetKind) : 'target'}{' '}
                    {finding.targetDomain ? (
                      <UntrustedText value={finding.targetDomain} mono maxLength={60} />
                    ) : null}{' '}
                    (score {formatNumber(finding.score)})
                  </li>
                ))}
              </ul>
            ),
        },
        {
          header: 'Reputation',
          cell: (url) =>
            url.reputation.length === 0 ? (
              <span className="text-muted-foreground">Not checked</span>
            ) : (
              <ul className="grid gap-0.5 text-xs">
                {url.reputation.map((entry, index) => (
                  <li key={index}>
                    {entry.provider} ({entry.kind}): {humanize(entry.status)}
                    {entry.category ? ` · ${humanize(entry.category)}` : ''}
                  </li>
                ))}
              </ul>
            ),
        },
      ]}
    />
  );
}

function PhishingRound({ round }: { round: ScanRound }) {
  const bec = engineOf(round, 'bec');
  const url = engineOf(round, 'url');
  const reasonCodes = [
    ...new Set([
      ...round.reasonCodes.filter(
        (code) => code.startsWith('phishing.') || code.startsWith('bec.'),
      ),
      ...(url?.reasonCodes ?? []).filter((code) => code.startsWith('phishing.')),
    ]),
  ];
  return (
    <div className="grid gap-4">
      <DetailList
        items={[
          {
            label: 'Phishing reason codes',
            value: <CodeList codes={reasonCodes} label="Phishing reason codes" />,
          },
        ]}
      />
      {bec?.bec ? (
        <BecBlock engine={bec} bec={bec.bec} />
      ) : (
        <NoData>
          {bec
            ? 'The BEC engine has no final result for this round (still running, failed, or skipped).'
            : `No BEC engine result in round ${round.round}.`}
        </NoData>
      )}
      <Block
        title="URL findings"
        description="Lookalike domains and reputation listings of the URL engine."
      >
        {url?.urls ? (
          <UrlFindings urls={url.urls} />
        ) : (
          <NoData>
            No per-URL results in this round (no URLs, or the URL engine has no final result).
          </NoData>
        )}
      </Block>
    </div>
  );
}

/** Section 6: phishing analysis (`bec` engine, `url` lookalike and reputation findings). */
export function PhishingSection() {
  return (
    <Section
      title="Phishing analysis"
      description="Explainable phishing and business-email-compromise results of the selected round. Feedback is shown read only."
    >
      <RoundPanel>{(round) => <PhishingRound round={round} />}</RoundPanel>
    </Section>
  );
}
