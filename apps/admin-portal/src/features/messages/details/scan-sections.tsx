'use client';

import { UntrustedText } from '@/components/domain';
import { formatDuration, formatNumber, humanize } from '@/lib/format';
import { CodeList, DetailList, EnumBadge, Section } from '../controls';
import { AuthResults } from '../scan-details';
import { SCAN_VERDICT_TONE } from '../semantic';
import { useMessageHeaders } from './headers-section';
import { Block, DataGrid, NoData, QueryBoundary } from './parts';
import { RoundPanel, engineOf, type Engine, type ScanRound } from './rounds';

/** Standard engine facts (outcome, reason codes, attempts, versions). */
export function EngineFacts({ engine }: { engine: Engine }) {
  const lastError = engine.attempts.filter((attempt) => attempt.errorCode).at(-1)?.errorCode;
  return (
    <DetailList
      items={[
        {
          label: 'Outcome',
          value: (
            <span className="flex flex-wrap items-center gap-2">
              <EnumBadge value={engine.outcome} tones={SCAN_VERDICT_TONE} emptyLabel="Pending" />
              {!engine.final ? (
                <span className="text-xs text-muted-foreground">No final result yet</span>
              ) : null}
            </span>
          ),
        },
        { label: 'Reason codes', value: <CodeList codes={engine.reasonCodes} /> },
        {
          label: 'Attempts',
          value: (
            <span className="text-xs">
              {engine.attempts.length}
              {lastError ? (
                <>
                  {' '}
                  · last error <span className="font-mono">{lastError}</span>
                </>
              ) : null}
            </span>
          ),
        },
        {
          label: 'Duration',
          value:
            engine.durationMs === null ? (
              <span className="text-muted-foreground">Not reported</span>
            ) : (
              formatDuration(engine.durationMs)
            ),
        },
        {
          label: 'Versions',
          value: (
            <span className="font-mono text-xs">
              {engine.engineVersion ?? 'engine unknown'}
              {engine.settingsVersion ? ` · settings ${engine.settingsVersion}` : ''}
            </span>
          ),
        },
      ]}
    />
  );
}

/** Section 4: authentication results (round `auth` + the stored Authentication-Results headers). */
export function AuthenticationSection({ messageId }: { messageId: string }) {
  return (
    <Section
      title="Authentication results"
      description="SPF, DKIM, DMARC and ARC as evaluated by the gateway for the selected scan round."
    >
      <RoundPanel>
        {(round) => (
          <div className="grid gap-4">
            {round.auth ? (
              <AuthResults auth={round.auth} />
            ) : (
              <NoData>
                No authentication results for round {round.round}: the round ran before the
                authentication engine reported, or it is still running.
              </NoData>
            )}
            <AuthenticationResultsHeaders messageId={messageId} />
          </div>
        )}
      </RoundPanel>
    </Section>
  );
}

function AuthenticationResultsHeaders({ messageId }: { messageId: string }) {
  const query = useMessageHeaders(messageId);
  return (
    <Block
      title="Authentication-Results headers"
      description="As stored from the message (written by receiving servers on the way; attacker-controlled text)."
    >
      <QueryBoundary query={query} label="Loading headers" rows={2}>
        {() => {
          const body = query.data;
          if (!body) return null;
          if (body.availability !== 'available') {
            return (
              <NoData>No stored headers for this message ({humanize(body.availability)}).</NoData>
            );
          }
          const rows = body.headers.filter(
            (header) => header.name.toLowerCase() === 'authentication-results',
          );
          if (rows.length === 0) {
            return <NoData>The message carries no Authentication-Results header.</NoData>;
          }
          return (
            <ul className="grid gap-1" aria-label="Authentication-Results headers">
              {rows.map((header) => (
                <li key={header.seq}>
                  <UntrustedText value={header.value} mono maxLength={400} />
                </li>
              ))}
            </ul>
          );
        }}
      </QueryBoundary>
    </Block>
  );
}

/** Section 5: spam score (the `rspamd` engine: score, threshold, action, symbols). */
export function SpamSection() {
  return (
    <Section
      title="Spam score"
      description="The Rspamd result of the selected round. Addresses in symbol options are masked for every user and never revealed."
    >
      <RoundPanel>{(round) => <SpamRound round={round} />}</RoundPanel>
    </Section>
  );
}

function SpamRound({ round }: { round: ScanRound }) {
  const engine = engineOf(round, 'rspamd');
  if (!engine) {
    return <NoData>No spam engine result in round {round.round}.</NoData>;
  }
  return (
    <div className="grid gap-4">
      <DetailList
        items={[
          {
            label: 'Score',
            value:
              engine.score === null ? (
                <span className="text-muted-foreground">Not reported</span>
              ) : (
                <span className="font-mono tabular-nums">{formatNumber(engine.score)}</span>
              ),
          },
          {
            label: 'Threshold',
            value:
              engine.requiredScore === null ? (
                <span className="text-muted-foreground">Not reported</span>
              ) : (
                <span className="font-mono tabular-nums">{formatNumber(engine.requiredScore)}</span>
              ),
          },
          {
            label: 'Action',
            value: engine.action ? (
              <span className="font-mono text-xs">{engine.action}</span>
            ) : (
              <span className="text-muted-foreground">None</span>
            ),
          },
        ]}
      />
      <EngineFacts engine={engine} />
      {engine.symbols.length === 0 ? (
        <NoData>No symbols were recorded.</NoData>
      ) : (
        <DataGrid
          caption={`Rspamd symbols of round ${round.round}`}
          captionVisible
          rows={engine.symbols}
          rowKey={(symbol, index) => `${symbol.name}-${index}`}
          columns={[
            {
              header: 'Symbol',
              cell: (symbol) => <span className="font-mono text-xs">{symbol.name}</span>,
              rowHeader: true,
            },
            {
              header: 'Score',
              cell: (symbol) => formatNumber(symbol.score),
              className: 'font-mono text-xs tabular-nums',
            },
            {
              header: 'Options',
              cell: (symbol) =>
                symbol.options.length === 0 ? (
                  <span className="text-muted-foreground">None</span>
                ) : (
                  <ul className="grid gap-0.5">
                    {symbol.options.map((option, index) => (
                      <li key={index}>
                        <UntrustedText value={option} mono maxLength={120} />
                      </li>
                    ))}
                  </ul>
                ),
              className: 'max-w-[28rem]',
            },
          ]}
        />
      )}
    </div>
  );
}
