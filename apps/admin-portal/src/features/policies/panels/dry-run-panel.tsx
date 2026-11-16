'use client';

import { HistoryIcon, SearchIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useMemo, useState, type Dispatch, type SetStateAction } from 'react';
import { DateTime, DirectionBadge } from '@/components/domain';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, EnumBadge, YesNo } from '@/features/messages/controls';
import { EvaluationResultView, type BuilderCatalog } from '../builder';
import { ChoiceSelect, IntegerInput } from '../builder/inputs';
import { messageHref } from '../links';
import { DISPOSITION_TONE } from '../semantic';
import { PanelSheet } from './panel-sheet';
import { TargetChooser } from './target-chooser';
import { refBelongsTo, type PolicyTarget, type TargetId, type TargetOption } from './targets';

type SampleResponse = SuccessBody<'PolicyToolsController_sampleDryRun_v1'>;
type SampleItem = SampleResponse['items'][number];
type MessageDryRun = SuccessBody<'PolicyMessagesController_dryRun_v1'>;
type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type SampleDirection = NonNullable<
  NonNullable<RequestBody<'PolicyToolsController_sampleDryRun_v1'>['sample']>['direction']
>;

export type DryRunMode = 'sample' | 'message';
export type WindowPreset = '24h' | '7d' | 'custom';

/** What the dry-run panel keeps while it is closed (the page owns it; design B8). */
export interface DryRunPanelState {
  readonly mode: DryRunMode;
  readonly targetId: TargetId;
  readonly window: WindowPreset;
  /** `datetime-local` values of the custom window (local time). */
  readonly customFrom: string;
  readonly customTo: string;
  readonly direction: string | undefined;
  readonly limit: number | undefined;
  readonly onlyChanged: boolean;
  readonly sample: SampleResponse | null;
  readonly sampleTarget: TargetId | null;
  /** The message id typed for "One message" and the one whose rounds are listed. */
  readonly messageInput: string;
  readonly messageId: string | null;
  readonly scanId: string | undefined;
  readonly message: MessageDryRun | null;
  readonly messageTarget: TargetId | null;
}

export function useDryRunPanelState(defaultTarget: TargetId) {
  return useState<DryRunPanelState>(() => ({
    mode: 'sample',
    targetId: defaultTarget,
    window: '7d',
    customFrom: '',
    customTo: '',
    direction: undefined,
    limit: undefined,
    onlyChanged: false,
    sample: null,
    sampleTarget: null,
    messageInput: '',
    messageId: null,
    scanId: undefined,
    message: null,
    messageTarget: null,
  }));
}

const DAY_MS = 86_400_000;
const DEFAULT_SAMPLE_LIMIT = 25;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The request window of a preset or the custom inputs, or why it cannot be sent. */
export function sampleWindow(
  state: Pick<DryRunPanelState, 'window' | 'customFrom' | 'customTo'>,
  maxDays: number,
  now: Date = new Date(),
): { from: string; to: string } | { problem: string } {
  if (state.window !== 'custom') {
    const days = state.window === '24h' ? 1 : 7;
    return { from: new Date(now.getTime() - days * DAY_MS).toISOString(), to: now.toISOString() };
  }
  const from = Date.parse(state.customFrom);
  const to = Date.parse(state.customTo);
  if (!Number.isFinite(from) || !Number.isFinite(to)) {
    return { problem: 'Enter both the start and the end of the window.' };
  }
  if (from >= to) return { problem: 'The start must be before the end.' };
  if (to - from > maxDays * DAY_MS) {
    return { problem: `The window can be at most ${maxDays} days long.` };
  }
  return { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
}

const Disposition = ({ value }: { value: string | null | undefined }) => (
  <EnumBadge value={value} tones={DISPOSITION_TONE} />
);

function ruleOf(decision: {
  source: string;
  ruleId: string | null;
  versionNo: number | null;
}): string {
  if (decision.ruleId) {
    return `Rule ${decision.ruleId}${decision.versionNo !== null ? ` (v${decision.versionNo})` : ''}`;
  }
  return humanize(decision.source);
}

/**
 * The dry-run panel (design B8): "Recent messages" re-evaluates the newest stored evaluations of
 * a window against the target on the server (`POST /policies/dry-run`, bounded, rate limited,
 * writes nothing); "One message" re-evaluates one stored round
 * (`POST /messages/{id}/scans/{scanId}/policy/dry-run`).
 */
export function PolicyDryRunPanel({
  open,
  onOpenChange,
  catalog,
  targets,
  state,
  onStateChange,
  onShowPath,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  catalog: BuilderCatalog;
  targets: readonly TargetOption[];
  state: DryRunPanelState;
  onStateChange: Dispatch<SetStateAction<DryRunPanelState>>;
  onShowPath?: (path: string) => void;
}) {
  const canSample = useCan('PolicyToolsController_sampleDryRun_v1');
  const canMessageDryRun = useCan('PolicyMessagesController_dryRun_v1');
  const canReadRounds = useCan('MessageScansController_scansOf_v1');
  const canMessage = canMessageDryRun && canReadRounds;
  const mode: DryRunMode =
    state.mode === 'message'
      ? canMessage
        ? 'message'
        : 'sample'
      : canSample
        ? 'sample'
        : 'message';
  const set = (patch: Partial<DryRunPanelState>) => onStateChange((s) => ({ ...s, ...patch }));
  return (
    <PanelSheet
      open={open}
      onOpenChange={onOpenChange}
      title="Dry run against stored messages"
      description="The server re-evaluates stored messages against the target and compares with the stored decision. Nothing is stored or changed."
    >
      {!canSample && !canMessage ? (
        <p className="text-sm text-muted-foreground">
          Dry runs need the <code className="font-mono">policy:manage</code> and{' '}
          <code className="font-mono">message:read</code> permissions.
        </p>
      ) : (
        <div className="grid min-w-0 gap-4">
          <TargetChooser
            targets={targets}
            value={state.targetId}
            onChange={(targetId) => set({ targetId })}
          />
          <Tabs value={mode} onValueChange={(next) => set({ mode: next as DryRunMode })}>
            <TabsList aria-label="Dry run kind">
              {canSample ? <TabsTrigger value="sample">Recent messages</TabsTrigger> : null}
              {canMessage ? <TabsTrigger value="message">One message</TabsTrigger> : null}
            </TabsList>
            {canSample ? (
              <TabsContent value="sample" className="grid min-w-0 gap-4">
                <SampleDryRun catalog={catalog} targets={targets} state={state} set={set} />
              </TabsContent>
            ) : null}
            {canMessage ? (
              <TabsContent value="message" className="grid min-w-0 gap-4">
                <MessageDryRunView
                  catalog={catalog}
                  targets={targets}
                  state={state}
                  set={set}
                  onShowPath={onShowPath}
                />
              </TabsContent>
            ) : null}
          </Tabs>
        </div>
      )}
    </PanelSheet>
  );
}

async function resolveTarget(target: TargetOption | undefined): Promise<PolicyTarget | null> {
  if (!target) return null;
  try {
    return await target.resolve();
  } catch {
    return null;
  }
}

function SampleDryRun({
  catalog,
  targets,
  state,
  set,
}: {
  catalog: BuilderCatalog;
  targets: readonly TargetOption[];
  state: DryRunPanelState;
  set: (patch: Partial<DryRunPanelState>) => void;
}) {
  const ids = { window: useId(), direction: useId(), limit: useId(), from: useId(), to: useId() };
  const sample = useApiMutation('PolicyToolsController_sampleDryRun_v1', { successMessage: null });
  const [preparing, setPreparing] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const maxDays = catalog.limits.historyRangeDays ?? 31;
  const maxLimit = catalog.limits.dryRunSampleMax ?? 50;
  const perMinute = catalog.limits.dryRunSamplesPerMinute;
  const limit = state.limit ?? Math.min(DEFAULT_SAMPLE_LIMIT, maxLimit);
  const target = targets.find((t) => t.id === state.targetId) ?? targets[0];
  const waiting = sample.retryAfterSeconds > 0;
  const busy = sample.isPending || preparing;
  const presets: Array<{ value: WindowPreset; label: string }> = [
    { value: '24h', label: 'Last 24 hours' },
    ...(maxDays >= 7 ? [{ value: '7d' as const, label: 'Last 7 days' }] : []),
    { value: 'custom', label: 'Custom window' },
  ];

  const run = async () => {
    const window = sampleWindow(state, maxDays);
    if ('problem' in window) {
      setProblem(window.problem);
      return;
    }
    if (limit < 1 || limit > maxLimit) {
      setProblem(`The number of messages must be between 1 and ${maxLimit}.`);
      return;
    }
    setProblem(null);
    setPreparing(true);
    const resolved = await resolveTarget(target).finally(() => setPreparing(false));
    if (resolved === null) return;
    const outcome = await sample.submit({
      body: {
        target: resolved,
        sample: {
          from: window.from,
          to: window.to,
          ...(state.direction ? { direction: state.direction as SampleDirection } : {}),
          limit,
        },
      },
    });
    if (outcome.ok) set({ sample: outcome.data, sampleTarget: target?.id ?? null });
  };

  return (
    <>
      <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="grid min-w-0 content-start gap-1">
          <Label id={ids.window} className="text-xs text-muted-foreground">
            Window
          </Label>
          <ChoiceSelect
            labelledBy={ids.window}
            value={state.window}
            options={presets}
            onChange={(value) => set({ window: (value as WindowPreset | undefined) ?? '7d' })}
          />
        </div>
        <div className="grid min-w-0 content-start gap-1">
          <Label id={ids.direction} className="text-xs text-muted-foreground">
            Direction
          </Label>
          <ChoiceSelect
            labelledBy={ids.direction}
            value={state.direction}
            unsetLabel="Any direction"
            options={catalog.messageDirections.map((d) => ({ value: d, label: humanize(d) }))}
            onChange={(direction) => set({ direction })}
          />
        </div>
        <div className="grid min-w-0 content-start gap-1">
          <Label htmlFor={ids.limit} className="text-xs text-muted-foreground">
            Messages (at most {maxLimit})
          </Label>
          <IntegerInput
            id={ids.limit}
            value={limit}
            min={1}
            max={maxLimit}
            onChange={(value) => set({ limit: value })}
          />
        </div>
      </div>
      {state.window === 'custom' ? (
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="grid min-w-0 gap-1">
            <Label htmlFor={ids.from} className="text-xs text-muted-foreground">
              From (your local time)
            </Label>
            <Input
              id={ids.from}
              type="datetime-local"
              value={state.customFrom}
              onChange={(event) => set({ customFrom: event.target.value })}
            />
          </div>
          <div className="grid min-w-0 gap-1">
            <Label htmlFor={ids.to} className="text-xs text-muted-foreground">
              To (your local time)
            </Label>
            <Input
              id={ids.to}
              type="datetime-local"
              value={state.customTo}
              onChange={(event) => set({ customTo: event.target.value })}
            />
          </div>
          <p className="text-xs text-muted-foreground sm:col-span-2">
            {`The window can be at most ${maxDays} days long.`}
          </p>
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => void run()} disabled={busy || waiting || !target}>
          <HistoryIcon aria-hidden />
          {busy ? 'Running …' : target?.needsSave ? 'Save and dry run' : 'Run dry run'}
        </Button>
        {waiting ? (
          <span className="text-xs text-muted-foreground" aria-live="polite">
            {`Rate limit reached: Run is available again in ${sample.retryAfterSeconds} s.`}
          </span>
        ) : perMinute ? (
          <span className="text-xs text-muted-foreground">
            {`At most ${perMinute} sample dry runs per minute.`}
          </span>
        ) : null}
      </div>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {problem}
        </p>
      ) : null}
      {sample.error && !sample.isPending && sample.error.status !== 429 ? (
        <ErrorState error={sample.error} compact />
      ) : null}
      {state.sample ? (
        <SampleResult
          response={state.sample}
          onlyChanged={state.onlyChanged}
          onOnlyChanged={(onlyChanged) => set({ onlyChanged })}
        />
      ) : null}
    </>
  );
}

function SampleResult({
  response,
  onlyChanged,
  onOnlyChanged,
}: {
  response: SampleResponse;
  onlyChanged: boolean;
  onOnlyChanged: (value: boolean) => void;
}) {
  const onlyChangedId = useId();
  const headingId = useId();
  const items = useMemo(
    () =>
      onlyChanged
        ? response.items.filter((item) => item.dispositionChanged || item.decisiveChanged)
        : response.items,
    [onlyChanged, response.items],
  );
  const { summary } = response;
  return (
    <section aria-labelledby={headingId} className="grid min-w-0 gap-3" data-testid="sample-result">
      <h3 id={headingId} className="text-base font-semibold">
        Dry run result (computed by the server)
      </h3>
      <DetailList
        items={[
          {
            label: 'Window',
            value: (
              <span>
                <DateTime value={response.window.from} mode="absolute" /> to{' '}
                <DateTime value={response.window.to} mode="absolute" />
              </span>
            ),
          },
          {
            label: 'Messages',
            value: `${formatNumber(response.evaluated)} evaluated, ${formatNumber(response.skipped)} skipped (limit ${formatNumber(response.limit)})`,
          },
          {
            label: 'Decision changes',
            value: `${formatNumber(summary.changed)} changed, ${formatNumber(summary.unchanged)} unchanged`,
          },
        ]}
      />
      {response.truncated ? (
        <p className="text-sm text-muted-foreground">
          The time budget ended before every selected message was evaluated; the counts cover the
          evaluated ones.
        </p>
      ) : null}
      {response.exhausted ? (
        <p className="text-sm text-muted-foreground">
          The window held fewer stored evaluations than the limit.
        </p>
      ) : null}
      <div className="min-w-0 overflow-x-auto rounded-md border">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Stored and dry-run decisions by disposition</caption>
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th scope="col" className="px-2 py-1.5 font-medium">
                Disposition
              </th>
              <th scope="col" className="px-2 py-1.5 font-medium">
                Stored
              </th>
              <th scope="col" className="px-2 py-1.5 font-medium">
                Dry run
              </th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(summary.stored).map(([disposition, stored]) => (
              <tr key={disposition} className="border-t">
                <th scope="row" className="px-2 py-1.5 text-left font-normal">
                  <Disposition value={disposition} />
                </th>
                <td className="px-2 py-1.5 tabular-nums">{formatNumber(stored)}</td>
                <td className="px-2 py-1.5 tabular-nums">
                  {formatNumber(summary.dryRun[disposition as keyof typeof summary.dryRun])}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {summary.transitions.length > 0 ? (
        <ul className="grid gap-1 text-sm" aria-label="Disposition changes">
          {summary.transitions.map((t) => (
            <li key={`${t.from}-${t.to}`} className="flex flex-wrap items-center gap-1.5">
              <Disposition value={t.from} />
              <span aria-hidden>→</span>
              <span className="sr-only">to</span>
              <Disposition value={t.to} />
              <span className="tabular-nums">{`: ${formatNumber(t.count)}`}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {response.invalidVersions.length > 0 ? (
        <div className="grid gap-1 text-sm">
          <p className="font-medium">Versions excluded as invalid</p>
          <ul className="grid gap-1 text-xs">
            {response.invalidVersions.map((v) => (
              <li key={`${v.policyId}-${v.versionNo}`} className="break-all">
                <span className="font-mono">{`${v.policyId} v${v.versionNo}`}</span>
                {`: ${v.violations.map((x) => `${x.path} ${x.code}`).join('; ')}`}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="flex items-center gap-2">
        <Checkbox
          id={onlyChangedId}
          checked={onlyChanged}
          onCheckedChange={(value) => onOnlyChanged(value === true)}
        />
        <Label htmlFor={onlyChangedId} className="font-normal">
          Only changed decisions
        </Label>
      </div>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {onlyChanged ? 'No decision changed.' : 'No stored message in this window.'}
        </p>
      ) : (
        <SampleItems items={items} />
      )}
    </section>
  );
}

function SampleItems({ items }: { items: readonly SampleItem[] }) {
  const captionId = useId();
  return (
    <div
      role="group"
      aria-labelledby={captionId}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region (design system: tables)
      tabIndex={0}
      className="min-w-0 overflow-x-auto rounded-md border"
    >
      <table className="w-full text-left text-sm">
        <caption id={captionId} className="sr-only">
          Stored and dry-run decisions per message
        </caption>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            {['Message', 'Received', 'Direction', 'Stored', 'Dry run', 'Change'].map((h) => (
              <th key={h} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={`${item.messageId ?? 'none'}-${item.scanId}`} className="border-t align-top">
              <td className="px-2 py-1.5">
                {item.messageId ? (
                  <Link
                    href={messageHref(item.messageId)}
                    className="font-mono text-xs text-primary underline-offset-2 hover:underline"
                  >
                    {`${item.messageId.slice(0, 8)}…`}
                    <span className="sr-only">{` Open message ${item.messageId}`}</span>
                  </Link>
                ) : (
                  <span className="text-muted-foreground">Unavailable</span>
                )}
              </td>
              <td className="px-2 py-1.5 whitespace-nowrap">
                <DateTime value={item.receivedAt} />
              </td>
              <td className="px-2 py-1.5">
                <DirectionBadge direction={item.direction} />
              </td>
              <td className="px-2 py-1.5">
                <div className="grid gap-0.5">
                  <Disposition value={item.stored.disposition} />
                  <span className="text-xs text-muted-foreground">{ruleOf(item.stored)}</span>
                </div>
              </td>
              <td className="px-2 py-1.5">
                {item.dryRun ? (
                  <div className="grid gap-0.5">
                    <Disposition value={item.dryRun.disposition} />
                    <span className="text-xs text-muted-foreground">{ruleOf(item.dryRun)}</span>
                  </div>
                ) : (
                  <span className="text-xs text-muted-foreground">{humanize(item.outcome)}</span>
                )}
              </td>
              <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                {item.dispositionChanged ? (
                  <EnumBadge
                    value="disposition_changed"
                    tones={{ disposition_changed: 'warning' }}
                  />
                ) : item.decisiveChanged ? (
                  <EnumBadge value="rule_changed" tones={{ rule_changed: 'info' }} />
                ) : (
                  <span className="text-muted-foreground">Same</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MessageDryRunView({
  catalog,
  targets,
  state,
  set,
  onShowPath,
}: {
  catalog: BuilderCatalog;
  targets: readonly TargetOption[];
  state: DryRunPanelState;
  set: (patch: Partial<DryRunPanelState>) => void;
  onShowPath?: (path: string) => void;
}) {
  const inputId = useId();
  const roundId = useId();
  const [problem, setProblem] = useState<string | null>(null);
  const [preparing, setPreparing] = useState(false);
  const dryRun = useApiMutation('PolicyMessagesController_dryRun_v1', { successMessage: null });
  const rounds = useApiQuery(
    'MessageScansController_scansOf_v1',
    { path: { messageId: state.messageId ?? '' }, query: { limit: 20 } },
    { enabled: state.messageId !== null },
  );
  const target = targets.find((t) => t.id === state.targetId) ?? targets[0];
  const evaluable = (rounds.data?.data ?? []).filter(
    (round: ScanRound) => round.status !== 'pending' && round.status !== 'running',
  );
  const open = (rounds.data?.data.length ?? 0) - evaluable.length;
  const waiting = dryRun.retryAfterSeconds > 0;
  const busy = dryRun.isPending || preparing;
  const responseTarget = targets.find((t) => t.id === state.messageTarget);
  const prefix = responseTarget?.editorRefPrefix;

  const find = () => {
    const id = state.messageInput.trim();
    if (!UUID.test(id)) {
      setProblem('Enter the message id (a UUID, as on the Email details page).');
      return;
    }
    setProblem(null);
    set({ messageId: id, scanId: undefined, message: null });
  };

  const run = async () => {
    if (!state.messageId || !state.scanId) return;
    setPreparing(true);
    const resolved = await resolveTarget(target).finally(() => setPreparing(false));
    if (resolved === null) return;
    const outcome = await dryRun.submit({
      path: { messageId: state.messageId, scanId: state.scanId },
      body: { target: resolved },
    });
    if (outcome.ok) set({ message: outcome.data, messageTarget: target?.id ?? null });
  };

  return (
    <>
      <div className="grid min-w-0 gap-1">
        <Label htmlFor={inputId} className="text-xs text-muted-foreground">
          Message id
        </Label>
        <div className="flex min-w-0 flex-wrap gap-2">
          <Input
            id={inputId}
            value={state.messageInput}
            onChange={(event) => set({ messageInput: event.target.value })}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                find();
              }
            }}
            placeholder="01933c3a-…"
            spellCheck={false}
            autoComplete="off"
            className="min-w-0 flex-1 font-mono sm:max-w-md"
          />
          <Button variant="outline" onClick={find}>
            <SearchIcon aria-hidden />
            Find scan rounds
          </Button>
        </div>
      </div>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {problem}
        </p>
      ) : null}
      {state.messageId ? (
        rounds.isLoading ? (
          <LoadingState label="Loading the scan rounds" rows={2} />
        ) : rounds.error ? (
          <ErrorState error={rounds.error} onRetry={() => void rounds.refetch()} compact />
        ) : evaluable.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            This message has no completed scan round to re-evaluate yet.
          </p>
        ) : (
          <div className="grid min-w-0 gap-1">
            <Label id={roundId} className="text-xs text-muted-foreground">
              Scan round
            </Label>
            <ChoiceSelect
              labelledBy={roundId}
              value={state.scanId}
              placeholder="Choose a completed round …"
              options={evaluable.map((round) => ({
                value: round.scanId,
                label: `Round ${round.round}: ${humanize(round.scanKind)}, ${humanize(round.status)}${round.verdict ? `, ${humanize(round.verdict)}` : ''}`,
              }))}
              onChange={(scanId) => set({ scanId, message: null })}
              className="sm:max-w-md"
            />
            {open > 0 ? (
              <p className="text-xs text-muted-foreground">
                {`${open} ${open === 1 ? 'round is' : 'rounds are'} still running and cannot be re-evaluated yet.`}
              </p>
            ) : null}
          </div>
        )
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          onClick={() => void run()}
          disabled={busy || waiting || !state.messageId || !state.scanId}
        >
          <HistoryIcon aria-hidden />
          {busy ? 'Running …' : target?.needsSave ? 'Save and dry run' : 'Run dry run'}
        </Button>
        {waiting ? (
          <span className="text-xs text-muted-foreground" aria-live="polite">
            {`Too many requests: try again in ${dryRun.retryAfterSeconds} s.`}
          </span>
        ) : null}
      </div>
      {dryRun.error && !dryRun.isPending && dryRun.error.status !== 429 ? (
        <ErrorState error={dryRun.error} compact />
      ) : null}
      {state.message && state.messageId ? (
        <MessageResult
          response={state.message}
          messageId={state.messageId}
          catalog={catalog}
          onShowPath={prefix ? onShowPath : undefined}
          isEditorRef={prefix ? refBelongsTo(prefix) : undefined}
        />
      ) : null}
    </>
  );
}

function MessageResult({
  response,
  messageId,
  catalog,
  onShowPath,
  isEditorRef,
}: {
  response: MessageDryRun;
  messageId: string;
  catalog: BuilderCatalog;
  onShowPath?: (path: string) => void;
  isEditorRef?: (ref: string) => boolean;
}) {
  const headingId = useId();
  const stored = response.stored;
  const decided = (d: { source: string; ruleId: string | null; versionNo: number | null }) =>
    ruleOf(d);
  return (
    <section
      aria-labelledby={headingId}
      className="grid min-w-0 gap-3"
      data-testid="message-result"
    >
      <h3 id={headingId} className="text-base font-semibold">
        Stored and recomputed decision
      </h3>
      <DetailList
        items={[
          {
            label: 'Message',
            value: (
              <Link
                href={messageHref(messageId)}
                className="font-mono text-xs break-all text-primary underline-offset-2 hover:underline"
              >
                {messageId}
              </Link>
            ),
          },
          {
            label: 'Stored disposition',
            value: stored ? (
              <span className="flex flex-wrap items-center gap-1.5">
                <Disposition value={stored.disposition} />
                <span className="text-xs text-muted-foreground">{decided(stored.decisive)}</span>
              </span>
            ) : (
              <span className="text-muted-foreground">No stored evaluation for this round</span>
            ),
          },
          {
            label: 'Recomputed disposition',
            value: (
              <span className="flex flex-wrap items-center gap-1.5">
                <Disposition value={response.result.disposition} />
                <span className="text-xs text-muted-foreground">
                  {decided(response.result.decisive)}
                </span>
              </span>
            ),
          },
          {
            label: 'Reproducible',
            value: (
              <span className="grid gap-0.5">
                <YesNo value={response.reproducible} />
                <span className="text-xs text-muted-foreground">
                  {response.reproducible
                    ? 'The same policies, settings and input reproduce the stored decision.'
                    : 'The target, the policies, the settings or the directory differ from the stored evaluation.'}
                </span>
              </span>
            ),
          },
        ]}
      />
      <EvaluationResultView
        response={response}
        catalog={catalog}
        onShowPath={onShowPath}
        isEditorRef={isEditorRef}
      />
    </section>
  );
}
