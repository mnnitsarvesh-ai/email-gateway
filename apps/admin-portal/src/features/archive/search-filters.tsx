'use client';

import { useEffect, useId, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';
import { FilterMultiSelect, FilterSelect, optionsOf } from '@/features/messages/controls';
import {
  ARCHIVE_CATEGORIES,
  ARCHIVE_DIRECTIONS,
  ARCHIVE_FINAL_ACTIONS,
  ARCHIVE_INGEST_SOURCES,
  ARCHIVE_RECORD_STATUSES,
  ARCHIVE_SEARCH_MAX_RANGE_DAYS,
  ARCHIVE_SOURCES,
  ARCHIVE_VERDICTS,
  INGEST_SOURCE_LABEL,
} from './model';
import {
  ARCHIVE_RANGE_KINDS,
  RANGE_LABEL,
  TEXT_FILTERS,
  customRangeError,
  riskError,
  textFilterError,
  type ArchiveFilterCapabilities,
  type ArchiveSearchPatch,
  type ArchiveSearchState,
} from './search-state';

const YES_NO = [
  { value: 'true', label: 'Yes' },
  { value: 'false', label: 'No' },
];

/**
 * The filter form of the archive (A17), shared by `/archive` (URL state) and the case search form
 * of eDiscovery (component state, A18). Reveal-gated filters (recipient, custodian, subject) are
 * not rendered without `message:reveal`; the hold filter needs hold permissions. Text values are
 * committed on Enter or blur (each search is audited with hashed values), validated inline.
 */
export function ArchiveFilters({
  state,
  setState,
  can,
  maxDays = ARCHIVE_SEARCH_MAX_RANGE_DAYS,
  holdOptions,
  idPrefix = 'archive',
  ingestSource = false,
}: {
  state: ArchiveSearchState;
  setState: (patch: ArchiveSearchPatch) => void;
  can: ArchiveFilterCapabilities;
  maxDays?: number;
  /** Holds offered by the hold filter (id → name); without it the filter is not shown. */
  holdOptions?: readonly { id: string; name: string }[];
  idPrefix?: string;
  /** Step 8.6: the copy-source filter (archive search only; eDiscovery searches every source). */
  ingestSource?: boolean;
}) {
  const risk = riskError(state);
  return (
    <div className="grid w-full min-w-0 basis-full gap-3">
      <div className="flex min-w-0 flex-wrap items-end gap-2">
        <DayRangeFields state={state} setState={setState} maxDays={maxDays} />
        <FilterMultiSelect
          label="Direction"
          values={state.direction}
          options={optionsOf(ARCHIVE_DIRECTIONS)}
          onChange={(v) => setState({ direction: v as ArchiveSearchState['direction'] })}
        />
        <FilterMultiSelect
          label="Category"
          values={state.category}
          options={optionsOf(ARCHIVE_CATEGORIES)}
          onChange={(v) => setState({ category: v as ArchiveSearchState['category'] })}
        />
        <FilterMultiSelect
          label="Captured by"
          values={state.source}
          options={optionsOf(ARCHIVE_SOURCES)}
          onChange={(v) => setState({ source: v as ArchiveSearchState['source'] })}
        />
        {ingestSource ? (
          <FilterSelect
            label="Copy source"
            value={state.ingestSource}
            options={ARCHIVE_INGEST_SOURCES.map((value) => ({
              value,
              label: INGEST_SOURCE_LABEL[value],
            }))}
            onChange={(v) => setState({ ingestSource: v as ArchiveSearchState['ingestSource'] })}
          />
        ) : null}
        <FilterMultiSelect
          label="Record status"
          values={state.status}
          options={optionsOf(ARCHIVE_RECORD_STATUSES)}
          onChange={(v) => setState({ status: v as ArchiveSearchState['status'] })}
        />
        <FilterMultiSelect
          label="Verdict"
          values={state.verdict}
          options={optionsOf(ARCHIVE_VERDICTS)}
          onChange={(v) => setState({ verdict: v as ArchiveSearchState['verdict'] })}
        />
        <FilterMultiSelect
          label="Final action"
          values={state.finalAction}
          options={optionsOf(ARCHIVE_FINAL_ACTIONS)}
          onChange={(v) => setState({ finalAction: v as ArchiveSearchState['finalAction'] })}
        />
        <FilterSelect
          label="Attachments"
          value={state.hasAttachments}
          options={YES_NO}
          onChange={(v) => setState({ hasAttachments: v as ArchiveSearchState['hasAttachments'] })}
        />
        <FilterSelect
          label="Malicious"
          value={state.malicious}
          options={YES_NO}
          onChange={(v) => setState({ malicious: v as ArchiveSearchState['malicious'] })}
        />
        <FilterSelect
          label="Held past expiry"
          value={state.legalHold}
          options={YES_NO}
          onChange={(v) => setState({ legalHold: v as ArchiveSearchState['legalHold'] })}
        />
        {can.holds && holdOptions ? (
          <FilterSelect
            label="Covered by legal hold"
            value={state.holdId}
            options={holdOptions.map((h) => ({ value: h.id, label: h.name }))}
            onChange={(v) => setState({ holdId: v })}
          />
        ) : null}
      </div>
      <div className="flex min-w-0 flex-wrap items-start gap-2">
        {TEXT_FILTERS.filter((f) => can.reveal || !f.reveal).map((filter) => (
          <ValidatedText
            key={filter.id}
            id={`${idPrefix}-${filter.id}`}
            label={filter.label}
            value={state[filter.id]}
            validate={(v) => textFilterError(filter.kind, v)}
            onCommit={(value) => setState({ [filter.id]: value })}
          />
        ))}
        <ValidatedText
          id={`${idPrefix}-riskMin`}
          label="Risk score from"
          inputMode="numeric"
          className="w-28"
          value={state.riskMin === undefined ? undefined : String(state.riskMin)}
          validate={riskBoundError}
          onCommit={(v) => setState({ riskMin: v === undefined ? undefined : Number(v) })}
        />
        <ValidatedText
          id={`${idPrefix}-riskMax`}
          label="Risk score to"
          inputMode="numeric"
          className="w-28"
          value={state.riskMax === undefined ? undefined : String(state.riskMax)}
          validate={riskBoundError}
          onCommit={(v) => setState({ riskMax: v === undefined ? undefined : Number(v) })}
        />
      </div>
      {risk ? (
        <p role="alert" className="text-xs font-medium text-destructive">
          {risk}
        </p>
      ) : null}
      {!can.reveal ? (
        <p className="text-xs text-muted-foreground">
          Recipient, custodian and subject filters are not offered: they would confirm masked values
          and need the message:reveal permission.
        </p>
      ) : null}
    </div>
  );
}

function riskBoundError(value: string): string | null {
  if (!value.trim()) return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 && n <= 1000 ? null : 'Enter a whole number 0–1000';
}

/** Range preset select plus the custom first/last day inputs (whole UTC days). */
export function DayRangeFields({
  state,
  setState,
  maxDays,
}: {
  state: Pick<ArchiveSearchState, 'range' | 'from' | 'to'>;
  setState: (patch: ArchiveSearchPatch) => void;
  maxDays: number;
}) {
  const fromId = useId();
  const toId = useId();
  const [from, setFrom] = useState(state.from ?? '');
  const [to, setTo] = useState(state.to ?? '');
  useEffect(() => setFrom(state.from ?? ''), [state.from]);
  useEffect(() => setTo(state.to ?? ''), [state.to]);
  const error = state.range === 'custom' ? customRangeError(from, to, maxDays) : null;
  const commit = (nextFrom: string, nextTo: string) => {
    if (customRangeError(nextFrom, nextTo, maxDays) === null) {
      setState({ range: 'custom', from: nextFrom, to: nextTo });
    }
  };
  return (
    <div className="flex min-w-0 flex-wrap items-end gap-2">
      <FilterSelect
        label="Received (UTC days)"
        value={state.range}
        allowAny={false}
        options={ARCHIVE_RANGE_KINDS.map((kind) => ({ value: kind, label: RANGE_LABEL[kind] }))}
        onChange={(value) => {
          const kind = (value ?? '7d') as ArchiveSearchState['range'];
          if (kind === 'custom') {
            const today = new Date().toISOString().slice(0, 10);
            const start = new Date(Date.now() - 6 * 86_400_000).toISOString().slice(0, 10);
            setState({ range: 'custom', from: state.from ?? start, to: state.to ?? today });
          } else {
            setState({ range: kind, from: undefined, to: undefined });
          }
        }}
      />
      {state.range === 'custom' ? (
        <>
          <div className="grid gap-1">
            <Label htmlFor={fromId} className="text-xs text-muted-foreground">
              First day
            </Label>
            <Input
              id={fromId}
              type="date"
              className="h-8 w-40"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              onBlur={() => commit(from, to)}
              aria-invalid={error ? true : undefined}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor={toId} className="text-xs text-muted-foreground">
              Last day
            </Label>
            <Input
              id={toId}
              type="date"
              className="h-8 w-40"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              onBlur={() => commit(from, to)}
              aria-invalid={error ? true : undefined}
            />
          </div>
          {error ? (
            <p role="alert" className="pb-1 text-xs font-medium text-destructive">
              {error}
            </p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

/** A text filter committed on Enter or blur when valid; the error is shown inline. */
export function ValidatedText({
  id,
  label,
  value,
  validate,
  onCommit,
  inputMode,
  className,
}: {
  id: string;
  label: string;
  value: string | undefined;
  validate: (value: string) => string | null;
  onCommit: (value: string | undefined) => void;
  inputMode?: 'text' | 'numeric' | 'email';
  className?: string;
}) {
  const [text, setText] = useState(value ?? '');
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setText(value ?? '');
    setError(null);
  }, [value]);
  const commit = () => {
    const next = text.trim();
    const problem = validate(next);
    setError(problem);
    if (problem) return;
    if (next !== (value ?? '')) onCommit(next === '' ? undefined : next);
  };
  return (
    <div className={cn('grid min-w-0 gap-1', className ?? 'w-56')}>
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      <Input
        id={id}
        value={text}
        inputMode={inputMode}
        autoComplete="off"
        spellCheck={false}
        className="h-8"
        onChange={(event) => setText(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            event.preventDefault();
            commit();
          }
        }}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : undefined}
      />
      {error ? (
        <p id={`${id}-error`} className="text-xs font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
