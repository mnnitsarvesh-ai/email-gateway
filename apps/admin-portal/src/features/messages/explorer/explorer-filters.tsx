'use client';

import { XIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, type ReactNode } from 'react';
import { DateTimeRangePicker } from '@/components/date-time-range-picker';
import { SearchChipInput, type SearchChip } from '@/components/search-chip-input';
import { Button } from '@/components/ui/button';
import { useApiQuery } from '@/lib/api/hooks';
import { FilterMultiSelect, FilterSelect, FilterText, optionsOf } from '../controls';
import { messageHref } from '../links';
import {
  DELIVERY_STATUSES,
  MAX_LIST_VALUES,
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_STATUSES,
  MESSAGE_VERDICTS,
  QUARANTINE_STATUSES,
  RISK_BANDS,
  rangePatch,
  rangeValueOf,
  riskBoundsError,
  type ExplorerPatch,
  type ExplorerState,
} from './explorer-state';
import {
  REVEAL_SEARCH_FIELDS,
  SEARCH_FIELDS,
  SEARCH_FIELD_IDS,
  isMessageUuid,
  type SearchFieldId,
} from './search-fields';

export interface ExplorerCapabilities {
  /** `message:reveal`: exact recipient and subject searches, and the subject reveal. */
  readonly reveal: boolean;
  /** `delivery:read`: the delivery status filter. */
  readonly delivery: boolean;
  /** `quarantine:read`: the quarantine status filter. */
  readonly quarantine: boolean;
  /** `domain:read`: the domain filter (lists the tenant's domains). */
  readonly domains: boolean;
}

const bandLabel = (band: { min: number; max: number }) => `${band.min}–${band.max}`;

/**
 * Search bar and filters of the Email Explorer (step 7.2 §2 E10). Controls a user may not use
 * are not rendered: subject searches without `message:reveal`, the delivery and quarantine
 * status filters without `delivery:read` / `quarantine:read`, the domain filter without
 * `domain:read`.
 */
export function ExplorerFilters({
  state,
  setState,
  can,
  searchStatus,
}: {
  state: ExplorerState;
  setState: (patch: ExplorerPatch) => void;
  can: ExplorerCapabilities;
  /** Refusal of the api shown next to the search (422/503). */
  searchStatus?: ReactNode;
}) {
  const fields = useMemo(
    () => SEARCH_FIELDS.filter((field) => can.reveal || !REVEAL_SEARCH_FIELDS.includes(field.id)),
    [can.reveal],
  );
  const chips: SearchChip[] = SEARCH_FIELD_IDS.flatMap((id) => {
    const value = state[id];
    return value && fields.some((field) => field.id === id) ? [{ fieldId: id, value }] : [];
  });
  const riskError = riskBoundsError(state);
  const band = RISK_BANDS.find((b) => b.min === state.riskMin && b.max === state.riskMax);

  return (
    <div className="grid w-full min-w-0 basis-full gap-3">
      <SearchChipInput
        label="Search messages"
        fields={fields}
        chips={chips}
        onCommit={(fieldId, value) => setState({ [fieldId as SearchFieldId]: value })}
        onRemove={(fieldId) => setState({ [fieldId as SearchFieldId]: undefined })}
        assist={(fieldId, text) =>
          fieldId === 'messageId' && isMessageUuid(text) ? (
            <Button asChild variant="outline" size="sm">
              <Link href={messageHref(text.toLowerCase())}>Open message</Link>
            </Button>
          ) : null
        }
        status={searchStatus}
      />
      <div className="flex min-w-0 flex-wrap items-end gap-2">
        <DateTimeRangePicker
          value={rangeValueOf(state)}
          onChange={(value) => setState(rangePatch(value))}
        />
        <FilterMultiSelect
          label="Direction"
          values={state.direction}
          options={optionsOf(MESSAGE_DIRECTIONS)}
          onChange={(direction) => setState({ direction: direction as ExplorerState['direction'] })}
        />
        <FilterMultiSelect
          label="Status"
          values={state.status}
          max={MAX_LIST_VALUES}
          options={optionsOf(MESSAGE_STATUSES)}
          onChange={(status) => setState({ status: status as ExplorerState['status'] })}
        />
        <FilterMultiSelect
          label="Verdict"
          values={state.verdict}
          max={MAX_LIST_VALUES}
          options={optionsOf(MESSAGE_VERDICTS)}
          onChange={(verdict) => setState({ verdict: verdict as ExplorerState['verdict'] })}
        />
        <FilterMultiSelect
          label="Action"
          values={state.action}
          max={MAX_LIST_VALUES}
          options={optionsOf(MESSAGE_ACTIONS)}
          onChange={(action) => setState({ action: action as ExplorerState['action'] })}
        />
        {can.domains ? (
          <DomainFilter value={state.domainId} onChange={(domainId) => setState({ domainId })} />
        ) : null}
        <FilterSelect
          label="Risk score band"
          value={band ? bandLabel(band) : undefined}
          options={RISK_BANDS.map((b) => ({ value: bandLabel(b), label: bandLabel(b) }))}
          onChange={(value) => {
            const next = RISK_BANDS.find((b) => bandLabel(b) === value);
            setState({ riskMin: next?.min, riskMax: next?.max });
          }}
        />
        <FilterText
          label="Risk from"
          type="number"
          inputMode="numeric"
          value={state.riskMin === undefined ? undefined : String(state.riskMin)}
          onCommit={(value) => setState({ riskMin: boundOf(value) })}
          className="w-24"
          inputClassName="w-24 min-w-0"
          description="Lowest risk score, 0 to 1000"
        />
        <FilterText
          label="Risk to"
          type="number"
          inputMode="numeric"
          value={state.riskMax === undefined ? undefined : String(state.riskMax)}
          onCommit={(value) => setState({ riskMax: boundOf(value) })}
          className="w-24"
          inputClassName="w-24 min-w-0"
          description="Highest risk score, 0 to 1000"
        />
        <FilterSelect
          label="Attachments"
          value={state.attachments ?? state.hasAttachments}
          options={[
            { value: 'true', label: 'With attachments' },
            { value: 'false', label: 'Without attachments' },
          ]}
          onChange={(attachments) =>
            setState({
              attachments: attachments as ExplorerState['attachments'],
              hasAttachments: undefined,
            })
          }
        />
        {can.delivery ? (
          <FilterSelect
            label="Delivery status"
            value={state.deliveryStatus}
            options={optionsOf(DELIVERY_STATUSES)}
            onChange={(deliveryStatus) =>
              setState({ deliveryStatus: deliveryStatus as ExplorerState['deliveryStatus'] })
            }
          />
        ) : null}
        {can.quarantine ? (
          <FilterSelect
            label="Quarantine status"
            value={state.quarantineStatus}
            options={optionsOf(QUARANTINE_STATUSES)}
            onChange={(quarantineStatus) =>
              setState({ quarantineStatus: quarantineStatus as ExplorerState['quarantineStatus'] })
            }
          />
        ) : null}
      </div>
      {riskError ? (
        <p role="alert" className="text-xs font-medium text-destructive">
          {riskError}
        </p>
      ) : null}
      {state.domainId && !can.domains ? (
        <p className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
          Filtered to the domain with id <span className="font-mono">{state.domainId}</span>.
          <Button
            variant="ghost"
            size="sm"
            className="h-6"
            onClick={() => setState({ domainId: undefined })}
          >
            <XIcon aria-hidden />
            Remove the domain filter
          </Button>
        </p>
      ) : null}
    </div>
  );
}

/** A risk bound typed by the user (0–1000 integers; anything else clears the bound). */
function boundOf(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 && n <= 1000 ? n : undefined;
}

/** The tenant's domains (first 100, `DomainsController_list_v1`, only with `domain:read`). */
function DomainFilter({
  value,
  onChange,
}: {
  value: string | undefined;
  onChange: (value: string | undefined) => void;
}) {
  const domains = useApiQuery(
    'DomainsController_list_v1',
    { query: { limit: 100 } },
    { staleTime: 5 * 60_000, refetchOnWindowFocus: false },
  );
  const options = (domains.data?.data ?? []).map((domain) => ({
    value: domain.id,
    label: domain.name,
  }));
  if (value && !options.some((option) => option.value === value)) {
    options.unshift({ value, label: domains.isLoading ? 'Loading …' : 'Another domain' });
  }
  return (
    <FilterSelect
      label="Domain"
      value={value}
      options={options}
      onChange={onChange}
      anyLabel={domains.error ? 'Any (domains could not be loaded)' : 'Any'}
    />
  );
}
