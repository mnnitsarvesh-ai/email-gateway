'use client';

import Link from 'next/link';
import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { useCan } from '@/lib/auth/me';
import { useCursorList } from '@/lib/api/hooks';
import { humanize } from '@/lib/format';
import { useDirectoryOptions } from '@/features/policies/use-directory-options';
import { splitList } from '@/features/domains/kit';
import { IMMUTABILITY_MODES, retentionHref, type ImmutabilityMode } from './model';

/**
 * Form fields of the archive and journaling settings (step 8.1 A22; split by step 8.6 between
 * Settings → Journaling and Archive → Retention and lock). Pure presentation: each panel owns
 * its draft and its PUT.
 */

/** The journal scope part of a draft (`archive-settings/1` `scope`). */
export interface ScopeDraft {
  scopeMode: 'all' | 'include' | 'exclude';
  domainIds: string[];
  departmentIds: string[];
  userIds: string[];
  addresses: string[];
}

export function Fieldset({
  legend,
  description,
  error,
  children,
}: {
  legend: string;
  description?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <fieldset className="grid gap-2" aria-invalid={error ? true : undefined}>
      <legend className="text-sm font-semibold">{legend}</legend>
      {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
      <div className="flex flex-wrap gap-x-6 gap-y-2">{children}</div>
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

export function CheckRow({
  id,
  label,
  checked,
  onChange,
  disabled,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  // At least 28 px per row: stacked checkboxes keep the 24 px target spacing (WCAG 2.5.8).
  return (
    <div className="flex min-h-7 items-center gap-2">
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(next) => onChange(next === true)}
      />
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
    </div>
  );
}

export function ToggleRow({
  id,
  label,
  description,
  checked,
  onChange,
  disabled,
  error,
}: {
  id: string;
  label: string;
  description?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  error?: string;
}) {
  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-3">
        <Switch
          id={id}
          checked={checked}
          disabled={disabled}
          onCheckedChange={onChange}
          aria-describedby={description ? `${id}-desc` : undefined}
        />
        <Label htmlFor={id}>{label}</Label>
      </div>
      {description ? (
        <p id={`${id}-desc`} className="text-xs text-muted-foreground">
          {description}
        </p>
      ) : null}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </div>
  );
}

export function ScopeFields({
  draft,
  set,
  errors,
}: {
  draft: ScopeDraft;
  set: (patch: Partial<ScopeDraft>) => void;
  errors: Record<string, string>;
}) {
  const canDomains = useCan('DomainsController_list_v1');
  const domains = useCursorList('DomainsController_list_v1', undefined, {
    limit: 100,
    enabled: canDomains && draft.scopeMode !== 'all',
  });
  const directory = useDirectoryOptions();
  const [addresses, setAddresses] = useState(draft.addresses.join('\n'));
  useEffect(() => setAddresses(draft.addresses.join('\n')), [draft.addresses]);
  return (
    <fieldset className="grid gap-3">
      <legend className="text-sm font-semibold">Journal scope</legend>
      <RadioGroup
        value={draft.scopeMode}
        onValueChange={(value) => set({ scopeMode: value as ScopeDraft['scopeMode'] })}
        className="flex flex-wrap gap-x-6 gap-y-2"
        aria-label="Journal scope"
      >
        {(
          [
            ['all', 'All mail of the organization'],
            ['include', 'Only the chosen parties'],
            ['exclude', 'All mail except the chosen parties'],
          ] as const
        ).map(([value, label]) => (
          <div key={value} className="flex items-center gap-2">
            <RadioGroupItem value={value} id={`archive-scope-${value}`} />
            <Label htmlFor={`archive-scope-${value}`} className="font-normal">
              {label}
            </Label>
          </div>
        ))}
      </RadioGroup>
      {errors.scope ? <p className="text-xs font-medium text-destructive">{errors.scope}</p> : null}
      {draft.scopeMode !== 'all' ? (
        <div className="grid gap-3 lg:grid-cols-2">
          <IdChecklist
            label="Domains"
            options={domains.rows.map((d) => ({ id: d.id, label: d.name }))}
            selected={draft.domainIds}
            onChange={(domainIds) => set({ domainIds })}
            error={errors.domainIds}
            unavailable={!canDomains ? 'Listing domains needs domain:read.' : undefined}
          />
          <IdChecklist
            label="Departments"
            options={directory.directory.departments ?? []}
            selected={draft.departmentIds}
            onChange={(departmentIds) => set({ departmentIds })}
            error={errors.departmentIds}
            unavailable={
              !directory.directory.departments ? 'Listing departments needs user:read.' : undefined
            }
          />
          <IdChecklist
            label="Users"
            options={directory.directory.users ?? []}
            selected={draft.userIds}
            onChange={(userIds) => set({ userIds })}
            error={errors.userIds}
            unavailable={!directory.directory.users ? 'Listing users needs user:read.' : undefined}
          />
          <div className="grid gap-1">
            <Label htmlFor="archive-scope-addresses">Addresses (one per line)</Label>
            <Textarea
              id="archive-scope-addresses"
              rows={4}
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              onBlur={() => set({ addresses: splitList(addresses).map((a) => a.toLowerCase()) })}
              aria-invalid={errors.addresses ? true : undefined}
              aria-describedby="archive-scope-addresses-help"
            />
            <p id="archive-scope-addresses-help" className="text-xs text-muted-foreground">
              Mailboxes of your organization (sender or recipient side), at most 1 000.
            </p>
            {errors.addresses ? (
              <p className="text-xs font-medium text-destructive">{errors.addresses}</p>
            ) : null}
          </div>
        </div>
      ) : null}
    </fieldset>
  );
}

/** A searchable checklist of directory ids (unknown selected ids stay listed by id). */
function IdChecklist({
  label,
  options,
  selected,
  onChange,
  error,
  unavailable,
}: {
  label: string;
  options: readonly { id: string; label: string }[];
  selected: readonly string[];
  onChange: (ids: string[]) => void;
  error?: string;
  unavailable?: string;
}) {
  const id = useId();
  const [filter, setFilter] = useState('');
  const known = new Set(options.map((o) => o.id));
  const unknown = selected.filter((s) => !known.has(s));
  const shown = useMemo(
    () =>
      options
        .filter((o) => !filter || o.label.toLowerCase().includes(filter.toLowerCase()))
        .slice(0, 50),
    [options, filter],
  );
  const toggle = (value: string, on: boolean) =>
    onChange(on ? [...selected, value] : selected.filter((s) => s !== value));
  return (
    <fieldset className="grid gap-1 rounded-md border p-3" aria-invalid={error ? true : undefined}>
      <legend className="px-1 text-sm font-medium">
        {label} ({selected.length} chosen)
      </legend>
      {unavailable ? <p className="text-xs text-muted-foreground">{unavailable}</p> : null}
      {options.length > 8 ? (
        <Input
          aria-label={`Filter ${label.toLowerCase()}`}
          placeholder="Filter …"
          className="h-8"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      ) : null}
      <div className="grid max-h-48 overflow-y-auto">
        {shown.map((option) => (
          <CheckRow
            key={option.id}
            id={`${id}-${option.id}`}
            label={option.label}
            checked={selected.includes(option.id)}
            onChange={(on) => toggle(option.id, on)}
          />
        ))}
        {unknown.map((value) => (
          <CheckRow
            key={value}
            id={`${id}-${value}`}
            label={`${value} (not listed)`}
            checked
            onChange={(on) => toggle(value, on)}
          />
        ))}
        {shown.length === 0 && unknown.length === 0 && !unavailable ? (
          <p className="text-xs text-muted-foreground">None available.</p>
        ) : null}
      </div>
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

const IMMUTABILITY_TEXT: Record<ImmutabilityMode, string> = {
  none: 'Objects are write-once and encrypted, but not locked by the storage.',
  governance:
    'Objects are locked until their retention date; only a privileged storage operator could bypass the lock.',
  compliance:
    'Objects are locked until their retention date for everyone. Irreversible: can never be weakened.',
};

export function ImmutabilityField({
  value,
  current,
  available,
  locked,
  onChange,
  error,
}: {
  value: ImmutabilityMode;
  current: ImmutabilityMode;
  available: boolean;
  locked: boolean;
  onChange: (value: ImmutabilityMode) => void;
  error?: string;
}) {
  return (
    <fieldset className="grid gap-2" aria-invalid={error ? true : undefined}>
      <legend className="text-sm font-semibold">Immutability (S3 Object Lock)</legend>
      <RadioGroup
        value={value}
        onValueChange={(next) => onChange(next as ImmutabilityMode)}
        className="grid gap-2"
        aria-label="Immutability"
      >
        {IMMUTABILITY_MODES.map((mode) => {
          const disabled =
            (locked && mode !== 'compliance') ||
            (!available && mode !== 'none' && mode !== current);
          return (
            <div key={mode} className="flex items-start gap-2">
              <RadioGroupItem
                value={mode}
                id={`archive-lock-${mode}`}
                disabled={disabled}
                aria-describedby={`archive-lock-${mode}-desc`}
                className="mt-0.5"
              />
              <div className="grid gap-0.5">
                <Label htmlFor={`archive-lock-${mode}`}>{humanize(mode)}</Label>
                <p id={`archive-lock-${mode}-desc`} className="text-xs text-muted-foreground">
                  {IMMUTABILITY_TEXT[mode]}
                </p>
              </div>
            </div>
          );
        })}
      </RadioGroup>
      {locked ? (
        <p className="text-xs text-muted-foreground">
          Compliance immutability is set and can no longer be changed.
        </p>
      ) : null}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </fieldset>
  );
}

const NO_POLICY = '__none';

export function DefaultPolicyField({
  value,
  options,
  loading,
  onChange,
  error,
}: {
  value: string | null;
  options: readonly { id: string; name: string; days: number }[];
  loading: boolean;
  onChange: (value: string | null) => void;
  error?: string;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor="archive-default-policy">Default retention policy</Label>
      <Select
        value={value ?? NO_POLICY}
        onValueChange={(next) => onChange(next === NO_POLICY ? null : next)}
      >
        <SelectTrigger
          id="archive-default-policy"
          className="max-w-md"
          aria-invalid={error ? true : undefined}
          aria-describedby="archive-default-policy-help"
        >
          <SelectValue placeholder={loading ? 'Loading …' : 'Choose a policy'} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NO_POLICY}>None</SelectItem>
          {options.map((option) => (
            <SelectItem key={option.id} value={option.id}>
              {option.name} ({option.days} days)
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p id="archive-default-policy-help" className="text-xs text-muted-foreground">
        Applies to every record no other policy matches; required while archiving is enabled.{' '}
        <Link
          href={retentionHref('policies')}
          className="text-primary underline underline-offset-2"
        >
          Create or edit retention policies
        </Link>
      </p>
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </div>
  );
}
