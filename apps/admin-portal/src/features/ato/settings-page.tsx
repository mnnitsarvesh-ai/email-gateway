'use client';

import Link from 'next/link';
import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { DateTime, ToneBadge } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { DetailList, Section } from '@/features/messages/controls';
import { ATO_HIGH_RISK_PRESET_ID } from '@/features/policies/builder/facts';
import { AtoErrorSummary, CapabilityList, FeatureOffNotice, ScrollRegion } from './components';
import {
  ACTION_LABELS,
  ATO_SIGNAL_CATEGORIES,
  CATEGORY_LABELS,
  labelOf,
  policyPresetHref,
  type AtoRule,
  type AtoSettings,
} from './model';

/**
 * `/ato/settings` (step 8.4 §6, §4.3 `ato-settings/1`): every tab edits one draft of the tenant's
 * explicit values (`stored`); a value left empty takes the default. Save sends the whole draft with
 * `expectedRowVersion` (`PUT /ato/settings`, CAS): a conflict asks to reload, an invalid document
 * lists the api's paths. Users without `ato:configure` see the same values read-only.
 */

export const SETTINGS_TABS: readonly TabDefinition[] = [
  { id: 'scoring', label: 'Thresholds and scoring' },
  { id: 'rules', label: 'Detection rules', ops: ['AtoRulesController_list_v1'] },
  { id: 'reputation', label: 'IP reputation' },
  { id: 'baselines', label: 'Baselines' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'automation', label: 'Automated responses' },
  { id: 'policy', label: 'Delivery policy' },
  { id: 'providers', label: 'Identity providers' },
];

type Doc = Record<string, unknown>;
type Path = readonly string[];

const isObject = (v: unknown): v is Doc => typeof v === 'object' && v !== null && !Array.isArray(v);

export function getPath(doc: unknown, path: Path): unknown {
  let node = doc;
  for (const key of path) {
    if (!isObject(node)) return undefined;
    node = node[key];
  }
  return node;
}

/** Sets (or with `undefined` removes) a value; emptied objects are removed (defaults apply). */
export function setPath(doc: Doc, path: Path, value: unknown): Doc {
  const [head, ...rest] = path;
  if (head === undefined) return doc;
  const copy: Doc = { ...doc };
  if (rest.length === 0) {
    if (value === undefined) delete copy[head];
    else copy[head] = value;
    return copy;
  }
  const child = setPath(isObject(doc[head]) ? doc[head] : {}, rest, value);
  if (Object.keys(child).length === 0) delete copy[head];
  else copy[head] = child;
  return copy;
}

interface Ctl {
  draft: Doc;
  effective: Doc;
  bounds: Doc;
  readOnly: boolean;
  set: (path: Path, value: unknown) => void;
}

function boundOf(ctl: Ctl, key: string): { min?: number; max?: number } {
  const b = ctl.bounds[key];
  return isObject(b) ? { min: Number(b.min), max: Number(b.max) } : {};
}

function Field({
  label,
  hint,
  children,
}: {
  label: (id: string) => ReactNode;
  hint?: string;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div className="grid content-start gap-1.5">
      {label(id)}
      {children(id)}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function NumberSetting({
  ctl,
  path,
  label,
  bound,
  hint,
}: {
  ctl: Ctl;
  path: Path;
  label: string;
  bound?: string | { min: number; max: number };
  hint?: string;
}) {
  const stored = getPath(ctl.draft, path);
  const effective = getPath(ctl.effective, path);
  const b = typeof bound === 'string' ? boundOf(ctl, bound) : (bound ?? {});
  const range =
    b.min !== undefined && b.max !== undefined && Number.isFinite(b.min) && Number.isFinite(b.max)
      ? `${b.min}–${b.max}`
      : null;
  return (
    <Field
      label={(id) => (
        <Label htmlFor={id} className="text-sm">
          {label}
        </Label>
      )}
      hint={[range ? `Allowed ${range}.` : null, hint, 'Empty = default.']
        .filter(Boolean)
        .join(' ')}
    >
      {(id) => (
        <Input
          id={id}
          type="number"
          inputMode="numeric"
          className="w-40"
          disabled={ctl.readOnly}
          min={b.min}
          max={b.max}
          value={typeof stored === 'number' ? String(stored) : ''}
          placeholder={typeof effective === 'number' ? String(effective) : undefined}
          onChange={(event) => {
            const text = event.target.value.trim();
            const n = Number(text);
            ctl.set(path, text === '' || !Number.isFinite(n) ? undefined : Math.trunc(n));
          }}
        />
      )}
    </Field>
  );
}

function BooleanSetting({
  ctl,
  path,
  label,
  hint,
}: {
  ctl: Ctl;
  path: Path;
  label: string;
  hint?: string;
}) {
  const value = getPath(ctl.draft, path) ?? getPath(ctl.effective, path);
  return (
    <Field
      hint={hint}
      label={(id) => (
        <Label htmlFor={id} className="text-sm">
          {label}
        </Label>
      )}
    >
      {(id) => (
        <Switch
          id={id}
          disabled={ctl.readOnly}
          checked={value === true}
          onCheckedChange={(checked) => ctl.set(path, checked === true)}
        />
      )}
    </Field>
  );
}

function ChoiceSetting({
  ctl,
  path,
  label,
  options,
  hint,
}: {
  ctl: Ctl;
  path: Path;
  label: string;
  options: ReadonlyArray<{ value: string; label: string }>;
  hint?: string;
}) {
  const value = getPath(ctl.draft, path) ?? getPath(ctl.effective, path);
  return (
    <Field
      hint={hint}
      label={(id) => (
        <Label htmlFor={id} className="text-sm">
          {label}
        </Label>
      )}
    >
      {(id) => (
        <Select
          value={typeof value === 'string' ? value : undefined}
          disabled={ctl.readOnly}
          onValueChange={(next) => ctl.set(path, next)}
        >
          <SelectTrigger id={id} className="w-64">
            <SelectValue placeholder="Default" />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </Field>
  );
}

function ListSetting({
  ctl,
  path,
  label,
  hint,
  placeholder,
}: {
  ctl: Ctl;
  path: Path;
  label: string;
  hint: string;
  placeholder: string;
}) {
  const value = getPath(ctl.draft, path) ?? getPath(ctl.effective, path);
  const lines = Array.isArray(value) ? value.map(String) : [];
  const [text, setText] = useState(lines.join('\n'));
  useEffect(() => {
    setText(lines.join('\n'));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset only when the stored value changes
  }, [JSON.stringify(lines)]);
  return (
    <Field
      hint={hint}
      label={(id) => (
        <Label htmlFor={id} className="text-sm">
          {label}
        </Label>
      )}
    >
      {(id) => (
        <Textarea
          id={id}
          rows={4}
          disabled={ctl.readOnly}
          value={text}
          placeholder={placeholder}
          spellCheck={false}
          className="font-mono text-xs"
          onChange={(event) => setText(event.target.value)}
          onBlur={() =>
            ctl.set(
              path,
              text
                .split(/[\n,]/)
                .map((line) => line.trim())
                .filter(Boolean),
            )
          }
        />
      )}
    </Field>
  );
}

/** `/ato/settings`. */
export function AtoSettingsPage() {
  return (
    <RouteGate gate={['AtoSettingsController_get_v1']}>
      <SettingsContent />
    </RouteGate>
  );
}

function SettingsContent() {
  const query = useApiQuery('AtoSettingsController_get_v1');
  if (query.isLoading) return <LoadingState label="Loading account takeover settings" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return (
    <SettingsEditor
      key={`${query.data.rowVersion}`}
      settings={query.data}
      reload={() => void query.refetch()}
    />
  );
}

function SettingsEditor({ settings, reload }: { settings: AtoSettings; reload: () => void }) {
  const canConfigure = useCan('AtoSettingsController_update_v1');
  const [draft, setDraft] = useState<Doc>(() => ({ ...settings.stored }));
  const dirty = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(settings.stored),
    [draft, settings.stored],
  );
  const save = useApiMutation('AtoSettingsController_update_v1', {
    invalidates: [
      'AtoSettingsController_get_v1',
      'AtoRulesController_list_v1',
      'AtoOverviewController_overview_v1',
    ],
    successMessage: 'Settings saved as a new version',
  });
  const ctl: Ctl = {
    draft,
    effective: settings.effective,
    bounds: settings.bounds,
    readOnly: !canConfigure || !settings.featureEnabled,
    set: (path, value) => setDraft((d) => setPath(d, path, value)),
  };
  const conflict = save.error instanceof ApiError && save.error.code === 'ato_settings_conflict';
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Account takeover settings"
        breadcrumbs={[{ label: 'Account takeover', href: '/ato' }, { label: 'Settings' }]}
        description={
          <span>
            Version {settings.version}
            {settings.updatedAt ? (
              <>
                {' '}
                · saved <DateTime value={settings.updatedAt} />
              </>
            ) : (
              ' · defaults'
            )}
            {settings.learning.active && settings.learning.endsAt ? (
              <>
                {' '}
                · learning until <DateTime value={settings.learning.endsAt} mode="absolute" />
              </>
            ) : null}
          </span>
        }
        actions={
          canConfigure && settings.featureEnabled ? (
            <div className="flex flex-wrap items-center gap-2">
              {dirty ? (
                <span className="text-xs text-muted-foreground">Unsaved changes</span>
              ) : null}
              <Button
                variant="outline"
                size="sm"
                disabled={!dirty || save.isPending}
                onClick={() => {
                  setDraft({ ...settings.stored });
                  save.reset();
                }}
              >
                Discard
              </Button>
              <Button
                size="sm"
                disabled={!dirty || save.isPending || save.retryAfterSeconds > 0}
                onClick={() =>
                  void save.submit({
                    body: { expectedRowVersion: settings.rowVersion, settings: draft },
                  })
                }
              >
                Save changes
              </Button>
            </div>
          ) : null
        }
      />
      {!settings.featureEnabled ? <FeatureOffNotice /> : null}
      {settings.storedInvalid ? (
        <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm">
          The stored settings could not be read and are ignored: the defaults apply. Saving replaces
          them.
        </p>
      ) : null}
      {!canConfigure ? (
        <p role="note" className="text-sm text-muted-foreground">
          You can view the settings; changing them needs the ato:configure permission.
        </p>
      ) : null}
      {save.error ? (
        <div className="grid gap-2">
          <AtoErrorSummary error={save.error} />
          {conflict ? (
            <Button variant="outline" size="sm" className="justify-self-start" onClick={reload}>
              Reload the current settings
            </Button>
          ) : null}
        </div>
      ) : null}
      <GatedTabs
        tabs={SETTINGS_TABS}
        label="Account takeover settings"
        keepParams={[]}
        render={(tab) => {
          switch (tab) {
            case 'rules':
              return <RulesTab ctl={ctl} />;
            case 'reputation':
              return <ReputationTab ctl={ctl} settings={settings} />;
            case 'baselines':
              return <BaselinesTab ctl={ctl} />;
            case 'notifications':
              return <NotificationsTab ctl={ctl} />;
            case 'automation':
              return <AutomationTab ctl={ctl} settings={settings} />;
            case 'policy':
              return <PolicyTab settings={settings} />;
            case 'providers':
              return <ProvidersTab settings={settings} />;
            default:
              return <ScoringTab ctl={ctl} />;
          }
        }}
      />
    </div>
  );
}

function Grid({ children }: { children: ReactNode }) {
  return <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{children}</div>;
}

function ScoringTab({ ctl }: { ctl: Ctl }) {
  return (
    <div className="grid gap-4">
      <Section
        title="Mode"
        description="Monitor detects and alerts; enforce also lets automation act (high impact only when allowed below)."
      >
        <Grid>
          <ChoiceSetting
            ctl={ctl}
            path={['mode']}
            label="Mode"
            options={[
              { value: 'monitor', label: 'Monitor (detect, alert, recommend)' },
              { value: 'enforce', label: 'Enforce (automation may act)' },
              { value: 'off', label: 'Off (paused, no policy facts)' },
            ]}
          />
          <NumberSetting
            ctl={ctl}
            path={['learningDays']}
            label="Learning period (days)"
            bound="learningDays"
          />
        </Grid>
      </Section>
      <Section
        title="Risk bands and incidents"
        description="Scores are 0–100; the bands give the level shown everywhere and used by policies."
      >
        <Grid>
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'bands', 'medium']}
            label="Medium from"
            bound="band"
          />
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'bands', 'high']}
            label="High from"
            bound="band"
          />
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'bands', 'critical']}
            label="Critical from"
            bound="band"
          />
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'incidentThreshold']}
            label="Open an incident from"
            bound="incidentThreshold"
            hint="At least the medium band."
          />
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'weakOnlyCap']}
            label="Cap with weak signals only"
            bound="weakOnlyCap"
            hint="Below the incident threshold: weak signals alone never open an incident."
          />
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'strongFloor']}
            label="Floor with a strong signal"
            bound="strongFloor"
            hint="At least the incident threshold."
          />
          <NumberSetting
            ctl={ctl}
            path={['scoring', 'incidentReopenCooldownMinutes']}
            label="Re-open cooldown after a false positive (minutes)"
            bound="incidentReopenCooldownMinutes"
          />
        </Grid>
      </Section>
      <Section
        title="Categories"
        description="Multiplier (per mille, 1000 = ×1) and half-life of each signal category."
      >
        <ScrollRegion label="Category multipliers and half-lives">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Category multipliers and half-lives</caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Category
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Multiplier (‰)
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Half-life (minutes)
                </th>
              </tr>
            </thead>
            <tbody>
              {ATO_SIGNAL_CATEGORIES.map((category) => (
                <tr key={category} className="border-t">
                  <th scope="row" className="px-2 py-1.5 text-left font-normal">
                    {CATEGORY_LABELS[category]}
                  </th>
                  <td className="px-2 py-1.5">
                    <CompactNumber
                      ctl={ctl}
                      path={['scoring', 'categoryMultipliers', category]}
                      bound="categoryMultiplierPermille"
                      label={`${CATEGORY_LABELS[category]} multiplier`}
                    />
                  </td>
                  <td className="px-2 py-1.5">
                    <CompactNumber
                      ctl={ctl}
                      path={['scoring', 'halfLifeMinutes', category]}
                      bound="halfLifeMinutes"
                      label={`${CATEGORY_LABELS[category]} half-life`}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollRegion>
      </Section>
    </div>
  );
}

function CompactNumber({
  ctl,
  path,
  bound,
  label,
}: {
  ctl: Ctl;
  path: Path;
  bound: string | { min: number; max: number };
  label: string;
}) {
  const stored = getPath(ctl.draft, path);
  const effective = getPath(ctl.effective, path);
  const b = typeof bound === 'string' ? boundOf(ctl, bound) : bound;
  return (
    <Input
      type="number"
      inputMode="numeric"
      aria-label={label}
      className="h-8 w-28"
      disabled={ctl.readOnly}
      min={b.min}
      max={b.max}
      value={typeof stored === 'number' ? String(stored) : ''}
      placeholder={typeof effective === 'number' ? String(effective) : undefined}
      onChange={(event) => {
        const text = event.target.value.trim();
        const n = Number(text);
        ctl.set(path, text === '' || !Number.isFinite(n) ? undefined : Math.trunc(n));
      }}
    />
  );
}

function RulesTab({ ctl }: { ctl: Ctl }) {
  const rules = useApiQuery('AtoRulesController_list_v1');
  if (rules.isLoading) return <LoadingState label="Loading the rule catalogue" variant="table" />;
  if (rules.error) return <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />;
  const data = rules.data;
  if (!data) return null;
  return (
    <Section
      title={`Detection rules (${data.rulesVersion})`}
      description="The versioned rule catalogue. Tune each rule’s state, weight and parameters within its bounds; rules that need missing operator data are unavailable."
    >
      <ul className="grid gap-2" aria-label="Detection rules">
        {data.data.map((rule) => (
          <RuleRow key={rule.code} ctl={ctl} rule={rule} />
        ))}
      </ul>
    </Section>
  );
}

function RuleRow({ ctl, rule }: { ctl: Ctl; rule: AtoRule }) {
  const base = ['rules', rule.code] as const;
  const enabledStored = getPath(ctl.draft, [...base, 'enabled']);
  const enabled = typeof enabledStored === 'boolean' ? enabledStored : rule.effective.enabled;
  const switchId = useId();
  return (
    <li className="grid gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid gap-0.5">
          <span className="font-medium">{rule.title}</span>
          <span className="font-mono text-xs text-muted-foreground">
            {rule.id} · {rule.code} · {labelOf(CATEGORY_LABELS, rule.category)} ·{' '}
            {humanize(rule.strength)}
          </span>
          <span className="text-xs text-muted-foreground">{rule.explanation}</span>
        </div>
        <div className="flex items-center gap-2">
          {!rule.availability.available ? (
            <ToneBadge
              tone="neutral"
              title={
                rule.availability.missing.length
                  ? `Needs ${rule.availability.missing.join(', ')}`
                  : undefined
              }
            >
              {rule.availability.reason === 'capabilities_unknown'
                ? 'Availability unknown'
                : 'Unavailable'}
            </ToneBadge>
          ) : null}
          <Label htmlFor={switchId} className="text-xs">
            Enabled
          </Label>
          <Switch
            id={switchId}
            disabled={ctl.readOnly}
            checked={enabled}
            aria-label={`${rule.title} enabled`}
            onCheckedChange={(checked) => ctl.set([...base, 'enabled'], checked === true)}
          />
        </div>
      </div>
      <div className="flex flex-wrap gap-3">
        <label className="grid gap-1 text-xs text-muted-foreground">
          Weight (default {rule.defaultWeight})
          <CompactNumber
            ctl={{ ...ctl, effective: { rules: { [rule.code]: rule.effective } } }}
            path={[...base, 'weight']}
            bound="ruleWeight"
            label={`${rule.title} weight`}
          />
        </label>
        {rule.params.map((p) => (
          <label key={p.name} className="grid gap-1 text-xs text-muted-foreground">
            {humanize(p.name)} ({p.min}–{p.max})
            <CompactNumber
              ctl={{ ...ctl, effective: { rules: { [rule.code]: rule.effective } } }}
              path={[...base, 'params', p.name]}
              bound={{ min: p.min, max: p.max }}
              label={`${rule.title} ${humanize(p.name)}`}
            />
          </label>
        ))}
      </div>
    </li>
  );
}

function ReputationTab({ ctl, settings }: { ctl: Ctl; settings: AtoSettings }) {
  return (
    <div className="grid gap-4">
      <Section
        title="IP reputation sources"
        description="Lookups go through the platform reputation service (platform threat feed and DNS block lists)."
      >
        <Grid>
          <BooleanSetting
            ctl={ctl}
            path={['ipReputation', 'useLocalFeed']}
            label="Platform threat feed"
          />
          <BooleanSetting
            ctl={ctl}
            path={['ipReputation', 'useDnsbl']}
            label="DNS block lists"
            hint="Only the zones the operator configured."
          />
        </Grid>
      </Section>
      <Section
        title="Networks"
        description="One CIDR per line (IPv4 /8 or longer, IPv6 /32 or longer, at most 100 each)."
      >
        <Grid>
          <ListSetting
            ctl={ctl}
            path={['ipReputation', 'trustedNetworks']}
            label="Trusted networks"
            hint="Sign-ins from these networks raise no access or reputation signals."
            placeholder="198.51.100.0/24"
          />
          <ListSetting
            ctl={ctl}
            path={['ipReputation', 'blockedNetworks']}
            label="Blocked networks"
            hint="Sign-ins from these networks count as a known-bad IP."
            placeholder="203.0.113.0/24"
          />
        </Grid>
      </Section>
      <Section title="Detection capabilities" description="Operator data the rules depend on.">
        <CapabilityList capabilities={settings.capabilities} />
      </Section>
    </div>
  );
}

function BaselinesTab({ ctl }: { ctl: Ctl }) {
  return (
    <div className="grid gap-4">
      <Section
        title="Behavioural baselines"
        description="Rebuilt daily from each account’s recent activity."
      >
        <Grid>
          <NumberSetting
            ctl={ctl}
            path={['baselines', 'windowDays']}
            label="Window (days)"
            bound="windowDays"
          />
          <NumberSetting
            ctl={ctl}
            path={['baselines', 'minActiveDays']}
            label="Mature after active days"
            bound="minActiveDays"
          />
          <NumberSetting
            ctl={ctl}
            path={['baselines', 'minEvents']}
            label="Mature after events"
            bound="minEvents"
          />
          <NumberSetting
            ctl={ctl}
            path={['baselines', 'volumeK']}
            label="Volume sensitivity (k × MAD)"
            bound="volumeK"
            hint="Lower values flag smaller increases."
          />
        </Grid>
      </Section>
      <Section title="Geography" description="Used only when a GeoIP City database is configured.">
        <Grid>
          <NumberSetting
            ctl={ctl}
            path={['geo', 'impossibleTravelKmh']}
            label="Impossible travel speed (km/h)"
            bound="impossibleTravelKmh"
          />
          <NumberSetting
            ctl={ctl}
            path={['geo', 'minDistanceKm']}
            label="Minimum distance (km)"
            bound="minDistanceKm"
          />
          <NumberSetting
            ctl={ctl}
            path={['geo', 'maxAccuracyRadiusKm']}
            label="Maximum location accuracy radius (km)"
            bound="maxAccuracyRadiusKm"
          />
        </Grid>
      </Section>
    </div>
  );
}

function NotificationsTab({ ctl }: { ctl: Ctl }) {
  return (
    <Section
      title="Notifications"
      description="E-mail alerts to users holding ato:respond (alerts, approvals) or ato:read (digests), minus personal opt-outs. Messages never contain IP addresses, subjects or recipients."
    >
      <Grid>
        <ChoiceSetting
          ctl={ctl}
          path={['notifications', 'incidentMinSeverity']}
          label="Alert on incidents from severity"
          options={['low', 'medium', 'high', 'critical'].map((s) => ({
            value: s,
            label: humanize(s),
          }))}
        />
        <NumberSetting
          ctl={ctl}
          path={['notifications', 'throttleMinutes']}
          label="At most one alert per (minutes)"
          bound="throttleMinutes"
        />
        <BooleanSetting
          ctl={ctl}
          path={['notifications', 'digest', 'daily']}
          label="Daily digest"
        />
        <BooleanSetting
          ctl={ctl}
          path={['notifications', 'digest', 'weekly']}
          label="Weekly digest (Mondays)"
        />
        <NumberSetting
          ctl={ctl}
          path={['notifications', 'digest', 'hourLocal']}
          label="Digest hour (organization time)"
          bound="digestHourLocal"
        />
        <BooleanSetting
          ctl={ctl}
          path={['notifications', 'includeOrganizationContact']}
          label="Include the organization’s notification address"
        />
        <ListSetting
          ctl={ctl}
          path={['notifications', 'socEmails']}
          label="SOC addresses"
          hint="At most 5; they receive alerts for the SOC audience."
          placeholder="soc@example.com"
        />
      </Grid>
    </Section>
  );
}

const AUTOMATABLE = [
  'alert_tenant_admins',
  'notify_soc',
  'escalate_investigation',
  'restrict_smtp_sending',
  'block_smtp_auth',
  'revoke_sessions',
  'require_mfa',
  'require_password_reset',
  'suspend_account',
  'remove_forwarding_rule',
  'revoke_oauth_grant',
] as const;

function AutomationTab({ ctl, settings }: { ctl: Ctl; settings: AtoSettings }) {
  return (
    <div className="grid gap-4">
      <Section
        title="Automation"
        description="A medium or high-impact response runs automatically only in enforce mode, at the minimum level, with a strong or correlation signal from at least two categories, for an unprotected account and within the hourly caps; otherwise it waits for an approval."
      >
        <DetailList
          items={[
            {
              label: 'Platform automation',
              value: settings.automation.platformEnabled ? 'Enabled' : 'Disabled by the operator',
            },
            {
              label: 'Platform cap per hour',
              value: String(settings.automation.platformMaxPerHour),
            },
            { label: 'Approval window', value: `${settings.automation.approvalTtlHours} hours` },
            {
              label: 'Active restrictions at most',
              value: String(settings.automation.maxActiveRestrictions),
            },
          ]}
        />
        <Grid>
          <NumberSetting
            ctl={ctl}
            path={['automation', 'maxAutomaticPerHour']}
            label="Automatic responses per hour"
            bound="maxAutomaticPerHour"
          />
          <ChoiceSetting
            ctl={ctl}
            path={['restrictions', 'defaultMode']}
            label="Default restriction mode"
            options={[
              { value: 'reject', label: 'Reject (5.7.1)' },
              { value: 'defer', label: 'Defer (4.7.1)' },
            ]}
          />
          <NumberSetting
            ctl={ctl}
            path={['restrictions', 'defaultDurationMinutes']}
            label="Default restriction duration (minutes)"
            bound="durationMinutes"
          />
        </Grid>
      </Section>
      <Section
        title="Per response"
        description="Off: never proposed. Recommend: proposed for approval. Automatic: runs when every condition holds."
      >
        <ScrollRegion label="Automation per response type">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Automation per response type</caption>
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Response
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Automation
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Minimum level
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Duration (minutes)
                </th>
              </tr>
            </thead>
            <tbody>
              {AUTOMATABLE.map((type) => (
                <tr key={type} className="border-t">
                  <th scope="row" className="px-2 py-1.5 text-left font-normal">
                    {ACTION_LABELS[type]}
                  </th>
                  <td className="px-2 py-1.5">
                    <InlineChoice
                      ctl={ctl}
                      path={['automation', type, 'mode']}
                      label={`${ACTION_LABELS[type]} automation`}
                      options={['off', 'recommend', 'automatic']}
                    />
                  </td>
                  <td className="px-2 py-1.5">
                    <InlineChoice
                      ctl={ctl}
                      path={['automation', type, 'minLevel']}
                      label={`${ACTION_LABELS[type]} minimum level`}
                      options={['high', 'critical']}
                    />
                  </td>
                  <td className="px-2 py-1.5">
                    <CompactNumber
                      ctl={ctl}
                      path={['automation', type, 'durationMinutes']}
                      bound="durationMinutes"
                      label={`${ACTION_LABELS[type]} duration`}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollRegion>
      </Section>
    </div>
  );
}

function InlineChoice({
  ctl,
  path,
  label,
  options,
}: {
  ctl: Ctl;
  path: Path;
  label: string;
  options: readonly string[];
}) {
  const value = getPath(ctl.draft, path) ?? getPath(ctl.effective, path);
  return (
    <Select
      value={typeof value === 'string' ? value : undefined}
      disabled={ctl.readOnly}
      onValueChange={(next) => ctl.set(path, next)}
    >
      <SelectTrigger aria-label={label} size="sm" className="w-36">
        <SelectValue placeholder="Default" />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o} value={o}>
            {humanize(o)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function PolicyTab({ settings }: { settings: AtoSettings }) {
  const canCreate = useCan('PolicyManagementController_create_v1');
  return (
    <Section
      title="Delivery policy"
      description="Tenant policies can hold or quarantine outbound and internal mail of risky accounts at the delivery gate, using the account takeover fields of the policy language (they may only make a decision stricter)."
    >
      <DetailList
        items={[
          {
            label: 'Active rule over account takeover fields',
            value: settings.policy.atoFieldsInUse ? (
              <ToneBadge tone="success">In use</ToneBadge>
            ) : (
              <ToneBadge tone="neutral">None</ToneBadge>
            ),
          },
        ]}
      />
      <p className="text-sm text-muted-foreground">
        The SMTP sending restriction stops new submissions; a policy rule also holds mail that was
        already accepted. The builder offers the fields in the “Account takeover” group of a rule’s
        conditions.
      </p>
      {canCreate ? (
        <Button asChild size="sm" className="justify-self-start">
          <Link href={policyPresetHref(ATO_HIGH_RISK_PRESET_ID)}>Create a hold rule</Link>
        </Button>
      ) : (
        <p className="text-xs text-muted-foreground">Creating policies needs policy:manage.</p>
      )}
    </Section>
  );
}

const SOURCE_LABELS: Record<string, string> = {
  portal_login: 'Portal sign-ins',
  account_change: 'Account changes (audit)',
  smtp_auth: 'SMTP authentication',
  smtp_submission: 'SMTP submissions',
  outbound_message: 'Outbound mail',
};

function ProvidersTab({ settings }: { settings: AtoSettings }) {
  return (
    <div className="grid gap-4">
      <Section
        title="Gateway sources"
        description="What the gateway observes itself, with the time of the last event."
      >
        <DetailList
          items={settings.sources.map((s) => ({
            label: SOURCE_LABELS[s.source] ?? humanize(s.source),
            value: <DateTime value={s.lastEventAt} emptyLabel="No event yet" />,
          }))}
        />
      </Section>
      {settings.identityProviders.map((p) => (
        <UnavailableState
          key={p.provider}
          step={p.availableInStep}
          title={
            p.provider === 'microsoft_entra'
              ? 'Microsoft Entra ID / Microsoft 365'
              : 'Google Workspace'
          }
          description="Provider sign-ins, risk events, OAuth consents, mailbox rules and provider-confirmed responses (revoke sessions, require MFA, suspend) arrive with the identity-provider adapters."
        />
      ))}
    </div>
  );
}
