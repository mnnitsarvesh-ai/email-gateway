'use client';

import { useId, useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { DetailList, Section, YesNo } from '@/features/messages/controls';
import { ChoiceSelect } from './builder/inputs';
import { NextEvaluationNote } from './lifecycle/dialog-shell';
import { detailNumber, POLICY_QUERIES, violationsOf } from './queries';
import { CATALOG_STALE_MS } from './use-builder-catalog';

type Settings = SuccessBody<'PolicySettingsController_get_v1'>;
type SettingsBody = RequestBody<'PolicySettingsController_put_v1'>['settings'];

/** The form's values (the effective settings; `recipientSplit` may follow the platform). */
export interface SettingsValues {
  allowRecommendationOverrides: boolean;
  recipientSplit: 'default' | 'on' | 'off';
  senderNonDelivery: boolean;
  alertsEnabled: boolean;
  platformTagHeader: boolean;
  platformTagOutbound: boolean;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const bool = (value: unknown): boolean | undefined =>
  typeof value === 'boolean' ? value : undefined;

/** The stored settings document restricted to the keys `PUT /policy-settings` accepts. */
function storedSettings(stored: Settings['settings']): SettingsBody {
  const out: SettingsBody = {};
  const allow = bool(stored.allowRecommendationOverrides);
  if (allow !== undefined) out.allowRecommendationOverrides = allow;
  const split = bool(stored.recipientSplit);
  if (split !== undefined) out.recipientSplit = split;
  if (isRecord(stored.notices)) {
    const v = bool(stored.notices.senderNonDelivery);
    if (v !== undefined) out.notices = { senderNonDelivery: v };
  }
  if (isRecord(stored.alerts)) {
    const v = bool(stored.alerts.enabled);
    if (v !== undefined) out.alerts = { enabled: v };
  }
  if (isRecord(stored.tagging)) {
    const header = bool(stored.tagging.platformTagHeader);
    const outbound = bool(stored.tagging.platformTagOutbound);
    if (header !== undefined || outbound !== undefined) {
      out.tagging = {
        ...(header !== undefined ? { platformTagHeader: header } : {}),
        ...(outbound !== undefined ? { platformTagOutbound: outbound } : {}),
      };
    }
  }
  return out;
}

export function settingsValuesOf(settings: Settings): SettingsValues {
  const split = bool(settings.settings.recipientSplit);
  return {
    allowRecommendationOverrides: settings.effective.allowRecommendationOverrides,
    recipientSplit: split === undefined ? 'default' : split ? 'on' : 'off',
    senderNonDelivery: settings.effective.notices.senderNonDelivery,
    alertsEnabled: settings.effective.alerts.enabled,
    platformTagHeader: settings.effective.tagging.platformTagHeader,
    platformTagOutbound: settings.effective.tagging.platformTagOutbound,
  };
}

/**
 * The `settings` of `PUT /policy-settings`: the stored document with only the changed values
 * written explicitly (unchanged keys keep their presence, so a key that follows the platform
 * default keeps following it); "Platform default" of `recipientSplit` removes the key.
 */
export function settingsBody(settings: Settings, values: SettingsValues): SettingsBody {
  const base = settingsValuesOf(settings);
  const out = storedSettings(settings.settings);
  if (values.allowRecommendationOverrides !== base.allowRecommendationOverrides) {
    out.allowRecommendationOverrides = values.allowRecommendationOverrides;
  }
  if (values.recipientSplit !== base.recipientSplit) {
    if (values.recipientSplit === 'default') delete out.recipientSplit;
    else out.recipientSplit = values.recipientSplit === 'on';
  }
  if (values.senderNonDelivery !== base.senderNonDelivery) {
    out.notices = { ...out.notices, senderNonDelivery: values.senderNonDelivery };
  }
  if (values.alertsEnabled !== base.alertsEnabled) {
    out.alerts = { ...out.alerts, enabled: values.alertsEnabled };
  }
  if (values.platformTagHeader !== base.platformTagHeader) {
    out.tagging = { ...out.tagging, platformTagHeader: values.platformTagHeader };
  }
  if (values.platformTagOutbound !== base.platformTagOutbound) {
    out.tagging = { ...out.tagging, platformTagOutbound: values.platformTagOutbound };
  }
  return out;
}

type SwitchKey = Exclude<keyof SettingsValues, 'recipientSplit'>;
const SWITCHES: ReadonlyArray<{ key: SwitchKey; label: string; description: string }> = [
  {
    key: 'allowRecommendationOverrides',
    label: 'Recommendation overrides',
    description:
      'Rules marked as overrides may replace a level-only platform recommendation with their decision. The strictness floor (hard blocks, failures, DLP holds) still applies.',
  },
  {
    key: 'senderNonDelivery',
    label: 'Sender non-delivery notices',
    description: 'Senders of rejected outbound mail are told that it was not delivered.',
  },
  {
    key: 'alertsEnabled',
    label: 'Policy alerts',
    description: 'ALERT actions are mailed to the users who may publish policies.',
  },
  {
    key: 'platformTagHeader',
    label: 'Platform tag header',
    description: 'Delivered copies carry the platform tag header when the recommendation tags.',
  },
  {
    key: 'platformTagOutbound',
    label: 'Platform tag on outbound mail',
    description: 'Outbound mail is tagged too (off: only inbound and internal mail).',
  },
];

/** Policy settings (`GET`/`PUT /policy-settings`, design B13): an editable form with `policy:publish`. */
export function PolicySettingsTab() {
  const settings = useApiQuery('PolicySettingsController_get_v1');
  const canEdit = useCan('PolicySettingsController_put_v1');
  const [saved, setSaved] = useState<string | null>(null);
  if (settings.isLoading) return <LoadingState label="Loading policy settings" rows={6} />;
  if (settings.error || !settings.data) {
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  }
  const s = settings.data;
  return (
    <div className="grid gap-4">
      {canEdit ? (
        <SettingsForm
          key={s.rowVersion}
          settings={s}
          onSaved={(generation) => setSaved(generation)}
          onReload={() => void settings.refetch()}
        />
      ) : (
        <EffectiveSettings settings={s} />
      )}
      {saved ? (
        <div role="status" className="rounded-md border bg-card p-3">
          <NextEvaluationNote generation={saved} />
        </div>
      ) : null}
      <Section title="Version">
        <DetailList
          items={[
            {
              label: 'Generation',
              value: <span className="font-mono text-xs">{s.generation}</span>,
            },
            { label: 'Row version', value: formatNumber(s.rowVersion) },
            {
              label: 'Settings hash',
              value: s.settingsSha256 ? (
                <span className="font-mono text-xs break-all">{s.settingsSha256}</span>
              ) : (
                <span className="text-muted-foreground">Defaults (nothing stored)</span>
              ),
            },
            {
              label: 'Updated',
              value: <DateTime value={s.updatedAt} mode="absolute" emptyLabel="Never" />,
            },
            {
              label: 'Violations',
              value:
                s.violations.length === 0 ? (
                  'None'
                ) : (
                  <ul className="grid gap-1 text-xs">
                    {s.violations.map((v, i) => (
                      <li key={i}>
                        <span className="font-mono">{v.path}</span>: {v.message}
                      </li>
                    ))}
                  </ul>
                ),
            },
          ]}
        />
      </Section>
    </div>
  );
}

function EffectiveSettings({ settings }: { settings: Settings }) {
  const e = settings.effective;
  return (
    <Section title="Effective policy settings" description="What applies to the next evaluation.">
      <DetailList
        items={[
          {
            label: 'Recommendation overrides',
            value: <YesNo value={e.allowRecommendationOverrides} />,
          },
          {
            label: 'Per-recipient evaluation',
            value:
              e.recipientSplit === undefined ? (
                <span className="text-muted-foreground">Platform default</span>
              ) : (
                <YesNo value={e.recipientSplit} />
              ),
          },
          {
            label: 'Sender non-delivery notices',
            value: <YesNo value={e.notices.senderNonDelivery} />,
          },
          { label: 'Policy alerts', value: <YesNo value={e.alerts.enabled} /> },
          { label: 'Platform tag header', value: <YesNo value={e.tagging.platformTagHeader} /> },
          {
            label: 'Platform tag on outbound mail',
            value: <YesNo value={e.tagging.platformTagOutbound} />,
          },
        ]}
      />
    </Section>
  );
}

function SettingsForm({
  settings,
  onSaved,
  onReload,
}: {
  settings: Settings;
  onSaved: (generation: string) => void;
  onReload: () => void;
}) {
  const ids = { split: useId(), base: useId() };
  const [values, setValues] = useState<SettingsValues>(() => settingsValuesOf(settings));
  const [confirmOverrides, setConfirmOverrides] = useState(false);
  const [messages, setMessages] = useState<string[]>([]);
  const catalog = useApiQuery('PolicyToolsController_catalog_v1', undefined, {
    staleTime: CATALOG_STALE_MS,
  });
  const platformSplit = catalog.data?.settingsDefaults.recipientSplit;
  const put = useApiMutation('PolicySettingsController_put_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Policy settings saved',
  });
  const base = settingsValuesOf(settings);
  const dirty = (Object.keys(values) as Array<keyof SettingsValues>).some(
    (key) => values[key] !== base[key],
  );
  const conflict = put.error?.code === 'policy_conflict';
  const violations = put.error?.code === 'policy_settings_invalid' ? violationsOf(put.error) : [];

  const save = async () => {
    setMessages([]);
    const outcome = await put.submit({
      body: { settings: settingsBody(settings, values), expectedRowVersion: settings.rowVersion },
    });
    if (outcome.ok) {
      onSaved(outcome.data.generation);
      return true;
    }
    if (outcome.error.code === 'policy_conflict') {
      const current = detailNumber(outcome.error, 'currentRowVersion');
      setMessages([
        `The settings changed since they were loaded${current !== null ? ` (row version ${current})` : ''}. Reload them and apply your change again.`,
      ]);
    } else if (outcome.error.status !== 429 && outcome.error.code !== 'policy_settings_invalid') {
      setMessages(outcome.error.messages);
    }
    return false;
  };

  const submit = () => {
    if (values.allowRecommendationOverrides && !base.allowRecommendationOverrides) {
      setConfirmOverrides(true);
      return;
    }
    void save();
  };

  return (
    <Section
      title="Policy settings"
      description="Organization-wide policy behaviour. A change increments the policy generation and applies to the next evaluation only."
    >
      <form
        aria-label="Policy settings"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
        className="grid min-w-0 gap-4"
      >
        <FormErrorSummary messages={messages} requestId={put.error?.requestId} />
        {violations.length > 0 ? (
          <ul role="alert" className="grid gap-1 text-sm text-destructive">
            {violations.map((v, i) => (
              <li key={i}>
                <span className="font-mono text-xs">{v.path}</span>
                {`: ${v.message}`}
              </li>
            ))}
          </ul>
        ) : null}
        <ul className="grid gap-3">
          {SWITCHES.map((item) => {
            const id = `${ids.base}-${item.key}`;
            return (
              <li key={item.key} className="flex items-start gap-3">
                <Switch
                  id={id}
                  checked={values[item.key]}
                  onCheckedChange={(checked) =>
                    setValues((current) => ({ ...current, [item.key]: checked }))
                  }
                  aria-describedby={`${id}-desc`}
                />
                <div className="grid gap-0.5">
                  <Label htmlFor={id}>{item.label}</Label>
                  <p id={`${id}-desc`} className="text-xs text-muted-foreground">
                    {item.description}
                  </p>
                </div>
              </li>
            );
          })}
        </ul>
        <div className="grid max-w-sm gap-1">
          <Label id={ids.split}>Per-recipient evaluation</Label>
          <ChoiceSelect
            labelledBy={ids.split}
            describedBy={`${ids.split}-desc`}
            value={values.recipientSplit}
            options={[
              {
                value: 'default',
                label:
                  platformSplit === undefined
                    ? 'Platform default'
                    : `Platform default (${platformSplit ? 'on' : 'off'})`,
              },
              { value: 'on', label: 'On' },
              { value: 'off', label: 'Off' },
            ]}
            onChange={(value) =>
              setValues((current) => ({
                ...current,
                recipientSplit:
                  (value as SettingsValues['recipientSplit'] | undefined) ?? 'default',
              }))
            }
          />
          <p id={`${ids.split}-desc`} className="text-xs text-muted-foreground">
            Decide per recipient when rules name recipients (one delivered copy for the allowed
            ones; the others are held or rejected).
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={!dirty || put.isPending || put.retryAfterSeconds > 0}>
            {put.isPending ? 'Saving …' : 'Save settings'}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!dirty || put.isPending}
            onClick={() => {
              setValues(base);
              setMessages([]);
              put.reset();
            }}
          >
            Discard changes
          </Button>
          {conflict ? (
            <Button type="button" variant="outline" onClick={onReload}>
              Reload the settings
            </Button>
          ) : null}
        </div>
        {put.error && !conflict && put.error.code !== 'policy_settings_invalid' ? (
          <ErrorState error={put.error} compact />
        ) : null}
      </form>
      <ConfirmDialog
        open={confirmOverrides}
        onOpenChange={setConfirmOverrides}
        title="Allow recommendation overrides?"
        description={
          <div className="grid gap-2">
            <p>
              Rules marked as overrides may then replace a level-only platform recommendation with
              their own decision, for example allow a partner’s message the risk score would hold.
            </p>
            <p>
              Each applied override is recorded in the evaluation and the change of this setting is
              audited. Hard blocks, engine failures and DLP holds are never overridden.
            </p>
          </div>
        }
        confirmLabel="Allow overrides and save"
        pending={put.isPending}
        onConfirm={() => save()}
      />
    </Section>
  );
}
