'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Switch } from '@/components/ui/switch';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { Section } from '@/features/messages/controls';
import { ACTION_LABELS, labelOf } from '../model';
import { MfaPrompt, ProviderErrorSummary, useMfaSession } from './components';
import {
  PROVIDER_ACTIONS,
  PROVIDER_QUERIES,
  SETTINGS_BOUNDS,
  STREAM_LABELS,
  bindingSettingsOf,
  type BindingSettings,
  type ProviderDetail,
  type ProviderStream,
} from './model';

/**
 * The binding settings `ato-idp-binding/1` of one integration (D10): the whole document is sent
 * with the row version (`PATCH /ato/providers/{id}`, CAS). A `409 ato_provider_conflict` asks
 * to reload; a `400 ato_provider_settings_invalid` lists the api's paths. `sections="actions"`
 * shows only the action fields (Actions tab) but still sends the full document.
 */
export function ProviderSettingsForm({
  provider: p,
  sections,
  onReload,
}: {
  provider: ProviderDetail;
  sections: 'all' | 'actions';
  onReload?: () => void;
}) {
  const queryClient = useQueryClient();
  const canEdit = useCan('AtoProvidersController_update_v1') && p.status !== 'disabled';
  const mfa = useMfaSession();
  const [draft, setDraft] = useState<BindingSettings>(() => bindingSettingsOf(p.settings));
  const [baseVersion, setBaseVersion] = useState(p.rowVersion);
  const [numbers, setNumbers] = useState(() => numberTexts(bindingSettingsOf(p.settings)));
  const ids = { poll: useId(), backfill: useId(), sweep: useId(), group: useId(), ou: useId() };
  const update = useApiMutation('AtoProvidersController_update_v1', {
    invalidates: PROVIDER_QUERIES,
    successMessage: 'Identity provider settings saved',
  });

  // A newer version from the api (after a save or a reload) replaces the draft.
  useEffect(() => {
    if (p.rowVersion !== baseVersion) {
      const next = bindingSettingsOf(p.settings);
      setDraft(next);
      setNumbers(numberTexts(next));
      setBaseVersion(p.rowVersion);
      update.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset only on a new row version
  }, [p.rowVersion]);

  const readOnly = !canEdit;
  const streams = p.streamDetails.filter((s) => s.role !== 'unsupported');
  const primaryOf = (stream: ProviderStream) =>
    p.streamDetails.find((s) => s.stream === stream)?.primary ?? null;
  const setStream = (stream: ProviderStream, enabled: boolean) =>
    setDraft((d) => {
      const next = { ...d, streams: { ...d.streams, [stream]: { enabled } } };
      // Disabling a primary disables its companions (D10: a companion needs its primary).
      if (!enabled) {
        for (const s of p.streamDetails) {
          if (s.role === 'companion' && s.primary === stream) next.streams[s.stream] = { enabled };
        }
      }
      return next;
    });
  const numberError = (key: keyof typeof numbers): string | null => {
    const text = numbers[key].trim();
    if (key === 'sweep' && text === '') return null;
    const n = Number(text);
    const bound =
      key === 'poll'
        ? SETTINGS_BOUNDS.pollIntervalSeconds
        : key === 'backfill'
          ? SETTINGS_BOUNDS.backfillDays
          : SETTINGS_BOUNDS.sweepIntervalHours;
    return text === '' || !Number.isInteger(n) || n < bound.min || n > bound.max
      ? `Enter a whole number from ${bound.min} to ${bound.max}`
      : null;
  };
  const invalid =
    sections === 'all' &&
    (numberError('poll') !== null ||
      numberError('backfill') !== null ||
      numberError('sweep') !== null);

  const save = async () => {
    if (invalid) return;
    const settings: BindingSettings = {
      ...draft,
      ...(sections === 'all'
        ? {
            pollIntervalSeconds: Number(numbers.poll),
            backfillDays: Number(numbers.backfill),
            snapshot: {
              sweepIntervalHours: numbers.sweep.trim() === '' ? null : Number(numbers.sweep),
            },
          }
        : {}),
      mfaEnforcement: {
        groupId:
          p.provider === 'microsoft_entra' ? emptyToNull(draft.mfaEnforcement.groupId) : null,
        orgUnitPath:
          p.provider === 'google_workspace' ? emptyToNull(draft.mfaEnforcement.orgUnitPath) : null,
      },
    };
    await update.submit({
      path: { integrationId: p.id },
      body: { rowVersion: p.rowVersion, settings },
    });
  };
  const reload = () => {
    update.reset();
    if (onReload) onReload();
    else void queryClient.invalidateQueries({ queryKey: ['AtoProvidersController_get_v1'] });
  };
  const conflict = update.error?.code === 'ato_provider_conflict';

  return (
    <Section
      title={sections === 'all' ? 'Settings' : 'Action settings'}
      description={
        sections === 'all'
          ? 'Streams, polling, backfill, mailbox sweep, actions and their configuration of this identity provider (settings version ' +
            `${p.settingsVersion}).`
          : 'Which provider actions may be requested, and their configuration.'
      }
    >
      <form
        className="grid gap-5"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        {p.settingsInvalid ? (
          <p role="note" className="text-sm text-destructive">
            The stored settings are no longer valid; the defaults apply until you save.
          </p>
        ) : null}
        {sections === 'all' ? (
          <>
            <fieldset className="grid gap-2">
              <legend className="mb-1 text-sm font-medium">Streams</legend>
              <ul className="grid gap-2 sm:grid-cols-2">
                {streams.map((s) => {
                  const primary = primaryOf(s.stream);
                  const blocked =
                    s.role === 'companion' && primary !== null && !draft.streams[primary].enabled;
                  const id = `setting-stream-${s.stream}`;
                  return (
                    <li key={s.stream} className="flex items-center gap-2">
                      <Switch
                        id={id}
                        disabled={readOnly || blocked}
                        checked={draft.streams[s.stream].enabled && !blocked}
                        onCheckedChange={(checked) => setStream(s.stream, checked === true)}
                      />
                      <Label htmlFor={id} className="text-sm font-normal">
                        {STREAM_LABELS[s.stream]}
                        {s.role === 'companion' && primary
                          ? ` (with ${STREAM_LABELS[primary].toLowerCase()})`
                          : ''}
                      </Label>
                    </li>
                  );
                })}
              </ul>
            </fieldset>
            <div className="grid gap-4 sm:grid-cols-3">
              <NumberField
                id={ids.poll}
                label="Poll interval (seconds)"
                hint={`${SETTINGS_BOUNDS.pollIntervalSeconds.min}–${SETTINGS_BOUNDS.pollIntervalSeconds.max}`}
                value={numbers.poll}
                error={numberError('poll')}
                disabled={readOnly}
                onChange={(poll) => setNumbers((n) => ({ ...n, poll }))}
              />
              <NumberField
                id={ids.backfill}
                label="Backfill days on (re)connect"
                hint={`${SETTINGS_BOUNDS.backfillDays.min}–${SETTINGS_BOUNDS.backfillDays.max}`}
                value={numbers.backfill}
                error={numberError('backfill')}
                disabled={readOnly}
                onChange={(backfill) => setNumbers((n) => ({ ...n, backfill }))}
              />
              <NumberField
                id={ids.sweep}
                label="Mailbox sweep interval (hours)"
                hint={`${SETTINGS_BOUNDS.sweepIntervalHours.min}–${SETTINGS_BOUNDS.sweepIntervalHours.max}; empty = provider default (${p.provider === 'google_workspace' ? 24 : 168} h)`}
                value={numbers.sweep}
                error={numberError('sweep')}
                disabled={readOnly}
                onChange={(sweep) => setNumbers((n) => ({ ...n, sweep }))}
              />
            </div>
          </>
        ) : null}
        <fieldset className="grid gap-2">
          <legend className="mb-1 text-sm font-medium">Actions</legend>
          <ul className="grid gap-2 sm:grid-cols-2">
            {PROVIDER_ACTIONS.map((a) => {
              const id = `setting-action-${sections}-${a}`;
              return (
                <li key={a} className="flex items-center gap-2">
                  <Switch
                    id={id}
                    disabled={readOnly}
                    checked={draft.actions[a].enabled}
                    onCheckedChange={(checked) =>
                      setDraft((d) => ({
                        ...d,
                        actions: { ...d.actions, [a]: { enabled: checked === true } },
                      }))
                    }
                  />
                  <Label htmlFor={id} className="text-sm font-normal">
                    {labelOf(ACTION_LABELS, a)}
                  </Label>
                </li>
              );
            })}
          </ul>
        </fieldset>
        {p.provider === 'microsoft_entra' ? (
          <div className="grid gap-1.5">
            <Label htmlFor={ids.group}>MFA enforcement group (object id)</Label>
            <Input
              id={ids.group}
              className="max-w-md font-mono"
              disabled={readOnly}
              value={draft.mfaEnforcement.groupId ?? ''}
              placeholder="00000000-0000-0000-0000-000000000000"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  mfaEnforcement: { ...d.mfaEnforcement, groupId: e.target.value },
                }))
              }
            />
            <p className="text-xs text-muted-foreground">
              “Require MFA” adds the user to this Entra group, which your Conditional Access policy
              requires MFA for. Empty = the action is not configured.
            </p>
          </div>
        ) : (
          <div className="grid gap-1.5">
            <Label htmlFor={ids.ou}>2-step verification organizational unit</Label>
            <Input
              id={ids.ou}
              className="max-w-md font-mono"
              disabled={readOnly}
              value={draft.mfaEnforcement.orgUnitPath ?? ''}
              placeholder="/Enforced 2SV"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  mfaEnforcement: { ...d.mfaEnforcement, orgUnitPath: e.target.value },
                }))
              }
            />
            <p className="text-xs text-muted-foreground">
              “Require MFA” moves the user into this organizational unit (it changes every policy of
              that unit for the user; roll back restores the previous unit). Starts with “/”. Empty
              = the action is not configured.
            </p>
          </div>
        )}
        {p.provider === 'microsoft_entra' ? (
          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">Forwarding inbox rules</legend>
            <RadioGroup
              value={draft.forwardingRemoval.mode}
              onValueChange={(mode) =>
                setDraft((d) => ({
                  ...d,
                  forwardingRemoval: { mode: mode === 'delete' ? 'delete' : 'disable' },
                }))
              }
              aria-label="Forwarding inbox rules"
              disabled={readOnly}
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem id={`${ids.group}-disable`} value="disable" />
                <Label htmlFor={`${ids.group}-disable`} className="text-sm font-normal">
                  Disable the rule (can be rolled back)
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem id={`${ids.group}-delete`} value="delete" />
                <Label htmlFor={`${ids.group}-delete`} className="text-sm font-normal">
                  Delete the rule (no roll back)
                </Label>
              </div>
            </RadioGroup>
          </fieldset>
        ) : null}
        {!readOnly && !mfa ? <MfaPrompt action="Changing identity-provider settings" /> : null}
        {update.error ? (
          <div className="grid gap-2">
            <ProviderErrorSummary error={update.error} />
            {conflict ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="justify-self-start"
                onClick={reload}
              >
                Reload the current settings
              </Button>
            ) : null}
          </div>
        ) : null}
        {readOnly ? (
          <p className="text-xs text-muted-foreground">
            {p.status === 'disabled'
              ? 'This identity provider was removed; its settings are read-only.'
              : 'Changing these settings needs ato:configure.'}
          </p>
        ) : (
          <Button
            type="submit"
            className="justify-self-start"
            disabled={!mfa || invalid || update.isPending || conflict}
          >
            Save settings
          </Button>
        )}
      </form>
    </Section>
  );
}

function numberTexts(s: BindingSettings) {
  return {
    poll: String(s.pollIntervalSeconds),
    backfill: String(s.backfillDays),
    sweep: s.snapshot.sweepIntervalHours === null ? '' : String(s.snapshot.sweepIntervalHours),
  };
}

const emptyToNull = (value: string | null): string | null => {
  const trimmed = value?.trim() ?? '';
  return trimmed === '' ? null : trimmed;
};

function NumberField({
  id,
  label,
  hint,
  value,
  error,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  value: string;
  error: string | null;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid content-start gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        className="w-40"
        disabled={disabled}
        value={value}
        aria-invalid={error ? true : undefined}
        aria-describedby={`${id}-hint${error ? ` ${id}-error` : ''}`}
        onChange={(e) => onChange(e.target.value)}
      />
      <p id={`${id}-hint`} className="text-xs text-muted-foreground">
        {hint}
      </p>
      {error ? (
        <p id={`${id}-error`} className="text-xs font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
