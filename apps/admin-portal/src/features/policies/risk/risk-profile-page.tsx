'use client';

import { RotateCcwIcon, SaveIcon, SendIcon, Trash2Icon } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useCallback, useId, useMemo, useState, type ReactNode } from 'react';
import { DateTime } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useUnsavedChanges } from '@/hooks/use-unsaved-changes';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { DetailList, EnumBadge, Section, YesNo } from '@/features/messages/controls';
import { isUuid } from '@/features/domains/kit';
import { ChoiceSelect, IntegerInput } from '../builder/inputs';
import { Toolbar, UnsavedChangesDialog } from '../editor/layout';
import { DefinitionJson } from '../editor/json-view';
import { policiesTabHref } from '../links';
import { detailNumber, RISK_QUERIES } from '../queries';
import { VERSION_STATUS_TONE } from '../semantic';
import {
  DeleteRiskDraftDialog,
  RiskActivateDialog,
  RiskPublishDialog,
  riskActivationLabel,
} from './risk-dialogs';
import {
  inputPathsOf,
  mergeOverrides,
  overridesOf,
  setLeaf,
  TRUST_MODES,
  unplacedViolations,
  violationsAt,
  type EffectiveProfile,
  type PlatformView,
  type RiskViolation,
} from './risk-model';

type RiskVersion = SuccessBody<'RiskProfilesController_getVersion_v1'>;
type Profile = SuccessBody<'RiskProfilesController_profile_v1'>;
type Range = { min: number; max: number };

const isRange = (value: unknown): value is Range =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as Range).min === 'number' &&
  typeof (value as Range).max === 'number';

const RISK_TAB_HREF = policiesTabHref('risk');

/**
 * `/policies/risk-profile/[versionId]` (design B13, B17): a risk-profile draft editor whose form
 * is generated from `GET /risk-scoring/platform-profile` (bounds, tunable groups, the hard-block
 * catalogue); published versions are shown read-only. Saving sends only the overrides that
 * differ from the platform profile; the api validates every bound.
 */
export function RiskProfileVersionPage({ versionId }: { versionId: string }) {
  return (
    <RouteGate gate={['RiskProfilesController_getVersion_v1']}>
      {isUuid(versionId) ? <RiskVersionLoader versionId={versionId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function RiskVersionLoader({ versionId }: { versionId: string }) {
  const version = useApiQuery('RiskProfilesController_getVersion_v1', { path: { versionId } });
  const platform = useApiQuery('RiskProfilesController_platformProfile_v1', undefined, {
    staleTime: 300_000,
  });
  const profile = useApiQuery('RiskProfilesController_profile_v1');
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(async () => {
    await Promise.all([version.refetch(), profile.refetch()]);
    setNonce((n) => n + 1);
  }, [version, profile]);
  const breadcrumbs = [
    { label: 'Policy management', href: '/policies' },
    { label: 'Risk scoring', href: RISK_TAB_HREF },
    { label: version.data ? `Version ${version.data.versionNo}` : 'Version' },
  ];
  if (version.error instanceof ApiError && version.error.status === 404) return <NotFoundView />;
  if (version.isLoading || platform.isLoading || profile.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Risk profile" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the risk profile version" rows={8} />
      </div>
    );
  }
  const error = version.error ?? platform.error ?? profile.error;
  if (error || !version.data || !platform.data || !profile.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Risk profile" breadcrumbs={breadcrumbs} />
        <ErrorState
          error={error}
          onRetry={() => {
            void version.refetch();
            void platform.refetch();
            void profile.refetch();
          }}
        />
      </div>
    );
  }
  return (
    <RiskVersionWorkspace
      key={nonce}
      version={version.data}
      platform={platform.data}
      profile={profile.data}
      breadcrumbs={breadcrumbs}
      onReload={reload}
    />
  );
}

function RiskVersionWorkspace({
  version: initialVersion,
  platform,
  profile,
  breadcrumbs,
  onReload,
}: {
  version: RiskVersion;
  platform: PlatformView;
  profile: Profile;
  breadcrumbs: Array<{ label: string; href?: string }>;
  onReload: () => Promise<void>;
}) {
  const router = useRouter();
  const canUpdate = useCan('RiskProfilesController_updateDraft_v1');
  const canPublish = useCan('RiskProfilesController_publish_v1');
  const canActivate = useCan('RiskProfilesController_activate_v1');
  const canDelete = useCan('RiskProfilesController_deleteDraft_v1');
  const [loaded, setLoaded] = useState(initialVersion);
  const draft = loaded.status === 'draft';
  const editable = draft && canUpdate;
  const [values, setValues] = useState<EffectiveProfile>(() =>
    mergeOverrides(platform.profile, initialVersion.overrides),
  );
  const [baseline, setBaseline] = useState(() => JSON.stringify(values));
  const [note, setNote] = useState(initialVersion.changeNote ?? '');
  const [violations, setViolations] = useState<RiskViolation[]>(
    () => initialVersion.resolved.violations,
  );
  const [problem, setProblem] = useState<{ text: string; reload: boolean } | null>(null);
  const [dialog, setDialog] = useState<'publish' | 'activate' | 'delete' | null>(null);
  const dirty =
    editable && (JSON.stringify(values) !== baseline || note.trim() !== (loaded.changeNote ?? ''));
  const guard = useUnsavedChanges(dirty, (href) => router.push(href));
  const overrides = useMemo(
    () => overridesOf(values, platform.profile, platform.bounds.tunableGroups),
    [values, platform],
  );
  const inputPaths = useMemo(() => inputPathsOf(platform), [platform]);
  const save = useApiMutation('RiskProfilesController_updateDraft_v1', {
    invalidates: RISK_QUERIES,
    successMessage: 'Risk-profile draft saved',
  });
  const activeNo = profile.active.versionNo;

  const submit = async () => {
    setProblem(null);
    const sent = JSON.stringify(values);
    const changeNote = note.trim();
    const outcome = await save.submit({
      path: { versionId: loaded.id },
      body: {
        overrides,
        changeNote: changeNote === '' ? null : changeNote,
        expectedRowVersion: loaded.rowVersion,
      },
    });
    if (outcome.ok) {
      setLoaded(outcome.data);
      setBaseline(sent);
      setViolations(outcome.data.resolved.violations);
      return;
    }
    const error = outcome.error;
    if (error.code === 'risk_profile_invalid') {
      const raw = error.details.violations;
      setViolations(
        Array.isArray(raw)
          ? raw.filter(
              (v): v is RiskViolation =>
                typeof v === 'object' &&
                v !== null &&
                typeof (v as RiskViolation).path === 'string' &&
                typeof (v as RiskViolation).message === 'string',
            )
          : [],
      );
      setProblem({
        text: 'The platform bounds do not accept these values; see the fields marked below.',
        reload: false,
      });
    } else if (error.code === 'risk_profile_version_conflict') {
      const current = detailNumber(error, 'currentRowVersion');
      setProblem({
        text: `Someone saved this draft since you opened it${current !== null ? ` (row version ${current})` : ''}. Reload it and apply your change again.`,
        reload: true,
      });
    } else if (error.code === 'risk_profile_version_immutable') {
      setProblem({
        text: 'This version was published meanwhile and can no longer change.',
        reload: true,
      });
    }
  };

  const formLevel = unplacedViolations(violations, inputPaths);
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={`Risk profile v${loaded.versionNo}`}
        breadcrumbs={breadcrumbs}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <EnumBadge value={loaded.status} tones={VERSION_STATUS_TONE} />
            {loaded.active ? <EnumBadge value="active" tones={{ active: 'success' }} /> : null}
            <span>{editable ? 'Edit mode' : 'View mode'}</span>
            {dirty ? <span className="font-medium text-foreground">Unsaved changes</span> : null}
          </span>
        }
      />
      <UnsavedChangesDialog guard={guard} />
      <p className="text-sm text-muted-foreground">{platform.notice}</p>
      <Toolbar label="Risk-profile actions">
        {editable ? (
          <Button
            onClick={() => void submit()}
            disabled={!dirty || save.isPending || save.retryAfterSeconds > 0}
          >
            <SaveIcon aria-hidden />
            {save.isPending ? 'Saving …' : 'Save'}
          </Button>
        ) : null}
        {draft && canPublish ? (
          <Button variant="outline" onClick={() => setDialog('publish')} disabled={dirty}>
            <SendIcon aria-hidden />
            Publish…
          </Button>
        ) : null}
        {loaded.status === 'published' && !loaded.active && canActivate ? (
          <Button variant="outline" onClick={() => setDialog('activate')}>
            <RotateCcwIcon aria-hidden />
            {riskActivationLabel(loaded.versionNo, activeNo)}
          </Button>
        ) : null}
        {draft && canDelete ? (
          <Button variant="ghost" onClick={() => setDialog('delete')}>
            <Trash2Icon aria-hidden />
            Delete draft
          </Button>
        ) : null}
        <Button variant="ghost" onClick={() => guard.guard(() => router.push(RISK_TAB_HREF))}>
          Back to risk scoring
        </Button>
      </Toolbar>
      {dirty && draft && canPublish ? (
        <p className="text-xs text-muted-foreground">Save your changes before publishing.</p>
      ) : null}
      {problem ? (
        <div role="alert" className="flex flex-wrap items-center gap-2 text-sm text-destructive">
          <span>{problem.text}</span>
          {problem.reload ? (
            <Button size="sm" variant="outline" onClick={() => void onReload()}>
              Reload the version
            </Button>
          ) : null}
        </div>
      ) : null}
      {save.error &&
      ![
        'risk_profile_invalid',
        'risk_profile_version_conflict',
        'risk_profile_version_immutable',
      ].includes(save.error.code) ? (
        <ErrorState error={save.error} compact />
      ) : null}
      {!loaded.resolved.valid ? (
        <p role="alert" className="text-sm text-destructive">
          The platform bounds no longer accept this version; scoring falls back to the platform
          profile while it is active.
        </p>
      ) : null}
      {formLevel.length > 0 ? (
        <div role="alert">
          <ul
            aria-label="Problems with the profile"
            className="grid gap-1 text-sm text-destructive"
          >
            {formLevel.map((v, i) => (
              <li key={`${v.path}-${i}`}>
                <span className="font-mono text-xs">{v.path}</span>
                {`: ${v.message}`}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <RiskForm
        platform={platform}
        values={values}
        onChange={setValues}
        editable={editable}
        violations={violations}
      />
      <Section title="Version details">
        <DetailList
          items={[
            {
              label: 'Change note',
              value: editable ? (
                <ChangeNote value={note} onChange={setNote} />
              ) : (
                (loaded.changeNote ?? <span className="text-muted-foreground">None</span>)
              ),
            },
            {
              label: 'Base profile',
              value: <span className="font-mono text-xs">{loaded.baseProfile}</span>,
            },
            {
              label: 'Valid against the platform bounds',
              value: <YesNo value={loaded.resolved.valid} />,
            },
            { label: 'Created', value: <DateTime value={loaded.createdAt} mode="absolute" /> },
            { label: 'Updated', value: <DateTime value={loaded.updatedAt} mode="absolute" /> },
            {
              label: 'Published',
              value: (
                <DateTime value={loaded.publishedAt} mode="absolute" emptyLabel="Not published" />
              ),
            },
          ]}
        />
      </Section>
      <Section
        title="Overrides document"
        description={
          editable
            ? 'What Save sends: only the values that differ from the platform profile.'
            : 'The stored overrides of this version.'
        }
      >
        <DefinitionJson
          definition={editable ? overrides : loaded.overrides}
          label="Risk-profile overrides"
        />
      </Section>
      {dialog === 'publish' ? (
        <RiskPublishDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          versionId={loaded.id}
          versionNo={loaded.versionNo}
          rowVersion={loaded.rowVersion}
          onDone={() => void onReload()}
        />
      ) : null}
      {dialog === 'activate' ? (
        <RiskActivateDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          versionId={loaded.id}
          versionNo={loaded.versionNo}
          activeVersionNo={activeNo}
          profileVersion={profile.profileVersion}
          onDone={() => void onReload()}
        />
      ) : null}
      {dialog === 'delete' ? (
        <DeleteRiskDraftDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null);
          }}
          versionId={loaded.id}
          versionNo={loaded.versionNo}
          rowVersion={loaded.rowVersion}
          onDeleted={() => router.push(RISK_TAB_HREF)}
        />
      ) : null}
    </div>
  );
}

function ChangeNote({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const id = useId();
  return (
    <>
      <Label htmlFor={id} className="sr-only">
        Change note
      </Label>
      <Input
        id={id}
        value={value}
        maxLength={512}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Why this version exists (optional)"
        autoComplete="off"
      />
    </>
  );
}

/** One labelled field of the generated form with its help text and server violations. */
function Field({
  label,
  help,
  violations,
  children,
}: {
  label: string;
  help?: string;
  violations: readonly RiskViolation[];
  children: (ids: { labelId: string; describedBy: string; invalid: boolean }) => ReactNode;
}) {
  const labelId = useId();
  const helpId = useId();
  const errorId = useId();
  const describedBy = [help ? helpId : null, violations.length > 0 ? errorId : null]
    .filter(Boolean)
    .join(' ');
  return (
    <div className="grid min-w-0 content-start gap-1">
      <Label id={labelId} className="text-xs text-muted-foreground">
        {label}
      </Label>
      {children({ labelId, describedBy, invalid: violations.length > 0 })}
      {help ? (
        <p id={helpId} className="text-xs text-muted-foreground">
          {help}
        </p>
      ) : null}
      {violations.length > 0 ? (
        <ul id={errorId} className="grid gap-0.5 text-xs font-medium text-destructive">
          {violations.map((v, i) => (
            <li key={i}>{v.message}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function RiskForm({
  platform,
  values,
  onChange,
  editable,
  violations,
}: {
  platform: PlatformView;
  values: EffectiveProfile;
  onChange: (values: EffectiveProfile) => void;
  editable: boolean;
  violations: readonly RiskViolation[];
}) {
  const b = platform.bounds;
  const p = platform.profile;
  const v = values as unknown as Record<string, Record<string, unknown>>;
  const base = p as unknown as Record<string, Record<string, unknown>>;
  const at = (path: string) => violationsAt(violations, path);
  const set = (
    section: Parameters<typeof setLeaf>[1],
    key: string,
    value: unknown,
    subkey?: string,
  ) => onChange(setLeaf(values, section, key, value, subkey));

  const numberField = (
    section: Parameters<typeof setLeaf>[1],
    key: string,
    label: string,
    range: Range,
    extra?: string,
  ) => {
    const current = v[section]?.[key];
    const platformValue = base[section]?.[key];
    return (
      <Field
        key={`${section}.${key}`}
        label={label}
        help={`Between ${range.min} and ${range.max}. Platform default: ${String(platformValue)}.${extra ? ` ${extra}` : ''}`}
        violations={at(`${section}.${key}`)}
      >
        {({ labelId, describedBy }) =>
          editable ? (
            <IntegerInput
              value={typeof current === 'number' ? current : undefined}
              min={range.min}
              max={range.max}
              labelledBy={labelId}
              describedBy={describedBy || undefined}
              onChange={(next) => {
                if (next !== undefined) set(section, key, next);
              }}
              className="max-w-40"
            />
          ) : (
            <p className="text-sm tabular-nums" aria-labelledby={labelId}>
              {String(current)}
            </p>
          )
        }
      </Field>
    );
  };

  const selectField = (
    section: Parameters<typeof setLeaf>[1],
    key: string,
    label: string,
    allowed: readonly string[],
    subkey?: string,
    extra?: string,
  ) => {
    const holder = v[section]?.[key];
    const current = subkey !== undefined ? (holder as Record<string, unknown>)?.[subkey] : holder;
    const baseHolder = base[section]?.[key];
    const platformValue =
      subkey !== undefined ? (baseHolder as Record<string, unknown>)?.[subkey] : baseHolder;
    const path = subkey !== undefined ? `${section}.${key}.${subkey}` : `${section}.${key}`;
    return (
      <Field
        key={path}
        label={label}
        help={`Platform default: ${humanize(String(platformValue))}.${extra ? ` ${extra}` : ''}`}
        violations={at(path)}
      >
        {({ labelId, describedBy, invalid }) =>
          editable ? (
            <ChoiceSelect
              labelledBy={labelId}
              describedBy={describedBy || undefined}
              invalid={invalid}
              value={typeof current === 'string' ? current : undefined}
              options={allowed.map((option) => ({ value: option, label: humanize(option) }))}
              disabled={allowed.length <= 1}
              onChange={(next) => {
                if (next !== undefined) set(section, key, next, subkey);
              }}
              className="max-w-56"
            />
          ) : (
            <p className="text-sm" aria-labelledby={labelId}>
              {humanize(String(current))}
            </p>
          )
        }
      </Field>
    );
  };

  const raiseOnly = (path: string) =>
    b.raiseOnly.includes(path) ? 'May only be raised above the platform default.' : undefined;

  return (
    <div className="grid min-w-0 gap-4" data-testid="risk-form">
      <Section
        title="Thresholds"
        description={`The score from which each level starts; each threshold at least ${b.thresholdMinGap} above the previous one.`}
      >
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Object.entries(b.thresholds).map(([level, range]) =>
            numberField('thresholds', level, `${humanize(level)} from score`, range),
          )}
        </div>
      </Section>
      <Section
        title="Recommended action per level"
        description="Actions never get weaker as the level rises."
      >
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(b.actions).map(([level, allowed]) =>
            selectField('actions', level, `${humanize(level)} risk`, allowed),
          )}
        </div>
      </Section>
      <Section
        title="Signal group weights"
        description="Multipliers in permille (1000 = the platform weight)."
      >
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {b.tunableGroups.map((group) =>
            numberField(
              'groupMultipliersPermille',
              group,
              humanize(group),
              b.groupMultiplierPermille,
            ),
          )}
        </div>
        {b.lockedGroups.length > 0 ? (
          <p className="text-xs text-muted-foreground">
            {`Locked at 1000: ${b.lockedGroups.map((g) => humanize(g)).join(', ')}.`}
          </p>
        ) : null}
      </Section>
      <Section
        title="Hard blocks"
        description="Platform verdicts that hold a message whatever the score."
      >
        <ul className="grid gap-3">
          {platform.hardBlocks.map((hb) => (
            <HardBlockRow
              key={hb.id}
              hardBlock={hb}
              value={(v.hardBlocks?.[hb.id] ?? {}) as { enabled?: boolean; action?: string }}
              editable={editable}
              violations={at(`hardBlocks.${hb.id}`)}
              onEnabled={(enabled) => set('hardBlocks', hb.id, enabled, 'enabled')}
              onAction={(action) => set('hardBlocks', hb.id, action, 'action')}
            />
          ))}
        </ul>
      </Section>
      <Section title="Engine failures and unknown results">
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(b.failures).map(([key, bound]) =>
            isRange(bound)
              ? numberField('failures', key, humanize(key), bound)
              : selectField(
                  'failures',
                  key,
                  humanize(key),
                  bound,
                  undefined,
                  raiseOnly(`failures.${key}`),
                ),
          )}
        </div>
      </Section>
      <Section title="Level floors">
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">
          {Object.entries(b.floors).map(([key, allowed]) =>
            selectField(
              'floors',
              key,
              humanize(key),
              allowed,
              undefined,
              raiseOnly(`floors.${key}`),
            ),
          )}
        </div>
      </Section>
      <Section title="Trust and AI">
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {selectField('trust', 'mode', 'Trusted sender handling', TRUST_MODES)}
          {numberField(
            'trust',
            'contentFactorPermille',
            'Content factor for trusted senders (permille)',
            b.trustContentFactorPermille,
          )}
          <AiSwitch
            value={values.ai.tagOnAiOnlyRaise}
            platformValue={p.ai.tagOnAiOnlyRaise}
            editable={editable}
            violations={at('ai.tagOnAiOnlyRaise')}
            onChange={(next) => set('ai', 'tagOnAiOnlyRaise', next)}
          />
        </div>
      </Section>
    </div>
  );
}

function HardBlockRow({
  hardBlock,
  value,
  editable,
  violations,
  onEnabled,
  onAction,
}: {
  hardBlock: PlatformView['hardBlocks'][number];
  value: { enabled?: boolean; action?: string };
  editable: boolean;
  violations: readonly RiskViolation[];
  onEnabled: (enabled: boolean) => void;
  onAction: (action: string) => void;
}) {
  const id = useId();
  const actionId = useId();
  const locked = hardBlock.control === 'locked';
  return (
    <li className="grid min-w-0 gap-2 rounded-md border p-3 sm:grid-cols-[minmax(0,1fr)_auto_14rem] sm:items-start">
      <div className="grid min-w-0 gap-0.5">
        <span className="font-mono text-xs break-all">{hardBlock.id}</span>
        <span className="text-xs text-muted-foreground">{`Fires when: ${hardBlock.firesWhen}. Verdict ${humanize(hardBlock.verdict)}.`}</span>
        {locked ? <span className="text-xs text-muted-foreground">Always on (locked).</span> : null}
        {violations.length > 0 ? (
          <ul className="grid gap-0.5 text-xs font-medium text-destructive">
            {violations.map((v, i) => (
              <li key={i}>{`${v.path}: ${v.message}`}</li>
            ))}
          </ul>
        ) : null}
      </div>
      <div className="flex items-center gap-2">
        {editable ? (
          <>
            <Switch
              id={id}
              checked={value.enabled === true}
              disabled={locked}
              onCheckedChange={onEnabled}
            />
            <Label htmlFor={id} className="font-normal">
              Enabled
            </Label>
          </>
        ) : (
          <p className="text-sm">
            Enabled: <YesNo value={value.enabled} />
          </p>
        )}
      </div>
      <div className="grid gap-1">
        <Label id={actionId} className="text-xs text-muted-foreground">
          Action
        </Label>
        {editable ? (
          <ChoiceSelect
            labelledBy={actionId}
            value={value.action}
            options={hardBlock.allowedActions.map((a) => ({ value: a, label: humanize(a) }))}
            disabled={hardBlock.allowedActions.length <= 1}
            onChange={(next) => {
              if (next !== undefined) onAction(next);
            }}
          />
        ) : (
          <p className="text-sm" aria-labelledby={actionId}>
            {value.action ? humanize(value.action) : 'None'}
          </p>
        )}
      </div>
    </li>
  );
}

function AiSwitch({
  value,
  platformValue,
  editable,
  violations,
  onChange,
}: {
  value: boolean;
  platformValue: boolean;
  editable: boolean;
  violations: readonly RiskViolation[];
  onChange: (value: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="grid content-start gap-1">
      <div className="flex items-center gap-2">
        {editable ? (
          <>
            <Switch
              id={id}
              checked={value}
              onCheckedChange={onChange}
              aria-describedby={`${id}-help`}
            />
            <Label htmlFor={id}>Tag messages raised by AI only</Label>
          </>
        ) : (
          <p className="text-sm">
            Tag messages raised by AI only: <YesNo value={value} />
          </p>
        )}
      </div>
      <p id={`${id}-help`} className="text-xs text-muted-foreground">
        {`Platform default: ${platformValue ? 'on' : 'off'}.`}
      </p>
      {violations.length > 0 ? (
        <ul className="grid gap-0.5 text-xs font-medium text-destructive">
          {violations.map((v, i) => (
            <li key={i}>{v.message}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
