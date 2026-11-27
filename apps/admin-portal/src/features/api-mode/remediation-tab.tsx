'use client';

import { useQueryClient } from '@tanstack/react-query';
import { ArrowDownIcon, ArrowUpIcon, PlusIcon, TrashIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { FormDialog, LabelledSelect, MutationError, Section } from '@/features/domains/kit';
import {
  DETECT_ONLY_NOTICE,
  HARD_DELETE_WARNING,
  MAX_RULES,
  MODE_TEXT,
  POLICY_SOURCE_LABEL,
  PolicyModeBadge,
  RULE_ACTIONS,
  RULE_LEVELS,
  RULE_VERDICTS,
  VERDICT_LABEL,
  actionLabel,
  remediationErrorText,
  ruleConditionText,
  type DomainOverride,
  type PolicyDocument,
  type PolicyMode,
  type RemediationPolicyView,
  type RuleAction,
  type RuleLevel,
  type RuleVerdict,
} from './remediation-model';

/** Queries a policy change makes stale (the policy view and the coverage badge). */
export const POLICY_QUERIES: readonly OperationId[] = [
  'ApiModeRemediationController_getPolicy_v1',
  'ApiModeController_overview_v1',
];

// ---- the editable draft ----------------------------------------------------------------------

export interface RuleDraft {
  readonly key: string;
  id: string;
  verdicts: RuleVerdict[];
  minLevel: RuleLevel | '';
  maxLevel: RuleLevel | '';
  hardBlock: 'any' | 'true' | 'false';
  minScore: string;
  action: RuleAction;
}

export interface PolicyDraft {
  mode: PolicyMode;
  rules: RuleDraft[];
}

let draftKey = 0;
const nextKey = () => `rule-${(draftKey += 1)}`;

/** The editable form of a stored document (`api-remediation-policy/1`, R2.1). */
export function draftOf(mode: PolicyMode, document: PolicyDocument): PolicyDraft {
  return {
    mode,
    rules: document.rules.map((rule) => ({
      key: nextKey(),
      id: rule.id,
      verdicts: rule.when.verdicts.filter((v): v is RuleVerdict =>
        (RULE_VERDICTS as readonly string[]).includes(v),
      ),
      minLevel: rule.when.minLevel ?? '',
      maxLevel: rule.when.maxLevel ?? '',
      hardBlock: rule.when.hardBlock === undefined ? 'any' : rule.when.hardBlock ? 'true' : 'false',
      minScore: rule.when.minScore === undefined ? '' : String(rule.when.minScore),
      action: rule.action,
    })),
  };
}

/** The document the PUT sends: only the bounds that are set (strict schema, R2.1). */
export function documentOf(draft: PolicyDraft): PolicyDocument {
  return {
    v: 1,
    rules: draft.rules.map((rule) => ({
      id: rule.id.trim(),
      when: {
        verdicts: [...rule.verdicts],
        ...(rule.minLevel ? { minLevel: rule.minLevel } : {}),
        ...(rule.maxLevel ? { maxLevel: rule.maxLevel } : {}),
        ...(rule.hardBlock === 'any' ? {} : { hardBlock: rule.hardBlock === 'true' }),
        ...(rule.minScore.trim() === '' ? {} : { minScore: Number(rule.minScore.trim()) }),
      },
      action: rule.action,
    })),
  };
}

const RULE_ID = /^[a-z0-9_-]{1,48}$/;

/**
 * Form hints before the PUT (the api validates the document with the strict schema and stays
 * authoritative; its `validation_failed` paths are shown as they come).
 */
export function validateDraft(draft: PolicyDraft): string[] {
  const errors: string[] = [];
  if (draft.rules.length === 0) errors.push('Add at least one rule.');
  if (draft.rules.length > MAX_RULES) errors.push(`At most ${MAX_RULES} rules.`);
  const seen = new Set<string>();
  draft.rules.forEach((rule, index) => {
    const n = index + 1;
    const id = rule.id.trim();
    if (!RULE_ID.test(id))
      errors.push(`Rule ${n}: the rule ID uses 1-48 characters a-z, 0-9, - and _.`);
    else if (seen.has(id)) errors.push(`Rule ${n}: the rule ID ${id} is used twice.`);
    seen.add(id);
    if (rule.verdicts.length === 0) errors.push(`Rule ${n}: choose at least one verdict.`);
    if (
      rule.minLevel &&
      rule.maxLevel &&
      RULE_LEVELS.indexOf(rule.maxLevel) < RULE_LEVELS.indexOf(rule.minLevel)
    )
      errors.push(`Rule ${n}: the maximum level is below the minimum level.`);
    const score = rule.minScore.trim();
    if (score !== '' && !(/^\d{1,4}$/.test(score) && Number(score) <= 1000))
      errors.push(`Rule ${n}: the minimum risk score is a whole number from 0 to 1000.`);
  });
  return errors;
}

function emptyRule(index: number): RuleDraft {
  return {
    key: nextKey(),
    id: `rule-${index + 1}`,
    verdicts: [],
    minLevel: '',
    maxLevel: '',
    hardBlock: 'any',
    minScore: '',
    action: 'tag',
  };
}

// ---- read-only view --------------------------------------------------------------------------

/** The rules of a document as a table (read-only users and the overrides list). */
export function PolicyRulesTable({ document, label }: { document: PolicyDocument; label: string }) {
  return (
    <div className="relative overflow-x-auto">
      <Table>
        <TableCaption className="sr-only">{label}</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>#</TableHead>
            <TableHead>Rule</TableHead>
            <TableHead>When</TableHead>
            <TableHead>Mailbox action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {document.rules.map((rule, index) => (
            <TableRow key={`${rule.id}-${index}`}>
              <TableCell className="tabular-nums">{index + 1}</TableCell>
              <TableCell>
                <UntrustedText value={rule.id} mono maxLength={48} />
              </TableCell>
              <TableCell className="text-sm">{ruleConditionText(rule)}</TableCell>
              <TableCell className="text-sm">{actionLabel(rule.action)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// ---- the editor ------------------------------------------------------------------------------

const LEVEL_OPTIONS = [
  { value: 'any', label: 'Any' },
  ...RULE_LEVELS.map((level) => ({
    value: level,
    label: level[0]!.toUpperCase() + level.slice(1),
  })),
];
const HARD_BLOCK_OPTIONS = [
  { value: 'any', label: 'Any' },
  { value: 'true', label: 'Hard block required' },
  { value: 'false', label: 'No hard block' },
];

function RuleEditor({
  rule,
  index,
  count,
  hardDeleteAvailable,
  onChange,
  onMove,
  onRemove,
}: {
  rule: RuleDraft;
  index: number;
  count: number;
  hardDeleteAvailable: boolean;
  onChange: (patch: Partial<RuleDraft>) => void;
  onMove: (delta: -1 | 1) => void;
  onRemove: () => void;
}) {
  const base = useId();
  const n = index + 1;
  const actions = RULE_ACTIONS.filter(
    (action) => action !== 'hard_delete' || hardDeleteAvailable || rule.action === 'hard_delete',
  );
  return (
    <li className="grid gap-3 rounded-md border p-3" aria-label={`Rule ${n}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold">
          Rule {n}
          {index === 0 ? (
            <span className="ml-2 text-xs font-normal text-muted-foreground">
              (evaluated first)
            </span>
          ) : null}
        </h4>
        <div className="flex gap-1">
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={index === 0}
            onClick={() => onMove(-1)}
            aria-label={`Move rule ${n} up`}
          >
            <ArrowUpIcon aria-hidden />
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={index === count - 1}
            onClick={() => onMove(1)}
            aria-label={`Move rule ${n} down`}
          >
            <ArrowDownIcon aria-hidden />
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={count === 1}
            onClick={onRemove}
            aria-label={`Remove rule ${n}`}
          >
            <TrashIcon aria-hidden />
          </Button>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <div className="grid gap-2">
          <Label htmlFor={`${base}-id`}>Rule ID of rule {n}</Label>
          <Input
            id={`${base}-id`}
            value={rule.id}
            maxLength={48}
            onChange={(event) => onChange({ id: event.target.value })}
          />
        </div>
        <LabelledSelect
          id={`${base}-action`}
          label={`Action of rule ${n}`}
          value={rule.action}
          onChange={(value) => onChange({ action: value as RuleAction })}
          options={actions.map((action) => ({
            value: action,
            label:
              action === 'hard_delete' && !hardDeleteAvailable
                ? `${actionLabel(action)} (turned off on this platform)`
                : actionLabel(action),
          }))}
        />
        <LabelledSelect
          id={`${base}-hb`}
          label={`Hard block (rule ${n})`}
          value={rule.hardBlock}
          onChange={(value) => onChange({ hardBlock: value as RuleDraft['hardBlock'] })}
          options={HARD_BLOCK_OPTIONS}
        />
        <LabelledSelect
          id={`${base}-min`}
          label={`Minimum risk level (rule ${n})`}
          value={rule.minLevel || 'any'}
          onChange={(value) => onChange({ minLevel: value === 'any' ? '' : (value as RuleLevel) })}
          options={LEVEL_OPTIONS}
        />
        <LabelledSelect
          id={`${base}-max`}
          label={`Maximum risk level (rule ${n})`}
          value={rule.maxLevel || 'any'}
          onChange={(value) => onChange({ maxLevel: value === 'any' ? '' : (value as RuleLevel) })}
          options={LEVEL_OPTIONS}
        />
        <div className="grid gap-2">
          <Label htmlFor={`${base}-score`}>Minimum risk score (rule {n})</Label>
          <Input
            id={`${base}-score`}
            inputMode="numeric"
            placeholder="Any (0-1000)"
            value={rule.minScore}
            onChange={(event) => onChange({ minScore: event.target.value })}
          />
        </div>
      </div>
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">Verdicts of rule {n} (any of)</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {RULE_VERDICTS.map((verdict) => {
            const id = `${base}-v-${verdict}`;
            return (
              <div key={verdict} className="flex items-center gap-2">
                <Checkbox
                  id={id}
                  checked={rule.verdicts.includes(verdict)}
                  onCheckedChange={(checked) =>
                    onChange({
                      verdicts:
                        checked === true
                          ? RULE_VERDICTS.filter((v) => v === verdict || rule.verdicts.includes(v))
                          : rule.verdicts.filter((v) => v !== verdict),
                    })
                  }
                />
                <Label htmlFor={id} className="font-normal">
                  {VERDICT_LABEL[verdict]}
                </Label>
              </div>
            );
          })}
        </div>
      </fieldset>
      {rule.action === 'hard_delete' ? (
        <p
          role="alert"
          className="rounded-md bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground"
        >
          <strong>Irreversible.</strong> {HARD_DELETE_WARNING}
          {hardDeleteAvailable
            ? ''
            : ' Hard delete is turned off on this platform, so this policy cannot be saved with it.'}
        </p>
      ) : null}
    </li>
  );
}

export interface PolicySubmission {
  readonly mode: PolicyMode;
  readonly document: PolicyDocument;
  readonly reason: string;
}

const PRESET_LABEL = {
  p1: 'P1 (platform default)',
  detectOnlyStart: 'Detect-only start (recommended for new tenants)',
  strict: 'Strict (P1 and spam to Junk)',
} as const;

/**
 * The policy editor (R15): mode with the detect-only recommendation, presets from the GET
 * response, the ordered rules (first match wins), the reason and the api's errors (CAS conflict,
 * hard delete refused, validation paths).
 */
export function PolicyEditor({
  scopeLabel,
  initialMode,
  initialDocument,
  presets,
  hardDeleteAvailable,
  pending,
  error,
  saveLabel = 'Save policy',
  onSave,
  onDiscard,
}: {
  scopeLabel: string;
  initialMode: PolicyMode;
  initialDocument: PolicyDocument;
  presets: RemediationPolicyView['presets'];
  hardDeleteAvailable: boolean;
  pending: boolean;
  error: ApiError | null;
  saveLabel?: string;
  onSave: (submission: PolicySubmission) => void;
  onDiscard?: () => void;
}) {
  const base = useId();
  const [draft, setDraft] = useState<PolicyDraft>(() => draftOf(initialMode, initialDocument));
  const [reason, setReason] = useState('');
  const [hints, setHints] = useState<string[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const update = (index: number, patch: Partial<RuleDraft>) =>
    setDraft((d) => ({
      ...d,
      rules: d.rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)),
    }));
  const move = (index: number, delta: -1 | 1) =>
    setDraft((d) => {
      const rules = [...d.rules];
      const [rule] = rules.splice(index, 1);
      rules.splice(index + delta, 0, rule!);
      return { ...d, rules };
    });
  const submit = () => {
    const problems = validateDraft(draft);
    if (reason.trim().length === 0) problems.push('Enter a reason.');
    if (reason.trim().length > 500) problems.push('The reason has at most 500 characters.');
    setHints(problems);
    if (problems.length > 0) return;
    onSave({ mode: draft.mode, document: documentOf(draft), reason: reason.trim() });
  };
  const errorText = remediationErrorText(error);
  return (
    <form
      className="grid gap-4"
      aria-label={`Remediation policy: ${scopeLabel}`}
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">Mode</legend>
        <RadioGroup
          value={draft.mode}
          onValueChange={(mode) => setDraft((d) => ({ ...d, mode: mode as PolicyMode }))}
          className="flex flex-wrap gap-4"
        >
          {(['detect_only', 'enforce'] as const).map((mode) => (
            <div key={mode} className="flex items-center gap-2">
              <RadioGroupItem id={`${base}-${mode}`} value={mode} />
              <Label htmlFor={`${base}-${mode}`} className="font-normal">
                {MODE_TEXT[mode]}
              </Label>
            </div>
          ))}
        </RadioGroup>
        <p role="note" className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
          {DETECT_ONLY_NOTICE}
          {draft.mode === 'enforce'
            ? ' In Enforce mode the actions below change mailboxes within seconds of the verdict.'
            : ''}
        </p>
      </fieldset>
      <div className="grid gap-2">
        <span className="text-sm font-medium">Presets</span>
        <div className="flex flex-wrap gap-2">
          {(Object.keys(PRESET_LABEL) as (keyof typeof PRESET_LABEL)[]).map((name) => (
            <Button
              key={name}
              type="button"
              size="sm"
              variant="outline"
              onClick={() => {
                const preset = presets[name];
                setDraft(draftOf(preset.mode, preset.document));
                setHints([]);
                setNotice(
                  `Preset ${PRESET_LABEL[name]} applied (${MODE_TEXT[preset.mode]}). Review the rules and save with a reason.`,
                );
              }}
            >
              Apply {PRESET_LABEL[name]}
            </Button>
          ))}
        </div>
        <div role="status" aria-live="polite" className="text-xs text-muted-foreground">
          {notice}
        </div>
      </div>
      <div className="grid gap-2">
        <h3 className="text-sm font-medium">Rules (evaluated in order; the first match wins)</h3>
        <p className="text-xs text-muted-foreground">
          A rule matches when the copy&apos;s verdict is one of its verdicts and every bound it sets
          holds. No match, or the action &quot;No action&quot;, leaves the message where it is.
          Clean and unknown verdicts are never remediated.
        </p>
        <ol className="grid gap-3" aria-label={`Rules of ${scopeLabel}`}>
          {draft.rules.map((rule, index) => (
            <RuleEditor
              key={rule.key}
              rule={rule}
              index={index}
              count={draft.rules.length}
              hardDeleteAvailable={hardDeleteAvailable}
              onChange={(patch) => update(index, patch)}
              onMove={(delta) => move(index, delta)}
              onRemove={() =>
                setDraft((d) => ({ ...d, rules: d.rules.filter((_, i) => i !== index) }))
              }
            />
          ))}
        </ol>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="justify-self-start"
          disabled={draft.rules.length >= MAX_RULES}
          onClick={() =>
            setDraft((d) => ({ ...d, rules: [...d.rules, emptyRule(d.rules.length)] }))
          }
        >
          <PlusIcon aria-hidden />
          Add rule
        </Button>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
        <Textarea
          id={`${base}-reason`}
          rows={2}
          maxLength={500}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          Stored in the audit log with the old and new policy fingerprints (at most 500 characters).
        </p>
      </div>
      {hints.length > 0 ? (
        <ul role="alert" className="grid gap-1 text-sm font-medium text-destructive">
          {hints.map((hint) => (
            <li key={hint}>{hint}</li>
          ))}
        </ul>
      ) : null}
      {error ? (
        <div role="alert" className="grid gap-1">
          {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
          <MutationError error={error} />
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={pending}>
          {pending ? 'Saving …' : saveLabel}
        </Button>
        {onDiscard ? (
          <Button type="button" size="sm" variant="ghost" onClick={onDiscard}>
            Discard changes
          </Button>
        ) : null}
      </div>
    </form>
  );
}

// ---- organization policy ---------------------------------------------------------------------

function OrganizationPolicy({ policy }: { policy: RemediationPolicyView }) {
  const canWrite = useCan('ApiModeRemediationController_putPolicy_v1');
  const queryClient = useQueryClient();
  const [version, setVersion] = useState(0);
  const save = useApiMutation('ApiModeRemediationController_putPolicy_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Remediation policy saved.',
    onSuccess: () => setVersion((v) => v + 1),
  });
  const org = policy.organization;
  return (
    <Section
      title="Organization policy"
      description="Applies to every mailbox of a domain in API or Hybrid mode that has no domain override. It maps the scan verdict and risk of each copy to a mailbox action."
      actions={<PolicyModeBadge mode={org.mode} />}
    >
      <p className="text-sm">
        {POLICY_SOURCE_LABEL[org.source]}
        {org.updatedAt ? (
          <>
            {' '}
            · updated <DateTime value={org.updatedAt} />
          </>
        ) : (
          ' · no policy of your own yet: the platform default applies'
        )}
      </p>
      {canWrite ? (
        <PolicyEditor
          key={version}
          scopeLabel="organization"
          initialMode={org.mode}
          initialDocument={org.document}
          presets={policy.presets}
          hardDeleteAvailable={policy.hardDeleteAvailable}
          pending={save.isPending}
          error={save.error}
          onDiscard={() => {
            save.reset();
            setVersion((v) => v + 1);
          }}
          onSave={({ mode, document, reason }) => {
            void save
              .submit({
                body: { mode, document, reason, expectedRowVersion: org.rowVersion },
              })
              .then(async (outcome) => {
                if (!outcome.ok && outcome.error.code === 'api_mode_remediation_policy_conflict')
                  await queryClient.invalidateQueries({
                    queryKey: ['ApiModeRemediationController_getPolicy_v1'],
                  });
              });
          }}
        />
      ) : (
        <>
          <p role="note" className="text-sm text-muted-foreground">
            {DETECT_ONLY_NOTICE}
          </p>
          <PolicyRulesTable document={org.document} label="Rules of the organization policy" />
        </>
      )}
    </Section>
  );
}

// ---- domain overrides ------------------------------------------------------------------------

function DomainPolicyDialog({
  policy,
  override,
  open,
  onOpenChange,
}: {
  policy: RemediationPolicyView;
  /** The override to edit; `null` adds one. */
  override: DomainOverride | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const selectId = useId();
  const queryClient = useQueryClient();
  const canListDomains = useCan('DomainsController_list_v1');
  const domains = useApiQuery(
    'DomainsController_list_v1',
    { query: { limit: 100 } },
    { enabled: open && override === null && canListDomains },
  );
  const taken = new Set(policy.domains.map((d) => d.domainId));
  const options = (domains.data?.data ?? [])
    .filter((d) => !taken.has(d.id))
    .map((d) => ({ value: d.id, label: d.unicodeName }));
  const [domainId, setDomainId] = useState('');
  const save = useApiMutation('ApiModeRemediationController_putDomainPolicy_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Domain override saved.',
    onSuccess: () => onOpenChange(false),
  });
  const target = override?.domainId ?? domainId;
  const start = override ?? policy.organization;
  return (
    <FormDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          save.reset();
          setDomainId('');
        }
        onOpenChange(next);
      }}
      wide
      title={override ? `Override of ${override.domainName}` : 'Add a domain override'}
      description={
        override
          ? 'This domain uses its own policy instead of the organization policy.'
          : 'The new override starts as a copy of the organization policy.'
      }
    >
      {override === null ? (
        canListDomains ? (
          domains.isLoading ? (
            <LoadingState label="Loading domains" rows={1} />
          ) : options.length === 0 ? (
            <p className="text-sm text-muted-foreground">Every domain already has an override.</p>
          ) : (
            <LabelledSelect
              id={selectId}
              label="Domain"
              value={domainId}
              onChange={setDomainId}
              options={options}
            />
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            Listing domains needs the domain read permission.
          </p>
        )
      ) : null}
      <PolicyEditor
        scopeLabel={override ? override.domainName : 'new domain override'}
        initialMode={start.mode}
        initialDocument={start.document}
        presets={policy.presets}
        hardDeleteAvailable={policy.hardDeleteAvailable}
        pending={save.isPending}
        error={save.error}
        saveLabel="Save override"
        onSave={({ mode, document, reason }) => {
          if (!target) return;
          void save
            .submit({
              path: { domainId: target },
              body: { mode, document, reason, expectedRowVersion: override?.rowVersion ?? null },
            })
            .then(async (outcome) => {
              if (!outcome.ok && outcome.error.code === 'api_mode_remediation_policy_conflict')
                await queryClient.invalidateQueries({
                  queryKey: ['ApiModeRemediationController_getPolicy_v1'],
                });
            });
        }}
      />
      {override === null && !target ? (
        <p className="text-xs text-muted-foreground">Choose a domain before saving.</p>
      ) : null}
    </FormDialog>
  );
}

function DomainOverrides({ policy }: { policy: RemediationPolicyView }) {
  const canPut = useCan('ApiModeRemediationController_putDomainPolicy_v1');
  const canDelete = useCan('ApiModeRemediationController_deleteDomainPolicy_v1');
  const [editing, setEditing] = useState<DomainOverride | null | 'new'>(null);
  const [removing, setRemoving] = useState<DomainOverride | null>(null);
  const remove = useApiMutation('ApiModeRemediationController_deleteDomainPolicy_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Override removed: the domain inherits the organization policy.',
  });
  return (
    <Section
      title="Domain overrides"
      description="A domain with an override uses its own policy; every other domain inherits the organization policy."
      actions={
        canPut ? (
          <Button size="sm" variant="outline" onClick={() => setEditing('new')}>
            <PlusIcon aria-hidden />
            Add domain override
          </Button>
        ) : null
      }
    >
      {policy.domains.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No domain override: every domain inherits the organization policy.
        </p>
      ) : (
        <div className="relative overflow-x-auto">
          <Table>
            <TableCaption className="sr-only">Domain overrides</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Rules</TableHead>
                <TableHead>Updated</TableHead>
                {canPut || canDelete ? <TableHead>Actions</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {policy.domains.map((d) => (
                <TableRow key={d.id}>
                  <TableCell className="font-medium">{d.domainName}</TableCell>
                  <TableCell>
                    <PolicyModeBadge mode={d.mode} />
                  </TableCell>
                  <TableCell className="text-sm">
                    <span className="tabular-nums">{formatNumber(d.document.rules.length)}</span>
                    <ul className="text-xs text-muted-foreground">
                      {d.document.rules.slice(0, 4).map((rule, i) => (
                        <li key={`${rule.id}-${i}`}>
                          {ruleConditionText(rule)} → {actionLabel(rule.action)}
                        </li>
                      ))}
                    </ul>
                  </TableCell>
                  <TableCell>
                    <DateTime value={d.updatedAt} />
                  </TableCell>
                  {canPut || canDelete ? (
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {canPut ? (
                          <Button size="sm" variant="outline" onClick={() => setEditing(d)}>
                            Edit <span className="sr-only">override of {d.domainName}</span>
                          </Button>
                        ) : null}
                        {canDelete ? (
                          <Button size="sm" variant="ghost" onClick={() => setRemoving(d)}>
                            Remove <span className="sr-only">override of {d.domainName}</span>
                          </Button>
                        ) : null}
                      </div>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {editing !== null ? (
        <DomainPolicyDialog
          key={editing === 'new' ? 'new' : editing.id}
          policy={policy}
          override={editing === 'new' ? null : editing}
          open
          onOpenChange={(open) => !open && setEditing(null)}
        />
      ) : null}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title={`Remove the override of ${removing?.domainName ?? 'this domain'}?`}
        description="The domain inherits the organization policy again. The change is audited."
        confirmLabel="Remove override"
        destructive
        error={remove.error ? <MutationError error={remove.error} /> : null}
        onConfirm={async () => {
          if (!removing) return false;
          const outcome = await remove.submit({ path: { domainId: removing.domainId } });
          return outcome.ok;
        }}
      />
    </Section>
  );
}

/** Tab "Remediation" (R15): the organization policy and the domain overrides. */
export function RemediationTab() {
  const policy = useApiQuery('ApiModeRemediationController_getPolicy_v1');
  if (policy.isLoading) return <LoadingState label="Loading the remediation policy" rows={6} />;
  if (policy.error)
    return <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />;
  if (!policy.data) return null;
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <p className="text-sm text-muted-foreground">
        After a copy is scanned, its verdict and risk decide a mailbox action. Messages moved to the
        quarantine folder, Junk or deleted items appear on the Quarantine page, where a release
        restores them to the Inbox. Copies that the inline gateway already decided (Hybrid) are
        never remediated automatically.
      </p>
      <OrganizationPolicy policy={policy.data} />
      <DomainOverrides policy={policy.data} />
    </div>
  );
}
