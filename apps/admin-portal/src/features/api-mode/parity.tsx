'use client';

import Link from 'next/link';
import { useId } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, LabelledSelect, MutationError } from '@/features/domains/kit';
import { CodeList } from '@/features/messages/controls';
import {
  ACTION_STATUS_LABEL,
  DECISION_SOURCE_LABEL,
  DETECT_ONLY_DEFAULT_DAYS,
  DETECT_ONLY_MAX_DAYS,
  DETECT_ONLY_THEN_LABEL,
  DLP_ACTION_LABEL,
  DispositionBadge,
  MAPPING_ACTIONS,
  MAPPING_KEY_HELP,
  MAPPING_KEY_LABEL,
  POLICY_MAPPING_KEYS,
  POLICY_STATE_TEXT,
  PolicyStateBadge,
  TAGGED_MAPPING_ACTIONS,
  detectOnlyUntil,
  postDeliveryReasonText,
  simulatedHistoryHref,
  type DetectOnlyThen,
  type DetectOnlyView,
  type DetectionDetail,
  type DlpFacts,
  type EffectivePolicyMapping,
  type PolicyEvaluation,
  type PolicyMappingKey,
  type PolicyView,
} from './parity-model';
import {
  POLICY_QUERIES,
  actionLabel,
  remediationErrorText,
  type RemediationDetail,
} from './remediation-model';

/**
 * Step API-4 surfaces shared by `/api-mode`, the add-domain wizard and the domain page: the
 * policy evaluation of a copy (detect mode), the DLP facts, the two lanes of a remediation
 * decision (`api-remediation-decision/2`), the policy-mapping editor, the detect-only period
 * fields and the ended-period banner. Explanation texts and rule refs are rendered as untrusted
 * text; the browser evaluates nothing.
 */

function ActionList({
  actions,
  label,
}: {
  actions: ReadonlyArray<{ type: string; status: string; reason: string | null }>;
  label: string;
}) {
  if (actions.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <ul className="grid gap-1" aria-label={label}>
      {actions.map((a, i) => (
        <li key={`${a.type}-${i}`} className="text-xs">
          <span className="font-mono">{a.type}</span> ·{' '}
          {ACTION_STATUS_LABEL[a.status] ?? humanize(a.status)}
          {a.reason ? (
            <span className="text-muted-foreground"> — {postDeliveryReasonText(a.reason)}</span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/** The policy evaluation of a detection (A12): disposition, decisive rule, actions, text. */
export function PolicyEvaluationSection({ detection }: { detection: DetectionDetail }) {
  const p: PolicyEvaluation | null = detection.policy;
  return (
    <section aria-label="Policy evaluation" className="grid gap-2 rounded-md border p-3">
      <h3 className="flex flex-wrap items-center gap-2 text-sm font-semibold">
        Policy evaluation <PolicyStateBadge state={detection.policyState} />
      </h3>
      <p className="text-xs text-muted-foreground">{POLICY_STATE_TEXT[detection.policyState]}</p>
      {p ? (
        <DetailList
          items={[
            {
              label: 'Disposition',
              value: (
                <DispositionBadge disposition={p.disposition} tagged={detection.policyTagged} />
              ),
            },
            {
              label: 'Decided by',
              value: `${DECISION_SOURCE_LABEL[p.decisionSource] ?? humanize(p.decisionSource)}${
                p.overrideApplied ? ' (allow override applied)' : ''
              }`,
            },
            {
              label: 'Decisive rule',
              value: p.decisiveRuleRef ? (
                <UntrustedText value={p.decisiveRuleRef} mono maxLength={120} />
              ) : (
                'None (platform default)'
              ),
            },
            {
              label: 'Matched rules',
              value:
                p.matchedRules.length === 0 ? (
                  'None'
                ) : (
                  <ul className="grid gap-0.5" aria-label="Matched rules">
                    {p.matchedRules.map((r) => (
                      <li key={r.ruleRef} className="text-xs">
                        <UntrustedText value={r.ruleRef} mono maxLength={120} /> →{' '}
                        {r.actions.join(', ')}
                      </li>
                    ))}
                  </ul>
                ),
            },
            {
              label: 'Actions',
              value: <ActionList actions={p.actions} label="Policy actions" />,
            },
            {
              label: 'After delivery',
              value: <ActionList actions={p.postDelivery} label="Post-delivery handling" />,
            },
            {
              label: 'Explanation',
              value: <UntrustedText value={p.explanation} maxLength={600} />,
            },
            { label: 'Evaluated', value: <DateTime value={p.evaluatedAt} mode="absolute" /> },
          ]}
        />
      ) : null}
    </section>
  );
}

/** DLP facts of a detection (A12): action, verdict and category codes; never matched values. */
export function DlpSection({ dlp }: { dlp: DlpFacts | null }) {
  if (!dlp) return null;
  return (
    <section aria-label="Data loss prevention" className="grid gap-2 rounded-md border p-3">
      <h3 className="text-sm font-semibold">Data loss prevention</h3>
      <DetailList
        items={[
          { label: 'DLP action', value: DLP_ACTION_LABEL[dlp.action] ?? humanize(dlp.action) },
          {
            label: 'DLP verdict',
            value: <UntrustedText value={dlp.verdict} mono maxLength={32} />,
          },
          { label: 'Categories', value: <CodeList codes={dlp.categories} /> },
        ]}
      />
    </section>
  );
}

type DecisionV2 = Extract<NonNullable<RemediationDetail['decision']>, { v: 2 }>;

/** The two lanes of a decision record v2 (A4.4): verdict rule, policy mapping, winner. */
export function DecisionLanes({ decision }: { decision: DecisionV2 }) {
  const { lanes } = decision;
  return (
    <div className="grid gap-2" aria-label="Decision lanes">
      <ul className="grid gap-1 text-xs">
        <li>
          <span className="font-medium">Verdict lane:</span>{' '}
          {lanes.verdict ? (
            <>
              rule <UntrustedText value={lanes.verdict.ruleId} mono maxLength={48} /> →{' '}
              {actionLabel(lanes.verdict.action)}
            </>
          ) : (
            'no action'
          )}
          {lanes.winner === 'verdict' ? ' (decided)' : ''}
        </li>
        <li>
          <span className="font-medium">Policy lane:</span>{' '}
          {lanes.policy ? (
            <>
              {MAPPING_KEY_LABEL[lanes.policy.key]} → {actionLabel(lanes.policy.action)}
            </>
          ) : (
            'no action'
          )}
          {lanes.winner === 'policy' ? ' (decided)' : ''}
        </li>
        {lanes.suppressedBy ? (
          <li>Verdict action suppressed by your policy&apos;s allow override.</li>
        ) : null}
      </ul>
      {decision.policyOutcome ? (
        <p className="text-xs">
          Policy outcome:{' '}
          <DispositionBadge
            disposition={decision.policyOutcome.disposition}
            tagged={decision.policyOutcome.tagged}
          />{' '}
          ·{' '}
          {DECISION_SOURCE_LABEL[decision.policyOutcome.decisionSource] ??
            humanize(decision.policyOutcome.decisionSource)}
          {decision.policyOutcome.dlpAction
            ? ` · DLP ${DLP_ACTION_LABEL[decision.policyOutcome.dlpAction]}`
            : ''}
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">No policy outcome (verdict rules only).</p>
      )}
      {decision.postDelivery.length > 0 ? (
        <ActionList actions={decision.postDelivery} label="Post-delivery handling" />
      ) : null}
    </div>
  );
}

/** Per-disposition mailbox action selects (A4.2; hard delete is never offered, R-I2). */
export function PolicyMappingEditor({
  value,
  onChange,
  readOnly = false,
}: {
  value: EffectivePolicyMapping;
  onChange: (next: EffectivePolicyMapping) => void;
  readOnly?: boolean;
}) {
  const base = useId();
  return (
    <fieldset className="grid gap-3 rounded-md border p-3">
      <legend className="px-1 text-sm font-medium">Your policies after delivery</legend>
      <p className="text-xs text-muted-foreground">
        What a disposition of your policies (rules, allow and block lists, DLP, BEC) does to the
        delivered copy. The stronger of the verdict rules above and this mapping wins. The platform
        default's risk recommendation on its own is not mapped: the verdict rules above already
        decide it.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        {POLICY_MAPPING_KEYS.map((key) => (
          <LabelledSelect
            key={key}
            id={`${base}-${key}`}
            label={MAPPING_KEY_LABEL[key]}
            value={value[key]}
            disabled={readOnly}
            description={MAPPING_KEY_HELP[key]}
            onChange={(next) => onChange({ ...value, [key]: next })}
            options={(key === 'allow_tagged' ? TAGGED_MAPPING_ACTIONS : MAPPING_ACTIONS).map(
              (action) => ({ value: action, label: actionLabel(action) }),
            )}
          />
        ))}
      </div>
    </fieldset>
  );
}

export interface DetectOnlyDraft {
  /** Days from now (empty = no period). */
  days: string;
  then: DetectOnlyThen;
}

export function detectOnlyDraftOf(view: DetectOnlyView | null): DetectOnlyDraft {
  return { days: '', then: view?.then ?? 'remind' };
}

/** Hint before the PUT (the api validates 1 h … 30 days). */
export function validateDetectOnlyDraft(draft: DetectOnlyDraft): string | null {
  const raw = draft.days.trim();
  if (raw === '') return null;
  if (!/^\d{1,2}$/.test(raw) || Number(raw) < 1 || Number(raw) > DETECT_ONLY_MAX_DAYS)
    return `The detect-only period is 1 to ${DETECT_ONLY_MAX_DAYS} days.`;
  return null;
}

/** Detect-only period fields of the policy editor (B7): days and what happens at the end. */
export function DetectOnlyFields({
  current,
  draft,
  onChange,
}: {
  current: DetectOnlyView | null;
  draft: DetectOnlyDraft;
  onChange: (next: DetectOnlyDraft) => void;
}) {
  const base = useId();
  return (
    <fieldset className="grid gap-3 rounded-md border p-3">
      <legend className="px-1 text-sm font-medium">Detect-only period</legend>
      {current ? (
        <p className="text-sm">
          {current.ended ? 'Ended' : 'Ends'} <DateTime value={current.until} mode="absolute" /> ·{' '}
          {DETECT_ONLY_THEN_LABEL[current.then]} · {formatNumber(current.simulatedSinceStart)}{' '}
          simulated actions since it started
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">
          No period: detect only stays until you switch to enforce.
        </p>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1">
          <Label htmlFor={`${base}-days`}>
            {current ? 'Start a new period of (days)' : 'Detect only for (days)'}
          </Label>
          <Input
            id={`${base}-days`}
            inputMode="numeric"
            placeholder={`e.g. ${DETECT_ONLY_DEFAULT_DAYS}`}
            value={draft.days}
            onChange={(event) => onChange({ ...draft, days: event.target.value })}
          />
          <p className="text-xs text-muted-foreground">
            1 to {DETECT_ONLY_MAX_DAYS} days; empty keeps the current period.
          </p>
        </div>
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">When the period ends</legend>
          <RadioGroup
            value={draft.then}
            onValueChange={(then) => onChange({ ...draft, then: then as DetectOnlyThen })}
            className="grid gap-2"
          >
            {(['remind', 'enforce'] as const).map((then) => (
              <div key={then} className="flex items-center gap-2">
                <RadioGroupItem id={`${base}-${then}`} value={then} />
                <Label htmlFor={`${base}-${then}`} className="font-normal">
                  {DETECT_ONLY_THEN_LABEL[then]}
                </Label>
              </div>
            ))}
          </RadioGroup>
        </fieldset>
      </div>
    </fieldset>
  );
}

type PolicyTarget =
  | { scope: 'organization'; view: PolicyView['organization'] }
  | { scope: 'domain'; view: PolicyView['domains'][number] };

/**
 * The ended-period banner (B7): shown while a period has ended and the policy is still detect
 * only. "Review simulated actions" opens History filtered to `simulated`; "Switch to enforce" and
 * "Extend 7 days" save the same document with a fixed, audited reason.
 */
export function DetectOnlyEndedBanner({ target }: { target: PolicyTarget }) {
  const view = target.view;
  const canOrg = useCan('ApiModeRemediationController_putPolicy_v1');
  const canDomain = useCan('ApiModeRemediationController_putDomainPolicy_v1');
  const canWrite = target.scope === 'organization' ? canOrg : canDomain;
  const org = useApiMutation('ApiModeRemediationController_putPolicy_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: 'Remediation policy saved.',
  });
  const domain = useApiMutation('ApiModeRemediationController_putDomainPolicy_v1', {
    invalidates: [...POLICY_QUERIES, 'ApiModeOnboardingController_domainOnboarding_v1'],
    successMessage: 'Domain override saved.',
  });
  if (!view.detectOnly || !view.detectOnly.ended || view.mode !== 'detect_only') return null;
  const scopeLabel =
    target.scope === 'organization' ? 'the organization policy' : target.view.domainName;
  const save = (mode: 'enforce' | 'detect_only', reason: string) => {
    const body = {
      mode,
      document: view.document,
      ...(mode === 'detect_only'
        ? {
            detectOnly: {
              until: detectOnlyUntil(DETECT_ONLY_DEFAULT_DAYS),
              then: view.detectOnly!.then,
            },
          }
        : {}),
      reason,
      expectedRowVersion: view.rowVersion,
    };
    if (target.scope === 'organization') void org.submit({ body });
    else void domain.submit({ path: { domainId: target.view.domainId }, body });
  };
  const pending = org.isPending || domain.isPending;
  const error = org.error ?? domain.error;
  const errorText = remediationErrorText(error);
  return (
    <div
      role="status"
      aria-label={`Detect-only period ended: ${scopeLabel}`}
      className="grid gap-2 rounded-md border border-tone-warning bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
    >
      <p>
        <strong>Detect-only period ended</strong> ({scopeLabel}):{' '}
        {formatNumber(view.detectOnly.simulatedSinceStart)} action
        {view.detectOnly.simulatedSinceStart === 1 ? '' : 's'} would have been taken. Review them
        and switch to enforce.
      </p>
      <div className="flex flex-wrap gap-2">
        <Button asChild size="sm" variant="outline">
          <Link href={simulatedHistoryHref()}>Review simulated actions</Link>
        </Button>
        {canWrite ? (
          <>
            <Button
              size="sm"
              disabled={pending}
              onClick={() =>
                save('enforce', 'Detect-only period ended: switched to enforce from the banner.')
              }
            >
              Switch to enforce
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled={pending}
              onClick={() =>
                save(
                  'detect_only',
                  `Detect-only period extended by ${DETECT_ONLY_DEFAULT_DAYS} days from the banner.`,
                )
              }
            >
              Extend {DETECT_ONLY_DEFAULT_DAYS} days
            </Button>
          </>
        ) : null}
      </div>
      {error ? (
        <div role="alert" className="grid gap-1">
          {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
          <MutationError error={error} />
        </div>
      ) : null}
    </div>
  );
}

export type { PolicyMappingKey };
