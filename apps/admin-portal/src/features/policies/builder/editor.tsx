'use client';

import { PlusIcon } from 'lucide-react';
import { useCallback, useEffect, useId, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { humanizeValue } from './summary';
import { useBuilderContext } from './context';
import { ExceptionsEditor } from './exceptions-editor';
import { ChoiceSelect, IntegerInput } from './inputs';
import {
  buildDefinition,
  documentBytes,
  MODEL_DSL_VERSION,
  newKey,
  rulesByPriority,
  type BuilderDefinition,
} from './model';
import { ViolationMessages } from './parts';
import { canAddRule, type BuilderCommand } from './reducer';
import { RuleCard } from './rule-card';

/** Above this many rules every card starts collapsed (design §4.7). */
export const COLLAPSE_RULES_ABOVE = 10;

const sizeText = (bytes: number): string =>
  bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;

/**
 * The policy editor (controlled; no data fetching): the policy direction and priority, the rules
 * in evaluation order and the policy-wide exceptions, with the document size against the
 * catalogue's `documentBytes`. Server violations that map to no node are listed at the top.
 */
export function PolicyBuilderEditor({
  state,
  dispatch,
}: {
  state: BuilderDefinition;
  dispatch: (command: BuilderCommand) => void;
}) {
  const { catalog, readOnly, focus, announce, unmapped } = useBuilderContext();
  const directionId = useId();
  const priorityId = useId();
  const priorityHelpId = useId();
  const sizeId = useId();
  const rulesHeadingId = useId();
  const exceptionsHeadingId = useId();
  const policyViolationsId = useId();
  const [added, setAdded] = useState<string | null>(null);

  // Focus requests (after add/remove/move) are fulfilled once the new tree is committed.
  useEffect(() => focus.flush());

  const ordered = useMemo(() => rulesByPriority(state.rules), [state.rules]);
  const indexOf = useMemo(
    () => new Map(state.rules.map((rule, i) => [rule.key, i])),
    [state.rules],
  );
  const bytes = useMemo(() => documentBytes(buildDefinition(state).definition), [state]);
  const limit = catalog.limits.documentBytes;
  const exceptionsScope = useMemo<BuilderDefinition>(() => {
    const scope: BuilderDefinition = {
      dslVersion: MODEL_DSL_VERSION,
      direction: state.direction,
      priority: state.priority,
      rules: [],
    };
    if (state.exceptions !== undefined) scope.exceptions = state.exceptions;
    return scope;
  }, [state.direction, state.priority, state.exceptions]);
  const registerAddRule = useCallback(
    (el: HTMLElement | null) => focus.register('policy:add-rule', el),
    [focus],
  );
  const capacity = canAddRule(state, catalog.limits);
  const collapse = state.rules.length > COLLAPSE_RULES_ABOVE;

  return (
    <div className="grid min-w-0 gap-4" data-builder="editor">
      <section
        aria-label="Policy settings"
        aria-describedby={unmapped.length > 0 ? policyViolationsId : undefined}
        className="grid min-w-0 gap-3 rounded-lg border bg-card p-3 sm:p-4"
      >
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="grid min-w-0 content-start gap-1">
            <Label id={directionId} className="text-xs text-muted-foreground">
              Policy direction
            </Label>
            {readOnly ? (
              <p className="text-sm">{humanizeValue(state.direction)}</p>
            ) : (
              <ChoiceSelect
                labelledBy={directionId}
                value={state.direction}
                options={catalog.policyDirections.map((d) => ({
                  value: d,
                  label: humanizeValue(d),
                }))}
                onChange={(direction) => {
                  if (direction !== undefined) dispatch({ type: 'set-policy', set: { direction } });
                }}
                className="sm:max-w-64"
              />
            )}
          </div>
          <div className="grid min-w-0 content-start gap-1">
            <Label htmlFor={priorityId} className="text-xs text-muted-foreground">
              Policy priority
            </Label>
            {readOnly ? (
              <p className="text-sm">{state.priority}</p>
            ) : (
              <IntegerInput
                id={priorityId}
                value={state.priority}
                max={catalog.limits.priorityMax}
                describedBy={priorityHelpId}
                onChange={(priority) => {
                  if (priority !== undefined) dispatch({ type: 'set-policy', set: { priority } });
                }}
                className="sm:max-w-40"
              />
            )}
            <p id={priorityHelpId} className="text-xs text-muted-foreground">
              Lower numbers run first.
            </p>
          </div>
        </div>
        <p id={sizeId} className="text-xs text-muted-foreground">
          {`Document size: ${sizeText(bytes)}${limit !== undefined ? ` of ${sizeText(limit)}` : ''}`}
          {limit !== undefined && bytes > limit ? (
            <span className="font-medium text-destructive"> (above the limit)</span>
          ) : null}
        </p>
        {unmapped.length > 0 ? (
          <div className="grid gap-1">
            <p className="text-xs font-semibold text-destructive">
              Problems with the policy as a whole
            </p>
            <ViolationMessages id={policyViolationsId} violations={unmapped} />
          </div>
        ) : null}
      </section>

      <section aria-labelledby={rulesHeadingId} className="grid min-w-0 gap-3">
        <h2 id={rulesHeadingId} className="text-lg font-semibold">
          {`Rules (${state.rules.length})`}
        </h2>
        {state.rules.length === 0 ? (
          <p className="text-sm text-muted-foreground">This policy has no rules yet.</p>
        ) : (
          <ol className="grid min-w-0 gap-3">
            {ordered.map((rule, position) => (
              <li key={rule.key} className="min-w-0">
                <RuleCard
                  rule={rule}
                  ruleIndex={indexOf.get(rule.key) ?? 0}
                  position={position}
                  count={ordered.length}
                  policyDirection={state.direction}
                  defaultCollapsed={collapse && rule.key !== added}
                  dispatch={dispatch}
                  previousRuleKey={position > 0 ? ordered[position - 1]!.key : null}
                />
              </li>
            ))}
          </ol>
        )}
        {readOnly ? null : (
          <div className="flex flex-wrap items-center gap-2">
            <Button
              ref={registerAddRule}
              variant="outline"
              disabled={!capacity.ok}
              onClick={() => {
                const key = newKey('r');
                const groupKey = newKey('n');
                const leafKey = newKey('n');
                setAdded(key);
                dispatch({ type: 'add-rule', key, groupKey, leafKey, limits: catalog.limits });
                focus.request(leafKey, key);
                announce(
                  'Rule added at the end of the evaluation order. Choose the field of its first condition.',
                );
              }}
            >
              <PlusIcon aria-hidden />
              Add rule
            </Button>
            {!capacity.ok ? (
              <span className="text-xs text-muted-foreground">{capacity.reason}</span>
            ) : null}
          </div>
        )}
      </section>

      <section
        aria-labelledby={exceptionsHeadingId}
        className="grid min-w-0 gap-2 rounded-lg border bg-card p-3 sm:p-4"
      >
        <h2 id={exceptionsHeadingId} className="text-lg font-semibold">
          Policy-wide exceptions
        </h2>
        <p className="text-xs text-muted-foreground">
          When any one of these conditions is true, the rules of this policy do not apply.
        </p>
        <ExceptionsEditor
          ruleKey={null}
          nodes={state.exceptions}
          scope={exceptionsScope}
          dispatch={dispatch}
        />
      </section>
    </div>
  );
}
