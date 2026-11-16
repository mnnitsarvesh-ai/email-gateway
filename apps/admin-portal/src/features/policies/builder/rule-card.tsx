'use client';

import { ChevronDownIcon, ChevronRightIcon } from 'lucide-react';
import { memo, useCallback, useId, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { cn } from '@/lib/utils';
import { ActionsEditor } from './actions-editor';
import { isAllDirections, isDispositionAction, whenPlacesOf } from './catalog';
import { ConditionTree, type TreeInfo } from './conditions';
import { useBuilderContext } from './context';
import { ExceptionsEditor } from './exceptions-editor';
import { ChoiceSelect, IntegerInput, ToggleList } from './inputs';
import { MODEL_DSL_VERSION, type BuilderDefinition, type BuilderRule } from './model';
import {
  HIGHLIGHT_CLASS,
  MoveButtons,
  RemoveButton,
  useNodeStatus,
  ViolationMessages,
} from './parts';
import type { BuilderCommand } from './reducer';
import { humanizeValue, lineText, summarizeRule } from './summary';

/**
 * One rule (design §4.7): id, priority, description, enabled switch, direction chips (only when
 * the policy covers every direction), the stop tri-state, the override switch (only for a rule
 * with a decision), its conditions, exceptions and actions. Rules are listed by priority; Move
 * up/Move down swap the two rules' priorities. Large policies start with every card collapsed.
 */
export const RuleCard = memo(function RuleCard({
  rule,
  ruleIndex,
  position,
  count,
  policyDirection,
  defaultCollapsed,
  dispatch,
  previousRuleKey,
}: {
  rule: BuilderRule;
  /** Position in the document's `rules` array (paths). */
  ruleIndex: number;
  /** Position in evaluation order. */
  position: number;
  count: number;
  policyDirection: string;
  defaultCollapsed: boolean;
  dispatch: (command: BuilderCommand) => void;
  previousRuleKey: string | null;
}) {
  const { catalog, readOnly, focus, announce, paths, highlightKey, names } = useBuilderContext();
  const headingId = useId();
  const bodyId = useId();
  const idInputId = useId();
  const priorityId = useId();
  const priorityHelpId = useId();
  const descriptionId = useId();
  const enabledId = useId();
  const stopLabelId = useId();
  const overrideId = useId();
  const overrideHelpId = useId();
  const directionsHelpId = useId();
  const violationsId = useId();
  const status = useNodeStatus([rule.key]);

  // A highlighted node inside this rule opens the card.
  const rulePath = paths.pathByKey.get(rule.key);
  const highlightPath = highlightKey ? paths.pathByKey.get(highlightKey) : undefined;
  const containsHighlight =
    rulePath !== undefined &&
    highlightPath !== undefined &&
    (highlightPath === rulePath || highlightPath.startsWith(`${rulePath}.`));
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const isCollapsed = collapsed && !containsHighlight;

  const scope = useMemo<BuilderDefinition>(
    () => ({
      dslVersion: MODEL_DSL_VERSION,
      direction: policyDirection,
      priority: 0,
      rules: [rule],
    }),
    [rule, policyDirection],
  );
  const actionTypes = rule.actions.map((a) => a.type);
  const placesKey = whenPlacesOf(catalog, actionTypes, rule.override).join(',');
  const whenInfo = useMemo<TreeInfo>(
    () => ({
      place: 'when',
      places: placesKey.split(',') as TreeInfo['places'],
      ruleKey: rule.key,
      scope,
      dispatch,
      rootName: `Conditions of rule ${rule.id}`,
      list: null,
    }),
    [placesKey, rule.key, rule.id, scope, dispatch],
  );

  const registerHeading = useCallback(
    (el: HTMLElement | null) => focus.register(rule.key, el),
    [focus, rule.key],
  );
  const registerUp = useCallback(
    (el: HTMLElement | null) => focus.register(`${rule.key}:up`, el),
    [focus, rule.key],
  );
  const registerDown = useCallback(
    (el: HTMLElement | null) => focus.register(`${rule.key}:down`, el),
    [focus, rule.key],
  );

  const update = (
    command: Omit<Extract<BuilderCommand, { type: 'update-rule' }>, 'type' | 'ruleKey'>,
  ) => dispatch({ type: 'update-rule', ruleKey: rule.key, ...command });
  const move = (direction: 'up' | 'down') => {
    dispatch({ type: 'move-rule', ruleKey: rule.key, direction });
    focus.request(`${rule.key}:${direction}`, `${rule.key}:${direction === 'up' ? 'down' : 'up'}`);
    announce(
      `Rule ${rule.id} moved ${direction}; it now runs ${position + (direction === 'up' ? 0 : 2)} of ${count}.`,
    );
  };

  const hasDecision = rule.actions.some((a) => isDispositionAction(catalog, a.type));
  const showOverride = hasDecision || rule.override !== undefined;
  const allDirections = isAllDirections(catalog, policyDirection);
  const showDirections = allDirections || rule.directions !== undefined;
  const summary = useMemo(
    () =>
      isCollapsed
        ? summarizeRule(
            catalog,
            {
              dslVersion: MODEL_DSL_VERSION,
              direction: policyDirection,
              priority: 0,
              rules: [rule],
            },
            rule,
            ruleIndex,
            names,
          )
        : null,
    [isCollapsed, catalog, policyDirection, rule, ruleIndex, names],
  );
  const title = `Rule ${rule.id}`;

  return (
    <section
      ref={status.ref}
      aria-labelledby={headingId}
      data-rule-key={rule.key}
      className={cn(
        'grid min-w-0 gap-3 rounded-lg border bg-card p-3 sm:p-4',
        status.highlighted && HIGHLIGHT_CLASS,
      )}
    >
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          className="size-7"
          aria-expanded={!isCollapsed}
          aria-controls={bodyId}
          aria-label={`${isCollapsed ? 'Expand' : 'Collapse'} ${title}`}
          onClick={() => setCollapsed(!isCollapsed)}
        >
          {isCollapsed ? <ChevronRightIcon aria-hidden /> : <ChevronDownIcon aria-hidden />}
        </Button>
        <h3
          id={headingId}
          ref={registerHeading}
          tabIndex={-1}
          className="min-w-0 text-base font-semibold break-all"
        >
          {title}
        </h3>
        <span className="text-xs text-muted-foreground">{`Priority ${rule.priority} · runs ${position + 1} of ${count}`}</span>
        {rule.enabled === false ? (
          <span className="rounded-sm bg-muted px-1.5 py-0.5 text-xs font-medium">Disabled</span>
        ) : null}
        {readOnly ? null : (
          <span className="ml-auto flex items-center gap-0.5">
            {count > 1 ? (
              <MoveButtons
                name={`rule ${rule.id}`}
                onUp={() => move('up')}
                onDown={() => move('down')}
                canUp={position > 0}
                canDown={position < count - 1}
                upRef={registerUp}
                downRef={registerDown}
              />
            ) : null}
            <RemoveButton
              name={`rule ${rule.id}`}
              onClick={() => {
                dispatch({ type: 'remove-rule', ruleKey: rule.key });
                focus.request(...(previousRuleKey ? [previousRuleKey] : []), 'policy:add-rule');
                announce(`Rule ${rule.id} removed.`);
              }}
            />
          </span>
        )}
      </div>

      {isCollapsed ? (
        <p id={bodyId} className="text-sm text-muted-foreground">
          {summary
            ? `${summary.when.map(lineText).join(' ')} → ${summary.then.map(lineText).join(' ')}`
            : null}
        </p>
      ) : (
        <div id={bodyId} className="grid min-w-0 gap-4">
          {readOnly ? (
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]">
              {rule.description !== undefined ? (
                <>
                  <dt className="text-xs text-muted-foreground">Description</dt>
                  <dd className="break-words">{rule.description}</dd>
                </>
              ) : null}
              <dt className="text-xs text-muted-foreground">Enabled</dt>
              <dd>
                {rule.enabled === false ? 'No' : rule.enabled === true ? 'Yes' : 'Yes (default)'}
              </dd>
              <dt className="text-xs text-muted-foreground">Directions</dt>
              <dd>
                {rule.directions
                  ? rule.directions.map(humanizeValue).join(', ')
                  : 'Every direction of the policy'}
              </dd>
              <dt className="text-xs text-muted-foreground">After a match</dt>
              <dd>
                {rule.stop === true
                  ? 'Stop evaluating later rules'
                  : rule.stop === false
                    ? 'Continue with later rules'
                    : 'Default'}
              </dd>
              {rule.override !== undefined ? (
                <>
                  <dt className="text-xs text-muted-foreground">Override</dt>
                  <dd>
                    {rule.override ? 'May override a level-only platform recommendation' : 'No'}
                  </dd>
                </>
              ) : null}
            </dl>
          ) : (
            <div className="grid min-w-0 gap-3">
              <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,10rem)_minmax(0,2fr)]">
                <div className="grid min-w-0 content-start gap-1">
                  <Label htmlFor={idInputId} className="text-xs text-muted-foreground">
                    Rule id
                  </Label>
                  <Input
                    id={idInputId}
                    value={rule.id}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(event) => update({ set: { id: event.target.value.trim() } })}
                    className="h-8 font-mono"
                  />
                </div>
                <div className="grid min-w-0 content-start gap-1">
                  <Label htmlFor={priorityId} className="text-xs text-muted-foreground">
                    Priority
                  </Label>
                  <IntegerInput
                    id={priorityId}
                    value={rule.priority}
                    max={catalog.limits.priorityMax}
                    describedBy={priorityHelpId}
                    onChange={(priority) => {
                      if (priority !== undefined) update({ set: { priority } });
                    }}
                  />
                  <p id={priorityHelpId} className="text-xs text-muted-foreground">
                    Lower numbers run first.
                  </p>
                </div>
                <div className="grid min-w-0 content-start gap-1 sm:col-span-2 lg:col-span-1">
                  <Label htmlFor={descriptionId} className="text-xs text-muted-foreground">
                    Description (optional)
                  </Label>
                  <Input
                    id={descriptionId}
                    value={rule.description ?? ''}
                    maxLength={catalog.limits.descriptionLength}
                    onChange={(event) =>
                      event.target.value === ''
                        ? update({ unset: ['description'] })
                        : update({ set: { description: event.target.value } })
                    }
                    className="h-8"
                  />
                </div>
              </div>
              <div className="flex min-w-0 flex-wrap items-start gap-x-6 gap-y-3">
                <div className="flex items-center gap-2 pt-1">
                  <Switch
                    id={enabledId}
                    checked={rule.enabled !== false}
                    onCheckedChange={(checked) =>
                      checked ? update({ unset: ['enabled'] }) : update({ set: { enabled: false } })
                    }
                  />
                  <Label htmlFor={enabledId}>Enabled</Label>
                </div>
                <div className="grid min-w-0 gap-1">
                  <span id={stopLabelId} className="text-xs text-muted-foreground">
                    After a match
                  </span>
                  <ChoiceSelect
                    labelledBy={stopLabelId}
                    value={
                      rule.stop === true ? 'stop' : rule.stop === false ? 'continue' : undefined
                    }
                    unsetLabel="Default"
                    options={[
                      { value: 'stop', label: 'Stop evaluating later rules' },
                      { value: 'continue', label: 'Continue with later rules' },
                    ]}
                    onChange={(next) =>
                      next === undefined
                        ? update({ unset: ['stop'] })
                        : update({ set: { stop: next === 'stop' } })
                    }
                    className="w-64"
                  />
                </div>
                {showOverride ? (
                  <div className="grid min-w-0 max-w-md gap-1">
                    <div className="flex items-center gap-2">
                      <Switch
                        id={overrideId}
                        checked={rule.override === true}
                        aria-describedby={overrideHelpId}
                        onCheckedChange={(checked) =>
                          checked
                            ? update({ set: { override: true } })
                            : update({ unset: ['override'] })
                        }
                      />
                      <Label htmlFor={overrideId}>
                        May override a level-only platform recommendation
                      </Label>
                    </div>
                    <p id={overrideHelpId} className="text-xs text-muted-foreground">
                      {hasDecision
                        ? 'Takes effect only when the organization allows recommendation overrides; the platform floor always applies.'
                        : 'This rule has no decision action, so an override has no effect; the server will refuse it.'}
                    </p>
                  </div>
                ) : null}
              </div>
              {showDirections ? (
                <div className="grid min-w-0 gap-1">
                  <span className="text-xs text-muted-foreground">Directions</span>
                  {allDirections ? (
                    <>
                      <ToggleList
                        label={`Directions of rule ${rule.id}`}
                        options={catalog.messageDirections.map((d) => ({
                          value: d,
                          label: humanizeValue(d),
                        }))}
                        values={rule.directions ?? []}
                        onChange={(directions) =>
                          directions.length > 0
                            ? update({ set: { directions } })
                            : update({ unset: ['directions'] })
                        }
                      />
                      <p id={directionsHelpId} className="text-xs text-muted-foreground">
                        None selected: every direction of the policy.
                      </p>
                    </>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {`This rule sets its own directions (${(rule.directions ?? []).map(humanizeValue).join(', ')}); the policy direction is ${humanizeValue(policyDirection)}. Rule directions are only needed when the policy covers every direction. `}
                      <Button
                        variant="link"
                        size="sm"
                        className="h-auto p-0 text-xs"
                        onClick={() => update({ unset: ['directions'] })}
                      >
                        Clear the rule directions
                      </Button>
                    </p>
                  )}
                </div>
              ) : null}
            </div>
          )}

          <section aria-label={`Conditions (IF) of rule ${rule.id}`} className="grid min-w-0 gap-2">
            <h4 className="text-sm font-semibold">Conditions (IF)</h4>
            <ConditionTree info={whenInfo} root={rule.when} />
          </section>
          <section
            aria-label={`Exceptions (UNLESS) of rule ${rule.id}`}
            className="grid min-w-0 gap-2"
          >
            <h4 className="text-sm font-semibold">Exceptions (UNLESS)</h4>
            <ExceptionsEditor
              ruleKey={rule.key}
              nodes={rule.unless}
              scope={scope}
              dispatch={dispatch}
              ruleLabel={`rule ${rule.id}`}
            />
          </section>
          <section aria-label={`Actions (THEN) of rule ${rule.id}`} className="grid min-w-0 gap-2">
            <h4 className="text-sm font-semibold">Actions (THEN)</h4>
            <ActionsEditor rule={rule} dispatch={dispatch} />
          </section>
        </div>
      )}
      <ViolationMessages id={violationsId} violations={status.violations} />
    </section>
  );
});
