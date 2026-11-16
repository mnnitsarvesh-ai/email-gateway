'use client';

import { ChevronDownIcon, PlusIcon } from 'lucide-react';
import { useCallback, useId, useRef } from 'react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { actionOf, type CatalogAction, type CatalogActionParam } from './catalog';
import { useBuilderContext } from './context';
import { ChoiceSelect } from './inputs';
import { newKey, type BuilderAction, type BuilderRule } from './model';
import {
  HIGHLIGHT_CLASS,
  MoveButtons,
  RemoveButton,
  useNodeStatus,
  ViolationMessages,
} from './parts';
import { canAddAction, type BuilderCommand } from './reducer';
import { humanizeValue } from './summary';

/**
 * The actions of a rule (design §4.7): added from `actionDefinitions` (one disposition, each
 * other action at most once is offered, by `kind`), parameter forms from the definition's
 * `params` (required marked, defaults as placeholders, `maxLength` attributes); an optional
 * parameter is written only when the user sets it.
 */

const UNKNOWN_KIND = 'Action';

function ParamInput({
  param,
  value,
  onSet,
  onUnset,
  registerRef,
}: {
  param: CatalogActionParam;
  value: unknown;
  onSet: (value: unknown) => void;
  onUnset: () => void;
  registerRef?: (element: HTMLElement | null) => void;
}) {
  const labelId = useId();
  const helpId = useId();
  const label = `${param.label}${param.required ? ' (required)' : ''}`;
  const help = param.description ? helpId : undefined;
  let control;
  if (param.type === 'enum') {
    control = (
      <ChoiceSelect
        registerRef={registerRef}
        labelledBy={labelId}
        describedBy={help}
        value={typeof value === 'string' ? value : undefined}
        placeholder="Choose …"
        unsetLabel={
          param.required
            ? undefined
            : `Not set${typeof param.default === 'string' ? ` (default: ${humanizeValue(param.default)})` : ''}`
        }
        options={(param.values ?? []).map((v) => ({ value: v, label: humanizeValue(v) }))}
        onChange={(next) => (next === undefined ? onUnset() : onSet(next))}
      />
    );
  } else if (param.type === 'boolean') {
    control = (
      <ChoiceSelect
        registerRef={registerRef}
        labelledBy={labelId}
        describedBy={help}
        value={value === true ? 'yes' : value === false ? 'no' : undefined}
        placeholder="Choose …"
        unsetLabel={
          param.required
            ? undefined
            : `Default${typeof param.default === 'boolean' ? ` (${param.default ? 'yes' : 'no'})` : ''}`
        }
        options={[
          { value: 'yes', label: 'Yes' },
          { value: 'no', label: 'No' },
        ]}
        onChange={(next) => (next === undefined ? onUnset() : onSet(next === 'yes'))}
      />
    );
  } else {
    control = (
      <Input
        ref={registerRef}
        value={typeof value === 'string' ? value : value === undefined ? '' : JSON.stringify(value)}
        maxLength={param.maxLength ?? undefined}
        placeholder={typeof param.default === 'string' ? `Default: ${param.default}` : undefined}
        aria-labelledby={labelId}
        aria-describedby={help}
        aria-required={param.required || undefined}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => (event.target.value === '' ? onUnset() : onSet(event.target.value))}
        className="h-8 min-w-0"
      />
    );
  }
  return (
    <div className="grid min-w-0 content-start gap-1">
      <span id={labelId} className="text-xs text-muted-foreground">
        {label}
      </span>
      {control}
      {param.description ? (
        <p id={helpId} className="text-xs text-muted-foreground">
          {param.description}
        </p>
      ) : null}
    </div>
  );
}

function ActionCard({
  rule,
  action,
  index,
  count,
  dispatch,
}: {
  rule: BuilderRule;
  action: BuilderAction;
  index: number;
  count: number;
  dispatch: (command: BuilderCommand) => void;
}) {
  const { catalog, readOnly, focus, announce } = useBuilderContext();
  const def = actionOf(catalog, action.type);
  const status = useNodeStatus([action.key]);
  const violationsId = useId();
  const label = def?.label ?? action.type;
  const statusRef = status.ref;
  const registerCard = useCallback(
    (el: HTMLElement | null) => {
      statusRef(el);
      focus.register(action.key, el);
    },
    [statusRef, focus, action.key],
  );
  const registerFirst = useCallback(
    (el: HTMLElement | null) => focus.register(`${action.key}:first`, el),
    [focus, action.key],
  );
  const registerUp = useCallback(
    (el: HTMLElement | null) => focus.register(`${action.key}:up`, el),
    [focus, action.key],
  );
  const registerDown = useCallback(
    (el: HTMLElement | null) => focus.register(`${action.key}:down`, el),
    [focus, action.key],
  );
  const known = new Set(def?.params.map((p) => p.name) ?? []);
  const unknown = Object.keys(action.params).filter((name) => !known.has(name));
  const move = (direction: 'up' | 'down') => {
    dispatch({ type: 'move-action', ruleKey: rule.key, actionKey: action.key, direction });
    focus.request(
      `${action.key}:${direction}`,
      `${action.key}:${direction === 'up' ? 'down' : 'up'}`,
    );
    announce(
      `${label} moved ${direction}, now ${index + (direction === 'up' ? 0 : 2)} of ${count}.`,
    );
  };
  return (
    <li className="min-w-0">
      <div
        ref={registerCard}
        tabIndex={-1}
        role="group"
        aria-label={`Action ${index + 1} of ${count}: ${label}`}
        aria-describedby={status.violations.length > 0 ? violationsId : undefined}
        data-action-key={action.key}
        className={cn(
          'grid min-w-0 gap-2 rounded-md border bg-card p-2',
          status.highlighted && HIGHLIGHT_CLASS,
        )}
      >
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {index > 0 ? (
            <span className="text-xs font-semibold text-muted-foreground" aria-hidden>
              AND
            </span>
          ) : null}
          <span className="text-sm font-semibold">{label}</span>
          <span className="text-xs text-muted-foreground">
            {def
              ? def.kind === 'disposition'
                ? 'Decision'
                : 'Additional action'
              : `${UNKNOWN_KIND} not in the catalogue`}
          </span>
          {readOnly ? null : (
            <span className="ml-auto flex items-center gap-0.5">
              {count > 1 ? (
                <MoveButtons
                  name={`action ${label}`}
                  onUp={() => move('up')}
                  onDown={() => move('down')}
                  canUp={index > 0}
                  canDown={index < count - 1}
                  upRef={registerUp}
                  downRef={registerDown}
                />
              ) : null}
              <RemoveButton
                name={`action ${label}`}
                onClick={() => {
                  dispatch({ type: 'remove-action', ruleKey: rule.key, actionKey: action.key });
                  focus.request(
                    ...(index > 0 ? [rule.actions[index - 1]!.key] : []),
                    `${rule.key}:add-action`,
                  );
                  announce(`${label} removed.`);
                }}
              />
            </span>
          )}
        </div>
        {def?.description ? (
          <p className="text-xs text-muted-foreground">{def.description}</p>
        ) : null}
        {readOnly ? (
          <ParamsText action={action} def={def} />
        ) : def && def.params.length > 0 ? (
          <div className="grid min-w-0 grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {def.params.map((param, i) => (
              <ParamInput
                key={param.name}
                param={param}
                value={action.params[param.name]}
                registerRef={i === 0 ? registerFirst : undefined}
                onSet={(value) =>
                  dispatch({
                    type: 'update-action',
                    ruleKey: rule.key,
                    actionKey: action.key,
                    set: { [param.name]: value },
                  })
                }
                onUnset={() =>
                  dispatch({
                    type: 'update-action',
                    ruleKey: rule.key,
                    actionKey: action.key,
                    unset: [param.name],
                  })
                }
              />
            ))}
          </div>
        ) : null}
        {!readOnly && unknown.length > 0 ? (
          <ul className="grid gap-1 text-xs" aria-label="Parameters not in the catalogue">
            {unknown.map((name) => (
              <li key={name} className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{`${name}: ${JSON.stringify(action.params[name])}`}</span>
                <span className="text-muted-foreground">(not in the catalogue)</span>
                <Button
                  variant="link"
                  size="sm"
                  className="h-auto p-0 text-xs"
                  onClick={() =>
                    dispatch({
                      type: 'update-action',
                      ruleKey: rule.key,
                      actionKey: action.key,
                      unset: [name],
                    })
                  }
                >
                  {`Remove ${name}`}
                </Button>
              </li>
            ))}
          </ul>
        ) : null}
        <ViolationMessages id={violationsId} violations={status.violations} />
      </div>
    </li>
  );
}

function ParamsText({ action, def }: { action: BuilderAction; def: CatalogAction | null }) {
  const entries = Object.entries(action.params);
  if (entries.length === 0) return null;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
      {entries.map(([name, value]) => {
        const param = def?.params.find((p) => p.name === name);
        return (
          <div key={name} className="contents">
            <dt className="text-xs text-muted-foreground">{param?.label ?? name}</dt>
            <dd className="break-words">
              {typeof value === 'boolean'
                ? value
                  ? 'Yes'
                  : 'No'
                : typeof value === 'string'
                  ? value
                  : JSON.stringify(value)}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

export function ActionsEditor({
  rule,
  dispatch,
}: {
  rule: BuilderRule;
  dispatch: (command: BuilderCommand) => void;
}) {
  const { catalog, readOnly, focus, announce } = useBuilderContext();
  const registerAdd = useCallback(
    (el: HTMLElement | null) => focus.register(`${rule.key}:add-action`, el),
    [focus, rule.key],
  );
  const reasonId = useId();
  const present = new Set(rule.actions.map((a) => a.type));
  const hasDisposition = rule.actions.some(
    (a) => actionOf(catalog, a.type)?.kind === 'disposition',
  );
  const offered = catalog.actionDefinitions.filter((def) =>
    def.kind === 'disposition' ? !hasDisposition : !present.has(def.type),
  );
  const decisions = offered.filter((def) => def.kind === 'disposition');
  const others = offered.filter((def) => def.kind !== 'disposition');
  const capacity = canAddAction(rule, catalog.limits);
  // The menu returns the focus to its trigger on close; after an add it goes to the new action.
  const added = useRef(false);
  const add = (def: CatalogAction) => {
    added.current = true;
    const key = newKey('a');
    dispatch({
      type: 'add-action',
      ruleKey: rule.key,
      actionType: def.type,
      key,
      limits: catalog.limits,
    });
    focus.request(`${key}:first`, key);
    announce(`${def.label} added.`);
  };
  return (
    <div className="grid min-w-0 gap-2">
      {rule.actions.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No action yet. A rule needs at least one action.
        </p>
      ) : (
        <ol className="grid min-w-0 gap-2">
          {rule.actions.map((action, index) => (
            <ActionCard
              key={action.key}
              rule={rule}
              action={action}
              index={index}
              count={rule.actions.length}
              dispatch={dispatch}
            />
          ))}
        </ol>
      )}
      {readOnly ? null : (
        <div className="flex flex-wrap items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                ref={registerAdd}
                variant="outline"
                size="sm"
                disabled={!capacity.ok || offered.length === 0}
                aria-describedby={!capacity.ok ? reasonId : undefined}
              >
                <PlusIcon aria-hidden />
                Add action
                <ChevronDownIcon className="opacity-60" aria-hidden />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="start"
              onCloseAutoFocus={(event) => {
                if (added.current) {
                  added.current = false;
                  event.preventDefault();
                }
              }}
            >
              {decisions.length > 0 ? (
                <DropdownMenuGroup>
                  <DropdownMenuLabel>Decision (at most one)</DropdownMenuLabel>
                  {decisions.map((def) => (
                    <DropdownMenuItem key={def.type} onSelect={() => add(def)}>
                      {def.label}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuGroup>
              ) : null}
              {decisions.length > 0 && others.length > 0 ? <DropdownMenuSeparator /> : null}
              {others.length > 0 ? (
                <DropdownMenuGroup>
                  <DropdownMenuLabel>Additional actions</DropdownMenuLabel>
                  {others.map((def) => (
                    <DropdownMenuItem key={def.type} onSelect={() => add(def)}>
                      {def.label}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuGroup>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
          {!capacity.ok ? (
            <span id={reasonId} className="text-xs text-muted-foreground">
              {capacity.reason}
            </span>
          ) : null}
        </div>
      )}
    </div>
  );
}
