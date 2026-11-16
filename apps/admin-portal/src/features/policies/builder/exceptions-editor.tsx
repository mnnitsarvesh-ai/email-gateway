'use client';

import { ShieldPlusIcon } from 'lucide-react';
import { useCallback, useId, useMemo } from 'react';
import { Button } from '@/components/ui/button';
import { ConditionTree, type TreeInfo } from './conditions';
import { useBuilderContext } from './context';
import { newKey, type BuilderDefinition, type BuilderNode } from './model';
import { canAddException, type BuilderCommand } from './reducer';

/**
 * Exceptions of a rule (`unless`) or of the whole policy (`exceptions`): each entry is its own
 * condition tree offering only the fields whose catalogue `contexts.exception` is true, only
 * operators `allowedInException`, the catalogue's exception quantifier and no NOT (unless the
 * catalogue allows exception negation).
 */
export function ExceptionsEditor({
  ruleKey,
  nodes,
  scope,
  dispatch,
  ruleLabel,
}: {
  /** `null` = policy-wide exceptions. */
  ruleKey: string | null;
  nodes: readonly BuilderNode[] | undefined;
  /** The document part the limits count on (the rule, or the policy exceptions). */
  scope: BuilderDefinition;
  dispatch: (command: BuilderCommand) => void;
  /** "rule block-exe" (names the trees for screen readers). */
  ruleLabel?: string;
}) {
  const { catalog, readOnly, focus, announce } = useBuilderContext();
  const addKey = `${ruleKey ?? 'policy'}:exceptions:add`;
  const registerAdd = useCallback(
    (el: HTMLElement | null) => focus.register(addKey, el),
    [focus, addKey],
  );
  const reasonId = useId();
  const capacity = canAddException(scope, ruleKey, catalog.limits);
  const list = useMemo(() => nodes ?? [], [nodes]);
  const infos = useMemo(
    () =>
      list.map((_, index): TreeInfo => ({
        place: 'exception',
        places: ['exception'],
        ruleKey,
        scope,
        dispatch,
        rootName:
          ruleKey === null
            ? `Policy-wide exception ${index + 1}`
            : `Exception ${index + 1}${ruleLabel ? ` of ${ruleLabel}` : ''}`,
        list: {
          index,
          count: list.length,
          prevKey: index > 0 ? list[index - 1]!.key : null,
          addKey,
        },
      })),
    [list, ruleKey, scope, dispatch, ruleLabel, addKey],
  );
  return (
    <div className="grid min-w-0 gap-2">
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {ruleKey === null ? 'No policy-wide exceptions.' : 'No exceptions.'}
        </p>
      ) : (
        <ol className="grid min-w-0 gap-2">
          {list.map((node, index) => (
            <li key={node.key} className="grid min-w-0 gap-1">
              {index > 0 ? (
                <span className="text-xs font-semibold text-muted-foreground" aria-hidden>
                  OR
                </span>
              ) : null}
              <ConditionTree info={infos[index]!} root={node} />
            </li>
          ))}
        </ol>
      )}
      {readOnly ? null : (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            ref={registerAdd}
            variant="outline"
            size="sm"
            disabled={!capacity.ok}
            aria-describedby={!capacity.ok ? reasonId : undefined}
            onClick={() => {
              const key = newKey('n');
              dispatch({ type: 'add-exception', ruleKey, key, limits: catalog.limits });
              focus.request(key);
              announce(
                ruleKey === null
                  ? 'Policy-wide exception added. Choose its field.'
                  : 'Exception added. Choose its field.',
              );
            }}
          >
            <ShieldPlusIcon aria-hidden />
            {ruleKey === null ? 'Add policy-wide exception' : 'Add exception'}
          </Button>
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
