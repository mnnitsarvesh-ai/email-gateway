'use client';

import { FolderPlusIcon, PlusIcon } from 'lucide-react';
import {
  createContext,
  memo,
  useCallback,
  useContext,
  useId,
  useMemo,
  type ReactNode,
} from 'react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import {
  changeLeafField,
  changeLeafOperator,
  fieldOf,
  fieldsForAll,
  operatorOf,
  operatorsFor,
  quantifierOf,
  type BuilderCatalog,
  type BuilderPlace,
  type CatalogField,
} from './catalog';
import { useBuilderContext, type Violation } from './context';
import { FieldPicker } from './field-picker';
import { ChoiceSelect } from './inputs';
import {
  newKey,
  type BuilderDefinition,
  type BuilderGroup,
  type BuilderLeaf,
  type BuilderNode,
  type BuilderNot,
} from './model';
import {
  HIGHLIGHT_CLASS,
  LEVEL_CLASS,
  LevelLabel,
  MoveButtons,
  RemoveButton,
  useNodeStatus,
  ViolationMessages,
  WarningMessages,
} from './parts';
import { canAddUnder, canWrap, type BuilderCommand, type LeafContent } from './reducer';
import { formatLeafValue } from './summary';
import { ValueEditor } from './value-editor';

/**
 * The condition tree editor (design §4.7, B14): groups are named fieldsets with an AND/OR
 * toggle, a NOT toggle, Move up/Move down and Remove; condition rows hold the field picker, the
 * operator select, the quantifier of list fields and the value input. Offering comes from the
 * catalogue (`contexts`, `operatorDefinitions`, `contextRules`); anything the server would refuse
 * at this place is flagged as a warning, never silently changed.
 */

export interface TreeInfo {
  /** `when` of a rule, or an exception (rule `unless` entry or policy-wide exception). */
  readonly place: 'when' | 'exception';
  /** The places whose field restrictions apply (offering = fields allowed in all of them). */
  readonly places: readonly BuilderPlace[];
  readonly ruleKey: string | null;
  /** The part of the document the limits are counted on (one rule, or the policy exceptions). */
  readonly scope: BuilderDefinition;
  readonly dispatch: (command: BuilderCommand) => void;
  /** Name of the tree root, e.g. "Conditions of rule block-exe" or "Exception 2 of rule …". */
  readonly rootName: string;
  /** For list roots (exceptions): position, size, previous entry and the list's add button. */
  readonly list: { index: number; count: number; prevKey: string | null; addKey: string } | null;
}

const TreeContext = createContext<TreeInfo | null>(null);

function useTree(): TreeInfo {
  const tree = useContext(TreeContext);
  if (!tree) throw new Error('Condition editors must be rendered inside a condition tree.');
  return tree;
}

interface ParentInfo {
  readonly groupKey: string;
  /** Level of the parent group (root group = 1). */
  readonly level: number;
  readonly index: number;
  readonly count: number;
  /** "all of the following (AND), level 2" */
  readonly description: string;
  readonly prevKey: string | null;
}

/** Where a node sits: in a group, at the root of its tree, or inside a NOT wrapper. */
type Position = ParentInfo | 'root' | 'wrapped';

export const joinerText = (joiner: 'all' | 'any'): string =>
  joiner === 'all' ? 'all of the following (AND)' : 'any of the following (OR)';

/** React key of a node: a NOT shown as a toggle keeps its child's key (no remount on toggle). */
const reactKeyOf = (node: BuilderNode): string =>
  node.kind === 'not' && node.child.kind !== 'not' ? reactKeyOf(node.child) : node.key;

const contentOf = (leaf: BuilderLeaf): LeafContent => {
  const content: LeafContent = {};
  if (leaf.field !== undefined) content.field = leaf.field;
  if (leaf.op !== undefined) content.op = leaf.op;
  if (leaf.value !== undefined) content.value = leaf.value;
  if (leaf.quantifier !== undefined) content.quantifier = leaf.quantifier;
  return content;
};

const labelsOfDispositions = (catalog: BuilderCatalog, dispositions: readonly string[]): string => {
  const labels = catalog.actionDefinitions
    .filter((a) => a.disposition !== null && dispositions.includes(a.disposition))
    .map((a) => a.label);
  if (labels.length <= 1) return labels.join('');
  return `${labels.slice(0, -1).join(', ')} or ${labels[labels.length - 1]!}`;
};

/** Catalogue-derived warnings of a condition at its place (the server's refusal wins anyway). */
export function leafWarnings(
  catalog: BuilderCatalog,
  tree: Pick<TreeInfo, 'place' | 'places'>,
  leaf: BuilderLeaf,
  field: CatalogField | null,
): string[] {
  const out: string[] = [];
  if (!field) {
    if (leaf.field !== undefined) {
      out.push(`The catalogue has no field ${leaf.field}; choose another field.`);
    }
    return out;
  }
  if (leaf.op !== undefined && !field.ops.includes(leaf.op)) {
    out.push(`${field.label} does not support the operator ${leaf.op}; choose another operator.`);
  }
  if (tree.place === 'when') {
    if (tree.places.includes('relaxingWhen') && !field.contexts.relaxingWhen) {
      out.push(
        `${field.label} is not accepted in a rule with ${labelsOfDispositions(catalog, catalog.contextRules.relaxingDispositions)} or an override; the server will refuse it.`,
      );
    }
    if (tree.places.includes('holdRule') && !field.contexts.holdRule) {
      out.push(
        `${field.label} is not accepted in a rule with ${labelsOfDispositions(catalog, catalog.contextRules.holdDispositions)}; the server will refuse it.`,
      );
    }
    return out;
  }
  if (!field.contexts.exception) {
    out.push(`${field.label} is not accepted in exceptions; the server will refuse it.`);
  }
  const operator = operatorOf(catalog, leaf.op);
  if (operator && !operator.allowedInException) {
    out.push(`“${operator.label}” is not accepted in exceptions; the server will refuse it.`);
  }
  const required = catalog.contextRules.exceptionQuantifier;
  if (field.quantified && leaf.quantifier !== required) {
    const phrase = quantifierOf(catalog, required)?.phrase ?? required;
    out.push(
      `An exception on a list field applies to “${phrase} ${catalog.scopeNouns[field.scope] ?? field.scope}” only; the server will refuse another quantifier.`,
    );
  }
  return out;
}

const NEGATION_WARNING =
  'Exceptions cannot be negated; remove the NOT (the server will refuse it).';

function useRegister(id: string) {
  const { focus } = useBuilderContext();
  return useCallback((el: HTMLElement | null) => focus.register(id, el), [focus, id]);
}

// ---------------------------------------------------------------------------------------------
// Tree root and node dispatch
// ---------------------------------------------------------------------------------------------

export function ConditionTree({ info, root }: { info: TreeInfo; root: BuilderNode }) {
  return (
    <TreeContext.Provider value={info}>
      <NodeView node={root} level={1} position="root" negatedBy={null} />
    </TreeContext.Provider>
  );
}

const NodeView = memo(function NodeView({
  node,
  level,
  position,
  negatedBy,
}: {
  node: BuilderNode;
  level: number;
  position: Position;
  negatedBy: string | null;
}) {
  if (node.kind === 'not') {
    if (node.child.kind === 'not')
      return <NotWrapper not={node} level={level} position={position} />;
    return <NodeView node={node.child} level={level} position={position} negatedBy={node.key} />;
  }
  if (node.kind === 'group') {
    return <ConditionGroup group={node} level={level} position={position} negatedBy={negatedBy} />;
  }
  return <ConditionRow leaf={node} position={position} negatedBy={negatedBy} />;
});

/** Structure controls of an element (the node, or the NOT shown through it): NOT, move, remove. */
function useElementControls(
  nodeKey: string,
  negatedBy: string | null,
  position: Position,
  noun: string,
) {
  const { catalog, focus, announce } = useBuilderContext();
  const tree = useTree();
  const elementKey = negatedBy ?? nodeKey;
  const negated = negatedBy !== null;
  const negationAllowed = tree.place === 'when' || catalog.contextRules.exceptionNegation;
  const wrap = canWrap(tree.scope, nodeKey, catalog.limits);
  const slot =
    typeof position === 'object'
      ? {
          index: position.index,
          count: position.count,
          prevKey: position.prevKey,
          addKey: `${position.groupKey}:add`,
        }
      : position === 'root'
        ? tree.list
        : null;
  // Names stay unique within a rule: nested levels and exception trees are named too.
  const where = [
    typeof position === 'object' && position.level > 1 ? `level ${position.level}` : null,
    tree.place === 'exception' ? tree.rootName.toLowerCase() : null,
  ].filter(Boolean);
  const name =
    typeof position === 'object'
      ? `${noun} ${position.index + 1}${where.length > 0 ? ` (${where.join(', ')})` : ''}`
      : position === 'root' && tree.list
        ? tree.rootName
        : noun;
  return {
    elementKey,
    negated,
    name,
    /** Offered where negation is allowed, and always to remove an existing NOT. */
    showNot: negated || negationAllowed,
    notDisabledReason: !negated && !wrap.ok ? wrap.reason : undefined,
    toggleNot: () => {
      tree.dispatch({ type: 'toggle-not', key: nodeKey, limits: catalog.limits });
      focus.request(`${nodeKey}:not`);
      announce(negated ? `NOT removed from ${name.toLowerCase()}.` : `${name} negated (NOT).`);
    },
    canMove: slot !== null && slot.count > 1,
    canUp: slot !== null && slot.index > 0,
    canDown: slot !== null && slot.index < slot.count - 1,
    move: (direction: 'up' | 'down') => {
      tree.dispatch({ type: 'move-node', key: elementKey, direction });
      focus.request(
        `${elementKey}:${direction}`,
        `${elementKey}:${direction === 'up' ? 'down' : 'up'}`,
        nodeKey,
      );
      if (slot) {
        const now = slot.index + (direction === 'up' ? 0 : 2);
        announce(`${noun} moved ${direction}, now ${now} of ${slot.count}.`);
      }
    },
    canRemove: slot !== null,
    remove: () => {
      if (slot) {
        focus.request(...[slot.prevKey, slot.addKey].filter((k): k is string => k !== null));
      }
      tree.dispatch({ type: 'remove-node', key: elementKey });
      announce(`${name} removed.`);
    },
  };
}

type Controls = ReturnType<typeof useElementControls>;

function NotButton({ nodeKey, controls }: { nodeKey: string; controls: Controls }) {
  const register = useRegister(`${nodeKey}:not`);
  return (
    <Button
      ref={register}
      variant={controls.negated ? 'default' : 'outline'}
      size="sm"
      className="h-7 px-2 font-semibold"
      aria-pressed={controls.negated}
      aria-label={`NOT: negate ${controls.name.toLowerCase()}`}
      title={controls.notDisabledReason ?? (controls.negated ? 'Remove NOT' : 'Negate (NOT)')}
      disabled={controls.notDisabledReason !== undefined}
      onClick={controls.toggleNot}
    >
      NOT
    </Button>
  );
}

function StructureButtons({ controls }: { controls: Controls }) {
  const registerUp = useRegister(`${controls.elementKey}:up`);
  const registerDown = useRegister(`${controls.elementKey}:down`);
  const name = controls.name.toLowerCase();
  if (!controls.canMove && !controls.canRemove) return null;
  return (
    <span className="flex items-center gap-0.5">
      {controls.canMove ? (
        <MoveButtons
          name={name}
          onUp={() => controls.move('up')}
          onDown={() => controls.move('down')}
          canUp={controls.canUp}
          canDown={controls.canDown}
          upRef={registerUp}
          downRef={registerDown}
        />
      ) : null}
      {controls.canRemove ? <RemoveButton name={name} onClick={controls.remove} /> : null}
    </span>
  );
}

/** "Add condition" / "Add group" (disabled at the catalogue limits, with the reason). */
function AddButtons({ parentKey, wraps }: { parentKey: string; wraps: boolean }) {
  const { catalog, focus, announce } = useBuilderContext();
  const tree = useTree();
  const registerAdd = useRegister(`${parentKey}:add`);
  const condition = canAddUnder(tree.scope, parentKey, 'condition', catalog.limits);
  const group = canAddUnder(tree.scope, parentKey, 'group', catalog.limits);
  const reasonId = useId();
  const reason = !condition.ok ? condition.reason : !group.ok ? group.reason : undefined;
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <Button
        ref={registerAdd}
        variant="outline"
        size="sm"
        disabled={!condition.ok}
        aria-describedby={!condition.ok ? reasonId : undefined}
        onClick={() => {
          const key = newKey('n');
          tree.dispatch({ type: 'add-condition', parentKey, key, limits: catalog.limits });
          focus.request(key);
          announce(
            wraps
              ? 'Condition added; both conditions now form a group (all of the following, AND). Choose its field.'
              : 'Condition added. Choose its field.',
          );
        }}
      >
        <PlusIcon aria-hidden />
        Add condition
      </Button>
      <Button
        variant="outline"
        size="sm"
        disabled={!group.ok}
        aria-describedby={!group.ok ? reasonId : undefined}
        onClick={() => {
          const key = newKey('n');
          const childKey = newKey('n');
          tree.dispatch({ type: 'add-group', parentKey, key, childKey, limits: catalog.limits });
          focus.request(childKey);
          announce('Group added with one condition. Choose its field.');
        }}
      >
        <FolderPlusIcon aria-hidden />
        Add group
      </Button>
      {reason ? (
        <span id={reasonId} className="text-xs text-muted-foreground">
          {reason}
        </span>
      ) : null}
    </div>
  );
}

const describedByOf = (...ids: Array<string | false | null | undefined>): string | undefined =>
  ids.filter(Boolean).join(' ') || undefined;

// ---------------------------------------------------------------------------------------------
// Groups and NOT wrappers
// ---------------------------------------------------------------------------------------------

function ConditionGroup({
  group,
  level,
  position,
  negatedBy,
}: {
  group: BuilderGroup;
  level: number;
  position: Position;
  negatedBy: string | null;
}) {
  const { readOnly, announce, catalog, focus } = useBuilderContext();
  const tree = useTree();
  const status = useNodeStatus([group.key, negatedBy]);
  const violationsId = useId();
  const warningsId = useId();
  const controls = useElementControls(group.key, negatedBy, position, 'Group');
  const registerPrimary = useCallback(
    (el: HTMLElement | null) => {
      focus.register(group.key, el);
      if (negatedBy) focus.register(negatedBy, el);
    },
    [focus, group.key, negatedBy],
  );
  // In view mode there is no control: the container itself takes the focus (error summary).
  const statusRef = status.ref;
  const containerRef = useCallback(
    (el: HTMLElement | null) => {
      statusRef(el);
      if (readOnly) registerPrimary(el);
    },
    [statusRef, readOnly, registerPrimary],
  );
  const description = `${joinerText(group.joiner)}, level ${level}`;
  const name = `${typeof position === 'object' ? `Group ${position.index + 1}` : tree.rootName}, ${description}${controls.negated ? ', negated (NOT)' : ''}`;
  const warnings =
    tree.place === 'exception' && controls.negated && !catalog.contextRules.exceptionNegation
      ? [NEGATION_WARNING]
      : [];
  const setJoiner = (joiner: 'all' | 'any') => {
    if (joiner === group.joiner) return;
    tree.dispatch({ type: 'set-joiner', key: group.key, joiner });
    announce(`The group now matches ${joinerText(joiner)}.`);
  };
  return (
    <fieldset
      ref={containerRef}
      tabIndex={readOnly ? -1 : undefined}
      data-node-key={group.key}
      aria-describedby={describedByOf(
        status.violations.length > 0 && violationsId,
        warnings.length > 0 && warningsId,
      )}
      className={cn(
        'grid min-w-0 gap-2 rounded-md',
        level > 1 && LEVEL_CLASS,
        status.highlighted && HIGHLIGHT_CLASS,
      )}
    >
      <legend className="sr-only">{name}</legend>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <LevelLabel level={level} />
        {readOnly ? (
          <span className="text-sm">
            {controls.negated ? <span className="font-semibold">NOT </span> : null}
            <span className="font-semibold">{group.joiner === 'all' ? 'All' : 'Any'}</span>
            {` of the following (${group.joiner === 'all' ? 'AND' : 'OR'})`}
          </span>
        ) : (
          <>
            <div
              role="group"
              aria-label={`Match: ${name}`}
              className="inline-flex rounded-md border p-0.5"
            >
              <Button
                ref={registerPrimary}
                variant={group.joiner === 'all' ? 'default' : 'ghost'}
                size="sm"
                className="h-7 px-2"
                aria-pressed={group.joiner === 'all'}
                onClick={() => setJoiner('all')}
              >
                All (AND)
              </Button>
              <Button
                variant={group.joiner === 'any' ? 'default' : 'ghost'}
                size="sm"
                className="h-7 px-2"
                aria-pressed={group.joiner === 'any'}
                onClick={() => setJoiner('any')}
              >
                Any (OR)
              </Button>
            </div>
            {controls.showNot ? <NotButton nodeKey={group.key} controls={controls} /> : null}
            <StructureButtons controls={controls} />
          </>
        )}
      </div>
      {group.children.length === 0 ? (
        <p className="text-xs text-muted-foreground">No conditions in this group yet.</p>
      ) : (
        <ol className="grid min-w-0 gap-2">
          {group.children.map((child, index) => {
            const nested =
              child.kind === 'group' || (child.kind === 'not' && child.child.kind === 'group');
            return (
              <li key={reactKeyOf(child)} className="grid min-w-0 gap-1">
                {index > 0 ? (
                  <span className="text-xs font-semibold text-muted-foreground" aria-hidden>
                    {group.joiner === 'all' ? 'AND' : 'OR'}
                  </span>
                ) : null}
                <NodeView
                  node={child}
                  level={nested ? level + 1 : level}
                  position={{
                    groupKey: group.key,
                    level,
                    index,
                    count: group.children.length,
                    description,
                    prevKey: index > 0 ? group.children[index - 1]!.key : null,
                  }}
                  negatedBy={null}
                />
              </li>
            );
          })}
        </ol>
      )}
      {readOnly ? null : <AddButtons parentKey={group.key} wraps={false} />}
      <WarningMessages id={warningsId} warnings={warnings} />
      <ViolationMessages id={violationsId} violations={status.violations} />
    </fieldset>
  );
}

/** A NOT of a NOT (kept as written): an explicit wrapper with "Remove NOT". */
function NotWrapper({
  not,
  level,
  position,
}: {
  not: BuilderNot;
  level: number;
  position: Position;
}) {
  const { readOnly, announce } = useBuilderContext();
  const tree = useTree();
  const status = useNodeStatus([not.key]);
  const violationsId = useId();
  const controls = useElementControls(not.key, null, position, 'Negation');
  const registerPrimary = useRegister(not.key);
  return (
    <div
      ref={status.ref}
      role="group"
      aria-label={`${typeof position === 'object' ? `Item ${position.index + 1}` : tree.rootName}: NOT (negation)`}
      aria-describedby={describedByOf(status.violations.length > 0 && violationsId)}
      data-node-key={not.key}
      className={cn(
        'grid min-w-0 gap-2 rounded-md border border-dashed p-2',
        status.highlighted && HIGHLIGHT_CLASS,
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold">NOT</span>
        {readOnly ? null : (
          <>
            <Button
              ref={registerPrimary}
              variant="outline"
              size="sm"
              className="h-7"
              onClick={() => {
                tree.dispatch({ type: 'toggle-not', key: not.child.key });
                announce('NOT removed.');
              }}
            >
              Remove NOT
            </Button>
            <StructureButtons controls={controls} />
          </>
        )}
      </div>
      <NodeView node={not.child} level={level} position="wrapped" negatedBy={null} />
      {tree.place === 'exception' ? (
        <WarningMessages id={`${violationsId}-w`} warnings={[NEGATION_WARNING]} />
      ) : null}
      <ViolationMessages id={violationsId} violations={status.violations} />
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Condition rows
// ---------------------------------------------------------------------------------------------

const FIELDS_GRID =
  'grid min-w-0 grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_minmax(0,1.5fr)]';

const pathEnds = (violations: readonly Violation[], suffix: string) =>
  violations.some((v) => v.path.endsWith(suffix));

function ConditionRow({
  leaf,
  position,
  negatedBy,
}: {
  leaf: BuilderLeaf;
  position: Position;
  negatedBy: string | null;
}) {
  const { catalog, readOnly, names, focus } = useBuilderContext();
  const tree = useTree();
  const status = useNodeStatus([leaf.key, negatedBy]);
  const fieldLabelId = useId();
  const opLabelId = useId();
  const valueLabelId = useId();
  const quantifierLabelId = useId();
  const violationsId = useId();
  const warningsId = useId();
  const controls = useElementControls(leaf.key, negatedBy, position, 'Condition');
  const field = fieldOf(catalog, leaf.field);
  const operator = operatorOf(catalog, leaf.op);
  const offeredFields = useMemo(() => fieldsForAll(catalog, tree.places), [catalog, tree.places]);
  const place: BuilderPlace = tree.place === 'exception' ? 'exception' : 'when';
  const offeredOps = leaf.field !== undefined ? operatorsFor(catalog, leaf.field, place) : [];
  const warnings = leafWarnings(catalog, tree, leaf, field);
  if (tree.place === 'exception' && controls.negated && !catalog.contextRules.exceptionNegation) {
    warnings.push(NEGATION_WARNING);
  }
  const registerPrimary = useCallback(
    (el: HTMLElement | null) => {
      focus.register(leaf.key, el);
      if (negatedBy) focus.register(negatedBy, el);
    },
    [focus, leaf.key, negatedBy],
  );
  // In view mode there is no control: the row itself takes the focus (error summary).
  const statusRef = status.ref;
  const containerRef = useCallback(
    (el: HTMLElement | null) => {
      statusRef(el);
      if (readOnly) registerPrimary(el);
    },
    [statusRef, readOnly, registerPrimary],
  );
  const name =
    typeof position === 'object'
      ? `Condition ${position.index + 1} of ${position.count} in ${position.description}`
      : position === 'root'
        ? tree.rootName
        : `${tree.rootName}: negated condition`;
  const describedBy = describedByOf(
    status.violations.length > 0 && violationsId,
    warnings.length > 0 && warningsId,
  );
  const update = (content: LeafContent) =>
    tree.dispatch({ type: 'update-leaf', key: leaf.key, leaf: content });
  const noun = field ? (catalog.scopeNouns[field.scope] ?? field.scope) : '';
  const phraseOf = (id: string) => quantifierOf(catalog, id)?.phrase ?? id;

  let quantifier: ReactNode = null;
  if (field?.quantified) {
    const required = catalog.contextRules.exceptionQuantifier;
    if (tree.place === 'exception') {
      quantifier = (
        <p className="text-xs text-muted-foreground">
          {`Applies to: ${leaf.quantifier === undefined ? 'not set' : `${phraseOf(leaf.quantifier)} ${noun}`}`}
          {leaf.quantifier !== required && !readOnly ? (
            <Button
              variant="link"
              size="sm"
              className="ml-1 h-auto p-0 text-xs"
              onClick={() => update({ ...contentOf(leaf), quantifier: required })}
            >
              {`Use “${phraseOf(required)} ${noun}”`}
            </Button>
          ) : null}
        </p>
      );
    } else if (readOnly) {
      quantifier =
        leaf.quantifier !== undefined ? (
          <p className="text-xs text-muted-foreground">{`Applies to: ${phraseOf(leaf.quantifier)} ${noun}`}</p>
        ) : null;
    } else {
      quantifier = (
        <div className="grid gap-1">
          <span id={quantifierLabelId} className="text-xs text-muted-foreground">
            Applies to
          </span>
          <ChoiceSelect
            labelledBy={quantifierLabelId}
            value={leaf.quantifier}
            unsetLabel={`Default (${phraseOf(catalog.contextRules.defaultQuantifier)} ${noun})`}
            options={catalog.quantifiers.map((q) => ({
              value: q.id,
              label: `${q.phrase} ${noun}`,
            }))}
            onChange={(next) => {
              const content = contentOf(leaf);
              delete content.quantifier;
              update(next === undefined ? content : { ...content, quantifier: next });
            }}
          />
        </div>
      );
    }
  }

  const fields: ReactNode = readOnly ? (
    <dl className={FIELDS_GRID} data-layout="condition-fields">
      <div className="grid min-w-0 content-start gap-0.5">
        <dt className="text-xs text-muted-foreground">Field</dt>
        <dd className="text-sm font-medium break-words">
          {field?.label ?? leaf.field ?? 'Not set'}
        </dd>
        {quantifier ? <dd>{quantifier}</dd> : null}
      </div>
      <div className="grid min-w-0 content-start gap-0.5">
        <dt className="text-xs text-muted-foreground">Operator</dt>
        <dd className="text-sm">{operator?.label ?? leaf.op ?? 'Not set'}</dd>
      </div>
      <div className="grid min-w-0 content-start gap-0.5">
        <dt className="text-xs text-muted-foreground">Value</dt>
        <dd className="text-sm break-words">{formatLeafValue(catalog, leaf, names) || 'None'}</dd>
      </div>
    </dl>
  ) : (
    <div className={FIELDS_GRID} data-layout="condition-fields">
      <div className="grid min-w-0 content-start gap-1">
        <span id={fieldLabelId} className="text-xs text-muted-foreground">
          Field
        </span>
        <FieldPicker
          catalog={catalog}
          fields={offeredFields}
          value={leaf.field}
          labelId={fieldLabelId}
          describedBy={describedBy}
          invalid={pathEnds(status.violations, '.field')}
          registerRef={registerPrimary}
          onChange={(next) => update(contentOf(changeLeafField(catalog, leaf, next, place)))}
        />
        {quantifier}
      </div>
      <div className="grid min-w-0 content-start gap-1">
        <span id={opLabelId} className="text-xs text-muted-foreground">
          Operator
        </span>
        <ChoiceSelect
          labelledBy={opLabelId}
          describedBy={describedBy}
          invalid={pathEnds(status.violations, '.op')}
          disabled={leaf.field === undefined}
          placeholder={leaf.field === undefined ? 'Choose a field first' : 'Choose an operator'}
          value={leaf.op}
          options={offeredOps.map((o) => ({ value: o.op, label: o.label }))}
          onChange={(op) => {
            if (op !== undefined) update(contentOf(changeLeafOperator(catalog, leaf, op)));
          }}
        />
        {operator?.description ? (
          <p className="text-xs text-muted-foreground">{operator.description}</p>
        ) : null}
      </div>
      <div className="grid min-w-0 content-start gap-1">
        <span id={valueLabelId} className="text-xs text-muted-foreground">
          Value
        </span>
        {field && operator && offeredOps.some((o) => o.op === operator.op) ? (
          <ValueEditor
            key={`${field.name}|${operator.op}`}
            field={field}
            operator={operator}
            value={leaf.value}
            labelledBy={valueLabelId}
            describedBy={describedBy}
            invalid={status.violations.some((v) => v.path.includes('.value'))}
            onChange={(value) => {
              const content = contentOf(leaf);
              delete content.value;
              update(value === undefined ? content : { ...content, value });
            }}
          />
        ) : leaf.value !== undefined ? (
          <p className="pt-2 font-mono text-xs break-all">{JSON.stringify(leaf.value)}</p>
        ) : (
          <p className="pt-2 text-xs text-muted-foreground">
            {leaf.field === undefined ? 'Choose a field first.' : 'Choose an operator first.'}
          </p>
        )}
      </div>
    </div>
  );

  return (
    <div
      ref={containerRef}
      tabIndex={readOnly ? -1 : undefined}
      role="group"
      aria-label={name}
      aria-describedby={describedBy}
      data-node-key={leaf.key}
      data-layout="condition-row"
      className={cn(
        'grid min-w-0 gap-2 rounded-md border bg-card p-2',
        status.highlighted && HIGHLIGHT_CLASS,
      )}
    >
      {controls.negated ? (
        <span className="w-fit rounded-sm bg-muted px-1.5 py-0.5 text-xs font-semibold">NOT</span>
      ) : null}
      {fields}
      {readOnly ? null : (
        <div className="flex min-w-0 flex-wrap items-center gap-1">
          {controls.showNot ? <NotButton nodeKey={leaf.key} controls={controls} /> : null}
          <StructureButtons controls={controls} />
        </div>
      )}
      {!readOnly && position === 'root' ? (
        <AddButtons parentKey={controls.elementKey} wraps />
      ) : null}
      <WarningMessages id={warningsId} warnings={warnings} />
      <ViolationMessages id={violationsId} violations={status.violations} />
    </div>
  );
}
