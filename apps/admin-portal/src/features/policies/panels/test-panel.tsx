'use client';

import { FlaskConicalIcon } from 'lucide-react';
import { useId, useState, type Dispatch, type SetStateAction } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import {
  EvaluationResultView,
  FACT_PRESETS,
  SyntheticFactsForm,
  ViolationList,
  type BuilderCatalog,
  type PolicyTestResponse,
  type SyntheticFacts,
  type Violation,
} from '../builder';
import { ChoiceSelect } from '../builder/inputs';
import { violationsOf } from '../queries';
import { PanelSheet } from './panel-sheet';
import { TargetChooser } from './target-chooser';
import { refBelongsTo, type PolicyTarget, type TargetId, type TargetOption } from './targets';

/** What the test panel keeps while it is closed (the page owns it; design B7). */
export interface TestPanelState {
  readonly targetId: TargetId;
  readonly facts: SyntheticFacts;
  readonly presetId: string | null;
  readonly response: PolicyTestResponse | null;
  /** The target the response was computed for (its "Show in editor" refs). */
  readonly responseTarget: TargetId | null;
}

export function useTestPanelState(defaultTarget: TargetId) {
  return useState<TestPanelState>(() => ({
    targetId: defaultTarget,
    facts: {},
    presetId: null,
    response: null,
    responseTarget: null,
  }));
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** The Advanced (JSON) view of the facts: the same object, edited as text (input hygiene only). */
function FactsJsonEditor({
  facts,
  onApply,
}: {
  facts: SyntheticFacts;
  onApply: (facts: SyntheticFacts) => void;
}) {
  const id = useId();
  const [text, setText] = useState(() => JSON.stringify(facts, null, 2));
  const [problem, setProblem] = useState<string | null>(null);
  const apply = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setProblem('This is not JSON. Fix the text or reset it to the form’s facts.');
      return;
    }
    if (!isPlainObject(parsed)) {
      setProblem('Enter a JSON object such as { "direction": "inbound" }.');
      return;
    }
    setProblem(null);
    // Shape and vocabulary are checked by the server (`400 policy_test_facts_invalid`).
    onApply(parsed);
  };
  return (
    <div className="grid min-w-0 gap-2">
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        Facts as JSON (the request’s <code className="font-mono">facts</code>)
      </Label>
      <Textarea
        id={id}
        value={text}
        onChange={(event) => setText(event.target.value)}
        rows={12}
        spellCheck={false}
        className="font-mono text-xs"
        aria-invalid={problem !== null || undefined}
        aria-describedby={problem ? `${id}-problem` : undefined}
      />
      {problem ? (
        <p id={`${id}-problem`} className="text-xs font-medium text-destructive">
          {problem}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" size="sm" onClick={apply}>
          Apply JSON
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setText(JSON.stringify(facts, null, 2));
            setProblem(null);
          }}
        >
          Reset to the form’s facts
        </Button>
      </div>
    </div>
  );
}

/**
 * The test panel (design B7): a target, synthetic facts (form, presets, JSON), Run →
 * `POST /policies/test` (writes nothing) and the server's result. The browser never evaluates.
 */
export function PolicyTestPanel({
  open,
  onOpenChange,
  catalog,
  targets,
  state,
  onStateChange,
  onShowPath,
  onInlineViolations,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  catalog: BuilderCatalog;
  targets: readonly TargetOption[];
  state: TestPanelState;
  onStateChange: Dispatch<SetStateAction<TestPanelState>>;
  /** "Show in editor" of a trace row of the edited document. */
  onShowPath?: (path: string) => void;
  /** Violations of an inline definition (`400 policy_definition_invalid`) for the editor. */
  onInlineViolations?: (violations: Violation[]) => void;
}) {
  const allowed = useCan('PolicyToolsController_test_v1');
  return (
    <PanelSheet
      open={open}
      onOpenChange={onOpenChange}
      title="Test with synthetic facts"
      description="The server evaluates the facts against the target and returns its decision. Nothing is stored."
    >
      {allowed ? (
        <TestPanelBody
          catalog={catalog}
          targets={targets}
          state={state}
          onStateChange={onStateChange}
          onShowPath={onShowPath}
          onInlineViolations={onInlineViolations}
        />
      ) : (
        <p className="text-sm text-muted-foreground">
          Testing needs the <code className="font-mono">policy:manage</code> permission.
        </p>
      )}
    </PanelSheet>
  );
}

function TestPanelBody({
  catalog,
  targets,
  state,
  onStateChange,
  onShowPath,
  onInlineViolations,
}: {
  catalog: BuilderCatalog;
  targets: readonly TargetOption[];
  state: TestPanelState;
  onStateChange: Dispatch<SetStateAction<TestPanelState>>;
  onShowPath?: (path: string) => void;
  onInlineViolations?: (violations: Violation[]) => void;
}) {
  const presetId = useId();
  const test = useApiMutation('PolicyToolsController_test_v1', { successMessage: null });
  const [jsonOpen, setJsonOpen] = useState(false);
  const [jsonNonce, setJsonNonce] = useState(0);
  const [preparing, setPreparing] = useState(false);
  const target = targets.find((t) => t.id === state.targetId) ?? targets[0];
  const set = (patch: Partial<TestPanelState>) => onStateChange((s) => ({ ...s, ...patch }));
  const busy = test.isPending || preparing;
  const waiting = test.retryAfterSeconds > 0;
  const definitionViolations =
    test.error?.code === 'policy_definition_invalid' ? violationsOf(test.error) : [];

  const run = async () => {
    if (!target) return;
    setPreparing(true);
    let resolved: PolicyTarget | null = null;
    try {
      resolved = await target.resolve();
    } catch {
      resolved = null;
    } finally {
      setPreparing(false);
    }
    if (resolved === null) return;
    const outcome = await test.submit({ body: { target: resolved, facts: state.facts } });
    if (outcome.ok) {
      set({ response: outcome.data, responseTarget: target.id });
    } else if (outcome.error.code === 'policy_definition_invalid') {
      onInlineViolations?.(violationsOf(outcome.error));
    }
  };

  const responseTarget = targets.find((t) => t.id === state.responseTarget);
  const editorPrefix = responseTarget?.editorRefPrefix;

  return (
    <div className="grid min-w-0 gap-4" data-testid="policy-test-panel">
      <TargetChooser
        targets={targets}
        value={target?.id ?? 'active'}
        onChange={(targetId) => set({ targetId })}
      />
      <div className="grid min-w-0 gap-1">
        <Label id={presetId} className="text-xs text-muted-foreground">
          Start from an example
        </Label>
        <ChoiceSelect
          labelledBy={presetId}
          value={state.presetId ?? undefined}
          unsetLabel="No example (keep my facts)"
          options={FACT_PRESETS.map((preset) => ({ value: preset.id, label: preset.label }))}
          onChange={(id) => {
            const preset = FACT_PRESETS.find((p) => p.id === id);
            set({ presetId: id ?? null, ...(preset ? { facts: preset.facts } : {}) });
            setJsonNonce((n) => n + 1);
          }}
          className="sm:max-w-80"
        />
        {state.presetId ? (
          <p className="text-xs text-muted-foreground">
            {FACT_PRESETS.find((p) => p.id === state.presetId)?.description}
          </p>
        ) : null}
      </div>
      <SyntheticFactsForm
        catalog={catalog}
        value={state.facts}
        onChange={(facts) => {
          set({ facts });
          setJsonNonce((n) => n + 1);
        }}
      />
      <Collapsible open={jsonOpen} onOpenChange={setJsonOpen}>
        <CollapsibleTrigger asChild>
          <Button variant="outline" size="sm">
            {jsonOpen ? 'Hide Advanced (JSON)' : 'Advanced (JSON)'}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="mt-2">
          <FactsJsonEditor
            key={jsonNonce}
            facts={state.facts}
            onApply={(facts) => set({ facts, presetId: null })}
          />
        </CollapsibleContent>
      </Collapsible>
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => void run()} disabled={busy || waiting || !target}>
          <FlaskConicalIcon aria-hidden />
          {busy ? 'Running …' : target?.needsSave ? 'Save and test' : 'Run test'}
        </Button>
        {waiting ? (
          <span className="text-xs text-muted-foreground" aria-live="polite">
            {`Too many requests: try again in ${test.retryAfterSeconds} s.`}
          </span>
        ) : null}
      </div>
      {test.error && !test.isPending ? (
        test.error.code === 'policy_test_facts_invalid' ? (
          <div
            role="alert"
            className="grid gap-1 rounded-md border border-destructive/40 p-3 text-sm"
          >
            <p className="font-semibold">The server did not accept these facts</p>
            <ul className="grid gap-0.5 text-xs">
              {test.error.messages.map((message, i) => (
                <li key={i} className="break-words">
                  {message}
                </li>
              ))}
            </ul>
            <p className="font-mono text-xs">policy_test_facts_invalid</p>
          </div>
        ) : definitionViolations.length > 0 ? (
          <ViolationList violations={definitionViolations} onSelect={onShowPath} />
        ) : test.error.status === 429 ? null : (
          <ErrorState error={test.error} compact />
        )
      ) : null}
      {state.response ? (
        <EvaluationResultView
          response={state.response}
          catalog={catalog}
          onShowPath={editorPrefix && onShowPath ? onShowPath : undefined}
          isEditorRef={editorPrefix ? refBelongsTo(editorPrefix) : undefined}
        />
      ) : null}
    </div>
  );
}
