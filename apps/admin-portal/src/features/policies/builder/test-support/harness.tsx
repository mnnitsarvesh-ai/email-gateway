'use client';

import { useMemo, type ReactNode } from 'react';
import type { BuilderCatalog } from '../catalog';
import { BuilderProvider, type BuilderDirectory, type Violation } from '../context';
import { PolicyBuilderEditor } from '../editor';
import { buildDefinition, parseDefinition, type BuilderDefinition } from '../model';
import { useBuilderState } from '../reducer';
import { TEST_CATALOG } from './catalog';

/** Parses a document for a test (throws on refusal). */
export function modelOf(doc: unknown): BuilderDefinition {
  const parsed = parseDefinition(doc);
  if (!parsed.ok) throw new Error(`refused: ${parsed.reason} at ${parsed.path}`);
  return parsed.model;
}

/**
 * The editor as a page would mount it (state hook + provider), with the built document exposed
 * in an `<output>` for assertions (test-only).
 */
export function EditorHarness({
  initial,
  catalog = TEST_CATALOG,
  readOnly = false,
  violations,
  highlightPath,
  directory,
  children,
}: {
  initial: BuilderDefinition;
  catalog?: BuilderCatalog;
  readOnly?: boolean;
  violations?: Violation[];
  highlightPath?: string | null;
  directory?: BuilderDirectory;
  /** Rendered inside the provider, above the editor (e.g. a ViolationList). */
  children?: ReactNode;
}) {
  const { state, dispatch, isDirty } = useBuilderState(initial);
  const { definition, paths } = useMemo(() => buildDefinition(state), [state]);
  return (
    <BuilderProvider
      catalog={catalog}
      readOnly={readOnly}
      violations={violations}
      paths={paths}
      highlightPath={highlightPath}
      directory={directory}
    >
      {children}
      <PolicyBuilderEditor state={state} dispatch={dispatch} />
      <output data-testid="definition" data-dirty={isDirty}>
        {JSON.stringify(definition)}
      </output>
    </BuilderProvider>
  );
}

/** The current document of an `EditorHarness`. */
export function currentDefinition(): Record<string, unknown> {
  const output = document.querySelector('[data-testid="definition"]');
  return JSON.parse(output?.textContent ?? 'null') as Record<string, unknown>;
}

export const ruleOf = (doc: Record<string, unknown>, i = 0): Record<string, unknown> =>
  (doc.rules as Array<Record<string, unknown>>)[i]!;
