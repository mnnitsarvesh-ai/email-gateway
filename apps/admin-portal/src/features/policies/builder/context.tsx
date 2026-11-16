'use client';

import {
  createContext,
  useCallback,
  useContext,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type Ref,
} from 'react';
import type { BuilderCatalog } from './catalog';
import { EMPTY_PATH_INDEX, keyForPath, type PathIndex } from './paths';
import type { DirectoryNames } from './summary';

/**
 * Shared state of the builder components (design §4.7): the catalogue, view or edit mode, the
 * server violations mapped onto node keys through the path index, the highlighted node, the
 * directory options, a polite live region for structural changes and focus requests (after an
 * add the focus moves to the new row, after a remove to the previous row).
 */

/** A server violation (`{ path, code, message }` of the validator, B4). */
export interface Violation {
  path: string;
  code: string;
  message: string;
}

/** A department or user the directory pickers offer. */
export interface DirectoryOption {
  id: string;
  label: string;
}

export interface BuilderDirectory {
  departments?: DirectoryOption[];
  users?: DirectoryOption[];
  loading?: boolean;
}

/** Focus targets by id (`<key>` = the node's primary control, `<key>:add` = its add button). */
export class FocusRegistry {
  private readonly elements = new Map<string, HTMLElement>();
  private pending: string[] | null = null;

  register(id: string, element: HTMLElement | null): void {
    if (element) this.elements.set(id, element);
    else this.elements.delete(id);
  }

  /** Focus the first registered id of the list after the next commit (`flush`). */
  request(...ids: string[]): void {
    this.pending = ids;
  }

  /** Called after a commit: focuses the first connected, enabled target; one attempt only. */
  flush(): void {
    const pending = this.pending;
    this.pending = null;
    if (!pending) return;
    for (const id of pending) {
      const element = this.elements.get(id);
      if (element?.isConnected && !(element as HTMLButtonElement).disabled) {
        element.focus();
        return;
      }
    }
  }

  focusNow(id: string): boolean {
    const element = this.elements.get(id);
    if (!element?.isConnected) return false;
    element.focus();
    element.scrollIntoView?.({ block: 'center' });
    return true;
  }
}

export interface BuilderContextValue {
  readonly catalog: BuilderCatalog;
  readonly readOnly: boolean;
  readonly paths: PathIndex;
  readonly violationsByKey: ReadonlyMap<string, readonly Violation[]>;
  /** Violations whose path maps to no node (policy level). */
  readonly unmapped: readonly Violation[];
  readonly highlightKey: string | null;
  readonly highlightPath: string | null;
  readonly directory: BuilderDirectory | undefined;
  readonly names: DirectoryNames;
  readonly announce: (message: string) => void;
  readonly focus: FocusRegistry;
}

const BuilderContext = createContext<BuilderContextValue | null>(null);

export function useBuilderContext(): BuilderContextValue {
  const value = useContext(BuilderContext);
  if (!value) throw new Error('Builder components must be rendered inside <BuilderProvider>.');
  return value;
}

/** The builder context when rendered inside a provider (ViolationList may live outside). */
export function useOptionalBuilderContext(): BuilderContextValue | null {
  return useContext(BuilderContext);
}

/** A stable ref callback registering an element as a focus target. */
export function useFocusTarget(id: string): (element: HTMLElement | null) => void {
  const { focus } = useBuilderContext();
  return useCallback((element: HTMLElement | null) => focus.register(id, element), [focus, id]);
}

interface Announcer {
  announce(message: string): void;
}

function LiveRegion({ apiRef }: { apiRef: Ref<Announcer> }) {
  const [message, setMessage] = useState({ text: '', n: 0 });
  useImperativeHandle(
    apiRef,
    () => ({ announce: (text: string) => setMessage((m) => ({ text, n: m.n + 1 })) }),
    [],
  );
  return (
    <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
      <span key={message.n}>{message.text}</span>
    </div>
  );
}

export function BuilderProvider({
  catalog,
  readOnly,
  violations,
  paths,
  highlightPath = null,
  directory,
  children,
}: {
  catalog: BuilderCatalog;
  readOnly: boolean;
  violations?: Violation[];
  paths?: PathIndex;
  highlightPath?: string | null;
  directory?: BuilderDirectory;
  children: ReactNode;
}) {
  const announcer = useRef<Announcer>(null);
  const announce = useCallback((message: string) => announcer.current?.announce(message), []);
  const [focus] = useState(() => new FocusRegistry());
  const index = paths ?? EMPTY_PATH_INDEX;
  const value = useMemo<BuilderContextValue>(() => {
    const violationsByKey = new Map<string, Violation[]>();
    const unmapped: Violation[] = [];
    for (const violation of violations ?? []) {
      const key = keyForPath(index, violation.path);
      if (key === null) unmapped.push(violation);
      else violationsByKey.set(key, [...(violationsByKey.get(key) ?? []), violation]);
    }
    const names: DirectoryNames = {
      departments: new Map((directory?.departments ?? []).map((d) => [d.id, d.label])),
      users: new Map((directory?.users ?? []).map((u) => [u.id, u.label])),
    };
    return {
      catalog,
      readOnly,
      paths: index,
      violationsByKey,
      unmapped,
      highlightKey: highlightPath ? keyForPath(index, highlightPath) : null,
      highlightPath,
      directory,
      names,
      announce,
      focus,
    };
  }, [catalog, readOnly, violations, index, highlightPath, directory, announce, focus]);
  return (
    <BuilderContext.Provider value={value}>
      {children}
      <LiveRegion apiRef={announcer} />
    </BuilderContext.Provider>
  );
}
