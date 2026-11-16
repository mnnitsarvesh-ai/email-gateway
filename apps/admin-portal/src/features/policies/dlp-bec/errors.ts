import type { FieldValues, Path, UseFormReturn } from 'react-hook-form';
import type { ApiError } from '@/lib/api/errors';
import { humanize } from '@/lib/format';

/**
 * Server errors of the DLP and BEC editors (design P8, step 7.3 §2 B13): `400 validation_failed`
 * lines (`"<path>: <issue>"`, dot-joined API paths) go to the form input that holds that path (a
 * list item is named by its textarea line), coded refusals get a sentence on the right input,
 * `409 version_conflict` offers to load the current version, `429` waits for `Retry-After`;
 * everything else is a form-level message. The code and request ID are always shown.
 */

export interface FieldRule<F extends string> {
  /** API path (dot-joined) the rule covers, with every path below it. */
  readonly path: string;
  readonly field: F;
  /** For list inputs: the textarea line of the `index`-th item of the request. */
  readonly line?: (index: number) => number | null;
}

/** A coded refusal explained on one input (`field`) or for the whole form. */
export interface Explanation<F extends string> {
  readonly field?: F;
  readonly message: string;
}

export type Explain<F extends string> = (error: ApiError) => Explanation<F> | null;

export interface Problem {
  readonly error: ApiError;
  /** Form-level sentences (field errors are on their inputs). */
  readonly messages: readonly string[];
  /** `409 version_conflict`: the form offers to load the current version. */
  readonly conflict: boolean;
  /** `403 mfa_required`: the action needs a session signed in with MFA. */
  readonly mfa: boolean;
}

const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;

function numberDetail(error: ApiError, key: string): number | null {
  const value = error.details[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Sentences for the refusals every DLP and BEC write shares. */
export function commonMessage(error: ApiError): string | null {
  if (error.status === 409 && error.code === 'version_conflict') {
    const current = numberDetail(error, 'currentVersion');
    return `Someone else changed this since it was loaded${current ? ` (now version ${current})` : ''}. Load the current version and apply your change again.`;
  }
  if (
    error.status === 409 &&
    (error.code === 'dlp_limit_reached' || error.code === 'bec_limit_reached')
  ) {
    const limit = numberDetail(error, 'limit');
    const resource =
      typeof error.details.resource === 'string' ? humanize(error.details.resource) : 'entries';
    return `Your organization reached its limit${limit !== null ? ` of ${limit}` : ''} for ${resource.toLowerCase()}. Delete an entry first.`;
  }
  if (error.status === 429) {
    return `Too many requests. Try again in ${error.retryAfterSeconds ?? 30} s.`;
  }
  if (error.status === 403 && error.code === 'mfa_required') {
    return 'This action requires a session with multi-factor authentication. Sign in again with your authenticator code.';
  }
  if (error.status === 403 && error.code === 'user_required') {
    return 'This action must be taken by a signed-in user.';
  }
  if (error.status === 404) {
    return 'It no longer exists, or you do not have access to it. Close this panel and reload the list.';
  }
  return null;
}

function splitLine(line: string): { path: string; issue: string } {
  const index = line.indexOf(': ');
  return index > 0
    ? { path: line.slice(0, index), issue: line.slice(index + 2) }
    : { path: '', issue: line };
}

/**
 * Applies a failed write to a form: field errors on the inputs (the first one focused) and the
 * form-level problem for `FormAlert`.
 */
export function applyServerError<T extends FieldValues>(
  form: UseFormReturn<T, unknown, unknown>,
  error: ApiError,
  rules: readonly FieldRule<Path<T>>[],
  explain?: Explain<Path<T>>,
): Problem {
  const messages: string[] = [];
  const fields = new Set<string>();
  const setField = (field: Path<T>, message: string) => {
    if (fields.has(field)) return;
    form.setError(field, { type: 'server', message }, { shouldFocus: fields.size === 0 });
    fields.add(field);
  };
  const specific = explain?.(error) ?? null;
  if (specific) {
    if (specific.field) setField(specific.field, specific.message);
    else messages.push(specific.message);
  } else if (error.status === 400 && error.code === 'validation_failed') {
    const sorted = [...rules].sort((a, b) => b.path.length - a.path.length);
    for (const line of error.messages) {
      const { path, issue } = splitLine(line);
      const rule = sorted.find((r) => path === r.path || path.startsWith(`${r.path}.`));
      if (!rule) {
        messages.push(line);
        continue;
      }
      const next = path.slice(rule.path.length + 1).split('.')[0] ?? '';
      const lineNo = rule.line && /^\d+$/.test(next) ? rule.line(Number(next)) : null;
      setField(rule.field, lineNo !== null ? `Line ${lineNo}: ${issue}` : issue);
    }
  } else {
    messages.push(commonMessage(error) ?? error.messages.join(' '));
  }
  if (messages.length === 0) {
    messages.push(
      `The API did not accept ${plural(fields.size, 'value', 'values')}; see the highlighted ${fields.size === 1 ? 'field' : 'fields'}.`,
    );
  }
  return {
    error,
    messages,
    conflict: error.status === 409 && error.code === 'version_conflict',
    mfa: error.status === 403 && error.code === 'mfa_required',
  };
}

/** The form-level problem of an error that has no inputs (deletes, lifts, withdrawals). */
export function problemOf(error: ApiError, explain?: (error: ApiError) => string | null): Problem {
  return {
    error,
    messages: [explain?.(error) ?? commonMessage(error) ?? error.messages.join(' ')],
    conflict: error.status === 409 && error.code === 'version_conflict',
    mfa: error.status === 403 && error.code === 'mfa_required',
  };
}

/** `409 *_in_use` of a delete: how many rows still refer to the entry. */
export function inUseMessage(error: ApiError, what: string): string | null {
  if (error.status !== 409 || !error.code.endsWith('_in_use')) return null;
  const references = numberDetail(error, 'references');
  return `${what}${references !== null ? ` (${references})` : ''}. Change those first, then delete again.`;
}

/**
 * The problem of a failed confirmation (delete, withdraw): in-use references (`inUse` names
 * them), or a version conflict, after which the dialog holds the current version and a second
 * confirm applies to it.
 */
export function confirmProblem(error: ApiError, inUse?: string): Problem {
  return problemOf(error, (e) => {
    const references = inUse ? inUseMessage(e, inUse) : null;
    if (references) return references;
    if (e.status === 409 && e.code === 'version_conflict') {
      const current = numberDetail(e, 'currentVersion');
      return `It changed since it was loaded${current ? ` (now version ${current})` : ''}. Check the current version and confirm again.`;
    }
    return null;
  });
}

/** A detail as a non-negative integer index (`index` of coded 400/422 refusals). */
export function indexDetail(error: ApiError): number | null {
  const value = numberDetail(error, 'index');
  return value !== null && value >= 0 ? value : null;
}
