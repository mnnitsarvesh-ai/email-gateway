import type { AnalysisResult } from './analyzers/analysis';

/**
 * Parent ↔ analyzer child protocol over the IPC channel (step 4.6 X4). Pure types and guards,
 * shared by both sides (child-side module: node built-ins and relative imports only).
 *
 * 1. child → `{ op: 'ready', version }` (handshake; the parent refuses another version);
 * 2. parent → `{ op: 'analyze', samplePath, detectedType }` (one job per child: one child per
 *    task, never reused);
 * 3. child → `{ op: 'result', ok: true, analysis }` or `{ op: 'result', ok: false, code }`.
 *
 * Test-only probes (`{ op: 'selftest', mode }`) are honoured only when the parent started the
 * child with `--selftest` (unit tests); production never passes it.
 */

export const SELFTEST_MODES = [
  'cpu',
  'memory',
  'heap',
  'hang',
  'crash',
  'write_outside',
  'write_output',
  'spawn',
  'env',
] as const;
export type SelftestMode = (typeof SELFTEST_MODES)[number];

export type ParentMessage =
  | { op: 'analyze'; samplePath: string; detectedType: string }
  | { op: 'selftest'; mode: SelftestMode; path?: string };

export type ChildMessage =
  | { op: 'ready'; version: string }
  | { op: 'result'; ok: true; analysis: AnalysisResult }
  | { op: 'result'; ok: false; code: string }
  | { op: 'probe'; mode: SelftestMode; outcome: string };

export const CODE_PATTERN = /^[a-z][a-z0-9_]{0,47}$/;

export function isParentMessage(value: unknown): value is ParentMessage {
  if (typeof value !== 'object' || value === null) return false;
  const m = value as { op?: unknown; samplePath?: unknown; detectedType?: unknown; mode?: unknown };
  if (m.op === 'analyze')
    return typeof m.samplePath === 'string' && typeof m.detectedType === 'string';
  if (m.op === 'selftest')
    return typeof m.mode === 'string' && (SELFTEST_MODES as readonly string[]).includes(m.mode);
  return false;
}

export function isChildMessage(value: unknown): value is ChildMessage {
  if (typeof value !== 'object' || value === null) return false;
  const op = (value as { op?: unknown }).op;
  return op === 'ready' || op === 'result' || op === 'probe';
}
