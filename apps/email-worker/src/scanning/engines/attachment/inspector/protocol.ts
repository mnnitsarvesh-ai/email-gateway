import type { InspectionResult, InspectLimits } from '../content';

/**
 * The worker ↔ inspector child protocol over the IPC channel (`serialization: 'advanced'`, so
 * Buffers travel as bytes; step 4.2 A4). Pure types and guards (no process API), shared by both
 * sides.
 */

/** Selftest modes (only with EG_INSPECTOR_SELFTEST=1, never in production). */
export const SELFTEST_MODES = ['cpu', 'memory', 'hang', 'crash'] as const;
export type SelftestMode = (typeof SELFTEST_MODES)[number];

export type WorkerMessage =
  | { op: 'inspect'; id: number; bytes: Uint8Array; limits: InspectLimits }
  | { op: 'selftest'; id: number; mode: SelftestMode };

/** Startup handshake (A4): the pool refuses a child whose bundle id differs from its own. */
export interface ReadyMessage {
  op: 'ready';
  yaraXVersion: string;
  bundleId: string;
  ruleCount: number;
}

export type ChildMessage =
  | ReadyMessage
  | { op: 'result'; id: number; ok: true; result: InspectionResult }
  | { op: 'result'; id: number; ok: false; code: string }
  /** The child could not start (bundle invalid, binding failed); it exits right after. */
  | { op: 'fatal'; code: string };

/** A bare error code (never a message that could quote content). */
export const CODE_PATTERN = /^[a-z][a-z0-9_]{0,47}$/;

export function isChildMessage(value: unknown): value is ChildMessage {
  if (typeof value !== 'object' || value === null) return false;
  const op = (value as { op?: unknown }).op;
  return op === 'ready' || op === 'result' || op === 'fatal';
}

export function isWorkerMessage(value: unknown): value is WorkerMessage {
  if (typeof value !== 'object' || value === null) return false;
  const message = value as { op?: unknown; id?: unknown };
  return (message.op === 'inspect' || message.op === 'selftest') && typeof message.id === 'number';
}
