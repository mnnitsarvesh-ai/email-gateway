import type { InspectionResult, InspectLimits } from '../content';

/**
 * The worker ↔ child protocol over the IPC channel (`serialization: 'advanced'`, so Buffers
 * travel as bytes; step 4.2 A4). Pure types and guards (no process API), shared by both sides
 * and by both child kinds of the generalized pool (step 4.5 D4): the attachment inspector
 * (`inspect`) and the DLP extractor (`extract`).
 */

/** Selftest modes (only with EG_INSPECTOR_SELFTEST=1, never in production). */
export const SELFTEST_MODES = ['cpu', 'memory', 'hang', 'crash'] as const;
export type SelftestMode = (typeof SELFTEST_MODES)[number];

/** What the worker knows about an attachment besides its bytes (DLP extractor, step 4.5 D4). */
export interface ExtractHint {
  declaredContentType: string | null;
  /** The extension of the attachment's filename (lower case, no dot), never the name. */
  filenameExt: string | null;
}

/**
 * The DLP extractor job (step 4.5 D4). `limits` is the extractor's own limit object (validated
 * by the extractor child); the pool treats it as opaque.
 */
export interface ExtractRequest<TLimits = unknown> {
  op: 'extract';
  id: number;
  bytes: Uint8Array;
  limits: TLimits;
  hint: ExtractHint;
}

export type WorkerMessage =
  | { op: 'inspect'; id: number; bytes: Uint8Array; limits: InspectLimits }
  | ExtractRequest
  | { op: 'selftest'; id: number; mode: SelftestMode };

/** Startup handshake (A4): the pool refuses a child whose bundle id differs from its own. */
export interface ReadyMessage {
  op: 'ready';
  yaraXVersion: string;
  bundleId: string;
  ruleCount: number;
}

/** Startup handshake of the DLP extractor child (step 4.5 D4). */
export interface ExtractorReadyMessage {
  op: 'ready';
  kind: 'dlp-extractor';
  extractorVersion: string;
}

export type ChildReadyMessage = ReadyMessage | ExtractorReadyMessage;

export type ChildMessage =
  | ChildReadyMessage
  | { op: 'result'; id: number; ok: true; result: InspectionResult }
  /** The DLP extractor's reply (step 4.5 D4); validated by the extractor's caller. */
  | { op: 'result'; id: number; ok: true; extraction: unknown }
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

export function isExtractorReady(message: ChildReadyMessage): message is ExtractorReadyMessage {
  return (message as { kind?: unknown }).kind === 'dlp-extractor';
}

export function isWorkerMessage(value: unknown): value is WorkerMessage {
  if (typeof value !== 'object' || value === null) return false;
  const message = value as { op?: unknown; id?: unknown };
  return (
    (message.op === 'inspect' || message.op === 'extract' || message.op === 'selftest') &&
    typeof message.id === 'number'
  );
}
