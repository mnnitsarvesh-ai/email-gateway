import { MetricsService } from '@email-gateway/common';
import type { HandleOutcome } from '@email-gateway/common';
import type { MessageState } from '@email-gateway/message-lifecycle';
import { aggregateRound } from './aggregate';
import type { EngineSettingsRow } from './registry';
import { ScanMetrics } from './scan-metrics';
import {
  type AttemptInput,
  type CompletionContext,
  type CompletionResult,
  decideOpen,
  type FinalizeInput,
  type FinalizeResult,
  type FinalRowInput,
  type OpenRoundInput,
  type OpenRoundResult,
  type ScanMessageRecord,
  type ScanRound,
  type ScanStore,
  stageTriggersFor,
  type SweepCandidate,
  type SweepResult,
} from './scan-store';

export const newMetrics = (): { metrics: ScanMetrics; registry: MetricsService } => {
  const registry = new MetricsService({ service: 'email-worker-test' });
  return { metrics: new ScanMetrics(registry), registry };
};

export interface FakeRow {
  engine: string;
  attempt: number;
  isFinal: boolean;
  outcome: string;
  errorCode: string | null;
  reasonCodes: string[];
  final?: FinalRowInput;
}

interface FakeScan extends ScanRound {
  status: 'running' | 'completed' | 'failed' | 'timed_out';
  verdict: string | null;
  reasonCodes: string[] | null;
}

/**
 * In-memory ScanStore with the lifecycle rules the repository applies under its locks (the
 * decision of `decideOpen`, E3 once, completion when every required engine has a final, the
 * completion transition with expectedRound). Unit tests only.
 */
export class FakeScanStore implements ScanStore {
  readonly ledger = new Set<string>();
  readonly messages = new Map<string, ScanMessageRecord>();
  readonly lifecycle = new Map<string, { state: MessageState; round: number }>();
  readonly scans: FakeScan[] = [];
  readonly rows = new Map<bigint, FakeRow[]>();
  readonly transitions: Array<{ key: string; to: string; reason: string; round: number }> = [];
  readonly outbox: Array<{ outcome: string; verdict: string; round: number }> = [];
  /** `scan_stage_ready.v1` rows written by finalize (B2). */
  readonly stageOutbox: Array<{
    engine: string;
    scanId: bigint;
    round: number;
    dependencies: Array<{ engine: string; outcome: string }>;
  }> = [];
  readonly settings = new Map<string, EngineSettingsRow>();
  settingsLoads = 0;
  failNext: { op: 'loadMessage' | 'openRound' | 'finalize'; error: Error } | null = null;
  private nextScanId = 1n;

  addMessage(message: ScanMessageRecord, state: MessageState = 'persisted', round = 0): void {
    this.messages.set(message.id.toString(), message);
    this.lifecycle.set(message.id.toString(), { state, round });
  }

  setState(messageId: bigint, state: MessageState, round: number): void {
    this.lifecycle.set(messageId.toString(), { state, round });
  }

  state(messageId: bigint) {
    return this.lifecycle.get(messageId.toString());
  }

  rowsOf(scanId: bigint): FakeRow[] {
    return this.rows.get(scanId) ?? [];
  }

  private maybeFail(op: 'loadMessage' | 'openRound' | 'finalize'): void {
    if (this.failNext?.op === op) {
      const { error } = this.failNext;
      this.failNext = null;
      throw error;
    }
  }

  isProcessed(consumer: string, eventId: string): Promise<boolean> {
    return Promise.resolve(this.ledger.has(`${consumer}:${eventId}`));
  }

  recordNoop(consumer: string, eventId: string): Promise<HandleOutcome> {
    const key = `${consumer}:${eventId}`;
    if (this.ledger.has(key)) return Promise.resolve('duplicate');
    this.ledger.add(key);
    return Promise.resolve('handled');
  }

  loadMessage(id: bigint, _receivedAt: Date, organizationId: bigint) {
    this.maybeFail('loadMessage');
    const m = this.messages.get(id.toString());
    return Promise.resolve(m && m.organizationId === organizationId ? m : null);
  }

  loadEngineSettings(organizationId: bigint, engine: string) {
    this.settingsLoads += 1;
    return Promise.resolve(this.settings.get(`${organizationId.toString()}:${engine}`) ?? null);
  }

  openRound(input: OpenRoundInput): Promise<OpenRoundResult> {
    this.maybeFail('openRound');
    const current = this.lifecycle.get(input.message.id.toString());
    if (!current) return Promise.resolve({ kind: 'skip', reason: 'message_not_found' });
    const decision = decideOpen(current, input.round, input.trigger);
    if (decision.action === 'skip')
      return Promise.resolve({ kind: 'skip', reason: decision.reason });
    const existing = this.scans.find(
      (s) => s.messageId === input.message.id && s.round === input.round,
    );
    if (input.trigger === 'stage' && decision.action === 'open') {
      if (!existing || existing.scanId !== input.scanId) {
        return Promise.resolve({ kind: 'skip', reason: 'stage_round_missing' });
      }
      const own = this.rowsOf(existing.scanId).filter((r) => r.engine === input.engine);
      return Promise.resolve({
        kind: 'open',
        round: { ...existing },
        finalExists: own.some((r) => r.isFinal),
        attempts: own.filter((r) => !r.isFinal).length,
        opened: false,
      });
    }
    if (decision.action === 'check_final') {
      const final =
        existing &&
        this.rowsOf(existing.scanId).some((r) => r.engine === input.engine && r.isFinal);
      return Promise.resolve({
        kind: 'skip',
        reason: final ? 'already_final' : `lifecycle_${current.state}`,
      });
    }
    let opened = false;
    if (decision.action === 'open_e3') {
      const key = `scan-open:${input.message.id.toString()}:0`;
      if (!this.transitions.some((t) => t.key === key)) {
        this.transitions.push({ key, to: 'scanning', reason: 'scan_started', round: 0 });
        this.lifecycle.set(input.message.id.toString(), { state: 'scanning', round: 0 });
        opened = true;
      }
    }
    let scan = existing;
    if (!scan) {
      scan = {
        scanId: this.nextScanId++,
        receivedAt: input.message.receivedAt,
        messageId: input.message.id,
        organizationId: input.message.organizationId,
        round: input.round,
        scanKind: input.scanKind,
        requiredEngines: [...input.requiredEngines],
        startedAt: input.now,
        deadlineAt: new Date(input.now.getTime() + input.deadlineSeconds * 1000),
        status: 'running',
        verdict: null,
        reasonCodes: null,
      };
      this.scans.push(scan);
    }
    const own = this.rowsOf(scan.scanId).filter((r) => r.engine === input.engine);
    return Promise.resolve({
      kind: 'open',
      round: { ...scan },
      finalExists: own.some((r) => r.isFinal),
      attempts: own.filter((r) => !r.isFinal).length,
      opened,
    });
  }

  recordAttempt(input: AttemptInput): Promise<void> {
    const list = this.rows.get(input.round.scanId) ?? [];
    if (!list.some((r) => r.engine === input.engine && r.attempt === input.attempt)) {
      list.push({
        engine: input.engine,
        attempt: input.attempt,
        isFinal: false,
        outcome: input.outcome,
        errorCode: input.errorCode,
        reasonCodes: [input.reasonCode],
      });
    }
    this.rows.set(input.round.scanId, list);
    return Promise.resolve();
  }

  finalize(input: FinalizeInput): Promise<FinalizeResult> {
    this.maybeFail('finalize');
    const key = `${input.consumer}:${input.eventId}`;
    if (this.ledger.has(key)) return Promise.resolve({ kind: 'duplicate' });
    this.ledger.add(key);
    const scan = this.scans.find((s) => s.scanId === input.round.scanId);
    let inserted = false;
    if (scan && input.final) {
      const list = this.rows.get(scan.scanId) ?? [];
      if (!list.some((r) => r.engine === input.final!.engine && r.isFinal)) {
        list.push({
          engine: input.final.engine,
          attempt: input.final.attempt,
          isFinal: true,
          outcome: input.final.outcome,
          errorCode: input.final.errorCode,
          reasonCodes: input.final.reasonCodes,
          final: input.final,
        });
        inserted = true;
      }
      this.rows.set(scan.scanId, list);
    }
    const stageTriggers: string[] = [];
    // As the repository: a message whose row is gone gets no stage trigger.
    if (scan && scan.status === 'running' && this.messages.has(scan.messageId.toString())) {
      const triggers = stageTriggersFor(
        scan.requiredEngines,
        this.rowsOf(scan.scanId).filter((r) => r.isFinal),
        inserted && input.final ? input.final.engine : null,
      );
      for (const trigger of triggers) {
        this.stageOutbox.push({ ...trigger, scanId: scan.scanId, round: scan.round });
        stageTriggers.push(trigger.engine);
      }
    }
    const completion = scan
      ? this.complete(scan, input.completion)
      : { kind: 'already_completed' as const };
    return Promise.resolve({ kind: 'handled', inserted, completion, stageTriggers });
  }

  sweepCandidates(now: Date, lookbackHours: number, limit: number): Promise<SweepCandidate[]> {
    const floor = now.getTime() - lookbackHours * 3_600_000;
    return Promise.resolve(
      this.scans
        .filter(
          (s) => s.status === 'running' && s.deadlineAt < now && s.deadlineAt.getTime() >= floor,
        )
        .slice(0, limit)
        .map((s) => ({
          scanId: s.scanId,
          receivedAt: s.receivedAt,
          messageId: s.messageId,
          organizationId: s.organizationId,
        })),
    );
  }

  sweepRound(candidate: SweepCandidate, now: Date): Promise<SweepResult> {
    const scan = this.scans.find((s) => s.scanId === candidate.scanId);
    if (!scan || scan.status !== 'running') {
      return Promise.resolve({ finalized: [], completion: { kind: 'already_completed' } });
    }
    const list = this.rows.get(scan.scanId) ?? [];
    const finalized: string[] = [];
    for (const engine of scan.requiredEngines) {
      if (list.some((r) => r.engine === engine && r.isFinal)) continue;
      list.push({
        engine,
        attempt: list.filter((r) => r.engine === engine).length + 1,
        isFinal: true,
        outcome: 'timeout',
        errorCode: 'deadline_exceeded',
        reasonCodes: ['engine.deadline_exceeded'],
      });
      finalized.push(engine);
    }
    this.rows.set(scan.scanId, list);
    return Promise.resolve({
      finalized,
      completion: this.complete(scan, { causationEventId: null, correlationId: 'x', now }),
    });
  }

  private complete(scan: FakeScan, ctx: CompletionContext): CompletionResult {
    if (scan.status !== 'running') return { kind: 'already_completed' };
    const finals = this.rowsOf(scan.scanId).filter((r) => r.isFinal);
    if (!scan.requiredEngines.every((e) => finals.some((f) => f.engine === e))) {
      return { kind: 'not_complete' };
    }
    const aggregate = aggregateRound(
      scan.requiredEngines,
      finals.map((f) => ({
        engine: f.engine,
        outcome: f.outcome as never,
        errorCode: f.errorCode,
        reasonCodes: f.reasonCodes,
        attempts: f.attempt,
      })),
    );
    scan.status = aggregate.scanStatus;
    scan.verdict = aggregate.verdict;
    scan.reasonCodes = aggregate.reasonCodes;
    const current = this.lifecycle.get(scan.messageId.toString());
    const key = `scan-complete:${scan.messageId.toString()}:${String(scan.round)}`;
    let transition: 'applied' | 'stale' | 'duplicate' = 'stale';
    if (this.transitions.some((t) => t.key === key)) transition = 'duplicate';
    else if (current && current.state === 'scanning' && current.round === scan.round) {
      transition = 'applied';
      this.transitions.push({
        key,
        to: aggregate.outcome,
        reason: aggregate.lifecycleReason,
        round: scan.round,
      });
      this.lifecycle.set(scan.messageId.toString(), {
        state: aggregate.outcome,
        round: scan.round,
      });
      this.outbox.push({
        outcome: aggregate.outcome,
        verdict: aggregate.verdict,
        round: scan.round,
      });
    }
    void ctx;
    return {
      kind: 'completed',
      aggregate,
      round: scan,
      transition,
      scannedEventId: transition === 'applied' ? 'event' : null,
    };
  }
}
