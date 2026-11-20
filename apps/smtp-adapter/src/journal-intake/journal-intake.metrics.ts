import { Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';
import type { JournalIntakeKind } from '@email-gateway/mail-routing';

/** `journal_intake_messages_total{outcome}`: one per intake message at the journal LMTP. */
export type IntakeMessageOutcome = 'accepted' | 'duplicate' | 'dropped' | 'tempfail';

/** Where a refusal happened: the RCPT policy, END-OF-MESSAGE or the LMTP re-check. */
export type IntakeRefusalStage = 'rcpt' | 'eom' | 'lmtp';

/** Bounded refusal codes (`journal_intake_refusals_total{code}`). */
export type IntakeRefusalCode =
  | 'unknown_address'
  | 'unavailable'
  | 'network'
  | 'tls'
  | 'one_destination'
  | 'rate'
  | 'size'
  | 'egress_unavailable'
  | 'marker_missing'
  | 'second_recipient';

/** `journal_intake_unwrap_total{format,result}`. */
export type IntakeFormat = 'journal_report' | 'journal_report_unparsed' | 'copy';

/**
 * Journal intake metrics of the smtp-adapter (step 8.6 D2.9; names are a dashboard and alert
 * contract, infrastructure/monitoring/rules). No organization or source labels: per-source facts
 * are the `journal_intake_counters` rows.
 */
@Injectable()
export class JournalIntakeMetrics {
  private readonly messages: Counter<'kind' | 'outcome'>;
  private readonly bytes: Counter<'kind'>;
  private readonly refusals: Counter<'stage' | 'code'>;
  private readonly unwrap: Counter<'format' | 'result'>;
  private readonly lmtp: Histogram<'kind'>;
  private readonly proof: Counter<'kind' | 'rule' | 'result'>;
  private readonly counterFlushErrors: Counter;

  constructor(metrics: MetricsService) {
    this.messages = metrics.counter(
      'journal_intake_messages_total',
      'Journal intake messages at the journal LMTP by source kind and outcome (step 8.6 D2.9)',
      ['kind', 'outcome'],
    );
    this.bytes = metrics.counter(
      'journal_intake_bytes_total',
      'Bytes of accepted journal intake messages (as received) by source kind',
      ['kind'],
    );
    this.refusals = metrics.counter(
      'journal_intake_refusals_total',
      'Journal intake refusals by stage (rcpt, eom, lmtp) and code',
      ['stage', 'code'],
    );
    this.unwrap = metrics.counter(
      'journal_intake_unwrap_total',
      'Journal report unwrapping by stored format and result (ok or the unparsed reason)',
      ['format', 'result'],
    );
    this.lmtp = metrics.histogram(
      'journal_intake_lmtp_seconds',
      'Duration of one journal LMTP transaction (DATA to reply)',
      ['kind'],
      [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120],
    );
    this.proof = metrics.counter(
      'journal_intake_proof_total',
      'Journal intake content proof results by source kind and failing rule (none on pass)',
      ['kind', 'rule', 'result'],
    );
    this.counterFlushErrors = metrics.counter(
      'journal_intake_counter_flush_errors_total',
      'Failed flushes of the per-source journal intake counters',
    );
  }

  message(kind: JournalIntakeKind, outcome: IntakeMessageOutcome): void {
    this.messages.inc({ kind, outcome });
  }

  accepted(kind: JournalIntakeKind, bytes: number): void {
    if (bytes > 0) this.bytes.inc({ kind }, bytes);
  }

  refused(stage: IntakeRefusalStage, code: IntakeRefusalCode): void {
    this.refusals.inc({ stage, code });
  }

  unwrapped(format: IntakeFormat, result: string): void {
    this.unwrap.inc({ format, result });
  }

  transaction(kind: JournalIntakeKind, seconds: number): void {
    this.lmtp.observe({ kind }, seconds);
  }

  proofResult(kind: JournalIntakeKind, rule: string, result: string): void {
    this.proof.inc({ kind, rule, result });
  }

  counterFlushFailed(): void {
    this.counterFlushErrors.inc();
  }
}
