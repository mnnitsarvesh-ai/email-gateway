import { becVerdictSchema } from '@email-gateway/security-contracts';
import type { BecFeedbackExportRecord } from '../dto/bec.schemas';
import { appliedAssessmentsOf, featuresOf, ruleCodesOf, shadowAssessmentsOf } from './bec-result';

/** The fields of a feedback row the export reads (never the note, message or user ids). */
export interface ExportFeedbackInput {
  publicId: string;
  kind: 'false_positive' | 'false_negative';
  createdAt: Date;
}

/** The fields of a result row the export reads. */
export interface ExportResultInput {
  rulesVersion: string;
  engineVersion: string;
  deterministicScore: number;
  score: number;
  verdict: string;
  deterministicVerdict: string;
  rules: unknown;
  features: unknown;
  ai: unknown;
  aiShadow: unknown;
}

/**
 * One NDJSON record of the retraining export (step 4.4 B11), exactly the B11 fields: versions,
 * the models used, fired codes, scores, verdicts, the stored AI feature vector and the top AI
 * labels. Built only from validated stored values; never bodies, excerpts, span text,
 * addresses, display names, domains, notes or message ids. Null when the result row is invalid.
 */
export function exportRecordOf(
  feedback: ExportFeedbackInput,
  result: ExportResultInput,
): BecFeedbackExportRecord | null {
  const verdict = becVerdictSchema.safeParse(result.verdict);
  const deterministicVerdict = becVerdictSchema.safeParse(result.deterministicVerdict);
  if (!verdict.success || !deterministicVerdict.success) return null;
  const applied = appliedAssessmentsOf(result.ai);
  const shadow = shadowAssessmentsOf(result.aiShadow);
  const all = [...applied, ...shadow];
  const local = all.find((a) => a.layer === 'local');
  const llm = all.find((a) => a.layer === 'llm');
  return {
    feedbackId: feedback.publicId,
    kind: feedback.kind,
    createdAt: feedback.createdAt.toISOString(),
    rulesVersion: result.rulesVersion,
    engineVersion: result.engineVersion,
    localModel: local ? { id: local.modelId, version: local.modelVersion } : null,
    llm: llm ? { modelId: llm.modelId, promptTemplateVersion: llm.promptTemplateVersion } : null,
    firedCodes: ruleCodesOf(result.rules),
    deterministicScore: result.deterministicScore,
    score: result.score,
    verdict: verdict.data,
    deterministicVerdict: deterministicVerdict.data,
    features: featuresOf(result.features),
    aiLabels: all.flatMap((a) => {
      if (a.status !== 'ok' || a.labels.length === 0) return [];
      const top = [...a.labels].sort((x, y) => y.confidence - x.confidence)[0]!;
      return [{ layer: a.layer, mode: a.mode, label: top.label, confidence: top.confidence }];
    }),
  };
}
