/**
 * The `account_takeover` category handler of the shared incident model (step 8.4 D12, D24,
 * ADR-0075): subject `ato_account`, permissions `ato:read` / `ato:manage`, detail from
 * `ato_incident_details` and the account, report sections, and the transition hook — on any terminal
 * transition the account's active incident is cleared; on `false_positive` the incident's active
 * signals are dismissed, the feedback's trusted contexts are added and the account is rescored.
 */
import { z } from 'zod';
import type { Prisma } from '@email-gateway/database';
import type {
  IncidentActor,
  IncidentCategoryHandler,
  IncidentReportSection,
  IncidentRow,
} from '@email-gateway/security-incidents';
import { renderExplanation, ruleTitle } from './explain';
import type { AtoStore } from './store';

type Tx = Prisma.TransactionClient;

/** Strict `categoryFeedback` of a false-positive resolution (§5.2). */
export const atoIncidentFeedbackSchema = z.strictObject({
  trustedContexts: z
    .array(
      z.strictObject({
        kind: z.enum(['ip_cidr', 'asn', 'country', 'device']),
        value: z.string().min(1).max(64),
        expiresInDays: z.number().int().min(1).max(365),
        reason: z.string().trim().min(1).max(512),
      }),
    )
    .max(20)
    .default([]),
  dismissSignals: z.boolean().default(true),
});
export type AtoIncidentFeedback = z.infer<typeof atoIncidentFeedbackSchema>;

export interface AtoIncidentHandlerDeps {
  /** The ATO store (lazy: the store needs the incident store, which needs this handler). */
  store: () => AtoStore;
  /** Bound of signals/responses listed in report sections (`API_ATO_REPORT_MAX_ITEMS`). */
  reportMaxItems?: number;
}

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

/** `atoIncidentHandler(deps)`: the `IncidentCategoryHandler` of `account_takeover`. */
export function atoIncidentHandler(deps: AtoIncidentHandlerDeps): IncidentCategoryHandler {
  const maxItems = Math.max(1, Math.min(deps.reportMaxItems ?? 500, 5000));

  async function loadDetail(tx: Tx, incident: IncidentRow): Promise<Record<string, unknown>> {
    const detail = await tx.atoIncidentDetail.findUnique({ where: { incidentId: incident.id } });
    const account = await tx.atoAccount.findFirst({
      where: { id: incident.subjectRefId, organizationId: incident.organizationId },
    });
    return {
      account: account
        ? {
            id: account.publicId,
            kind: account.kind,
            address: account.address,
            userId: account.userId?.toString() ?? null,
            connectorId: account.connectorId?.toString() ?? null,
            riskScore: account.riskScore,
            riskLevel: account.riskLevel,
            protected: account.protected,
          }
        : null,
      riskScoreAtOpen: detail?.riskScoreAtOpen ?? null,
      peakRiskScore: detail?.peakRiskScore ?? null,
      detectionReason: detail?.detectionReason ?? null,
      recommendedActions: detail?.recommendedActions ?? [],
      relatedIps: detail?.relatedIps ?? [],
      geoSummary: detail?.geoSummary ?? null,
      deviceSummary: detail?.deviceSummary ?? null,
      counts: {
        signals: detail?.signalCount ?? 0,
        authEvents: detail?.authEventCount ?? 0,
        messages: detail?.messageCount ?? 0,
        findings: detail?.findingCount ?? 0,
      },
    };
  }

  return {
    category: 'account_takeover',
    subjectTypes: ['ato_account'],
    permissions: { read: 'ato:read', manage: 'ato:manage' },
    feedbackSchema: atoIncidentFeedbackSchema,

    async resolveSubject(tx, organizationId, ref) {
      if (ref.type !== 'ato_account') return null;
      const account = await tx.atoAccount.findUnique({ where: { publicId: ref.publicId } });
      if (!account || account.organizationId !== organizationId) return null;
      return { refId: account.id, refTime: null, publicId: account.publicId };
    },

    loadDetail,

    // Lock order account → incident everywhere (the detect role locks the account, then its
    // incident; `onTransition` updates and rescores the account).
    async lockSubject(tx, incident) {
      await deps.store().lockSubjectAccount(tx, incident.organizationId, incident.subjectRefId);
    },

    async onTransition(tx, incident, _from, to, actor: IncidentActor, feedback: unknown) {
      if (to !== 'false_positive' && to !== 'resolved') return;
      const store = deps.store();
      await store.clearActiveIncident(tx, incident.organizationId, incident);
      if (to !== 'false_positive') return;
      const parsed = atoIncidentFeedbackSchema.parse(feedback ?? {});
      let dismissed = 0;
      if (parsed.dismissSignals) {
        dismissed = await store.dismissIncidentSignals(tx, {
          organizationId: incident.organizationId,
          incidentId: incident.id,
          actor,
          reason: `false positive: ${incident.publicId}`,
        });
      }
      const now = store.now();
      for (const c of parsed.trustedContexts) {
        await store.addTrustedContext(tx, {
          organizationId: incident.organizationId,
          accountId: incident.subjectRefId,
          kind: c.kind,
          value: c.value,
          reason: c.reason,
          expiresAt: new Date(now.getTime() + c.expiresInDays * 86_400_000),
          source: 'false_positive_feedback',
          incidentId: incident.id,
          actor,
        });
      }
      if (parsed.trustedContexts.length > 0 || dismissed > 0) {
        await store.incidents.recordEvent(tx, {
          organizationId: incident.organizationId,
          incidentId: incident.id,
          eventType: 'ato.feedback_applied',
          actor,
          details: { dismissedSignals: dismissed, trustedContexts: parsed.trustedContexts.length },
        });
      }
      const settings = await store.ensureSettings(tx, incident.organizationId);
      await store.rescore(tx, {
        organizationId: incident.organizationId,
        accountId: incident.subjectRefId,
        trigger: parsed.trustedContexts.length > 0 ? 'feedback' : 'dismissal',
        settings,
      });
    },

    async reportSections(tx, incident): Promise<IncidentReportSection[]> {
      const detail = await loadDetail(tx, incident);
      const signals = await tx.atoRiskSignal.findMany({
        where: { organizationId: incident.organizationId, incidentId: incident.id },
        orderBy: [{ detectedAt: 'asc' }, { id: 'asc' }],
        take: maxItems,
      });
      const responses = await tx.atoResponseAction.findMany({
        where: { organizationId: incident.organizationId, incidentId: incident.id },
        orderBy: { id: 'asc' },
        take: maxItems,
      });
      return [
        {
          id: 'ato.detection',
          title: 'Detection reason',
          data: {
            account: detail.account,
            riskScoreAtOpen: detail.riskScoreAtOpen,
            peakRiskScore: detail.peakRiskScore,
            detectionReason: detail.detectionReason,
            recommendedActions: detail.recommendedActions,
          },
        },
        {
          id: 'ato.signals',
          title: 'Signals',
          data: signals.map((s) => {
            const evidence = (s.evidence ?? {}) as Record<string, unknown>;
            return {
              code: s.ruleCode,
              title: ruleTitle(s.ruleCode),
              category: s.category,
              strength: s.strength,
              weight: s.weight,
              status: s.status,
              occurrences: s.occurrences,
              firstOccurredAt: iso(s.firstOccurredAt),
              lastOccurredAt: iso(s.lastOccurredAt),
              explanation: renderExplanation(s.ruleCode, evidence),
            };
          }),
        },
        {
          id: 'ato.context',
          title: 'Related IPs, geography and devices',
          data: {
            relatedIps: detail.relatedIps,
            geoSummary: detail.geoSummary,
            deviceSummary: detail.deviceSummary,
            counts: detail.counts,
          },
        },
        {
          id: 'ato.responses',
          title: 'Responses',
          data: responses.map((r) => ({
            id: r.publicId,
            type: r.actionType,
            provider: r.provider,
            impact: r.impact,
            status: r.status,
            providerStatus: r.providerStatus,
            resultCode: r.resultCode,
            requestedAt: iso(r.createdAt),
            completedAt: iso(r.completedAt),
          })),
        },
      ];
    },
  };
}
