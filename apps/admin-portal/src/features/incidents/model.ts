import type { ReactNode } from 'react';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';

/**
 * The generic security incident model in the portal (step 8.4 D24, §5.2, §6; ADR-0075): one list,
 * one detail layout and one report for every incident category. Categories register their label,
 * permissions, subject picker, detail panels, false-positive feedback fields and report sections
 * (`categories.tsx`); 8.4 registers `account_takeover`, ATP-4 appends its categories later
 * without a second incident page.
 */

export type IncidentSummary = ListItem<'IncidentsController_list_v1'>;
export type IncidentDetail = SuccessBody<'IncidentsController_get_v1'>;
export type IncidentTimelineEntry = ListItem<'IncidentsController_timeline_v1'>;
export type IncidentMessage = ListItem<'IncidentsController_messages_v1'>;
export type IncidentReport = SuccessBody<'IncidentsController_report_v1'>;
export type IncidentStatus = IncidentSummary['status'];
export type IncidentSeverity = IncidentSummary['severity'];
export type ResolutionCode = NonNullable<IncidentSummary['resolutionCode']>;

export const INCIDENT_STATUSES = [
  'open',
  'investigating',
  'confirmed',
  'false_positive',
  'mitigated',
  'resolved',
] as const satisfies readonly IncidentStatus[];
export const ACTIVE_INCIDENT_STATUSES = [
  'open',
  'investigating',
  'confirmed',
  'mitigated',
] as const satisfies readonly IncidentStatus[];
export const INCIDENT_SEVERITIES = [
  'low',
  'medium',
  'high',
  'critical',
] as const satisfies readonly IncidentSeverity[];

export const STATUS_LABELS: Record<IncidentStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  confirmed: 'Confirmed',
  false_positive: 'False positive',
  mitigated: 'Mitigated',
  resolved: 'Resolved',
};

/** Verb of a transition button ("Start investigating", "Confirm", …). */
export const TRANSITION_LABELS: Record<IncidentStatus, string> = {
  open: 'Re-open',
  investigating: 'Start investigating',
  confirmed: 'Confirm compromise',
  false_positive: 'Resolve as false positive',
  mitigated: 'Mark mitigated',
  resolved: 'Resolve',
};

export const RESOLUTION_LABELS: Record<ResolutionCode, string> = {
  remediated: 'Remediated',
  false_positive: 'False positive',
  benign_activity: 'Benign activity',
  duplicate: 'Duplicate',
  other: 'Other',
};

export const STATUS_TONE: Readonly<Record<string, Tone>> = {
  open: 'danger',
  investigating: 'warning',
  confirmed: 'orange',
  mitigated: 'info',
  false_positive: 'neutral',
  resolved: 'success',
};

export const SEVERITY_TONE: Readonly<Record<string, Tone>> = {
  low: 'info',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
};

export const incidentHref = (id: string) => `/incidents/${id}`;
export const incidentReportHref = (id: string) => `/incidents/${id}/report`;

/** What a category contributes to the generic pages. */
export interface IncidentCategoryUi {
  readonly id: string;
  readonly label: string;
  /** Permission of the category's reads (the generic routes answer 404 without it). */
  readonly readPermission: string;
  readonly managePermission: string;
  readonly subjectType: string;
  readonly subjectLabel: string;
  /** Link to the subject's own page (ATO: the account), or null. */
  readonly subjectHref: (subjectId: string) => string | null;
  /** Picker of a manual incident's subject (returns the subject public id and its label). */
  readonly SubjectPicker: (props: {
    value: { id: string; label: string } | null;
    onChange: (value: { id: string; label: string } | null) => void;
  }) => ReactNode;
  /** The category's panels of the detail page. */
  readonly DetailPanels: (props: { incident: IncidentDetail }) => ReactNode;
  /** Fields of the false-positive resolution (`categoryFeedback` of PATCH /incidents/{id}). */
  readonly FeedbackFields?: (props: {
    incident: IncidentDetail;
    value: Record<string, unknown>;
    onChange: (value: Record<string, unknown>) => void;
  }) => ReactNode;
  /** Initial feedback when the false-positive dialog opens. */
  readonly initialFeedback?: () => Record<string, unknown>;
  /** Renders one category section of the report (`null` = generic rendering). */
  readonly ReportSection?: (props: { section: IncidentReport['sections'][number] }) => ReactNode;
}
