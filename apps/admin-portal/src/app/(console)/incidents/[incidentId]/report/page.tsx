import { IncidentReportPage } from '@/features/incidents';

/** Incident report print view (step 8.4 §6, D16). */
export default async function IncidentReportRoute({
  params,
}: {
  params: Promise<{ incidentId: string }>;
}) {
  const { incidentId } = await params;
  return <IncidentReportPage incidentId={incidentId} />;
}
