import { IncidentPage } from '@/features/incidents';

/** Incident details with the category's panels (step 8.4 §6, D24). */
export default async function IncidentRoute({
  params,
}: {
  params: Promise<{ incidentId: string }>;
}) {
  const { incidentId } = await params;
  return <IncidentPage incidentId={incidentId} />;
}
