import { ReportPage } from '@/features/assistant/report-page';

/** Full-size view of one AI chat report (step AI-R D9). */
export default async function AssistantReportRoute({
  params,
}: {
  params: Promise<{ reportId: string }>;
}) {
  const { reportId } = await params;
  return <ReportPage reportId={reportId} />;
}
