import { CasePage } from '@/features/ediscovery';

/** One eDiscovery case (`?tab=overview|custodians|holds|searches|exports`, step 8.1 A28). */
export default async function CaseRoute({ params }: { params: Promise<{ caseId: string }> }) {
  const { caseId } = await params;
  return <CasePage caseId={caseId} />;
}
