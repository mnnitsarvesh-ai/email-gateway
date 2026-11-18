import { CaseSearchPage } from '@/features/ediscovery';

/** One case search with its hits and review (step 8.1 A18, A28). */
export default async function CaseSearchRoute({
  params,
}: {
  params: Promise<{ caseId: string; searchId: string }>;
}) {
  const { caseId, searchId } = await params;
  return <CaseSearchPage caseId={caseId} searchId={searchId} />;
}
