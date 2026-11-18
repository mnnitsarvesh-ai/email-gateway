import { LegalHoldDetailPage } from '@/features/ediscovery';

/** One legal hold (step 8.1 A12, A28). */
export default async function LegalHoldRoute({ params }: { params: Promise<{ holdId: string }> }) {
  const { holdId } = await params;
  return <LegalHoldDetailPage holdId={holdId} />;
}
