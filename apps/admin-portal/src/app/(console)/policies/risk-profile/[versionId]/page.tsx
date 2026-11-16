import { RiskProfileVersionPage } from '@/features/policies';

/** A risk-profile draft editor or published version view (step 7.3 design B13, B17). */
export default async function RiskProfileVersionRoute({
  params,
}: {
  params: Promise<{ versionId: string }>;
}) {
  const { versionId } = await params;
  return <RiskProfileVersionPage versionId={versionId} />;
}
