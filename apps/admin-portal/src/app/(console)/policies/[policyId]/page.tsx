import { PolicyDetail } from '@/features/policies';

/** Policy detail (`?tab=overview|versions|audit`, step 7.3 design B17). */
export default async function PolicyDetailRoute({
  params,
}: {
  params: Promise<{ policyId: string }>;
}) {
  const { policyId } = await params;
  return <PolicyDetail policyId={policyId} />;
}
