import { PolicyComparePage } from '@/features/policies';

/** The diff of two versions of a policy (`?from=&to=&view=`, design B10, B17). */
export default async function PolicyCompareRoute({
  params,
}: {
  params: Promise<{ policyId: string }>;
}) {
  const { policyId } = await params;
  return <PolicyComparePage policyId={policyId} />;
}
