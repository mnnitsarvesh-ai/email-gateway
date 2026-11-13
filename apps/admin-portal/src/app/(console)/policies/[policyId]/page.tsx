import { PolicyDetail } from '@/features/policies';

/** Policy detail (design §3.1). */
export default async function PolicyDetailRoute({
  params,
}: {
  params: Promise<{ policyId: string }>;
}) {
  const { policyId } = await params;
  return <PolicyDetail policyId={policyId} />;
}
