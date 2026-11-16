import { PolicyVersionPage } from '@/features/policies';

/** A policy version in the builder: edit mode for drafts, view mode otherwise (design B17). */
export default async function PolicyVersionRoute({
  params,
}: {
  params: Promise<{ policyId: string; versionNo: string }>;
}) {
  const { policyId, versionNo } = await params;
  return <PolicyVersionPage policyId={policyId} versionNo={versionNo} />;
}
