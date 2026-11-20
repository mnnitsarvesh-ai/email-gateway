import { AtoProviderPage } from '@/features/ato';

/** One identity-provider integration (step 8.5 §7). */
export default async function AtoProviderRoute({
  params,
}: {
  params: Promise<{ integrationId: string }>;
}) {
  const { integrationId } = await params;
  return <AtoProviderPage integrationId={integrationId} />;
}
