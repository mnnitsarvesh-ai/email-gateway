import { AtoAccountPage } from '@/features/ato';

/** Account details (step 8.4 §6). */
export default async function AtoAccountRoute({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = await params;
  return <AtoAccountPage accountId={accountId} />;
}
