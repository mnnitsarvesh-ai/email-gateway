import { SelfEntryDetail } from '@/features/quarantine';

/** One of my quarantined messages (design §3.1; linked from quarantine digests). */
export default async function QuarantineSelfEntryRoute({
  params,
}: {
  params: Promise<{ entryId: string }>;
}) {
  const { entryId } = await params;
  return <SelfEntryDetail entryId={entryId} />;
}
