import { EntryDetail } from '@/features/quarantine';

/** Quarantine entry detail (design §3.1). */
export default async function QuarantineEntryRoute({
  params,
}: {
  params: Promise<{ entryId: string }>;
}) {
  const { entryId } = await params;
  return <EntryDetail entryId={entryId} />;
}
