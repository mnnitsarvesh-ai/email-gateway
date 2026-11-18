import { ArchiveDetails } from '@/features/archive';

/** Archived message details (step 8.1 A19, A28). */
export default async function ArchiveMessageRoute({
  params,
}: {
  params: Promise<{ messageId: string }>;
}) {
  const { messageId } = await params;
  return <ArchiveDetails messageId={messageId} />;
}
