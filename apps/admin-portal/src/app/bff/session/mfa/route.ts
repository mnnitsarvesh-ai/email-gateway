import { bffRoute } from '@/server/bff/route';
import { verifyMfa } from '@/server/bff/session-routes';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = bffRoute(verifyMfa);
