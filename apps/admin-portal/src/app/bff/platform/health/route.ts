import { bffRoute } from '@/server/bff/route';
import { platformHealth } from '@/server/bff/session-routes';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const GET = bffRoute(platformHealth);
