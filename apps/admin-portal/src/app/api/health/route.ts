import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/** Liveness probe for the portal itself; it does not depend on the API being up. */
export function GET(): NextResponse {
  return NextResponse.json({ service: 'admin-portal', status: 'ok' });
}
