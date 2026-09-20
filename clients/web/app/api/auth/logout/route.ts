import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const origin = request.headers.get('origin');
  if (origin && origin !== request.nextUrl.origin) {
    return NextResponse.json({ detail: 'Cross-site logout rejected' }, { status: 403 });
  }

  const response = NextResponse.json({ status: 'logged_out' });
  response.cookies.delete('nova_access_token');
  response.cookies.delete('nova_refresh_token');
  return response;
}
