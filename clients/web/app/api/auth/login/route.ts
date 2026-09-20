import { NextRequest, NextResponse } from 'next/server';

const API_BASE = (process.env.AGENT_API_URL || 'http://localhost:8000').replace(/\/$/, '');

export async function POST(request: NextRequest) {
  const payload = await request.json();

  const upstream = await fetch(API_BASE + '/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    cache: 'no-store',
  });

  if (!upstream.ok) {
    const body = await upstream.text();
    return new NextResponse(body, {
      status: upstream.status,
      headers: {
        'content-type': upstream.headers.get('content-type') || 'application/json',
      },
    });
  }

  const tokens = (await upstream.json()) as {
    access_token: string;
    refresh_token: string;
  };

  const response = NextResponse.json({ status: 'ok' });
  const secure = process.env.NODE_ENV === 'production';

  response.cookies.set('nova_access_token', tokens.access_token, {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    path: '/',
    maxAge: 60 * 60 * 24,
  });
  response.cookies.set('nova_refresh_token', tokens.refresh_token, {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });

  return response;
}
