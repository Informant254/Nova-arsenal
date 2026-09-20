import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const API_BASE = (process.env.AGENT_API_URL || 'http://localhost:8000').replace(/\/$/, '');

type Tokens = {
  access_token: string;
  refresh_token: string;
};

function applyAuthCookies(response: NextResponse, tokens: Tokens) {
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
}

function buildHeaders(request: NextRequest, accessToken?: string) {
  const headers = new Headers();
  const contentType = request.headers.get('content-type');
  const explicitAuthorization = request.headers.get('authorization');
  const accept = request.headers.get('accept');

  if (contentType) headers.set('content-type', contentType);
  if (accept) headers.set('accept', accept);

  if (explicitAuthorization) {
    headers.set('authorization', explicitAuthorization);
  } else if (accessToken) {
    headers.set('authorization', 'Bearer ' + accessToken);
  }

  return headers;
}

async function refreshAccessToken(refreshToken: string): Promise<Tokens | null> {
  const url = new URL(API_BASE + '/api/auth/refresh');
  url.searchParams.set('refresh_token', refreshToken);

  const response = await fetch(url, {
    method: 'POST',
    cache: 'no-store',
  });

  if (!response.ok) return null;
  return (await response.json()) as Tokens;
}

async function proxy(request: NextRequest, path: string[]) {
  const suffix = path.map(encodeURIComponent).join('/');
  const url = new URL(API_BASE + '/api/' + suffix);
  request.nextUrl.searchParams.forEach((value, key) => url.searchParams.append(key, value));

  const hasBody = !['GET', 'HEAD'].includes(request.method);
  const body = hasBody ? await request.arrayBuffer() : undefined;
  const originalAccessToken = request.cookies.get('nova_access_token')?.value;
  const refreshToken = request.cookies.get('nova_refresh_token')?.value;

  const send = (accessToken?: string) =>
    fetch(url, {
      method: request.method,
      headers: buildHeaders(request, accessToken),
      body,
      cache: 'no-store',
      redirect: 'manual',
    });

  let upstream = await send(originalAccessToken);
  let refreshedTokens: Tokens | null = null;

  if (upstream.status === 401 && refreshToken) {
    refreshedTokens = await refreshAccessToken(refreshToken);
    if (refreshedTokens) {
      upstream = await send(refreshedTokens.access_token);
    }
  }

  const responseHeaders = new Headers();
  const upstreamType = upstream.headers.get('content-type');
  const cacheControl = upstream.headers.get('cache-control');

  if (upstreamType) responseHeaders.set('content-type', upstreamType);
  if (cacheControl) responseHeaders.set('cache-control', cacheControl);
  responseHeaders.set('x-nova-upstream-status', String(upstream.status));

  const response = new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });

  if (refreshedTokens) applyAuthCookies(response, refreshedTokens);
  if (upstream.status === 401 && refreshToken && !refreshedTokens) {
    response.cookies.delete('nova_access_token');
    response.cookies.delete('nova_refresh_token');
  }

  return response;
}

type RouteContext = { params: { path: string[] } };

export async function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context.params.path);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context.params.path);
}

export async function PUT(request: NextRequest, context: RouteContext) {
  return proxy(request, context.params.path);
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  return proxy(request, context.params.path);
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  return proxy(request, context.params.path);
}
