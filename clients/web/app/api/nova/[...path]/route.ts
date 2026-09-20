import type { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';

const API_BASE = (process.env.AGENT_API_URL || 'http://localhost:8000').replace(/\/$/, '');

async function proxy(request: NextRequest, path: string[]) {
  const suffix = path.map(encodeURIComponent).join('/');
  const url = new URL(`${API_BASE}/api/${suffix}`);
  request.nextUrl.searchParams.forEach((value, key) => url.searchParams.append(key, value));

  const headers = new Headers();
  const contentType = request.headers.get('content-type');
  const authorization = request.headers.get('authorization');
  const accept = request.headers.get('accept');

  if (contentType) headers.set('content-type', contentType);
  if (authorization) headers.set('authorization', authorization);
  if (accept) headers.set('accept', accept);

  const hasBody = !['GET', 'HEAD'].includes(request.method);
  const upstream = await fetch(url, {
    method: request.method,
    headers,
    body: hasBody ? await request.arrayBuffer() : undefined,
    cache: 'no-store',
    redirect: 'manual',
  });

  const responseHeaders = new Headers();
  const upstreamType = upstream.headers.get('content-type');
  const cacheControl = upstream.headers.get('cache-control');

  if (upstreamType) responseHeaders.set('content-type', upstreamType);
  if (cacheControl) responseHeaders.set('cache-control', cacheControl);
  responseHeaders.set('x-nova-upstream-status', String(upstream.status));

  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
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
