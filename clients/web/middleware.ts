import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
  const hasAccess = Boolean(request.cookies.get('nova_access_token')?.value);
  const hasRefresh = Boolean(request.cookies.get('nova_refresh_token')?.value);

  if (!hasAccess && !hasRefresh) {
    const login = new URL('/login', request.url);
    login.searchParams.set('next', request.nextUrl.pathname);
    return NextResponse.redirect(login);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!login|api|_next/static|_next/image|favicon.ico).*)'],
};
