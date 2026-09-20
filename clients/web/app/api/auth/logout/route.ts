import { NextResponse } from 'next/server';

export async function POST() {
  const response = NextResponse.json({ status: 'logged_out' });
  response.cookies.delete('nova_access_token');
  response.cookies.delete('nova_refresh_token');
  return response;
}
