'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Bot,
  BrainCircuit,
  LogOut,
  MessageSquareText,
  Waves,
} from 'lucide-react';
import type { ReactNode } from 'react';

const items = [
  { href: '/', label: 'Overview', icon: Waves },
  { href: '/chat', label: 'Chat', icon: MessageSquareText },
  { href: '/sessions', label: 'Sessions', icon: Bot },
  { href: '/settings', label: 'Models', icon: BrainCircuit },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  if (pathname === '/login') {
    return <>{children}</>;
  }

  async function logout() {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.localStorage.removeItem('nova_chat_session');
    window.location.assign('/login');
  }

  return (
    <div className="min-h-screen bg-[#070a0f] text-zinc-100">
      <div className="mx-auto flex min-h-screen max-w-[1600px]">
        <aside className="hidden w-64 shrink-0 border-r border-white/10 bg-black/20 p-5 md:flex md:flex-col">
          <Link href="/" className="mb-8 flex items-center gap-3 px-2">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-emerald-400/20 bg-emerald-400/10 text-emerald-300">
              N
            </div>
            <div>
              <div className="font-semibold tracking-wide">NOVA</div>
              <div className="text-xs text-zinc-500">Arsenal console</div>
            </div>
          </Link>

          <nav className="space-y-1">
            {items.map(({ href, label, icon: Icon }) => {
              const active = href === '/' ? pathname === '/' : pathname.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={[
                    'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition',
                    active
                      ? 'bg-emerald-400/10 text-emerald-200 ring-1 ring-emerald-400/20'
                      : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-100',
                  ].join(' ')}
                >
                  <Icon size={17} />
                  {label}
                </Link>
              );
            })}
          </nav>

          <div className="mt-auto space-y-3">
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3 text-xs leading-5 text-zinc-500">
              Active testing stays behind Nova&apos;s authorization controls. The dashboard focuses on
              conversation, visibility, and review.
            </div>
            <button
              onClick={() => void logout()}
              className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-zinc-500 transition hover:bg-white/5 hover:text-zinc-200"
            >
              <LogOut size={16} />
              Sign out
            </button>
          </div>
        </aside>

        <div className="min-w-0 flex-1">
          <header className="flex items-center justify-between border-b border-white/10 bg-black/20 px-5 py-4 md:hidden">
            <Link href="/" className="font-semibold tracking-wide text-emerald-300">
              NOVA
            </Link>
            <div className="flex items-center gap-1">
              {items.map(({ href, label, icon: Icon }) => (
                <Link
                  key={href}
                  href={href}
                  aria-label={label}
                  className="rounded-lg p-2 text-zinc-400 hover:bg-white/5 hover:text-white"
                >
                  <Icon size={18} />
                </Link>
              ))}
              <button
                onClick={() => void logout()}
                aria-label="Sign out"
                className="rounded-lg p-2 text-zinc-500 hover:bg-white/5 hover:text-white"
              >
                <LogOut size={18} />
              </button>
            </div>
          </header>
          {children}
        </div>
      </div>
    </div>
  );
}
