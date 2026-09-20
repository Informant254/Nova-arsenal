'use client';

import { ChevronRight, RefreshCw } from 'lucide-react';
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';

import { novaFetch } from '@/lib/nova-api';

type Session = {
  session_id: string;
  goal: string;
  target?: string;
  status: string;
  summary?: string;
  agents?: Record<string, unknown>;
  created_at?: string;
};

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await novaFetch<{ sessions: Session[] }>('work-sessions');
      setSessions(data.sessions || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load sessions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <main className="p-5 md:p-8 lg:p-10">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 flex items-start justify-between gap-4">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-[0.25em] text-emerald-400">
              Visibility
            </p>
            <h1 className="text-3xl font-semibold">Work sessions</h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-500">
              Read-only session monitoring in the dashboard. Starting or changing active research
              jobs remains behind the API&apos;s authorization controls.
            </p>
          </div>
          <button
            onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-sm text-zinc-400 hover:bg-white/5 hover:text-white"
          >
            <RefreshCw size={15} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="mb-5 rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {loading ? (
          <div className="panel p-8 text-sm text-zinc-500">Loading sessions…</div>
        ) : sessions.length === 0 ? (
          <div className="panel p-10 text-center">
            <div className="text-sm text-zinc-400">No work sessions yet.</div>
            <div className="mt-2 text-xs text-zinc-600">
              Sessions created through authorized workflows will appear here.
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {sessions.map((session) => (
              <Link
                key={session.session_id}
                href={'/sessions/' + encodeURIComponent(session.session_id)}
                className="panel block p-5 transition hover:border-emerald-400/20 hover:bg-white/[0.05]"
              >
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <Status value={session.status} />
                      <span className="font-mono text-xs text-zinc-600">{session.session_id}</span>
                    </div>
                    <h2 className="font-medium text-zinc-100">{session.goal || 'Untitled session'}</h2>
                    {session.target && (
                      <p className="mt-2 text-xs text-zinc-500">Target context: {session.target}</p>
                    )}
                    {session.summary && (
                      <p className="mt-3 line-clamp-3 max-w-3xl text-sm leading-6 text-zinc-400">
                        {session.summary}
                      </p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2 text-right text-xs text-zinc-500">
                    <span>{session.agents ? Object.keys(session.agents).length : 0} agents</span>
                    <ChevronRight size={15} className="text-zinc-700" />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}

function Status({ value }: { value: string }) {
  const normalized = (value || 'unknown').toLowerCase();
  const style =
    normalized === 'completed'
      ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300'
      : normalized === 'running'
        ? 'border-sky-400/20 bg-sky-400/10 text-sky-300'
        : normalized === 'failed' || normalized === 'cancelled'
          ? 'border-red-400/20 bg-red-400/10 text-red-300'
          : 'border-white/10 bg-white/5 text-zinc-400';

  return (
    <span className={'rounded-full border px-2.5 py-1 text-[11px] capitalize ' + style}>
      {normalized}
    </span>
  );
}
