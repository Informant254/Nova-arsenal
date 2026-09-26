'use client';

import { ArrowLeft, RefreshCw } from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';

import { novaFetch } from '@/lib/nova-api';

type AgentResult = {
  agent_id: string;
  role: string;
  status: string;
  findings: Array<Record<string, unknown>>;
  summary: string;
  confidence: number;
  steps: number;
  duration_ms: number;
  error?: string;
};

type SessionEvent = {
  event_type: string;
  message: string;
  agent_id?: string;
  ts: string;
};

type SessionDetail = {
  session_id: string;
  goal: string;
  target: string;
  status: string;
  roles: string[];
  max_concurrent: number;
  authorized: boolean;
  authorization_ref: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  agents: Record<string, AgentResult>;
  agent_count: number;
  findings_count: number;
  summary?: string;
  events?: SessionEvent[];
  event_count?: number;
};

export default function SessionDetailPage() {
  const params = useParams<{ sessionId: string }>();
  const sessionId = params?.sessionId || '';
  const [session, setSession] = useState<SessionDetail | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError('');
    try {
      const data = await novaFetch<SessionDetail>(
        'work-sessions/' + encodeURIComponent(sessionId),
      );
      setSession(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load session');
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void load();
  }, [load]);

  const agents = useMemo(
    () => Object.values(session?.agents || {}),
    [session],
  );

  const completedAgents = agents.filter((agent) => agent.status === 'completed').length;
  const failedAgents = agents.filter((agent) => agent.status === 'failed').length;

  return (
    <main className="p-5 md:p-8 lg:p-10">
      <div className="mx-auto max-w-6xl">
        <div className="mb-6 flex items-center justify-between gap-3">
          <Link
            href="/sessions"
            className="inline-flex items-center gap-2 text-sm text-zinc-500 transition hover:text-zinc-200"
          >
            <ArrowLeft size={15} />
            Work sessions
          </Link>
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
          <div className="panel p-8 text-sm text-zinc-500">Loading session…</div>
        ) : !session ? (
          <div className="panel p-8 text-sm text-zinc-500">Session unavailable.</div>
        ) : (
          <>
            <section className="panel p-6">
              <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <Status value={session.status} />
                    <span className="font-mono text-xs text-zinc-600">
                      {session.session_id}
                    </span>
                  </div>
                  <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">
                    {session.goal || 'Untitled work session'}
                  </h1>
                  <p className="mt-3 text-sm text-zinc-500">
                    Target context: {session.target || 'unspecified'}
                  </p>
                  {session.summary && (
                    <p className="mt-5 max-w-4xl text-sm leading-6 text-zinc-400">
                      {session.summary}
                    </p>
                  )}
                </div>

                <div className="grid min-w-[240px] grid-cols-2 gap-3 text-center">
                  <Metric label="Agents" value={String(session.agent_count ?? agents.length)} />
                  <Metric label="Findings" value={String(session.findings_count ?? 0)} />
                  <Metric label="Completed" value={String(completedAgents)} />
                  <Metric label="Failed" value={String(failedAgents)} />
                </div>
              </div>
            </section>

            <div className="mt-6 grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
              <section className="panel overflow-hidden">
                <div className="border-b border-white/10 px-5 py-4">
                  <h2 className="font-medium">Agent outcomes</h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    Read-only results from the session workers.
                  </p>
                </div>
                <div className="divide-y divide-white/5">
                  {agents.length === 0 ? (
                    <div className="p-6 text-sm text-zinc-500">No agents recorded.</div>
                  ) : (
                    agents.map((agent) => (
                      <article key={agent.agent_id} className="p-5">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-medium capitalize">{agent.role}</span>
                              <Status value={agent.status} compact />
                            </div>
                            <div className="mt-1 font-mono text-[10px] text-zinc-700">
                              {agent.agent_id}
                            </div>
                          </div>
                          <div className="text-right text-xs text-zinc-500">
                            <div>{agent.findings?.length || 0} findings</div>
                            <div className="mt-1">
                              {agent.duration_ms ? Math.round(agent.duration_ms) + ' ms' : 'duration n/a'}
                            </div>
                          </div>
                        </div>

                        {agent.summary && (
                          <p className="mt-3 text-sm leading-6 text-zinc-400">
                            {agent.summary}
                          </p>
                        )}

                        {agent.error && (
                          <div className="mt-3 rounded-lg border border-red-400/15 bg-red-400/5 px-3 py-2 text-xs text-red-300">
                            {agent.error}
                          </div>
                        )}
                      </article>
                    ))
                  )}
                </div>
              </section>

              <div className="space-y-6">
                <section className="panel p-5">
                  <h2 className="font-medium">Authorization</h2>
                  <div className="mt-4 space-y-3 text-sm">
                    <Row
                      label="Explicitly authorized"
                      value={session.authorized ? 'Yes' : 'No'}
                      emphasis={session.authorized}
                    />
                    <Row
                      label="Reference"
                      value={session.authorization_ref || 'Not provided'}
                    />
                    <Row
                      label="Max concurrency"
                      value={String(session.max_concurrent)}
                    />
                    <Row
                      label="Roles"
                      value={(session.roles || []).join(', ') || 'None'}
                    />
                  </div>
                </section>

                <section className="panel overflow-hidden">
                  <div className="border-b border-white/10 px-5 py-4">
                    <h2 className="font-medium">Timeline</h2>
                    <p className="mt-1 text-xs text-zinc-500">
                      Latest {Math.min(session.events?.length || 0, 100)} of {session.event_count || session.events?.length || 0} events.
                    </p>
                  </div>
                  <div className="max-h-[520px] overflow-y-auto">
                    {(session.events || []).length === 0 ? (
                      <div className="p-5 text-sm text-zinc-500">No events recorded.</div>
                    ) : (
                      <div className="divide-y divide-white/5">
                        {(session.events || []).map((event, index) => (
                          <div key={event.ts + '-' + index} className="p-4">
                            <div className="flex items-center justify-between gap-3">
                              <span className="text-xs font-medium text-zinc-300">
                                {event.event_type.replaceAll('_', ' ')}
                              </span>
                              <span className="text-[10px] text-zinc-700">
                                {formatDate(event.ts)}
                              </span>
                            </div>
                            <p className="mt-2 text-xs leading-5 text-zinc-500">
                              {event.message}
                            </p>
                            {event.agent_id && (
                              <div className="mt-2 font-mono text-[10px] text-zinc-700">
                                {event.agent_id}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </section>
              </div>
            </div>
          </>
        )}
      </div>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-3">
      <div className="text-xl font-semibold">{value}</div>
      <div className="mt-1 text-[10px] uppercase tracking-wider text-zinc-600">{label}</div>
    </div>
  );
}

function Row({
  label,
  value,
  emphasis = false,
}: {
  label: string;
  value: string;
  emphasis?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-zinc-600">{label}</span>
      <span className={emphasis ? 'text-right text-emerald-300' : 'text-right text-zinc-300'}>
        {value}
      </span>
    </div>
  );
}

function Status({
  value,
  compact = false,
}: {
  value: string;
  compact?: boolean;
}) {
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
    <span
      className={
        'rounded-full border capitalize ' +
        style +
        (compact ? ' px-2 py-0.5 text-[10px]' : ' px-2.5 py-1 text-[11px]')
      }
    >
      {normalized}
    </span>
  );
}

function formatDate(value: string) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
}
