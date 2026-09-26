'use client';

import { Activity, Bot, BrainCircuit, MessageSquareText } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';

import { novaFetch } from '@/lib/nova-api';

type LlmStatus = {
  primary: { provider: string; model: string; has_key: boolean };
  active_providers: string[];
};

type RoutingStatus = {
  total_routes: number;
  provider_stats: Record<
    string,
    { success?: number; failure?: number; avg_latency_ms?: number }
  >;
};

type SessionsResponse = {
  sessions: Array<{ session_id: string; status: string; goal: string }>;
};

export default function Home() {
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [llm, setLlm] = useState<LlmStatus | null>(null);
  const [routing, setRouting] = useState<RoutingStatus | null>(null);
  const [sessions, setSessions] = useState<SessionsResponse | null>(null);

  useEffect(() => {
    void novaFetch<{ status: string }>('health')
      .then((data) => setHealthy(data.status === 'healthy'))
      .catch(() => setHealthy(false));

    void novaFetch<LlmStatus>('llm/status').then(setLlm).catch(() => setLlm(null));
    void novaFetch<RoutingStatus>('llm/routing').then(setRouting).catch(() => setRouting(null));
    void novaFetch<SessionsResponse>('work-sessions').then(setSessions).catch(() => setSessions(null));
  }, []);

  const stats = routing?.provider_stats || {};
  const observedCalls = Object.values(stats).reduce(
    (sum, row) => sum + (row.success || 0) + (row.failure || 0),
    0,
  );

  return (
    <main className="p-5 md:p-8 lg:p-10">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-[0.25em] text-emerald-400">
              Nova-Arsenal
            </p>
            <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">
              Research workspace
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-400">
              One console for conversation, model routing, session visibility, and review.
              Active testing remains behind explicit authorization controls in the API.
            </p>
          </div>
          <Link
            href="/chat"
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-400 px-4 py-2.5 text-sm font-medium text-black transition hover:bg-emerald-300"
          >
            <MessageSquareText size={17} />
            Open Nova chat
          </Link>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Metric
            icon={Activity}
            label="API"
            value={healthy === null ? 'Checking' : healthy ? 'Healthy' : 'Offline'}
            detail="Same-origin proxy"
          />
          <Metric
            icon={BrainCircuit}
            label="Primary model"
            value={llm ? llm.primary.provider : '—'}
            detail={llm?.primary.model || 'No model status'}
          />
          <Metric
            icon={Bot}
            label="Work sessions"
            value={String(sessions?.sessions.length ?? 0)}
            detail="Visible session snapshots"
          />
          <Metric
            icon={BrainCircuit}
            label="Observed LLM calls"
            value={String(observedCalls)}
            detail={String(llm?.active_providers.length ?? 0) + ' active providers'}
          />
        </div>

        <div className="mt-8 grid gap-6 lg:grid-cols-[1.25fr_0.75fr]">
          <section className="panel p-6">
            <div className="mb-5">
              <h2 className="text-lg font-medium">Provider telemetry</h2>
              <p className="mt-1 text-sm text-zinc-500">
                Nova learns reliability and latency from actual calls instead of imaginary benchmark tables.
              </p>
            </div>
            <div className="space-y-3">
              {Object.keys(stats).length === 0 ? (
                <Empty text="No runtime routing telemetry yet. Chat with Nova to generate some." />
              ) : (
                Object.entries(stats).map(([provider, row]) => {
                  const success = row.success || 0;
                  const failure = row.failure || 0;
                  const total = success + failure;
                  const successRate = total ? Math.round((success / total) * 100) : 0;
                  return (
                    <div
                      key={provider}
                      className="grid gap-2 rounded-xl border border-white/10 bg-black/20 p-4 sm:grid-cols-[1fr_auto_auto]"
                    >
                      <div>
                        <div className="font-medium">{provider}</div>
                        <div className="text-xs text-zinc-500">{successRate}% observed success</div>
                      </div>
                      <div className="text-sm text-zinc-400">{total} calls</div>
                      <div className="text-sm text-zinc-400">
                        {row.avg_latency_ms ? Math.round(row.avg_latency_ms) + ' ms avg' : 'latency n/a'}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>

          <section className="panel p-6">
            <h2 className="text-lg font-medium">Active brain</h2>
            <div className="mt-5 rounded-xl border border-emerald-400/15 bg-emerald-400/[0.05] p-4">
              <div className="text-xs uppercase tracking-wider text-zinc-500">Primary</div>
              <div className="mt-2 text-lg font-medium text-emerald-200">
                {llm ? llm.primary.provider + ' / ' + llm.primary.model : 'Unavailable'}
              </div>
            </div>
            <div className="mt-5">
              <div className="mb-2 text-xs uppercase tracking-wider text-zinc-500">Active providers</div>
              <div className="flex flex-wrap gap-2">
                {(llm?.active_providers || []).length ? (
                  llm!.active_providers.map((provider) => (
                    <span
                      key={provider}
                      className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-zinc-300"
                    >
                      {provider}
                    </span>
                  ))
                ) : (
                  <span className="text-sm text-zinc-500">None reported</span>
                )}
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="panel p-5">
      <div className="mb-5 flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-zinc-500">{label}</span>
        <Icon size={17} className="text-emerald-400" />
      </div>
      <div className="truncate text-2xl font-semibold">{value}</div>
      <div className="mt-1 truncate text-xs text-zinc-500">{detail}</div>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-zinc-500">
      {text}
    </div>
  );
}
