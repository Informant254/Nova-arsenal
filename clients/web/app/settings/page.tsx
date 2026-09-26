'use client';

import { RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';

import { novaFetch } from '@/lib/nova-api';

type ProviderRow = {
  provider: string;
  configured: boolean;
  requires_key: boolean;
  key_env: string[];
  default_model: string;
  has_key: boolean;
  key_hint: string;
};

type UserProfile = {
  role: 'viewer' | 'analyst' | 'admin';
};

type ByokStatus = {
  primary: { provider: string; model: string; has_key: boolean };
  fallbacks: { provider: string; model: string; has_key: boolean }[];
  active_providers: string[];
  env_keys_detected: string[];
  provider_catalog: ProviderRow[];
};

type Account = {
  provider: string;
  auth_type: string;
  email: string;
  label: string;
  source: string;
  expires_at: string;
  expired: boolean;
  token_hint: string;
  updated_at: string;
  has_token: boolean;
  meta: Record<string, unknown>;
};

type LocalEndpoint = {
  kind: string;
  base_url: string;
  models: string[];
  healthy: boolean;
  preferred_model: string;
  label: string;
  error: string;
};

type AccountsStatus = {
  accounts: Account[];
  local_llm: {
    available: boolean;
    endpoints: LocalEndpoint[];
  };
};

type RoutingStatus = {
  total_routes: number;
  provider_stats: Record<
    string,
    {
      success?: number;
      failure?: number;
      avg_latency_ms?: number;
    }
  >;
  recent_routes?: Array<{
    provider: string;
    model: string;
    category: string;
    confidence: number;
    reason: string;
  }>;
};

export default function SettingsPage() {
  const [status, setStatus] = useState<ByokStatus | null>(null);
  const [accounts, setAccounts] = useState<AccountsStatus | null>(null);
  const [routing, setRouting] = useState<RoutingStatus | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [modelStatus, accountStatus, routingStatus, userProfile] = await Promise.all([
        novaFetch<ByokStatus>('llm/status'),
        novaFetch<AccountsStatus>('llm/accounts'),
        novaFetch<RoutingStatus>('llm/routing'),
        novaFetch<UserProfile>('auth/me'),
      ]);
      setStatus(modelStatus);
      setAccounts(accountStatus);
      setRouting(routingStatus);
      setProfile(userProfile);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load model status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function reload() {
    setReloading(true);
    setError('');
    try {
      await novaFetch('llm/reload', { method: 'POST' });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reload failed');
    } finally {
      setReloading(false);
    }
  }

  const observedCalls = useMemo(() => {
    return Object.values(routing?.provider_stats || {}).reduce(
      (sum, row) => sum + (row.success || 0) + (row.failure || 0),
      0,
    );
  }, [routing]);

  return (
    <main className="p-5 md:p-8 lg:p-10">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-[0.25em] text-emerald-400">
              Model control plane
            </p>
            <h1 className="text-3xl font-semibold">Models</h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-500">
              Runtime provider visibility, local engine discovery, account status, and routing telemetry.
              Full credentials are never returned to this dashboard.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => void load()}
              className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-sm text-zinc-400 hover:bg-white/5 hover:text-white"
            >
              <RefreshCw size={15} />
              Refresh
            </button>
            {profile && profile.role !== 'viewer' && (
              <button
                onClick={() => void reload()}
                disabled={reloading}
                className="rounded-xl bg-emerald-400 px-4 py-2 text-sm font-medium text-black hover:bg-emerald-300 disabled:opacity-50"
              >
                {reloading ? 'Reloading…' : 'Reload config'}
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-5 rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {loading ? (
          <div className="panel p-8 text-sm text-zinc-500">Loading model stack…</div>
        ) : status ? (
          <>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <Metric
                label="Primary"
                value={status.primary.provider}
                detail={status.primary.model}
              />
              <Metric
                label="Active providers"
                value={String(status.active_providers.length)}
                detail={status.active_providers.join(', ') || 'none'}
              />
              <Metric
                label="Observed calls"
                value={String(observedCalls)}
                detail={String(routing?.total_routes || 0) + ' routing decisions'}
              />
              <Metric
                label="Local engines"
                value={String(accounts?.local_llm?.endpoints?.length || 0)}
                detail={accounts?.local_llm?.available ? 'at least one reachable' : 'none detected'}
              />
            </div>

            <div className="mt-6 grid gap-6 lg:grid-cols-2">
              <section className="panel overflow-hidden">
                <div className="border-b border-white/10 px-5 py-4">
                  <h2 className="font-medium">Account connections</h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    Public metadata only. Tokens and refresh credentials stay server-side.
                  </p>
                </div>
                <div className="divide-y divide-white/5">
                  {(accounts?.accounts || []).length === 0 ? (
                    <div className="p-5 text-sm text-zinc-500">
                      No account-based provider logins stored.
                    </div>
                  ) : (
                    accounts!.accounts.map((account) => (
                      <div key={account.provider} className="p-5">
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <div className="font-medium">{account.label || account.provider}</div>
                            <div className="mt-1 text-xs text-zinc-500">
                              {account.provider} · {account.auth_type} · {account.source}
                            </div>
                            {account.email && (
                              <div className="mt-1 text-xs text-zinc-600">{account.email}</div>
                            )}
                          </div>
                          <span
                            className={[
                              'rounded-full border px-2.5 py-1 text-[10px]',
                              account.expired
                                ? 'border-red-400/20 bg-red-400/10 text-red-300'
                                : 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300',
                            ].join(' ')}
                          >
                            {account.expired ? 'expired' : 'available'}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <section className="panel overflow-hidden">
                <div className="border-b border-white/10 px-5 py-4">
                  <h2 className="font-medium">Local runtimes</h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    Ollama and OpenAI-compatible servers discovered by Nova.
                  </p>
                </div>
                <div className="divide-y divide-white/5">
                  {(accounts?.local_llm?.endpoints || []).length === 0 ? (
                    <div className="p-5 text-sm text-zinc-500">
                      No local model server detected.
                    </div>
                  ) : (
                    accounts!.local_llm.endpoints.map((endpoint) => (
                      <div key={endpoint.kind + endpoint.base_url} className="p-5">
                        <div className="flex items-start justify-between gap-4">
                          <div className="min-w-0">
                            <div className="font-medium">{endpoint.label || endpoint.kind}</div>
                            <div className="mt-1 truncate font-mono text-xs text-zinc-600">
                              {endpoint.base_url}
                            </div>
                            <div className="mt-2 text-xs text-zinc-500">
                              {endpoint.preferred_model || endpoint.models[0] || 'No model reported'}
                            </div>
                          </div>
                          <span
                            className={[
                              'rounded-full border px-2.5 py-1 text-[10px]',
                              endpoint.healthy
                                ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300'
                                : 'border-red-400/20 bg-red-400/10 text-red-300',
                            ].join(' ')}
                          >
                            {endpoint.healthy ? 'healthy' : 'offline'}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>

            <section className="panel mt-6 overflow-hidden">
              <div className="border-b border-white/10 px-5 py-4">
                <h2 className="font-medium">Runtime routing</h2>
                <p className="mt-1 text-xs text-zinc-500">
                  Reliability and latency learned from actual provider calls.
                </p>
              </div>
              <div className="divide-y divide-white/5">
                {Object.keys(routing?.provider_stats || {}).length === 0 ? (
                  <div className="p-5 text-sm text-zinc-500">
                    No runtime telemetry yet.
                  </div>
                ) : (
                  Object.entries(routing!.provider_stats).map(([provider, row]) => {
                    const success = row.success || 0;
                    const failure = row.failure || 0;
                    const total = success + failure;
                    const successRate = total ? Math.round((success / total) * 100) : 0;
                    return (
                      <div
                        key={provider}
                        className="grid gap-3 p-5 sm:grid-cols-[1fr_auto_auto]"
                      >
                        <div>
                          <div className="font-medium">{provider}</div>
                          <div className="mt-1 text-xs text-zinc-600">
                            {successRate}% observed success
                          </div>
                        </div>
                        <div className="text-sm text-zinc-500">{total} calls</div>
                        <div className="text-sm text-zinc-500">
                          {row.avg_latency_ms
                            ? Math.round(row.avg_latency_ms) + ' ms avg'
                            : 'latency n/a'}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </section>

            <section className="panel mt-6 overflow-hidden">
              <div className="border-b border-white/10 px-5 py-4">
                <h2 className="font-medium">Provider catalog</h2>
                <p className="mt-1 text-xs text-zinc-500">
                  Defaults are fallbacks only. Environment or account configuration wins.
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[680px] text-left text-sm">
                  <thead className="bg-black/20 text-xs uppercase tracking-wider text-zinc-600">
                    <tr>
                      <th className="px-5 py-3">Provider</th>
                      <th className="px-5 py-3">Credential</th>
                      <th className="px-5 py-3">Default model</th>
                      <th className="px-5 py-3">Environment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.provider_catalog.map((provider) => (
                      <tr key={provider.provider} className="border-t border-white/5">
                        <td className="px-5 py-4 font-medium">{provider.provider}</td>
                        <td className="px-5 py-4">
                          {!provider.requires_key ? (
                            <span className="text-emerald-300">local / no key</span>
                          ) : provider.has_key ? (
                            <span className="text-emerald-300">detected</span>
                          ) : (
                            <span className="text-zinc-600">not set</span>
                          )}
                        </td>
                        <td className="px-5 py-4 text-zinc-400">{provider.default_model}</td>
                        <td className="px-5 py-4 font-mono text-xs text-zinc-600">
                          {provider.key_env.join(', ') || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel mt-6 p-5">
              <h2 className="font-medium">Configuration</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-500">
                Provider credentials and model overrides stay in the server environment or
                <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5 text-zinc-300">.env</code>.
                Useful overrides include
                <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5 text-zinc-300">LLM_PROVIDER</code>
                and
                <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5 text-zinc-300">LLM_MODEL</code>.
                The dashboard intentionally does not accept or display full secret keys.
              </p>
            </section>
          </>
        ) : (
          <div className="panel p-8 text-sm text-zinc-500">No model status available.</div>
        )}
      </div>
    </main>
  );
}

function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="panel p-5">
      <div className="text-xs uppercase tracking-wider text-zinc-600">{label}</div>
      <div className="mt-3 truncate text-2xl font-semibold">{value}</div>
      <div className="mt-1 truncate text-xs text-zinc-500">{detail}</div>
    </div>
  );
}
